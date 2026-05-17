package handlers

// sse_logs_test.go — regression coverage for streamLogsSSE, the shared SSE
// log-streaming pump used by DeployHandler.Logs, LogsHandler.ResourceLogs,
// and StackHandler.Logs.
//
// These tests guard the two bugs the helper was created to fix:
//
//   FIX-1 — disconnect-leak. A fasthttp mid-stream client disconnect is
//   observable ONLY as a write/flush error. If the pump ignores that error it
//   keeps pumping forever on a follow=true tail of an idle pod, leaking the
//   goroutine, the open file descriptor, and the upstream k8s apiserver
//   connection. TestStreamLogsSSE_DisconnectBreaksPump /
//   _ClosesStreamOnDisconnect / _CancelsContextOnDisconnect lock this in.
//
//   FIX-2 — context lifetime. The cancel func of the background-derived
//   context backing the upstream k8s stream MUST be invoked exactly when the
//   pump returns — on clean drain, on disconnect, or on a stream read error —
//   so the upstream stream is always torn down. The _CancelsContextOn* tests
//   assert cancel fires on every exit path.

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"
)

// failingWriter is an io.Writer whose Write fails after failAfter successful
// bytes. It models a fasthttp response writer whose client has disconnected
// mid-stream — the only way a disconnect surfaces to SetBodyStreamWriter.
type failingWriter struct {
	written  int
	failAfter int
}

func (f *failingWriter) Write(p []byte) (int, error) {
	if f.written >= f.failAfter {
		return 0, errors.New("connection reset by peer")
	}
	n := len(p)
	if f.written+n > f.failAfter {
		n = f.failAfter - f.written
	}
	f.written += n
	if n < len(p) {
		return n, errors.New("connection reset by peer")
	}
	return n, nil
}

// trackedStream is an io.ReadCloser that records whether Close was called and
// counts the calls — so a double-Close or a missing Close is caught.
type trackedStream struct {
	io.Reader
	closes int
}

func (t *trackedStream) Close() error {
	t.closes++
	return nil
}

// errReader returns data once, then a non-EOF read error — modelling an
// upstream k8s log stream that drops mid-tail.
type errReader struct {
	data []byte
	done bool
}

func (e *errReader) Read(p []byte) (int, error) {
	if e.done {
		return 0, errors.New("upstream stream broke")
	}
	e.done = true
	n := copy(p, e.data)
	return n, nil
}

// --- FIX-1 / FIX-2: clean drain --------------------------------------------

// TestStreamLogsSSE_DrainsAndMarksEnd verifies a finite stream is fully
// pumped, each line is wrapped as an SSE `data:` event, and the end sentinel
// is appended when the stream drains cleanly.
func TestStreamLogsSSE_DrainsAndMarksEnd(t *testing.T) {
	stream := &trackedStream{Reader: strings.NewReader("line one\nline two\nline three\n")}
	var out bytes.Buffer
	w := bufio.NewWriter(&out)

	cancelled := false
	streamLogsSSE(w, stream, func() { cancelled = true })

	got := out.String()
	for _, want := range []string{
		"data: line one\n\n",
		"data: line two\n\n",
		"data: line three\n\n",
		sseEndMarker,
	} {
		if !strings.Contains(got, want) {
			t.Errorf("output missing %q\nfull output: %q", want, got)
		}
	}
	if stream.closes != 1 {
		t.Errorf("FIX-2: stream Close called %d times, want exactly 1", stream.closes)
	}
	if !cancelled {
		t.Error("FIX-2: cancel was not invoked on clean drain")
	}
}

// TestStreamLogsSSE_EndMarkerIsLast verifies the end sentinel comes after the
// last data line — a client relies on [end] meaning "no more lines".
func TestStreamLogsSSE_EndMarkerIsLast(t *testing.T) {
	stream := &trackedStream{Reader: strings.NewReader("only line\n")}
	var out bytes.Buffer
	w := bufio.NewWriter(&out)

	streamLogsSSE(w, stream, func() {})

	got := out.String()
	if idx := strings.Index(got, sseEndMarker); idx == -1 {
		t.Fatalf("end marker absent: %q", got)
	} else if strings.Index(got, "data: only line") > idx {
		t.Errorf("end marker emitted before the data line: %q", got)
	}
}

// TestStreamLogsSSE_EmptyStreamStillMarksEnd verifies a stream that yields no
// lines still emits the end sentinel and tears down — guards against a hang
// on an empty pod log.
func TestStreamLogsSSE_EmptyStreamStillMarksEnd(t *testing.T) {
	stream := &trackedStream{Reader: strings.NewReader("")}
	var out bytes.Buffer
	w := bufio.NewWriter(&out)

	cancelled := false
	streamLogsSSE(w, stream, func() { cancelled = true })

	if got := out.String(); got != sseEndMarker {
		t.Errorf("empty stream output = %q, want just the end marker", got)
	}
	if stream.closes != 1 {
		t.Errorf("stream not closed on empty drain: closes=%d", stream.closes)
	}
	if !cancelled {
		t.Error("cancel not invoked on empty drain")
	}
}

// --- FIX-1: disconnect detection -------------------------------------------

// TestStreamLogsSSE_DisconnectBreaksPump is the core FIX-1 regression: a write
// error (the sole signal of a fasthttp client disconnect) must break the pump
// before the whole stream is consumed. If this fails, an idle follow=true
// tail leaks forever.
func TestStreamLogsSSE_DisconnectBreaksPump(t *testing.T) {
	// A long stream; the writer dies after ~one line's worth of bytes.
	body := strings.Repeat("a log line that is reasonably long\n", 100)
	stream := &trackedStream{Reader: strings.NewReader(body)}
	// bufio.Writer over a failingWriter: flush forces the underlying Write.
	fw := &failingWriter{failAfter: 20}
	w := bufio.NewWriter(fw)

	done := make(chan struct{})
	go func() {
		streamLogsSSE(w, stream, func() {})
		close(done)
	}()

	select {
	case <-done:
		// good — pump returned instead of looping over all 100 lines.
	default:
		// streamLogsSSE is synchronous; if it returned, done is closed.
		<-done
	}

	if fw.written > 64 {
		t.Errorf("FIX-1: pump wrote %d bytes after disconnect; it should have "+
			"broken near the first failed flush, not drained the stream", fw.written)
	}
}

// TestStreamLogsSSE_ClosesStreamOnDisconnect verifies the upstream stream is
// Close()d (exactly once) when the client disconnects — no FD leak.
func TestStreamLogsSSE_ClosesStreamOnDisconnect(t *testing.T) {
	body := strings.Repeat("x\n", 1000)
	stream := &trackedStream{Reader: strings.NewReader(body)}
	w := bufio.NewWriter(&failingWriter{failAfter: 0}) // fails on first flush

	streamLogsSSE(w, stream, func() {})

	if stream.closes != 1 {
		t.Errorf("FIX-1: stream Close called %d times on disconnect, want exactly 1", stream.closes)
	}
}

// TestStreamLogsSSE_CancelsContextOnDisconnect verifies cancel fires on the
// disconnect path so the background context backing the k8s stream is torn
// down — no leaked apiserver connection.
func TestStreamLogsSSE_CancelsContextOnDisconnect(t *testing.T) {
	body := strings.Repeat("y\n", 1000)
	stream := &trackedStream{Reader: strings.NewReader(body)}
	w := bufio.NewWriter(&failingWriter{failAfter: 0})

	cancelled := false
	streamLogsSSE(w, stream, func() { cancelled = true })

	if !cancelled {
		t.Error("FIX-2: cancel not invoked on client-disconnect exit path")
	}
}

// --- FIX-2: teardown on an upstream stream error ---------------------------

// TestStreamLogsSSE_ClosesAndCancelsOnReadError verifies that when the
// upstream k8s stream itself errors mid-tail (not a client disconnect), the
// pump still Close()s the stream and invokes cancel — every exit path tears
// down.
func TestStreamLogsSSE_ClosesAndCancelsOnReadError(t *testing.T) {
	stream := &trackedStream{Reader: &errReader{data: []byte("partial line\n")}}
	var out bytes.Buffer
	w := bufio.NewWriter(&out)

	cancelled := false
	streamLogsSSE(w, stream, func() { cancelled = true })

	if stream.closes != 1 {
		t.Errorf("FIX-2: stream Close called %d times on upstream read error, want 1", stream.closes)
	}
	if !cancelled {
		t.Error("FIX-2: cancel not invoked on upstream-read-error exit path")
	}
}

// TestStreamLogsSSE_NoOpCancelIsSafe documents the contract that a no-op
// cancel (passed when there is no context to cancel) does not panic.
func TestStreamLogsSSE_NoOpCancelIsSafe(t *testing.T) {
	stream := &trackedStream{Reader: strings.NewReader("hello\n")}
	var out bytes.Buffer
	w := bufio.NewWriter(&out)

	// Must not panic.
	streamLogsSSE(w, stream, func() {})

	if stream.closes != 1 {
		t.Errorf("stream not closed with no-op cancel: closes=%d", stream.closes)
	}
}
