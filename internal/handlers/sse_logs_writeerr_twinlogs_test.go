package handlers

// sse_logs_writeerr_twinlogs_test.go — covers the two write-error early-return
// arms of streamLogsSSE (sse_logs.go) that the existing sse_logs_test.go leaves
// open because its failingWriter only ever surfaces the error at the *Flush*
// call (line 64), never at the WriteString call itself:
//
//	sse_logs.go:61-63  — WriteString of a data line returns an error → return.
//	sse_logs.go:72-74  — WriteString of the end marker returns an error → return.
//
// A bufio.Writer's WriteString only returns an error when an internal flush
// (forced when its buffer fills) hits the underlying writer's error. The
// existing tests use the default 4 KiB buffer, so the small SSE lines never
// force a mid-WriteString flush — the error always lands on the explicit
// w.Flush() instead. Wrapping an immediately-failing writer in a size-1 bufio
// buffer forces the flush to happen *inside* WriteString, surfacing the error
// at lines 61 and 72.

import (
	"bufio"
	"strings"
	"testing"
)

// alwaysFailWriter fails on the very first Write — modelling a fasthttp client
// that disconnected before any byte landed.
type alwaysFailWriter struct{ writes int }

func (a *alwaysFailWriter) Write(p []byte) (int, error) {
	a.writes++
	return 0, errWriteClosed
}

// errWriteClosed is a sentinel write error (kept as a package-level var so the
// closure above stays allocation-free and the intent is named).
var errWriteClosed = &writeClosedError{}

type writeClosedError struct{}

func (*writeClosedError) Error() string { return "writer closed" }

// TestStreamLogsSSE_DataWriteStringError_BreaksPump drives sse_logs.go:61-63:
// the WriteString of a data line returns an error (not just the later Flush),
// so the pump returns immediately and the deferred Close + cancel still run.
func TestStreamLogsSSE_DataWriteStringError_BreaksPump(t *testing.T) {
	stream := &trackedStream{Reader: strings.NewReader("a line that exceeds one byte\nsecond line\n")}
	// size-1 buffer → the first WriteString forces an internal flush mid-write,
	// surfacing the underlying writer error from WriteString itself (line 61),
	// not from the explicit Flush (line 64).
	fw := &alwaysFailWriter{}
	w := bufio.NewWriterSize(fw, 1)

	cancelled := false
	streamLogsSSE(w, stream, func() { cancelled = true })

	if stream.closes != 1 {
		t.Errorf("stream Close called %d times after WriteString error, want 1", stream.closes)
	}
	if !cancelled {
		t.Error("cancel not invoked after data-line WriteString error")
	}
}

// TestStreamLogsSSE_EndMarkerWriteStringError drives sse_logs.go:72-74: an empty
// stream writes no data lines, then the end-marker WriteString hits the failing
// underlying writer (via the size-1 buffer flush) and returns — exercising the
// end-marker write-error branch. Teardown (Close + cancel) still runs via defer.
func TestStreamLogsSSE_EndMarkerWriteStringError(t *testing.T) {
	stream := &trackedStream{Reader: strings.NewReader("")} // no data lines
	fw := &alwaysFailWriter{}
	w := bufio.NewWriterSize(fw, 1)

	cancelled := false
	streamLogsSSE(w, stream, func() { cancelled = true })

	if fw.writes == 0 {
		t.Error("end-marker WriteString did not reach the underlying writer")
	}
	if stream.closes != 1 {
		t.Errorf("stream Close called %d times after end-marker write error, want 1", stream.closes)
	}
	if !cancelled {
		t.Error("cancel not invoked after end-marker WriteString error")
	}
}
