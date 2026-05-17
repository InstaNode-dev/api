package handlers

// sse_logs.go — shared SSE log-streaming pump for the three live-tail handlers.
//
// DeployHandler.Logs, LogsHandler.ResourceLogs, and StackHandler.Logs all
// stream customer-app pod logs over Server-Sent Events. They used to each
// inline the same scanner-loop, which drifted: a bug-hunt flagged copy-paste
// divergence across them. streamLogsSSE is the single source of truth.
//
// Two bugs this helper fixes (and guards against re-introducing):
//
//   FIX-1 — disconnect detection. With fasthttp's SetBodyStreamWriter, a
//   client closing the browser tab mid-stream is observable ONLY as a
//   w.Flush() (or w.WriteString) error. The old code did `_ = w.Flush()`,
//   discarding that error. For a follow=true tail of an idle pod,
//   scanner.Scan() never returns false — so the goroutine, the open file
//   descriptor, and the upstream k8s apiserver connection all leaked forever
//   after the client went away. streamLogsSSE captures every write/flush
//   error and breaks the loop on the first one.
//
//   FIX-2 — context lifetime. The log stream must be opened with a context
//   derived from context.Background(), NOT the fiber request context: the
//   SetBodyStreamWriter callback runs AFTER the handler returns, by which
//   point fasthttp may have recycled/cancelled c.Context(). The caller passes
//   the cancel func of that background-derived context here; streamLogsSSE
//   invokes it when the pump returns (finite stream drained, client
//   disconnect, or write error) so the upstream k8s stream is always torn
//   down exactly when streaming ends.

import (
	"bufio"
	"io"
)

// sseEndMarker is the final SSE event written when a log stream drains to
// completion. Clients treat it as the end-of-stream sentinel.
const sseEndMarker = "data: [end]\n\n"

// streamLogsSSE pumps lines from logStream to the SSE writer w until the
// stream ends or the client disconnects, then tears everything down.
//
// It is the function passed to fasthttp's SetBodyStreamWriter. Contract:
//
//   - logStream is Close()d before return (finite drain, client disconnect,
//     or write error all reach the deferred Close).
//   - cancel is invoked before return so the background context backing the
//     upstream k8s log stream is cancelled exactly when streaming ends.
//     Pass a no-op (func(){}) if there is no context to cancel.
//   - A write or flush error (the ONLY way a fasthttp client disconnect is
//     observable) breaks the pump immediately — no goroutine/FD/apiserver
//     connection leak on an idle follow=true tail.
func streamLogsSSE(w *bufio.Writer, logStream io.ReadCloser, cancel func()) {
	defer cancel()
	defer logStream.Close()

	scanner := bufio.NewScanner(logStream)
	for scanner.Scan() {
		// A write error means the client has gone away — fasthttp surfaces a
		// mid-stream disconnect only here. Stop immediately so the deferred
		// Close + cancel tear down the upstream k8s stream.
		if _, err := w.WriteString("data: " + scanner.Text() + "\n\n"); err != nil {
			return
		}
		if err := w.Flush(); err != nil {
			return
		}
	}

	// Stream drained cleanly — signal end of stream. Errors here are ignored:
	// the client is already gone or the stream finished, and the deferred
	// Close + cancel run regardless.
	if _, err := w.WriteString(sseEndMarker); err != nil {
		return
	}
	_ = w.Flush()
}
