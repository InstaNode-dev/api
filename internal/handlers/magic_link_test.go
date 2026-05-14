package handlers

// magic_link_test.go — unit tests for the magic-link Start helpers.
//
// These tests cover the conditional-log helper extracted from Start() after
// the 2026-05-14 RESEND_API_KEY=CHANGE_ME outage. The bug was that the
// .sent log line fired unconditionally AFTER the warn line, so NR alerting
// saw every magic-link request as "sent" while no emails were actually
// delivered. These assertions guard the mutually-exclusive invariant:
// exactly one of {email_send_failed, sent} fires per Start() call.
//
// Lives in package `handlers` (not handlers_test) so we can call the
// package-private logMagicLinkSendResult without re-exporting it.

import (
	"bytes"
	"encoding/json"
	"errors"
	"log/slog"
	"strings"
	"testing"
)

// captureSlog redirects the default slog logger to an in-memory buffer for
// the duration of fn and returns the captured JSON lines. The handler in
// behaviour-under-test uses slog.Info / slog.Warn against the default
// logger; we swap it out, run, then restore the previous default.
func captureSlog(t *testing.T, fn func()) string {
	t.Helper()
	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&buf, nil)))
	defer slog.SetDefault(prev)
	fn()
	return buf.String()
}

// extractLogMessages parses the captured JSON-lines buffer into the slice of
// `msg` strings, one per line. Used to assert presence / absence of
// specific log lines without coupling to field ordering.
func extractLogMessages(t *testing.T, captured string) []string {
	t.Helper()
	var msgs []string
	for _, line := range strings.Split(strings.TrimRight(captured, "\n"), "\n") {
		if line == "" {
			continue
		}
		var row map[string]any
		if err := json.Unmarshal([]byte(line), &row); err != nil {
			t.Fatalf("captureSlog produced non-JSON line %q: %v", line, err)
		}
		if m, ok := row["msg"].(string); ok {
			msgs = append(msgs, m)
		}
	}
	return msgs
}

// TestLogMagicLinkSendResult_SuccessEmitsSent asserts that a nil sendErr
// produces exactly the .sent line and never the email_send_failed warn.
//
// Regression guard for the original (pre-fix) bug — if a future refactor
// re-unconditions the .sent log, this test fails.
func TestLogMagicLinkSendResult_SuccessEmitsSent(t *testing.T) {
	captured := captureSlog(t, func() {
		logMagicLinkSendResult(nil, "req-success-123")
	})

	msgs := extractLogMessages(t, captured)

	var sawSent, sawFailed bool
	for _, m := range msgs {
		switch m {
		case "magic_link.start.sent":
			sawSent = true
		case "magic_link.start.email_send_failed":
			sawFailed = true
		}
	}

	if !sawSent {
		t.Errorf("expected magic_link.start.sent log line, got messages: %v\nraw: %s", msgs, captured)
	}
	if sawFailed {
		t.Errorf("did NOT expect magic_link.start.email_send_failed on success path, got messages: %v\nraw: %s", msgs, captured)
	}
}

// TestLogMagicLinkSendResult_FailureEmitsWarnNotSent is the explicit
// regression test for the 2026-05-14 outage. With a non-nil sendErr, the
// warn must fire and the .sent line must NOT fire — otherwise NR alerting
// will once again silently report email-success during a provider outage.
func TestLogMagicLinkSendResult_FailureEmitsWarnNotSent(t *testing.T) {
	captured := captureSlog(t, func() {
		logMagicLinkSendResult(errors.New("api key invalid"), "req-failure-456")
	})

	msgs := extractLogMessages(t, captured)

	var sawSent, sawFailed bool
	for _, m := range msgs {
		switch m {
		case "magic_link.start.sent":
			sawSent = true
		case "magic_link.start.email_send_failed":
			sawFailed = true
		}
	}

	if !sawFailed {
		t.Errorf("expected magic_link.start.email_send_failed log line on failure, got messages: %v\nraw: %s", msgs, captured)
	}
	if sawSent {
		t.Errorf("did NOT expect magic_link.start.sent on failure path — this is the 2026-05-14 false-success bug; got messages: %v\nraw: %s", msgs, captured)
	}
}

// TestLogMagicLinkSendResult_FailureIncludesRequestID asserts the warn-line
// payload carries the request_id field so an operator can correlate the
// failure with the request in NR (or trace it through downstream logs).
// Without this, an outage looks anonymous and we lose the per-request
// thread when triaging.
func TestLogMagicLinkSendResult_FailureIncludesRequestID(t *testing.T) {
	const wantRequestID = "req-traceability-789"

	captured := captureSlog(t, func() {
		logMagicLinkSendResult(errors.New("network timeout"), wantRequestID)
	})

	// Locate the email_send_failed JSON object and assert request_id.
	var found bool
	for _, line := range strings.Split(strings.TrimRight(captured, "\n"), "\n") {
		if line == "" {
			continue
		}
		var row map[string]any
		if err := json.Unmarshal([]byte(line), &row); err != nil {
			t.Fatalf("captureSlog produced non-JSON line %q: %v", line, err)
		}
		if row["msg"] == "magic_link.start.email_send_failed" {
			got, ok := row["request_id"].(string)
			if !ok {
				t.Errorf("magic_link.start.email_send_failed line missing request_id field: %v", row)
				continue
			}
			if got != wantRequestID {
				t.Errorf("request_id mismatch: got %q want %q", got, wantRequestID)
			}
			found = true
		}
	}
	if !found {
		t.Fatalf("did not find magic_link.start.email_send_failed line in captured output: %s", captured)
	}
}
