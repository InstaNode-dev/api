package email_test

import (
	"context"
	"testing"
	"time"

	"instant.dev/internal/email"
)

// noopClient returns a noop email client (no RESEND_API_KEY).
func noopClient() *email.Client {
	return email.New("")
}

// TestSendPaymentFailed_NoopClient_ReturnsNil verifies the noop client returns nil without error.
func TestSendPaymentFailed_NoopClient_ReturnsNil(t *testing.T) {
	c := noopClient()
	err := c.SendPaymentFailed(context.Background(), "user@example.com", 1, nil)
	if err != nil {
		t.Fatalf("expected nil error from noop client, got: %v", err)
	}
}

// TestSendPaymentFailed_AttemptCount1_NotUrgent verifies attempt 1 sends without error.
func TestSendPaymentFailed_AttemptCount1_NotUrgent(t *testing.T) {
	c := noopClient()
	next := time.Now().Add(72 * time.Hour)
	err := c.SendPaymentFailed(context.Background(), "user@example.com", 1, &next)
	if err != nil {
		t.Fatalf("attempt 1: expected nil, got: %v", err)
	}
}

// TestSendPaymentFailed_AttemptCount3_FinalAttempt verifies the final attempt (3) sends without error.
func TestSendPaymentFailed_AttemptCount3_FinalAttempt(t *testing.T) {
	c := noopClient()
	err := c.SendPaymentFailed(context.Background(), "user@example.com", 3, nil)
	if err != nil {
		t.Fatalf("attempt 3 (final): expected nil, got: %v", err)
	}
}

// TestSendPaymentFailed_NilNextAttemptDate verifies nil nextAttemptDate does not panic.
func TestSendPaymentFailed_NilNextAttemptDate(t *testing.T) {
	c := noopClient()
	// Must not panic.
	err := c.SendPaymentFailed(context.Background(), "user@example.com", 2, nil)
	if err != nil {
		t.Fatalf("nil nextAttemptDate: expected nil, got: %v", err)
	}
}

// TestSendPaymentFailed_WithNextAttemptDate verifies a non-nil nextAttemptDate sends without error.
func TestSendPaymentFailed_WithNextAttemptDate(t *testing.T) {
	c := noopClient()
	next := time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)
	err := c.SendPaymentFailed(context.Background(), "user@example.com", 2, &next)
	if err != nil {
		t.Fatalf("with nextAttemptDate: expected nil, got: %v", err)
	}
}

// Trial email tests removed on 2026-05-14 per policy memory
// project_no_trial_pay_day_one.md — the SendTrialStarted, SendTrialWarning,
// and SendTrialExpired functions no longer exist.
