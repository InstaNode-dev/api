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

// TestSendTrialWarning_NoopClient_ReturnsNil verifies the noop client returns nil.
func TestSendTrialWarning_NoopClient_ReturnsNil(t *testing.T) {
	c := noopClient()
	trialEnd := time.Now().Add(48 * time.Hour)
	err := c.SendTrialWarning(context.Background(), "user@example.com", 3, trialEnd)
	if err != nil {
		t.Fatalf("SendTrialWarning: expected nil, got: %v", err)
	}
}

// TestSendTrialExpired_NoopClient_ReturnsNil verifies the noop client returns nil.
func TestSendTrialExpired_NoopClient_ReturnsNil(t *testing.T) {
	c := noopClient()
	err := c.SendTrialExpired(context.Background(), "user@example.com")
	if err != nil {
		t.Fatalf("SendTrialExpired: expected nil, got: %v", err)
	}
}

// TestSendTrialStarted_NoopClient_ReturnsNil verifies the noop client returns nil.
func TestSendTrialStarted_NoopClient_ReturnsNil(t *testing.T) {
	c := noopClient()
	trialEnd := time.Now().Add(14 * 24 * time.Hour)
	err := c.SendTrialStarted(context.Background(), "user@example.com", "Acme Corp", trialEnd)
	if err != nil {
		t.Fatalf("SendTrialStarted: expected nil, got: %v", err)
	}
}
