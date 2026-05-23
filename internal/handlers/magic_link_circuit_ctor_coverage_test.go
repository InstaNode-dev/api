package handlers

// magic_link_circuit_ctor_coverage_test.go — covers the three public
// constructors / accessors on the magic-link circuit breaker that the
// existing white-box state-machine tests don't touch (they use the
// with-config test constructor instead). Pure logic, no backends.

import (
	"context"
	"errors"
	"testing"
)

func TestMagicLinkCircuit_PublicConstructors(t *testing.T) {
	// newCircuitBreakingMailer wires the package-default threshold/cooldown.
	inner := &flakyMailer{}
	cb := newCircuitBreakingMailer(inner)
	if cb.threshold != magicLinkCircuitThreshold {
		t.Errorf("threshold = %d; want %d", cb.threshold, magicLinkCircuitThreshold)
	}
	if cb.cooldown != magicLinkCircuitCooldown {
		t.Errorf("cooldown = %v; want %v", cb.cooldown, magicLinkCircuitCooldown)
	}

	// NewCircuitBreakingMagicLinkMailer returns the interface form and a
	// success call passes through to the inner mailer.
	m := NewCircuitBreakingMagicLinkMailer(inner)
	if m == nil {
		t.Fatal("NewCircuitBreakingMagicLinkMailer returned nil")
	}
	if err := m.SendMagicLink(context.Background(), "a@b.com", "https://x"); err != nil {
		t.Fatalf("SendMagicLink (closed, inner ok): %v", err)
	}
}

func TestMagicLinkCircuit_MetricsSnapshot(t *testing.T) {
	// Drive one success + one failure so the snapshot reflects real movement.
	before := GetMagicLinkCircuitMetrics()
	inner := &flakyMailer{}
	cb := newCircuitBreakingMailer(inner)
	_ = cb.SendMagicLink(context.Background(), "a@b.com", "https://x") // success
	inner.setErr(errors.New("boom"))
	_ = cb.SendMagicLink(context.Background(), "a@b.com", "https://x") // failure

	after := GetMagicLinkCircuitMetrics()
	if after.Attempts < before.Attempts+2 {
		t.Errorf("Attempts did not advance: before=%d after=%d", before.Attempts, after.Attempts)
	}
	if after.Failures < before.Failures+1 {
		t.Errorf("Failures did not advance: before=%d after=%d", before.Failures, after.Failures)
	}
}
