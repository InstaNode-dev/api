package email

// fail_open_metrics_test.go — P2 regression
// (CIRCUIT-RETRY-AUDIT-2026-05-20). Confirms the email Client's two
// documented fail-open paths bump the FailOpenEvents counter so a
// downstream Postgres brownout becomes observable instead of silent.

import (
	"context"
	"errors"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	"instant.dev/internal/metrics"
)

// counterValue reads the current value of a labelled counter via the
// prometheus DTO surface. Returns 0 if the counter / label combo doesn't
// exist yet — promauto auto-creates it on the first Inc.
func counterValue(t *testing.T, labels ...string) float64 {
	t.Helper()
	ch := make(chan prometheus.Metric, 64)
	metrics.FailOpenEvents.WithLabelValues(labels...).Collect(ch)
	close(ch)
	var sum float64
	for m := range ch {
		var pb dto.Metric
		if err := m.Write(&pb); err != nil {
			t.Fatalf("counter.Write: %v", err)
		}
		sum += pb.GetCounter().GetValue()
	}
	return sum
}

// failingSuppression returns (false, err) on every IsSuppressed call,
// driving the fail-open metric path.
type failingSuppression struct{}

func (failingSuppression) IsSuppressed(_ context.Context, _ string) (bool, error) {
	return false, errors.New("simulated postgres brownout")
}

// TestSuppressionFailOpen_IncrementsMetric — P2 contract.
// A SuppressionChecker DB error MUST bump the email_suppression fail-
// open counter so a brownout is alertable. The send itself proceeds
// (fail-open semantics unchanged).
func TestSuppressionFailOpen_IncrementsMetric(t *testing.T) {
	before := counterValue(t, "email_suppression", "db_error")

	c := New(Config{Provider: string(ProviderNoop)})
	c.WithSuppressionChecker(failingSuppression{})

	if err := c.SendPaymentFailed(context.Background(), "u@example.com", 1, nil); err != nil {
		t.Fatalf("send must fail-open on suppression error; got %v", err)
	}

	after := counterValue(t, "email_suppression", "db_error")
	if after <= before {
		t.Errorf("FailOpenEvents{subsystem=email_suppression} did not increment: before=%v after=%v",
			before, after)
	}
}

// TestLedgerProbeFailOpen_IncrementsMetric — P2 contract. A
// SendLedger.Sent DB error MUST bump the email_ledger_probe fail-open
// counter; the send proceeds.
func TestLedgerProbeFailOpen_IncrementsMetric(t *testing.T) {
	before := counterValue(t, "email_ledger_probe", "db_error")

	c := New(Config{Provider: string(ProviderNoop)})
	ledger := newFakeLedger()
	ledger.probeErr = errors.New("simulated DB outage")
	c.WithSendLedger(ledger)

	if err := c.SendPaymentSucceededWithKey(context.Background(), "u@example.com", "key-z", PaymentReceipt{}); err != nil {
		t.Fatalf("send must fail-open on ledger probe error; got %v", err)
	}

	after := counterValue(t, "email_ledger_probe", "db_error")
	if after <= before {
		t.Errorf("FailOpenEvents{subsystem=email_ledger_probe} did not increment: before=%v after=%v",
			before, after)
	}
}
