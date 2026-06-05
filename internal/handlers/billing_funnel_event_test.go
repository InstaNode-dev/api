package handlers_test

// billing_funnel_event_test.go — WS4: asserts the claimed->paid funnel custom
// event (InstantFunnel, step=paid) fires from handleSubscriptionCharged
// alongside the existing instant_conversion_funnel_total{step="paid"} counter.
// Covers the emit site at billing.go's paid step with a recording emitter so the
// per-entity NR bridge is verified end-to-end through the real webhook path.

import (
	"context"
	"net/http"
	"sync"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"instant.dev/common/analyticsevent"
	"instant.dev/internal/handlers"
	"instant.dev/internal/testhelpers"
)

// funnelRecorder captures InstantFunnel events. Satisfies analyticsevent.Emitter
// (Record never errors/panics into the caller).
type funnelRecorder struct {
	mu     sync.Mutex
	events []struct {
		eventType string
		attrs     map[string]any
	}
}

func (r *funnelRecorder) Record(_ context.Context, eventType string, attrs map[string]any) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.events = append(r.events, struct {
		eventType string
		attrs     map[string]any
	}{eventType, attrs})
}
func (r *funnelRecorder) Name() string { return "recording" }
func (r *funnelRecorder) Close() error { return nil }

func TestBillingWebhook_SubscriptionCharged_EmitsPaidFunnelEvent(t *testing.T) {
	db, cleanDB := billingStateNeedsDB(t)
	defer cleanDB()

	// Install a recording emitter (factory-wrapped, same Sanitize + fail-open as
	// prod) and restore the default afterward.
	rec := &funnelRecorder{}
	wrapped, err := analyticsevent.Factory(analyticsevent.Config{Override: rec})
	require.NoError(t, err)
	handlers.SetAnalyticsEmitter(wrapped)
	t.Cleanup(func() { handlers.SetAnalyticsEmitter(analyticsevent.NewNoop()) })

	app, cfg := billingWebhookDBApp(t, db)

	teamID := testhelpers.MustCreateTeamDB(t, db, "hobby")
	defer db.Exec(`DELETE FROM teams WHERE id = $1::uuid`, teamID)

	payload := makeSubscriptionChargedPayloadWithPlan(
		t, teamID, "sub_test_"+uuid.NewString(), cfg.RazorpayPlanIDPro,
	)
	req := signedWebhookRequest(t, payload)
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	// Exactly one InstantFunnel step=paid event, carrying the paid tier + teamId
	// and no PII.
	var paidAttrs map[string]any
	var paidCount int
	rec.mu.Lock()
	for _, ev := range rec.events {
		if ev.eventType == analyticsevent.EventFunnel &&
			ev.attrs[analyticsevent.AttrFunnelStep] == analyticsevent.FunnelStepPaid {
			paidAttrs = ev.attrs
			paidCount++
		}
	}
	rec.mu.Unlock()

	require.Equal(t, 1, paidCount, "expected exactly one paid funnel event")
	assert.Equal(t, "pro", paidAttrs[analyticsevent.AttrTier])
	assert.Equal(t, teamID, paidAttrs[analyticsevent.AttrTeamID])
	assert.Equal(t, handlers.ServiceNameAPIForTest, paidAttrs[analyticsevent.AttrServiceName])
	for k := range paidAttrs {
		_, ok := analyticsevent.AllowedAttributes[k]
		assert.Truef(t, ok, "paid funnel event carried non-allowlisted key %q", k)
	}
}
