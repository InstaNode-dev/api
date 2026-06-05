package handlers

import (
	"context"
	"sync"
	"testing"

	"instant.dev/common/analyticsevent"
)

// recordingEmitter is a test analyticsevent.Emitter that captures every event it
// receives so a test can assert an emit site fired with the right step + attrs.
// It satisfies the Emitter contract (Record never errors/panics into the caller).
type recordingEmitter struct {
	mu     sync.Mutex
	events []recordedEvent
	closed bool
}

type recordedEvent struct {
	eventType string
	attrs     map[string]any
}

func (r *recordingEmitter) Record(_ context.Context, eventType string, attrs map[string]any) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.events = append(r.events, recordedEvent{eventType: eventType, attrs: attrs})
}
func (r *recordingEmitter) Name() string { return "recording" }
func (r *recordingEmitter) Close() error { r.closed = true; return nil }

func (r *recordingEmitter) last() recordedEvent {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.events) == 0 {
		return recordedEvent{}
	}
	return r.events[len(r.events)-1]
}
func (r *recordingEmitter) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.events)
}

// installRecordingEmitter swaps in a recording emitter for the duration of a
// test and restores the previous (default noop) emitter afterward, so tests
// don't leak the global across the package. The emitter is wrapped via the
// factory so it goes through the same Sanitize + fail-open path production uses.
func installRecordingEmitter(t *testing.T) *recordingEmitter {
	t.Helper()
	rec := &recordingEmitter{}
	wrapped, err := analyticsevent.Factory(analyticsevent.Config{Override: rec})
	if err != nil {
		t.Fatalf("Factory(Override) err = %v", err)
	}
	prev := getAnalyticsEmitter()
	SetAnalyticsEmitter(wrapped)
	t.Cleanup(func() { SetAnalyticsEmitter(prev) })
	return rec
}

// --- emitter accessor / default ------------------------------------------------

func TestGetAnalyticsEmitter_DefaultsToNoop(t *testing.T) {
	// The package init installs a non-nil noop emitter. Re-store it to be sure we
	// observe the inert default regardless of test ordering, then restore.
	prev := getAnalyticsEmitter()
	t.Cleanup(func() { SetAnalyticsEmitter(prev) })

	SetAnalyticsEmitter(analyticsevent.NewNoop())
	e := getAnalyticsEmitter()
	if e == nil {
		t.Fatal("getAnalyticsEmitter returned nil — must never be nil")
	}
	if e.Name() != analyticsevent.BackendNoop {
		t.Fatalf("default emitter Name = %q, want %q", e.Name(), analyticsevent.BackendNoop)
	}
	// The inert default must not error or panic on an emit.
	recordFunnelEvent(context.Background(), funnelStepProvision, funnelAttrs{Tier: "anonymous"})
}

func TestSetAnalyticsEmitter_NilIgnored(t *testing.T) {
	prev := getAnalyticsEmitter()
	t.Cleanup(func() { SetAnalyticsEmitter(prev) })

	rec := &recordingEmitter{}
	SetAnalyticsEmitter(rec)
	// A nil set must be ignored, leaving the previously-installed emitter intact.
	SetAnalyticsEmitter(nil)
	if getAnalyticsEmitter() != analyticsevent.Emitter(rec) {
		t.Fatal("SetAnalyticsEmitter(nil) overwrote the installed emitter — must be ignored")
	}
}

// --- recordFunnelEvent: step + attrs ------------------------------------------

func TestRecordFunnelEvent_EmitsFunnelEventWithStepAndAttrs(t *testing.T) {
	rec := installRecordingEmitter(t)

	recordFunnelEvent(context.Background(), funnelStepProvision, funnelAttrs{
		Tier:        "anonymous",
		Env:         "production",
		Fingerprint: "fp-bucket-hash",
		TeamID:      "team-uuid",
	})

	if rec.count() != 1 {
		t.Fatalf("expected 1 event, got %d", rec.count())
	}
	got := rec.last()
	if got.eventType != analyticsevent.EventFunnel {
		t.Fatalf("eventType = %q, want %q", got.eventType, analyticsevent.EventFunnel)
	}
	want := map[string]string{
		analyticsevent.AttrFunnelStep:  funnelStepProvision,
		analyticsevent.AttrServiceName: serviceNameAPI,
		analyticsevent.AttrTier:        "anonymous",
		analyticsevent.AttrEnv:         "production",
		analyticsevent.AttrFingerprint: "fp-bucket-hash",
		analyticsevent.AttrTeamID:      "team-uuid",
	}
	for k, v := range want {
		if got.attrs[k] != v {
			t.Errorf("attr %q = %v, want %q", k, got.attrs[k], v)
		}
	}
}

func TestRecordFunnelEvent_OmitsEmptyOptionalAttrs(t *testing.T) {
	rec := installRecordingEmitter(t)

	// The top-of-funnel landing site carries no tier/env/fp/team.
	recordFunnelEvent(context.Background(), funnelStepLanding, funnelAttrs{})

	got := rec.last()
	if got.attrs[analyticsevent.AttrFunnelStep] != funnelStepLanding {
		t.Fatalf("step = %v, want %q", got.attrs[analyticsevent.AttrFunnelStep], funnelStepLanding)
	}
	if got.attrs[analyticsevent.AttrServiceName] != serviceNameAPI {
		t.Errorf("service should always be present, got %v", got.attrs[analyticsevent.AttrServiceName])
	}
	for _, k := range []string{
		analyticsevent.AttrTier, analyticsevent.AttrEnv,
		analyticsevent.AttrFingerprint, analyticsevent.AttrTeamID,
	} {
		if _, ok := got.attrs[k]; ok {
			t.Errorf("empty optional attr %q should be omitted, got %v", k, got.attrs[k])
		}
	}
}

// TestRecordFunnelEvent_EachCanonicalStep covers every funnel step constant the
// emit sites use, so all four in-package aliases are exercised.
func TestRecordFunnelEvent_EachCanonicalStep(t *testing.T) {
	rec := installRecordingEmitter(t)
	steps := []string{funnelStepLanding, funnelStepProvision, funnelStepClaim, funnelStepPaid}
	for _, s := range steps {
		recordFunnelEvent(context.Background(), s, funnelAttrs{Tier: "free"})
	}
	if rec.count() != len(steps) {
		t.Fatalf("expected %d events, got %d", len(steps), rec.count())
	}
	for i, ev := range rec.events {
		if ev.attrs[analyticsevent.AttrFunnelStep] != steps[i] {
			t.Errorf("event %d step = %v, want %q", i, ev.attrs[analyticsevent.AttrFunnelStep], steps[i])
		}
	}
}

// --- PII safety ----------------------------------------------------------------

// TestRecordFunnelEvent_DoesNotEmitPII asserts the factory-wrapped emit path
// drops any non-allowlisted attribute and never carries a raw email — proving
// the sanitize chokepoint is in the emit path even if a future funnelAttrs field
// regresses. (toMap itself only produces allowlisted keys; this guards the path.)
func TestRecordFunnelEvent_DoesNotEmitPII(t *testing.T) {
	rec := installRecordingEmitter(t)
	recordFunnelEvent(context.Background(), funnelStepClaim, funnelAttrs{
		Tier:   "free",
		TeamID: "team-uuid",
	})
	got := rec.last()
	for k := range got.attrs {
		if _, ok := analyticsevent.AllowedAttributes[k]; !ok {
			t.Errorf("emitted non-allowlisted (potential PII) key %q", k)
		}
	}
	if _, ok := got.attrs[analyticsevent.AttrEmail]; ok {
		t.Error("raw email key must never appear in a funnel event")
	}
}

// TestFunnelAttrs_ToMap_OnlyAllowlistedKeys is the registry-iterating guard
// (CLAUDE.md rule 18): every key funnelAttrs can produce must be on the PII
// allowlist, so a new field can't leak by construction.
func TestFunnelAttrs_ToMap_OnlyAllowlistedKeys(t *testing.T) {
	full := funnelAttrs{Tier: "t", Env: "e", Fingerprint: "f", TeamID: "tid"}
	for k := range full.toMap(funnelStepProvision) {
		if _, ok := analyticsevent.AllowedAttributes[k]; !ok {
			t.Errorf("funnelAttrs.toMap emits non-allowlisted key %q", k)
		}
	}
}

// --- wire-contract guard -------------------------------------------------------

// TestFunnelStepsMatchCanonical asserts the in-package step aliases equal the
// canonical analyticsevent constants the dashboards FACET on. A drift here
// silently splits the funnel across two step values.
func TestFunnelStepsMatchCanonical(t *testing.T) {
	cases := []struct{ alias, canonical string }{
		{funnelStepLanding, analyticsevent.FunnelStepLanding},
		{funnelStepProvision, analyticsevent.FunnelStepProvision},
		{funnelStepClaim, analyticsevent.FunnelStepClaim},
		{funnelStepPaid, analyticsevent.FunnelStepPaid},
	}
	for _, c := range cases {
		if c.alias != c.canonical {
			t.Errorf("step alias %q != canonical %q", c.alias, c.canonical)
		}
	}
}
