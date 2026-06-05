package handlers

import (
	"context"
	"sync/atomic"

	"instant.dev/common/analyticsevent"
)

// WS4 behavioral-intelligence funnel events.
//
// This file is the api's bridge from the existing Prometheus conversion-funnel
// counter (instant_conversion_funnel_total — an AGGREGATE count) to the
// per-entity / per-cohort New Relic custom event (InstantFunnel) that the WS4
// observability plan needs for funnel + retention analysis (anon→claim→
// provision→paid). The Prometheus counter stays exactly where it is; every
// funnel emit site now ALSO records an InstantFunnel custom event alongside it.
//
// Why a package-level emitter instead of a struct field on every handler: the
// funnel emit sites live across nine independently-constructed handler structs
// (DBHandler, CacheHandler, OnboardingHandler, BillingHandler, …), each with
// its own constructor. The api already shares process-wide observability deps
// (the `metrics` package globals) the same way. The router wires the concrete
// emitter ONCE at boot via [SetAnalyticsEmitter]; until then — and in every
// unit test that doesn't opt in — the default is the no-op emitter, so funnel
// emission is INERT by default and can NEVER block, slow, or error a request.
//
// Fail-open + inert-by-default IS the flag protection: the analyticsevent
// package wraps every backend so a panic in the sink is swallowed and a nil /
// unconfigured backend is a silent drop. No separate feature flag is needed —
// ANALYTICS_BACKEND defaulting to "noop" means this code path does nothing in
// prod until New Relic is explicitly configured.

// emitterBox wraps the [analyticsevent.Emitter] interface in a single concrete
// struct type so [analyticsEmitter] (an atomic.Value) always sees ONE concrete
// type across Stores — atomic.Value panics if successive Store calls pass
// different concrete types, which a bare interface value would (noop{} vs the
// factory's wrapped{}). The box is the invariant concrete type.
type emitterBox struct{ e analyticsevent.Emitter }

// analyticsEmitter holds the process-wide emitter (boxed). atomic.Value so
// [SetAnalyticsEmitter] (called once at boot, before serving) and the per-request
// reads in [recordFunnelEvent] are race-free. Defaults to the no-op emitter via
// the package init below.
var analyticsEmitter atomic.Value // stores emitterBox

func init() {
	// Inert default: no analytics sink until the router wires one. The no-op
	// emitter drops every event with zero deps and can never error.
	analyticsEmitter.Store(emitterBox{e: analyticsevent.NewNoop()})
}

// SetAnalyticsEmitter installs the process-wide analytics emitter. Called once
// from the router at boot with the emitter built from ANALYTICS_BACKEND (noop by
// default; the New Relic sink when configured). A nil emitter is ignored so a
// mis-wire degrades to the existing no-op rather than panicking on first emit.
func SetAnalyticsEmitter(e analyticsevent.Emitter) {
	if e == nil {
		return
	}
	analyticsEmitter.Store(emitterBox{e: e})
}

// getAnalyticsEmitter returns the current process-wide emitter, never nil.
func getAnalyticsEmitter() analyticsevent.Emitter {
	if box, ok := analyticsEmitter.Load().(emitterBox); ok && box.e != nil {
		return box.e
	}
	return analyticsevent.NewNoop()
}

// serviceNameAPI is the AttrServiceName value every funnel event from this
// service carries, so a dashboard can FACET by which service emitted the step.
const serviceNameAPI = "api"

// Funnel-step values re-exported from analyticsevent so the per-handler emit
// sites (db/cache/nosql/…/onboarding/billing) reference one in-package constant
// and don't each need to import common/analyticsevent. These MUST stay equal to
// the analyticsevent constants — funnelStepsMatchCanonical (in the test) asserts
// it, and the wire contract (dashboards FACET on these exact strings) depends on
// it.
const (
	funnelStepProvision = analyticsevent.FunnelStepProvision
	funnelStepClaim     = analyticsevent.FunnelStepClaim
	funnelStepPaid      = analyticsevent.FunnelStepPaid
	funnelStepLanding   = analyticsevent.FunnelStepLanding
)

// recordFunnelEvent emits one [analyticsevent.EventFunnel] custom event for the
// given funnel step alongside the existing Prometheus counter. It is the single
// chokepoint every funnel emit site routes through so the attribute set stays
// uniform and PII-safe.
//
// Attributes are intentionally low-cardinality and allowlisted (the
// analyticsevent wrapper drops anything not on the PII allowlist before the
// event leaves the process): step, tier, env, service, and — when known — the
// already-hashed fingerprint bucket (SHA256(/24+ASN), never a raw IP) and team
// id (an opaque UUID, not PII). Empty values are omitted so an absent field
// reads as "missing" in NRQL rather than "".
//
// FAIL-OPEN: this never returns an error and the wrapper swallows any panic, so
// a funnel emit can never affect the request path. Callers MUST NOT wrap it in
// error handling.
func recordFunnelEvent(ctx context.Context, step string, attrs funnelAttrs) {
	getAnalyticsEmitter().Record(ctx, analyticsevent.EventFunnel, attrs.toMap(step))
}

// funnelAttrs is the typed, PII-safe attribute payload for a funnel event. Only
// these fields can reach an event; the package allowlist is the backstop.
type funnelAttrs struct {
	// Tier is the plan tier the funnel step occurred at ("anonymous", "free",
	// "pro", …). Low cardinality.
	Tier string
	// Env is the resolved environment ("development", "production", …).
	Env string
	// Fingerprint is the already-hashed SHA256(/24+ASN) anonymous bucket, or ""
	// for an authenticated step. Never a raw IP.
	Fingerprint string
	// TeamID is the owning team UUID (opaque id, not PII), or "" when unknown
	// (e.g. anonymous provisions before a claim).
	TeamID string
}

// toMap renders funnelAttrs + the step into the flat attribute map the emitter
// consumes, omitting empty values so NRQL facets stay clean.
func (a funnelAttrs) toMap(step string) map[string]any {
	out := map[string]any{
		analyticsevent.AttrFunnelStep:  step,
		analyticsevent.AttrServiceName: serviceNameAPI,
	}
	if a.Tier != "" {
		out[analyticsevent.AttrTier] = a.Tier
	}
	if a.Env != "" {
		out[analyticsevent.AttrEnv] = a.Env
	}
	if a.Fingerprint != "" {
		out[analyticsevent.AttrFingerprint] = a.Fingerprint
	}
	if a.TeamID != "" {
		out[analyticsevent.AttrTeamID] = a.TeamID
	}
	return out
}
