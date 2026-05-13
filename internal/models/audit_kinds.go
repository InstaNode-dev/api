package models

// audit_kinds.go — named constants for audit_log.kind values that downstream
// systems (e.g. the Loops worker) match on. Centralising these strings stops
// callers from typo-drifting "subscription.canceled" vs "subscription.cancelled"
// at emit sites; the Loops forwarder consumes the exact value of these
// constants.
//
// New kinds added here MUST also be wired into the Loops forwarder map (see
// PR #10 in the worker repo) or they will be dropped silently.

const (
	// AuditKindOnboardingClaimed fires once per successful POST /claim — the
	// anonymous-to-claimed conversion completing. Drives the "welcome" Loops
	// lifecycle email.
	AuditKindOnboardingClaimed = "onboarding.claimed"

	// AuditKindSubscriptionUpgraded fires when a Razorpay subscription.charged
	// webhook moves a team to a strictly higher tier (e.g. hobby → pro). Does
	// NOT fire on first-charge from free/anonymous — see AuditKindSubscriptionStarted
	// when that kind is added.
	AuditKindSubscriptionUpgraded = "subscription.upgraded"

	// AuditKindSubscriptionDowngraded fires when a Razorpay subscription.charged
	// webhook moves a team to a strictly lower tier (e.g. pro → hobby) — for
	// example after a plan change that bills the cheaper plan.
	AuditKindSubscriptionDowngraded = "subscription.downgraded"

	// AuditKindSubscriptionCanceled fires on subscription.cancelled webhook.
	// Drives the "we'd love to know why" Loops cancellation email. Note the
	// single-l US spelling — matches the Loops forwarder map. The Razorpay
	// event name uses the double-l UK spelling, which is handled inside the
	// billing handler.
	AuditKindSubscriptionCanceled = "subscription.canceled"
)
