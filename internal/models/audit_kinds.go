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

	// AuditKindSubscriptionCanceledByAdmin fires when an operator demotes a
	// paying customer via POST /api/v1/admin/customers/:id/tier and the
	// demotion triggers an out-of-band Razorpay subscription cancellation.
	// Distinct from AuditKindSubscriptionCanceled (which is the customer's
	// own self-serve cancel via Razorpay webhook) so the Loops forwarder /
	// Brevo template can send a "your subscription was canceled by support"
	// email rather than the standard customer-initiated copy. Metadata
	// carries cancel_attempted + cancel_succeeded booleans so a downstream
	// consumer can distinguish "we canceled in Razorpay" from "we tried but
	// the call failed — operator must reconcile in the Razorpay dashboard."
	AuditKindSubscriptionCanceledByAdmin = "subscription.canceled_by_admin"

	// AuditKindPromoteApprovalRequested fires when the agent API creates a
	// pending promote_approvals row (target env != development). Drives the
	// Brevo template `instanode-promote-approval-v1` — the forwarder reads
	// metadata.{from_env,to_env,stack_slug,approve_url,requested_by_email}
	// and emails the operator a clickable approval link.
	AuditKindPromoteApprovalRequested = "promote.approval_requested"

	// AuditKindPromoteApproved fires when the user clicks the email link
	// and the row atomically flips from 'pending' to 'approved'. Drives
	// an optional "confirmation" email from the forwarder + downstream
	// analytics. The worker that actually runs the promote consumes the
	// row (status='approved' AND executed_at IS NULL) — it does NOT
	// re-read this audit row.
	AuditKindPromoteApproved = "promote.approved"

	// AuditKindPromoteRejected fires when an admin marks a row 'rejected'
	// via POST /api/v1/promotions/:id/reject. Symmetric with
	// AuditKindPromoteApproved so the dashboard timeline shows both
	// terminal states.
	AuditKindPromoteRejected = "promote.rejected"

	// AuditKindPromoteExecuted fires when the worker (out of scope for
	// the email-link approval PR — landing in worker repo follow-up)
	// actually executes the cached promote and flips the row to
	// 'executed'. Until the worker lands, an operator can manually
	// trigger the original promote endpoint with the approval_id in
	// the request body — that path emits this kind too.
	AuditKindPromoteExecuted = "promote.executed"
)
