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

	// AuditKindPaymentGraceStarted fires when Razorpay sends a
	// subscription.charged_failed (or payment.failed during an active
	// subscription) and we open a 7-day grace window. Drives the Brevo
	// "your payment failed, we'll retry" lifecycle email
	// (template: instanode-payment-grace-started-v1). Metadata carries
	// {subscription_id, attempted_amount, retry_at, expires_at} so the
	// email can render the recovery deadline. Fires exactly once per
	// grace period — the partial-unique index uq_payment_grace_team_active
	// guarantees no duplicate-emission on webhook redelivery.
	AuditKindPaymentGraceStarted = "payment.grace_started"

	// AuditKindPaymentGraceReminder fires every 6 hours during an active
	// grace window from the worker's payment_grace_reminder job (separate
	// PR). Up to 28 reminders over the 7-day window. Drives the Brevo
	// "still no payment, N days left" reminder email
	// (template: instanode-payment-grace-reminder-v1). Metadata carries
	// {subscription_id, reminder_index, reminders_total, expires_at} so
	// the email can render "reminder 3 of 28" copy.
	AuditKindPaymentGraceReminder = "payment.grace_reminder"

	// AuditKindPaymentGraceRecovered fires when subscription.charged
	// succeeds during an active grace window — i.e. the customer's
	// card recovered and Razorpay pushed through the charge. Drives the
	// Brevo "you're back in good standing" recovery email
	// (template: instanode-payment-grace-recovered-v1). Metadata carries
	// {subscription_id, grace_id, started_at, recovered_at} so the email
	// can render "your account was at risk for N days" copy.
	AuditKindPaymentGraceRecovered = "payment.grace_recovered"

	// AuditKindPaymentGraceTerminated fires when the worker's
	// payment_grace_terminator job sweeps a grace row whose expires_at
	// has passed. The destructive work (Razorpay subscription cancel
	// + resource soft-delete) lives in the worker; this audit row is
	// the trigger for the Brevo "your account has been suspended"
	// final email (template: instanode-payment-grace-terminated-v1).
	// Metadata carries {subscription_id, grace_id, terminated_at,
	// razorpay_cancel_succeeded, resources_deleted_count} so support
	// can reconcile with Razorpay if the cancel call failed.
	AuditKindPaymentGraceTerminated = "payment.grace_terminated"

	// AuditKindAdminAccess fires on every hit to the admin route prefix —
	// success (2xx) AND rejected (403). Written by middleware.AdminAuditEmit
	// installed on the admin route group after RequireAdmin. Drives the BI
	// query "who accessed what admin surface and when" and supplies the
	// raw signal an SOC dashboard pivots on if leaked admin credentials
	// are suspected.
	//
	// Metadata shape (verified by middleware.adminAuditMetadata):
	//
	//	{
	//	  "email":            "<caller's JWT email, lowercased>",
	//	  "ip":               "<client IP — same source as the fingerprint>",
	//	  "path_suffix":      "<path with the secret prefix stripped, e.g. customers/:team_id/tier>",
	//	  "http_status":      <int>,
	//	  "user_agent_brief": "<first 120 chars of UA, scrubbed of tokens>"
	//	}
	//
	// CRITICAL: path_suffix is the SUFFIX only — the unguessable
	// ADMIN_PATH_PREFIX is stripped before persistence. Storing the
	// full path would defeat the whole point of the prefix gate
	// (a DB read would leak the secret to anyone with audit_log access).
	// The metadata blob is asserted prefix-free in tests via grep.
	AuditKindAdminAccess = "admin.access"
)
