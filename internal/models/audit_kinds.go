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

	// Payment dunning lifecycle kinds (PR #66) — fire from Razorpay webhook
	// + the worker's payment_grace_reminder + payment_grace_terminator jobs.
	AuditKindPaymentGraceStarted    = "payment.grace_started"
	AuditKindPaymentGraceReminder   = "payment.grace_reminder"
	AuditKindPaymentGraceRecovered  = "payment.grace_recovered"
	AuditKindPaymentGraceTerminated = "payment.grace_terminated"

	// Promote approval lifecycle (PR #65) — non-dev promotes require an
	// email-link approval before the worker executes them.
	AuditKindPromoteApprovalRequested = "promote.approval_requested"
	AuditKindPromoteApproved          = "promote.approved"
	AuditKindPromoteRejected          = "promote.rejected"
	AuditKindPromoteExecuted          = "promote.executed"

	// AuditKindAdminAccess fires on every hit to the admin route prefix.
	// path_suffix MUST be the suffix only — the unguessable
	// ADMIN_PATH_PREFIX is stripped before persistence.
	AuditKindAdminAccess = "admin.access"

	// AuditKindAuthLogin fires on every successful authentication that mints
	// a session JWT — OAuth (GitHub / Google, both POST and browser
	// callback variants), magic-link callback, and any other flow that
	// terminates by handing the caller a session token. Drives the
	// "new sign-in" Brevo notification + powers NR per-provider login
	// dashboards. Metadata carries `provider` (email | github | google |
	// impersonation), `ip`, and `user_agent`.
	AuditKindAuthLogin = "auth.login"

	// AuditKindVaultRead fires once per successful GET
	// /api/v1/vault/:env/:key that returned 200. Misses (404, validation
	// failures, tier rejections) do NOT emit — the audit row is signal that
	// a real plaintext was returned to the caller. Metadata: `env`,
	// `key_name`, `team_id`.
	AuditKindVaultRead = "vault.read"

	// AuditKindVaultWrite fires on every successful vault mutation:
	// PUT (create or new-version), rotate (alias for PUT), and DELETE.
	// Metadata: `env`, `key_name`, `team_id`, and `operation`
	// (create | update | delete) so the downstream forwarder can branch on
	// the action without re-parsing the kind.
	AuditKindVaultWrite = "vault.write"

	// AuditKindDeployCreated fires immediately after POST /deploy/new
	// inserts the deployments row — BEFORE the async build runs. This is
	// the "user clicked deploy" signal; reaching healthy or failed is
	// reported separately via deploy.healthy / deploy.failed. Metadata:
	// `deploy_id`, `team_id`, `env`, `app_name`.
	AuditKindDeployCreated = "deploy.created"

	// AuditKindDeployHealthy fires when the async deploy reconciliation
	// observes the new pod's readinessProbe pass (or, in the current
	// architecture, when the synchronous compute.Deploy + status update
	// chain completes without error). Metadata: `deploy_id`, `team_id`,
	// `time_to_healthy_seconds`.
	AuditKindDeployHealthy = "deploy.healthy"

	// AuditKindDeployFailed fires when the deploy fails terminally — build
	// step OR rollout step. Metadata: `deploy_id`, `team_id`,
	// `failure_stage` (build | rollout), `error_summary` (truncated error
	// message — full error stays in the deployments.error_message column).
	AuditKindDeployFailed = "deploy.failed"
)
