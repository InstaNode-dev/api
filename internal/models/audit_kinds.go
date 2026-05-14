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

	// Deploy TTL lifecycle (Wave FIX-J — migration 045). Each kind names one
	// inflection point in the auto-24h-TTL-with-reminders flow so on-call,
	// the dashboard's Recent Activity feed, and the Loops/Brevo event
	// forwarder can render the chain end-to-end without inventing copy.
	//
	// AuditKindDeployMadePermanent fires when a caller explicitly opts a
	// deploy out of TTL — either via POST /deploy/new with ttl_policy =
	// 'permanent' OR POST /api/v1/deployments/:id/make-permanent. Metadata:
	// {deploy_id, team_id, source: "deploy_new" | "make_permanent_endpoint",
	// previous_ttl_policy}.
	AuditKindDeployMadePermanent = "deploy.made_permanent"

	// AuditKindDeployTTLSet fires on POST /api/v1/deployments/:id/ttl —
	// the user chose a custom (non-24h) TTL. Metadata: {deploy_id,
	// team_id, hours, expires_at}. Distinct from made_permanent so a
	// dashboard subscriber can render the two outcomes differently.
	AuditKindDeployTTLSet = "deploy.ttl_set"

	// AuditKindDeployExpiringSoon fires once per reminder dispatch — six
	// rows per deploy over the final 12h (T-12h, T-10h, ..., T-2h). The
	// worker's deployment_reminder job emits this AFTER the email send
	// succeeds. Metadata: {deploy_id, team_id, reminder_index (1..6),
	// hours_remaining, expires_at}.
	AuditKindDeployExpiringSoon = "deploy.expiring_soon"

	// AuditKindDeployExpired fires when the worker's deployment_expirer
	// soft-deletes a deploy whose expires_at has passed. Metadata:
	// {deploy_id, team_id, expires_at, ttl_policy (auto_24h | custom)}.
	AuditKindDeployExpired = "deploy.expired"

	// AuditKindTeamSettingsChanged fires when an owner/admin mutates a
	// team's preferences via PATCH /api/v1/team/settings. Metadata:
	// {field, old_value, new_value, changed_by_user_id}.
	AuditKindTeamSettingsChanged = "team.settings_changed"

	// AuditKindStorageIAMUserCreated fires when a successful /storage/new
	// in MinIO admin mode mints a per-tenant IAM user. Surfaces the
	// "tenant just got their own key" event so on-call / compliance can
	// reconstruct who held which key when. Metadata carries the
	// access_key_id (per-tenant prefix-scoped, NOT the master) and the
	// resource_id; the secret is never persisted in the audit trail.
	AuditKindStorageIAMUserCreated = "storage.iam_user_created"

	// AuditKindStorageIAMUserDeleted fires when DELETE /api/v1/resources/:id
	// (or the worker-driven expiry path) removes a per-tenant IAM user.
	// Pair this with the corresponding "_created" event to bound how long
	// a given key existed.
	AuditKindStorageIAMUserDeleted = "storage.iam_user_deleted"

	// AuditKindFamilyBulkTwin fires once per successful POST
	// /api/v1/families/bulk-twin call. Metadata carries source_env,
	// target_env, twinned_count, skipped_count, failure_count so the
	// dashboard's Recent Activity feed can render a single line per
	// bulk operation (rather than N lines for the underlying twins,
	// which already each emit their own `provision` kind row).
	AuditKindFamilyBulkTwin = "family.bulk_twin"

	// AuditKindBackupRequested fires on every successful POST
	// /api/v1/resources/:id/backup — the API persisted a pending
	// resource_backups row and the worker will pick it up within 30s.
	// Metadata: {resource_id, triggered_by, backup_kind}. The worker
	// emits its own terminal-state kinds when the backup completes or
	// fails (not wired into this constant — they live in the worker repo).
	AuditKindBackupRequested = "backup.requested"

	// AuditKindRestoreRequested fires on every successful POST
	// /api/v1/resources/:id/restore. Metadata: {resource_id, backup_id,
	// triggered_by}. Distinct kind from backup.requested so a Loops /
	// dashboard subscriber can filter to "user clicked Restore" vs
	// "scheduled backup ran" — a restore is a much higher-signal event
	// (user is recovering, may need support).
	AuditKindRestoreRequested = "restore.requested"

	// Data-access audit kinds (W7-C — customer-facing audit export).
	// Compliance buyers (Team tier) need a complete trail of who read
	// what + when. These fire on every successful customer-facing read
	// of resource state (NOT internal scans/probes, which would flood
	// the table — see resource.go for the "only on explicit reveal"
	// rule applied to AuditKindConnectionURLDecrypted).
	//
	// Best-effort: emit-site failures must NEVER block the underlying
	// read. See resource.go for the goroutine pattern. The new GET
	// /api/v1/audit endpoint surfaces these to the customer along with
	// the existing onboarding.* / subscription.* / promote.* kinds.

	// AuditKindResourceRead fires on every successful GET
	// /api/v1/resources/:id. Metadata: {resource_id, resource_type,
	// accessed_by_user_id}. Per-resource resolution — one row per call.
	AuditKindResourceRead = "resource.read"

	// AuditKindConnectionURLDecrypted fires when a connection_url is
	// decrypted server-side for return to the customer (the explicit
	// "show connection string" reveal in the dashboard, or the
	// /credentials endpoint). Does NOT fire on internal scans, the
	// rotation flow's intermediate decrypt, or pause/resume — those
	// are operational reads, not data-access reveals.
	// Metadata: {resource_id, purpose: "customer_reveal"}.
	AuditKindConnectionURLDecrypted = "connection_url.decrypted"

	// AuditKindResourceListByTeam fires once per GET /api/v1/resources
	// call (lower-resolution than per-resource — compliance-useful but
	// must not generate a row per result). Metadata:
	// {count_returned, env_filter}.
	AuditKindResourceListByTeam = "resource.list_by_team"

	// Right-to-be-forgotten / GDPR Article 17 lifecycle (migration 032).
	//
	// AuditKindTeamDeletionRequested fires when an owner calls
	// DELETE /api/v1/team with a matching confirm_team_slug. The team
	// enters a 30-day grace window — resources are paused, the Razorpay
	// subscription is cancelled best-effort, and the worker's
	// team_deletion_executor will tombstone the row after the window
	// elapses. Metadata: {requested_by_user_id, confirm_slug_provided,
	// razorpay_cancel_result}.
	AuditKindTeamDeletionRequested = "team.deletion_requested"

	// AuditKindTeamDeletionCanceled fires when an owner calls
	// POST /api/v1/team/restore inside the 30-day grace window. Reverses
	// the deletion — status returns to 'active', paused resources
	// resume. Metadata: {canceled_by_user_id, days_remaining_at_cancel}.
	AuditKindTeamDeletionCanceled = "team.deletion_canceled"

	// AuditKindTombstoned fires when the worker's team_deletion_executor
	// completes a per-team destruction pass. Metadata:
	// {resource_count_destroyed, s3_bytes_freed, duration_seconds}.
	// Distinct from team.deletion_requested so dashboards and the Loops
	// forwarder can render the two phases independently. Producer: the
	// worker module (see worker/internal/jobs/team_deletion_executor.go).
	AuditKindTombstoned = "team.tombstoned"

	// AuditKindTeamDeletionFailed fires when the worker's executor sees
	// a per-team error (one resource fails to deprovision, S3 delete
	// errors, etc.) — the team stays in deletion_requested state so an
	// operator can investigate and re-run. Metadata: {error,
	// failed_at_step, resource_id (when applicable)}.
	AuditKindTeamDeletionFailed = "team.deletion_failed"

	// AuditKindResourceMetricsQueried fires when a caller successfully fetches
	// GET /api/v1/resources/:id/metrics. The audit row's metadata records the
	// resolved window_seconds + samples_count so the Loops forwarder /
	// downstream consumers can distinguish "the customer is actively watching
	// p95" from a one-off page load. NOT emitted on tier-gated 402 or
	// ownership 403/404 paths — pre-auth queries shouldn't pollute the feed.
	AuditKindResourceMetricsQueried = "resource.metrics_queried"

	// AuditKindTeamUpdated fires on PATCH /api/v1/team. metadata.field +
	// metadata.new_value document what changed. Per-user-id is captured on
	// the audit row.
	AuditKindTeamUpdated = "team.updated"

	// GitHub auto-deploy lifecycle (migration 035). Customers wire a
	// deployment to a GitHub repo; pushes to the tracked branch trigger
	// a fresh deploy via the worker. Each kind documents one inflection
	// point so on-call + the Loops forwarder can see the full chain.
	//
	// AuditKindGitHubConnected fires on POST /api/v1/deployments/:id/github
	// after the row lands in app_github_connections. Metadata: {app_id,
	// github_repo, branch, connection_id}.
	AuditKindGitHubConnected = "github.connected"

	// AuditKindGitHubDisconnected fires on DELETE
	// /api/v1/deployments/:id/github. Metadata: {app_id, connection_id}.
	AuditKindGitHubDisconnected = "github.disconnected"

	// AuditKindGitHubPushReceived fires on every accepted POST to
	// /webhooks/github/:webhook_id — signature passed, push event parsed.
	// Metadata: {connection_id, commit_sha, branch, pusher}. Does NOT
	// fire on signature failures (those emit github.signature_failed
	// instead).
	AuditKindGitHubPushReceived = "github.push_received"

	// AuditKindGitHubDeployTriggered fires once the pending_github_deploys
	// row has been inserted (the worker will drain shortly). Distinct from
	// push_received so a downstream consumer can tell "we accepted the
	// signal" from "we will rebuild". Metadata: {connection_id, app_id,
	// commit_sha, pending_id}.
	AuditKindGitHubDeployTriggered = "github.deploy_triggered"

	// AuditKindGitHubSignatureFailed fires when an inbound webhook fails
	// HMAC verification. Metadata: {connection_id (best-effort, may be
	// empty if the row lookup itself failed), ip, user_agent}. Surface
	// to on-call so a leaked secret OR a misconfigured customer is loud.
	AuditKindGitHubSignatureFailed = "github.signature_failed"

	// Email-confirmed deletion lifecycle (Wave FIX-I, migration 044).
	// Two-step destruction for paid-tier deploys + stacks: the agent calls
	// DELETE → API queues a pending_deletions row + emails the user, who
	// confirms via POST /confirm-deletion?token=<tok>. Each kind below
	// captures one inflection point so the audit log reconstructs the
	// full chain (request → email-sent → confirm | cancel | expire).
	//
	// AuditKindDeployDeletionRequested fires on DELETE /api/v1/deployments/:id
	// once the pending_deletions row lands. Metadata: {deploy_id, team_id,
	// pending_deletion_id, expires_at, email_sent_to (masked)}.
	AuditKindDeployDeletionRequested = "deploy.deletion_requested"

	// AuditKindDeployDeletionConfirmed fires when POST
	// /api/v1/deployments/:id/confirm-deletion?token=<tok> resolves a
	// valid pending row. Emitted BEFORE the actual deprovision call so
	// the audit ordering reads request → confirm → (deprovision side
	// effects). Metadata: {deploy_id, team_id, pending_deletion_id,
	// freed_at, age_seconds_in_pending}.
	AuditKindDeployDeletionConfirmed = "deploy.deletion_confirmed"

	// AuditKindDeployDeletionCancelled fires when DELETE
	// /api/v1/deployments/:id/confirm-deletion cancels a pending row.
	// The resource remains active and the slot stays consumed.
	// Metadata: {deploy_id, team_id, pending_deletion_id}.
	AuditKindDeployDeletionCancelled = "deploy.deletion_cancelled"

	// AuditKindDeployDeletionExpired fires when the worker's
	// pending_deletion_expirer flips a row past its TTL to status=expired.
	// The resource remains active (no destruction without explicit
	// confirmation). Metadata: {deploy_id, team_id,
	// pending_deletion_id, age_seconds}.
	AuditKindDeployDeletionExpired = "deploy.deletion_expired"

	// AuditKindStackDeletionRequested / Confirmed / Cancelled / Expired
	// mirror the deploy.* kinds for the /api/v1/stacks/:slug flow.
	// Identical metadata schema except {stack_id, stack_slug} replace
	// {deploy_id} so a single downstream forwarder can branch on the
	// resource_type discriminator without parsing the kind.
	AuditKindStackDeletionRequested = "stack.deletion_requested"
	AuditKindStackDeletionConfirmed = "stack.deletion_confirmed"
	AuditKindStackDeletionCancelled = "stack.deletion_cancelled"
	AuditKindStackDeletionExpired   = "stack.deletion_expired"
)
