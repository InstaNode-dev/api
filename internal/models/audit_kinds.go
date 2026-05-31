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

	// AuditKindBillingChargeUndeliverable fires when a Razorpay
	// subscription.charged webhook confirms a real card charge that the
	// platform CANNOT translate into a delivered upgrade — the team is
	// unresolvable (bad/missing notes, not a transient DB fault — see F2's
	// teamResolveUnretryable classification) OR the resolved plan tier is
	// not in plans.yaml (F3). This is the make-good worklist signal: an
	// operator must reconcile the charge in the Razorpay dashboard (issue a
	// refund or hand-grant the tier). Metadata carries subscription_id,
	// payment_id, and reason ("team_unresolvable" | "unknown_tier") plus
	// resolved_tier / plan_id when known. The audit row is paired with a
	// loud slog.Error so an alert can key on the kind. This kind is
	// intentionally NOT wired into the worker's email forwarder
	// (supportedAuditKinds) — it is an internal operator alert, not a
	// customer-facing email; a customer who was wrongly charged should hear
	// from a human, not an automated template.
	AuditKindBillingChargeUndeliverable = "billing.charge_undeliverable"

	// AuditKindTeamTTLPoliciesPromoted fires when a paid-tier upgrade
	// (free→hobby/hobby_plus/pro/growth/team) promotes the team's
	// deployment TTL state via PromoteDeploymentTTLsForTeam: existing
	// auto_24h deploys flipped to permanent + the team default flipped
	// if it was still auto_24h. Metadata carries `count_deploys_promoted`
	// (int), `team_default_flipped` (bool), and `reason` ("tier_upgrade").
	// This kind is intentionally NOT wired into the worker's customer-email
	// forwarder — it's an internal observability signal, not a user-facing
	// notification (the upgrade itself already triggers the
	// subscription.upgraded email, which is enough customer comms).
	AuditKindTeamTTLPoliciesPromoted = "team.ttl_policies_promoted"

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

	// AuditKindDeployRedeployRequested fires the moment a redeploy compute
	// path is accepted (after status is flipped to 'building' and BEFORE
	// the async rebuild runs). Emitted on both POST /deploy/:id/redeploy
	// AND POST /deploy/new with redeploy=true. Metadata: {deploy_id,
	// team_id, app_id, env, source: "redeploy_endpoint" |
	// "deploy_new_in_place"}. Distinct from deploy.created so the activity
	// feed can distinguish "new app shipped" from "existing app rebuilt".
	AuditKindDeployRedeployRequested = "deploy.redeploy.requested"

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
	// errors, etc.) — the team stays in deletion_pending state so an
	// operator and the orphan-sweep reconciler can investigate and
	// retry. Metadata: {error, failed_at_step, resource_id (when
	// applicable)}.
	AuditKindTeamDeletionFailed = "team.deletion_failed"

	// AuditKindOrphanSweepReclaimed fires when the worker's orphan-sweep
	// reconciler detects and completes the teardown of an orphan — a
	// customer DB, k8s namespace, storage prefix, or Razorpay subscription
	// whose owning team is gone or tombstoned. This is the eventually-
	// consistent safety net that finishes any partial team deletion.
	// Metadata: {orphan_kind, identifier, action}. Producer: the worker
	// module (see worker/internal/jobs/orphan_sweep_reconciler.go).
	AuditKindOrphanSweepReclaimed = "team.orphan_reclaimed"

	// AuditKindOrphanSweepFailed fires when the orphan-sweep reconciler
	// finds an orphan it cannot reclaim (provider error, cancel failure).
	// The orphan stays for the next sweep; this row is the operator
	// alert. Metadata: {orphan_kind, identifier, error}.
	AuditKindOrphanSweepFailed = "team.orphan_sweep_failed"

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

	// Storage-quota suspend/unsuspend lifecycle. Producer: the WORKER's
	// storage-quota enforcement job (worker/internal/jobs) — NOT the api.
	// The api side of this contract is twofold: (1) declare the canonical
	// kind strings here so a downstream consumer never typo-drifts against
	// the worker's emit site, and (2) the worker's event_email_mapping.go +
	// lifecycle_emails.go register a builder + Go renderer keyed on these
	// exact strings so each suspend/unsuspend produces a customer email and
	// a dashboard Recent-Activity row. Adding either kind here WITHOUT the
	// matching worker wiring means the audit row lands but no email is sent
	// (see this file's header note and the worker repo's
	// TestEveryEmailKindHasAGoRenderer / TestEventEmail_AllSupportedKindsHaveBuilder).
	//
	// AuditKindResourceQuotaSuspended fires when the worker suspends a
	// customer resource for exceeding its storage-quota limit (the
	// provider-side CONNECT/ACL revoke + resources.status='suspended'
	// transition). Metadata carries resource_id, resource_type, and the
	// resource name so the email body can name the affected resource and
	// the renderer can tell the customer how to recover (delete data or
	// upgrade the plan).
	AuditKindResourceQuotaSuspended = "resource.quota_suspended"

	// AuditKindResourceQuotaUnsuspended fires when the worker lifts a prior
	// storage-quota suspension — the customer freed enough space (or
	// upgraded) and the resource is back online. Metadata mirrors
	// resource.quota_suspended (resource_id, resource_type, name) so the
	// "your resource is back" email can name it.
	AuditKindResourceQuotaUnsuspended = "resource.quota_unsuspended"

	// Pending-propagation lifecycle (migration 058) — the durable retry
	// queue for "tier elevated in the platform DB but infra regrade not
	// yet applied" scenarios. The api enqueues `pending_propagations`
	// rows from handleSubscriptionCharged; the worker's propagation_runner
	// pulls eligible rows and dispatches by `kind`. These three audit
	// kinds capture each terminal/transient inflection point so an
	// operator can reconstruct the full chain.
	//
	// AuditKindPropagationApplied fires when the worker successfully
	// dispatches every per-resource action for a pending_propagations row
	// and stamps `applied_at`. Metadata: {propagation_id, kind, team_id,
	// target_tier (for tier_elevation), attempts, duration_ms}. INFO-level
	// ledger event — no email. The Loops/Brevo forwarder is intentionally
	// NOT wired for this kind (it would spam a customer with "your upgrade
	// landed in the infra" every charge); the existing subscription.upgraded
	// kind is what the customer-facing email keys on.
	AuditKindPropagationApplied = "propagation.applied"

	// AuditKindPropagationRetrying fires on every failed attempt where the
	// worker re-schedules with exponential backoff (attempts < maxAttempts).
	// DEBUG-level — would otherwise spam INFO at the per-tick frequency
	// of a Razorpay outage. Metadata: {propagation_id, kind, team_id,
	// attempts, next_attempt_at, last_error}. NOT wired into the email
	// forwarder — this is operational noise, not a customer event.
	AuditKindPropagationRetrying = "propagation.retrying"

	// AuditKindPropagationDeadLettered is the alert-able signal. Fires
	// when the worker exhausts maxAttempts on a pending_propagations row
	// and stamps `failed_at`. Paired with a structured slog ERROR (so the
	// NR alert can key on either the audit row OR the log line) and
	// matches the `billing.charge_undeliverable` pattern: an operator
	// reconciliation event, NOT a customer-facing email. The kind is
	// intentionally NOT wired into the worker's event-email forwarder
	// (supportedAuditKinds) — a customer whose infra cap silently
	// stayed at hobby after paying for pro deserves a human follow-up,
	// not an automated template. Metadata: {propagation_id, kind,
	// team_id, target_tier, attempts, last_error, age_seconds}.
	AuditKindPropagationDeadLettered = "propagation.dead_lettered"

	// AuditKindProvisionPersistenceFailed fires from finalizeProvision when the
	// backend provision RPC succeeded but a post-RPC persistence step
	// (connection-URL encrypt/store, provider_resource_id store, pending→active
	// flip) failed. This is the MR-P0-3 orphan-prevention signal: at the
	// moment we know "the customer got real credentials downstream but our
	// platform DB cannot address the row", we tear down the backend object
	// (best-effort), soft-delete the row, return 503 to the caller, AND emit
	// this audit kind so operators can reconstruct exactly when the platform
	// produced an unreachable resource. NOT wired into the Loops/Brevo email
	// forwarder — this is an internal operator alert, not a customer event
	// (mirrors AuditKindBillingChargeUndeliverable and
	// AuditKindPropagationDeadLettered). Metadata: {resource_id, resource_type,
	// log_prefix, provider_resource_id, request_id, tier, env}. INFO-level
	// audit row + ERROR-level slog line (already emitted at the per-step
	// failure) for NR alerting.
	AuditKindProvisionPersistenceFailed = "provision.persistence_failed"

	// AuditKindBrevoWebhookUnauthorized fires from POST /webhooks/brevo/:secret
	// when the URL-token compare fails (B18 hardening, 2026-05-21). Persisted
	// best-effort via safego.Go so a DB outage NEVER blocks the 401 owed to
	// the caller; the audit row carries presence booleans + a masked source-IP
	// subnet (never the secret value itself) so an operator can see "X auth
	// failures over Y minutes" without grepping NR logs. Useful as the signal
	// for a sustained burst from a non-Brevo IP (the URL-token-auth surface
	// is a known soft target relative to HMAC-signed webhooks).
	AuditKindBrevoWebhookUnauthorized = "webhook.brevo.unauthorized"

	// AuditKindRazorpayWebhookUnauthorized fires from POST /razorpay/webhook
	// when verifyRazorpaySignature returns false (B18 hardening, 2026-05-21).
	// Same shape as the Brevo unauthorized kind: persisted best-effort via
	// safego.Go, metadata carries presence booleans + masked source-IP subnet
	// only (never the raw signature or webhook secret). Detects probing
	// attempts against the billing-webhook path with crafted payloads.
	AuditKindRazorpayWebhookUnauthorized = "webhook.razorpay.unauthorized"

	// AuditKindRazorpayWebhookTeamNotFound fires from POST /razorpay/webhook
	// when a Razorpay webhook arrives with a VALID signature but the team
	// referenced via notes.team_id (or the subscription_id fallback) does
	// not exist in our DB — i.e. models.UpgradeTeamAllTiersWithSubscription
	// returned models.ErrTeamNotFound (Wave-3 chaos verify P3, 2026-05-21).
	//
	// Operationally interesting cases all map to this row:
	//   - Razorpay-dashboard typo in subscription `notes` (operator paste error)
	//   - A team that was deleted while its Razorpay subscription survived
	//     (cancel-first abort gate raced; orphan-sweep reconciler will pick
	//     it up but the leaked webhook is the loudest signal)
	//   - A synthetic chaos probe with a real signature but bogus team_id
	//     (Wave-3 test #6 is exactly this shape)
	//   - An attacker who somehow obtained the webhook secret probing for
	//     valid-signature paths (signature already verified to land here —
	//     unlike webhook.razorpay.unauthorized, which is the signature-fail
	//     case)
	//
	// Counterpart to AuditKindRazorpayWebhookUnauthorized: that kind is the
	// "signature failed" signal; this kind is the "signature passed but the
	// payload references a non-existent team" signal. Both are operator-only
	// (IntentionallyNoConsumer in the reliability_contract spec) — sending an
	// automated customer email here would only confuse a deleted/typo'd team.
	//
	// Persisted best-effort via safego.Go with a 3s bounded-timeout context
	// (matches the resource.read / brevo.unauthorized pattern, NEVER
	// context.Background — see CLAUDE.md rule 16 + the bounded-context audit
	// in 2026-05-20). Metadata carries:
	//   - event_type:     Razorpay webhook event name (e.g. "subscription.charged")
	//   - event_id:       Razorpay X-Razorpay-Event-Id (replay-protection id)
	//   - notes_team_id:  the team_id the payload claimed (safe to log raw —
	//                     UUID shape; correlates with operator dashboard search)
	//   - subscription_id: from the parsed subscription entity
	// Deliberately NO email, no PII, no payload body — operator-visibility
	// only (mirrors webhook.razorpay.unauthorized + billing.charge_undeliverable).
	AuditKindRazorpayWebhookTeamNotFound = "razorpay.webhook.team_not_found"
)

// PropagationKind* are the discriminator values for pending_propagations.kind.
// Named constants (not scattered string literals) per CLAUDE.md conventions —
// a typo in one emit site versus another silently dropped two distinct
// emitters of the same logical event in the 2026-05-15 expiry-email
// regression, and rule 16 enumerate-before-edit specifically called this
// out as the modal failure mode. The worker's propagation_runner registry
// uses the SAME constants (vendored via the propagation kinds file there)
// so a missing handler for a registered kind fails the build, not prod.
const (
	// PropagationKindTierElevation is the only kind today: a Razorpay
	// subscription.charged / .activated has committed the upgrade to
	// teams.plan_tier + resources.tier; the worker must call
	// provisioner.RegradeResource for every active resource on the team
	// so the infra cap (ALTER ROLE … CONNECTION LIMIT, Redis CONFIG SET
	// maxmemory, …) matches the resource.tier snapshot. The row's
	// target_tier carries the tier the api wants regraded TO.
	PropagationKindTierElevation = "tier_elevation"
)
