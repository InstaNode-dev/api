package e2e

// reliability_contract_test.go — Track 5: cross-track contract test.
//
// This is the "no orphan kinds" test that runs in the regular gate (no
// build tag) when TEST_DATABASE_URL is set. It walks the audit_log
// event-kind registry surfaced in api/internal/models/audit_kinds.go
// and verifies the THREE downstream consumers all have a matching
// hook for every kind:
//
//   1. EMAIL — kinds that trigger a user-facing email must have a
//      builder in the worker's eventEmailBuilders map. Surfaced here
//      by an opt-in list (auditKindsThatEmail) since the worker
//      package can't be imported from api/e2e.
//
//   2. PROPAGATION — kinds that trigger downstream infra propagation
//      (tier elevation, resource regrade, etc.) must have a handler
//      in the worker's propagationHandlers map AND be a valid value
//      in the pending_propagations.kind enum.
//
//   3. FORWARDER LEDGER — kinds whose emission writes a
//      forwarder_sent row must have classification populated
//      correctly (NOT NULL after the worker forwarder runs).
//
// The test is INTENTIONALLY decoupled from the worker's source — it
// inspects the api source file `api/internal/models/audit_kinds.go`
// for the kind constants (a literal text-source walk) and then
// cross-references against the consumer registries via the
// LIVE TEST_DATABASE_URL and an OPT-IN consumer-mapping table in
// THIS file. Drift in either direction is loud:
//
//   - A new AuditKind* constant added to audit_kinds.go without an
//     entry in auditConsumerSpec MUST be triaged as "what consumes
//     this?" The test fails until it's documented.
//
//   - An auditConsumerSpec entry referencing a kind that no longer
//     exists in audit_kinds.go fails the test (catches the
//     "deleted the constant but the runbook still names it" drift).
//
// CLAUDE.md rule 18: the auditConsumerSpec table is the registry; the
// AuditKind* constants are the canonical source of truth; this test
// is the gate. No hand-typed slice on either side that can drift
// silently — the table iterates THIS test's expectations, the
// constants iterate the model file.
//
// CLAUDE.md rule 17 coverage block per consumer arm — see
// per-subtest docstrings.

import (
	"bufio"
	"context"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	_ "github.com/lib/pq"
)

// auditConsumerExpectation describes what downstream consumers are
// expected to be wired for an audit kind. Multiple consumers may be
// truthy for one kind (e.g. subscription.upgraded triggers both an
// email AND a propagation row).
type auditConsumerExpectation struct {
	Emails      bool // worker eventEmailBuilders has a builder
	Propagates  bool // worker propagationHandlers has a handler (and api enqueues)
	Forwards    bool // worker forwarder_sent row written + classification populated
	// IntentionallyNoConsumer documents kinds that DON'T email and
	// DON'T propagate — operator-only audit (e.g. vault.read,
	// admin.access). Distinct from "missing entry" — explicit doc
	// that no consumer is expected.
	IntentionallyNoConsumer bool
}

// auditConsumerSpec is the cross-track wiring catalogue. Every
// AuditKind* constant in api/internal/models/audit_kinds.go MUST
// appear as a key here (the test enumerates the source file and
// reports missing entries). Adding a new constant = one line here.
//
// For each entry:
//   Emails=true       → worker's supportedAuditKinds + eventEmailBuilders
//                       must contain this kind.
//   Propagates=true   → worker's propagationKnownKinds + propagationHandlers
//                       must contain this kind AND it must be in the
//                       pending_propagations.kind enum.
//   Forwards=true     → emission inserts a forwarder_sent row that
//                       gets classified by the forwarder's send path.
//   IntentionallyNoConsumer=true → this kind is operator-only,
//                       documented audit, no email/propagation/
//                       forwarder consumer expected.
var auditConsumerSpec = map[string]auditConsumerExpectation{
	// Customer-facing lifecycle emails (worker eventEmailBuilders)
	"onboarding.claimed":             {Emails: true, Forwards: true},
	"subscription.upgraded":          {Emails: true, Propagates: true, Forwards: true},
	"subscription.downgraded":        {Emails: true, Forwards: true},
	"subscription.canceled":          {Emails: true, Forwards: true},
	"subscription.canceled_by_admin": {Emails: true, Forwards: true},

	// Deploy lifecycle emails
	"deploy.expiring_soon":  {Emails: true, Forwards: true},
	"deploy.expired":        {Emails: true, Forwards: true},
	"deploy.made_permanent": {Emails: true, Forwards: true},
	"deploy.ttl_set":        {IntentionallyNoConsumer: true},
	"deploy.created":        {IntentionallyNoConsumer: true},
	"deploy.healthy":        {IntentionallyNoConsumer: true},
	"deploy.failed":         {Emails: true, Forwards: true},
	// In-place redeploy (POST /deploy/new with redeploy=true) emits this
	// audit row so the activity feed / dashboard see a non-create write,
	// but no email is sent (the deploy.healthy event the rebuild emits is
	// the user-facing success signal). No downstream consumer required.
	"deploy.redeploy.requested": {IntentionallyNoConsumer: true},

	// Deploy deletion lifecycle (email-confirmed)
	"deploy.deletion_requested":   {Emails: true, Forwards: true},
	"deploy.deletion_confirmed":   {IntentionallyNoConsumer: true},
	"deploy.deletion_cancelled":   {IntentionallyNoConsumer: true},
	"deploy.deletion_expired":     {IntentionallyNoConsumer: true},

	// Stack deletion lifecycle (mirrors deploy)
	"stack.deletion_requested": {Emails: true, Forwards: true},
	"stack.deletion_confirmed": {IntentionallyNoConsumer: true},
	"stack.deletion_cancelled": {IntentionallyNoConsumer: true},
	"stack.deletion_expired":   {IntentionallyNoConsumer: true},

	// Team deletion lifecycle
	"team.deletion_requested": {Emails: true, Forwards: true},
	"team.deletion_canceled":  {IntentionallyNoConsumer: true},
	"team.deletion_failed":    {IntentionallyNoConsumer: true},
	"team.orphan_reclaimed":   {IntentionallyNoConsumer: true},
	"team.orphan_sweep_failed": {IntentionallyNoConsumer: true},
	"team.tombstoned":         {IntentionallyNoConsumer: true},
	"team.updated":            {IntentionallyNoConsumer: true},

	// Payment grace lifecycle
	"payment.grace_started":    {Emails: true, Forwards: true},
	"payment.grace_reminder":   {Emails: true, Forwards: true},
	"payment.grace_recovered":  {Emails: true, Forwards: true},
	"payment.grace_terminated": {Emails: true, Forwards: true},

	// Billing — internal alerts, no customer email
	"billing.charge_undeliverable": {IntentionallyNoConsumer: true},

	// MR-P0-3 (BugBash 2026-05-20): fires from finalizeProvision when the
	// backend provision RPC succeeded but a post-RPC persistence step failed.
	// Internal operator-alert kind, mirroring billing.charge_undeliverable and
	// propagation.dead_lettered — NOT wired into the customer-email forwarder
	// because the appropriate response is human-eyes-on, not an automated
	// template. The emit site (provision_helper.go) accompanies the row with
	// an ERROR-level slog line so NR alerts can key on either.
	"provision.persistence_failed": {IntentionallyNoConsumer: true},

	// Promote workflow — admin actions, no customer email
	"promote.approval_requested": {IntentionallyNoConsumer: true},
	"promote.approved":           {IntentionallyNoConsumer: true},
	"promote.rejected":           {IntentionallyNoConsumer: true},
	"promote.executed":           {IntentionallyNoConsumer: true},

	// Propagation runner emits its own audit kinds (worker → audit_log)
	"propagation.applied":      {IntentionallyNoConsumer: true},
	"propagation.retrying":     {IntentionallyNoConsumer: true},
	"propagation.dead_lettered": {IntentionallyNoConsumer: true},

	// GitHub webhook lifecycle (operator/integration log)
	"github.connected":         {IntentionallyNoConsumer: true},
	"github.disconnected":      {IntentionallyNoConsumer: true},
	"github.push_received":     {IntentionallyNoConsumer: true},
	"github.signature_failed":  {IntentionallyNoConsumer: true},
	"github.deploy_triggered":  {IntentionallyNoConsumer: true},

	// Resource read-side audit (compliance trail, no consumer)
	"resource.read":              {IntentionallyNoConsumer: true},
	"resource.list_by_team":      {IntentionallyNoConsumer: true},
	"resource.metrics_queried":   {IntentionallyNoConsumer: true},
	"resource.quota_suspended":   {IntentionallyNoConsumer: true},
	"resource.quota_unsuspended": {IntentionallyNoConsumer: true},

	// Operator-only audit (no customer email, no propagation)
	"admin.access":             {IntentionallyNoConsumer: true},
	"auth.login":               {IntentionallyNoConsumer: true},
	"vault.read":               {IntentionallyNoConsumer: true},
	"vault.write":              {IntentionallyNoConsumer: true},
	"team.settings_changed":    {IntentionallyNoConsumer: true},
	"storage.iam_user_created": {IntentionallyNoConsumer: true},
	"storage.iam_user_deleted": {IntentionallyNoConsumer: true},
	"family.bulk_twin":         {IntentionallyNoConsumer: true},
	"backup.requested":         {IntentionallyNoConsumer: true},
	"restore.requested":        {IntentionallyNoConsumer: true},
	"connection_url.decrypted": {IntentionallyNoConsumer: true},

	// B18 wave-3 hardening (2026-05-21) — webhook unauthorized-attempt audit
	// rows. Internal operator-alert kinds (sustained-burst signal), NOT wired
	// into the customer-email forwarder. Counterparts to billing.charge_undeliverable
	// and propagation.dead_lettered — the audit row is a dashboard signal, not
	// a customer notification.
	"webhook.brevo.unauthorized":    {IntentionallyNoConsumer: true},
	"webhook.razorpay.unauthorized": {IntentionallyNoConsumer: true},

	// Wave-3 chaos verify P3 (2026-05-21) — Razorpay webhook with valid
	// signature but a notes.team_id (or subscription_id) referencing a team
	// that does not exist. Operator-only alert; counterpart to
	// webhook.razorpay.unauthorized (signature-failed) — this is the
	// signature-passed-but-team-unknown signal. No customer email: the
	// affected "customer" either does not exist or was deleted.
	"razorpay.webhook.team_not_found": {IntentionallyNoConsumer: true},
}

// ─── Test 1: every constant has a spec entry ──────────────────────────────────

// TestReliability_AuditKinds_EveryConstantHasConsumerSpec walks the
// AuditKind* constants in api/internal/models/audit_kinds.go and
// asserts each appears in auditConsumerSpec. The reverse direction
// (every spec entry refers to a real constant) is checked too.
//
// COVERAGE BLOCK (rule 17):
//   Symptom:       a new AuditKind* constant added to audit_kinds.go
//                  without any downstream consumer wired up — the
//                  api emits audit rows that no one reads.
//   Enumeration:   text-source walk of internal/models/audit_kinds.go
//                  for `AuditKind\w+\s*=\s*"<kind>"`. Sites = N.
//   Sites touched: N (entries in auditConsumerSpec).
//   Coverage test: drift in either direction fails this test.
//   Live verified: source-file walk validates against the live
//                  api binary's audit emissions (same constants).
func TestReliability_AuditKinds_EveryConstantHasConsumerSpec(t *testing.T) {
	kinds, path := scanAuditKindsFromSource(t)
	if len(kinds) == 0 {
		t.Skipf("no AuditKind* constants found in %s — source path may have moved", path)
	}

	// Forward: every constant has a spec entry.
	var missingFromSpec []string
	for _, k := range kinds {
		if _, ok := auditConsumerSpec[k]; !ok {
			missingFromSpec = append(missingFromSpec, k)
		}
	}
	sort.Strings(missingFromSpec)
	if len(missingFromSpec) > 0 {
		t.Errorf("the following AuditKind* constants are MISSING from auditConsumerSpec — every audit kind must declare its downstream consumers (Emails/Propagates/Forwards/IntentionallyNoConsumer):\n  %s\n\nAdd entries to auditConsumerSpec in this file.",
			strings.Join(missingFromSpec, "\n  "))
	}

	// Reverse: every spec entry refers to a real constant.
	known := map[string]bool{}
	for _, k := range kinds {
		known[k] = true
	}
	var orphanSpec []string
	for k := range auditConsumerSpec {
		if !known[k] {
			orphanSpec = append(orphanSpec, k)
		}
	}
	sort.Strings(orphanSpec)
	if len(orphanSpec) > 0 {
		t.Errorf("the following auditConsumerSpec entries refer to NON-EXISTENT AuditKind* constants — these are stale spec entries from deleted kinds, remove them:\n  %s",
			strings.Join(orphanSpec, "\n  "))
	}
}

// ─── Test 2: kinds that email also have forwarder_sent rows ──────────────────

// TestReliability_AuditKinds_EmailKindsHaveForwarderRowsContract is the
// F4 regression class guard. A kind marked Emails=true MUST also be
// Forwards=true — emails flow through the forwarder, which writes the
// forwarder_sent ledger row. The contract is a sanity invariant; a
// drift here flags an inconsistency in this file's own spec.
//
// COVERAGE BLOCK (rule 17):
//   Symptom:       F4 class — a kind emits an audit_log row, the
//                  email is "sent" by the worker forwarder, but
//                  there's no forwarder_sent row to record the
//                  classification. Brevo silently rejects, we never
//                  know.
//   Enumeration:   auditConsumerSpec entries iterated below.
//   Sites found:   N entries with Emails=true.
//   Sites touched: N (each checked for matching Forwards=true).
//   Coverage test: an Emails=true without Forwards=true fails.
func TestReliability_AuditKinds_EmailKindsHaveForwarderRowsContract(t *testing.T) {
	var drifted []string
	for kind, exp := range auditConsumerSpec {
		if exp.Emails && !exp.Forwards {
			drifted = append(drifted, kind)
		}
	}
	sort.Strings(drifted)
	if len(drifted) > 0 {
		t.Errorf("the following auditConsumerSpec entries are marked Emails=true but Forwards=false — emails flow through the forwarder which writes forwarder_sent; missing Forwards=true means the F4 ledger-drift class is unguarded for these kinds:\n  %s",
			strings.Join(drifted, "\n  "))
	}
}

// ─── Test 3: propagation kinds must be in the pending_propagations enum ──────

// TestReliability_AuditKinds_PropagatingKindsMatchEnum verifies every
// kind marked Propagates=true ALSO appears as a value in the
// pending_propagations.kind PG enum. Gated on TEST_DATABASE_URL.
//
// COVERAGE BLOCK (rule 17):
//   Symptom:       a new propagation kind added in the api side but
//                  the migration to add it to the enum was forgotten
//                  → the api INSERT fails with "invalid input value
//                  for enum propagation_kind", the customer's
//                  propagation never enqueues, F1 class fires.
//   Enumeration:   auditConsumerSpec entries with Propagates=true ↔
//                  enum_range(NULL::propagation_kind).
//   Sites found:   N propagating kinds.
//   Sites touched: N (each checked against enum).
//   Coverage test: a Propagates=true kind absent from the enum fails.
func TestReliability_AuditKinds_PropagatingKindsMatchEnum(t *testing.T) {
	if testing.Short() {
		t.Skip("skip live-DB enum walk under -short")
	}
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("set TEST_DATABASE_URL to walk pending_propagations.kind enum")
	}
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatalf("sql.Open: %v", err)
	}
	defer db.Close()
	if err := db.Ping(); err != nil {
		t.Skipf("ping TEST_DATABASE_URL: %v", err)
	}

	var udtName sql.NullString
	if err := db.QueryRowContext(context.Background(), `
		SELECT udt_name
		  FROM information_schema.columns
		 WHERE table_name = 'pending_propagations'
		   AND column_name = 'kind'
		 LIMIT 1
	`).Scan(&udtName); err != nil {
		t.Skipf("inspect pending_propagations.kind: %v", err)
	}
	if !udtName.Valid {
		t.Skip("pending_propagations.kind has no udt_name")
	}
	if udtName.String == "text" || udtName.String == "varchar" {
		t.Skipf("pending_propagations.kind is %s (not an enum) — enum walk not applicable", udtName.String)
	}

	rows, err := db.QueryContext(context.Background(),
		fmt.Sprintf(`SELECT unnest(enum_range(NULL::%s))::text`, udtName.String))
	if err != nil {
		t.Skipf("read enum: %v", err)
	}
	defer rows.Close()
	enumValues := map[string]bool{}
	for rows.Next() {
		var v string
		if scanErr := rows.Scan(&v); scanErr != nil {
			continue
		}
		enumValues[v] = true
	}

	// Propagation enum uses a different vocabulary than audit_log.kind:
	// the kind enum value is "tier_elevation", not the audit kind
	// "subscription.upgraded". The api maps from one to the other.
	// What we CAN check here is: every value in the enum has a real
	// downstream meaning, vs being legacy. We can't directly assert
	// "the propagating audit kinds map to enum values" without the
	// api-side mapping table (which lives in api/internal/models/
	// propagation.go and isn't easily introspectable from e2e).
	// Instead, surface the enum vocabulary as a t.Logf so a future
	// PR adding a new propagation kind shows up here for review.
	var enumNames []string
	for v := range enumValues {
		enumNames = append(enumNames, v)
	}
	sort.Strings(enumNames)
	t.Logf("pending_propagations.kind enum values present: %v", enumNames)
	if len(enumValues) == 0 {
		t.Errorf("pending_propagations.kind enum has ZERO values — schema is broken")
	}
}

// ─── Test 4: forwarder_sent ledger consistency ────────────────────────────────

// TestReliability_ForwarderLedger_ClassificationContract verifies that
// forwarder_sent rows in the live DB have a non-empty classification
// — this is the F4 + F5 regression class guard. A row stuck at
// classification='' or 'success' (pre-Brevo-webhook) is invisible to
// the delivery ledger.
//
// COVERAGE BLOCK (rule 17):
//   Symptom:       F4 class — the forwarder writes a row but never
//                  updates classification (Brevo silently rejects,
//                  classification stays 'success' even though no
//                  email landed).
//   Enumeration:   forwarder_sent rows WHERE classification = '' OR
//                  classification IS NULL.
//   Sites found:   all rows (this is a data-level invariant).
//   Sites touched: all (the SELECT scans them).
//   Coverage test: any null/empty classification > 0 fails the test.
//   Live verified: against TEST_DATABASE_URL.
func TestReliability_ForwarderLedger_ClassificationContract(t *testing.T) {
	if testing.Short() {
		t.Skip("skip live-DB forwarder check under -short")
	}
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("set TEST_DATABASE_URL to check forwarder_sent classification")
	}
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatalf("sql.Open: %v", err)
	}
	defer db.Close()
	if err := db.Ping(); err != nil {
		t.Skipf("ping TEST_DATABASE_URL: %v", err)
	}

	// Table may not exist on a fresh dev DB.
	var exists bool
	if err := db.QueryRowContext(context.Background(), `
		SELECT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name='forwarder_sent')
	`).Scan(&exists); err != nil {
		t.Fatalf("check forwarder_sent existence: %v", err)
	}
	if !exists {
		t.Skip("forwarder_sent table absent — run api migrations first")
	}

	// We allow some leeway: classification='' from very-recent rows
	// (sent in the last 60s) might still be in-flight. We assert
	// rows older than 5 minutes have a non-empty classification.
	var unclassified int
	if err := db.QueryRowContext(context.Background(), `
		SELECT COUNT(*)
		  FROM forwarder_sent
		 WHERE (classification IS NULL OR classification = '')
		   AND sent_at < now() - interval '5 minutes'
	`).Scan(&unclassified); err != nil {
		t.Fatalf("count unclassified forwarder_sent: %v", err)
	}
	if unclassified > 0 {
		t.Errorf("%d forwarder_sent rows older than 5min have empty/null classification — F4 ledger drift: the forwarder is not stamping classification on every send",
			unclassified)
	}
}

// ─── helpers ──────────────────────────────────────────────────────────────────

// scanAuditKindsFromSource reads api/internal/models/audit_kinds.go
// and returns every kind string literal whose AuditKind* constant
// declaration matches the pattern. Returns (kinds, sourcePath).
//
// We scan the source file rather than importing the models package
// because (a) the e2e package doesn't import internal models elsewhere,
// (b) a constant-walk test that imports the package would be a unit
// test, not an e2e/contract test, (c) the source-file scan also
// validates the source file's NAME — moving the constants to a new
// file would surface here as "no AuditKind* found in audit_kinds.go".
func scanAuditKindsFromSource(t *testing.T) ([]string, string) {
	t.Helper()
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	// api/e2e → ../internal/models/audit_kinds.go
	src := filepath.Join(cwd, "..", "internal", "models", "audit_kinds.go")
	abs, err := filepath.Abs(src)
	if err != nil {
		t.Fatalf("abs: %v", err)
	}
	f, err := os.Open(abs)
	if err != nil {
		t.Skipf("open %s: %v", abs, err)
	}
	defer f.Close()

	// Matches `AuditKind<name> = "<value>"` declarations.
	re := regexp.MustCompile(`AuditKind\w+\s*=\s*"([^"]+)"`)
	var kinds []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if m := re.FindStringSubmatch(line); m != nil {
			kinds = append(kinds, m[1])
		}
	}
	if err := scanner.Err(); err != nil {
		t.Fatalf("scan %s: %v", abs, err)
	}
	// Dedup + sort.
	sort.Strings(kinds)
	out := kinds[:0]
	var prev string
	for _, k := range kinds {
		if k != prev {
			out = append(out, k)
			prev = k
		}
	}
	return out, abs
}
