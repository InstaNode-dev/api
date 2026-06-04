package handlers_test

// stacks_block_integration_test.go — W4 stack-block integration suite.
//
// Closes the remaining P0/P1 STACK legs of the USER-FLOW matrix
// (docs/sessions/2026-06-04/USER-FLOW-INVENTORY-AND-TEST-MATRIX.md) that
// lacked a dedicated DB-backed handler-level assertion:
//
//   D11  POST /stacks/new          — multi-service create persists the stack row
//                                     + one stack_services row per manifest
//                                     service, all carrying the resolved env tag
//                                     (rule 11: omitted env → 'development').
//   D4   POST /stacks/new (anon)   — NULL team_id + 6h TTL (mig 005 / PR #214).
//   D2/  POST /stacks/new over cap — 402 + agent_action from plans.Registry
//   C2.S                            (rule 3: limits never hardcoded).
//   D12  PATCH /stacks/:slug/env   — env_vars JSONB merge (mig 062) AND the
//                                     keys_set / keys_deleted / total_after
//                                     audit-log counters (rule 12: the ledger is
//                                     the truth surface — the HTTP body carries
//                                     only the merged env; the counters are
//                                     stamped on the stack.env.updated audit_log
//                                     row). keys_set counts ONLY non-empty
//                                     upserts; a no-op empty-delete of an absent
//                                     key counts as NEITHER a set NOR a delete.
//        PATCH … deleting stack    — 409 stack_deleting under the FOR UPDATE
//                                     teardown guard (mig/PR #238).
//
// Everything here is in-repo integration via testhelpers.SetupTestDB + the
// package's NoopStackProvider app builder (newStackTestApp) and existing seed
// helpers (testhelpers.MustCreateTeamDB, MustSignSessionJWT, postStackNew,
// multipartBody, createMinimalTarball, seedStackWithService). NOTHING here
// redefines an existing helper.
//
// The keys_set/keys_deleted/total_after counters were the single uncovered
// behavior on the stack-block matrix rows: stack_env_persist_test.go asserts
// the DB round-trip + masking but never reads those counters, and the handler's
// rule-12 comment (stack.go ~L1245) explicitly notes the old len(body.Env)-
// deletes math over-counted no-op deletes. This suite reads them off the
// stack.env.updated audit_log row and is the regression gate for that fix.

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"instant.dev/internal/testhelpers"
)

// stackBlockPatchEnvResp is the PATCH /stacks/:slug/env response envelope.
// The handler returns only ok / env / message in the HTTP body; the rule-12
// audit-surface counters (keys_set / keys_deleted / total_after) live in the
// audit_log row's metadata, NOT the response (rule 12: the ledger is the truth
// surface, not the handler's 200). This struct decodes the body half; the
// counters are read from audit_log via stackBlockEnvAuditCounters.
type stackBlockPatchEnvResp struct {
	OK      bool              `json:"ok"`
	Env     map[string]string `json:"env"`
	Message string            `json:"message"`
	Error   string            `json:"error"`
}

// stackBlockEnvCounters mirrors the audit_log metadata the UpdateEnv handler
// stamps on every successful PATCH (kind='stack.env.updated').
type stackBlockEnvCounters struct {
	KeysSet     int `json:"keys_set"`
	KeysDeleted int `json:"keys_deleted"`
	TotalAfter  int `json:"total_after"`
}

// patchStackEnvBlock PATCHes /stacks/:slug/env and decodes the response body.
// auth=="" exercises the RequireAuth gate.
func patchStackEnvBlock(t *testing.T, app *fiber.App, slug string, env map[string]string, auth string) (*http.Response, stackBlockPatchEnvResp) {
	t.Helper()
	body, _ := json.Marshal(map[string]any{"env": env})
	req := httptest.NewRequest(http.MethodPatch, "/stacks/"+slug+"/env", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	if auth != "" {
		req.Header.Set("Authorization", "Bearer "+auth)
	}
	resp, err := app.Test(req, 10000)
	require.NoError(t, err)
	var parsed stackBlockPatchEnvResp
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&parsed))
	return resp, parsed
}

// stackBlockEnvAuditCounters reads the keys_set/keys_deleted/total_after
// counters from the most-recent stack.env.updated audit_log row for the given
// stack. The audit insert is fire-and-forget (safego.Go), so it polls briefly.
// minRows lets a caller wait until the Nth PATCH's row has landed (rows are
// ordered by created_at DESC, so index 0 is the latest).
func stackBlockEnvAuditCounters(t *testing.T, db *sql.DB, stackID string, minRows int) stackBlockEnvCounters {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for {
		var n int
		require.NoError(t, db.QueryRowContext(context.Background(),
			`SELECT COUNT(*) FROM audit_log WHERE kind='stack.env.updated' AND resource_id=$1::uuid`,
			stackID).Scan(&n))
		if n >= minRows {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("stack.env.updated audit row never landed: have %d, want >=%d", n, minRows)
		}
		time.Sleep(20 * time.Millisecond)
	}
	var meta []byte
	require.NoError(t, db.QueryRowContext(context.Background(),
		`SELECT metadata FROM audit_log
		   WHERE kind='stack.env.updated' AND resource_id=$1::uuid
		   ORDER BY created_at DESC, id DESC LIMIT 1`,
		stackID).Scan(&meta))
	var c stackBlockEnvCounters
	require.NoError(t, json.Unmarshal(meta, &c))
	return c
}

// stackIDForSlug resolves a stack's UUID from its slug (audit_log.resource_id
// is the stack UUID, not the slug).
func stackIDForSlug(t *testing.T, db *sql.DB, slug string) string {
	t.Helper()
	var id string
	require.NoError(t, db.QueryRowContext(context.Background(),
		`SELECT id::text FROM stacks WHERE slug=$1`, slug).Scan(&id))
	return id
}

// readStackEnvVars reads stacks.env_vars directly so persistence is asserted
// against the row, not the (masked) handler response.
func readStackEnvVars(t *testing.T, db *sql.DB, slug string) map[string]string {
	t.Helper()
	var raw sql.NullString
	require.NoError(t, db.QueryRowContext(context.Background(),
		`SELECT env_vars::text FROM stacks WHERE slug = $1`, slug).Scan(&raw))
	out := map[string]string{}
	if raw.Valid && raw.String != "" {
		require.NoError(t, json.Unmarshal([]byte(raw.String), &out))
	}
	return out
}

// ── D11 — multi-service create persists stack + per-service rows + env tag ────

// TestStackBlock_D11_MultiService_PersistsMembersAndEnvTag is the matrix D11
// row: a 2-service manifest must persist one stacks row plus exactly one
// stack_services row per declared service, and (rule 11) every row must carry
// the resolved env tag. With no `env` field on /stacks/new, the default is
// 'development' (mig 026) — accidental no-env creates land in the lowest-stakes
// bucket, never production.
func TestStackBlock_D11_MultiService_PersistsMembersAndEnvTag(t *testing.T) {
	requireTestDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	ensureStackTables(t, db)

	teamID := testhelpers.MustCreateTeamDB(t, db, "pro") // pro: deployments_apps=10
	jwt := testhelpers.MustSignSessionJWT(t, mustUUIDStr(), teamID, "d11@example.com")
	app := newStackTestApp(t, db)

	tarball := createMinimalTarball(t)
	resp := postStackNew(t, app, jwt, testManifest, map[string][]byte{
		"api":    tarball,
		"worker": tarball,
	})
	defer resp.Body.Close()
	require.Equal(t, http.StatusAccepted, resp.StatusCode)

	var created struct {
		OK      bool   `json:"ok"`
		StackID string `json:"stack_id"`
	}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&created))
	require.True(t, created.OK)
	slug := created.StackID
	require.NotEmpty(t, slug)

	// One stacks row, env tag = development (rule 11 default).
	var stackEnv, stackTier string
	var stackTeam sql.NullString
	require.NoError(t, db.QueryRowContext(context.Background(),
		`SELECT env, tier, team_id::text FROM stacks WHERE slug = $1`, slug,
	).Scan(&stackEnv, &stackTier, &stackTeam))
	assert.Equal(t, "development", stackEnv, "no-env create resolves to development (mig 026 / rule 11)")
	assert.Equal(t, "pro", stackTier, "authenticated stack snapshots the team plan_tier at creation")
	require.True(t, stackTeam.Valid, "authenticated stack must carry the team_id")
	assert.Equal(t, teamID, stackTeam.String)

	// Exactly two member services, both linked to the stack.
	var svcCount int
	require.NoError(t, db.QueryRowContext(context.Background(), `
		SELECT COUNT(*) FROM stack_services ss
		JOIN stacks s ON s.id = ss.stack_id
		WHERE s.slug = $1`, slug).Scan(&svcCount))
	assert.Equal(t, 2, svcCount, "one stack_services row per declared manifest service")

	// The member service NAMES match the manifest (enumeration, not a count).
	rows, err := db.QueryContext(context.Background(), `
		SELECT ss.name FROM stack_services ss
		JOIN stacks s ON s.id = ss.stack_id
		WHERE s.slug = $1 ORDER BY ss.name`, slug)
	require.NoError(t, err)
	defer rows.Close()
	var names []string
	for rows.Next() {
		var n string
		require.NoError(t, rows.Scan(&n))
		names = append(names, n)
	}
	require.NoError(t, rows.Err())
	assert.Equal(t, []string{"api", "worker"}, names, "member rows must be exactly the manifest services")
}

// ── D4 — anonymous stack: NULL team_id + 6h TTL ──────────────────────────────

// TestStackBlock_D4_Anonymous_NullTeamAnd6hTTL is the matrix D4 row. Anonymous
// deploy goes through /stacks/new (NOT /deploy/new, which is RequireAuth +
// deployments.team_id NOT NULL — memory
// project_anonymous_deploy_via_stacks_not_deploy_new). The row must carry NULL
// team_id and a ~6h expires_at (PR #214 anonymousStackTTL), tighter than the
// 24h anon-data-resource TTL because a stack is live compute.
func TestStackBlock_D4_Anonymous_NullTeamAnd6hTTL(t *testing.T) {
	requireTestDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	ensureStackTables(t, db)
	app := newStackTestApp(t, db)

	resp := postStackNew(t, app, "", testManifestSingleService, map[string][]byte{
		"web": createMinimalTarball(t),
	})
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusServiceUnavailable {
		t.Skip("POST /stacks/new: service unavailable")
	}
	require.Equal(t, http.StatusAccepted, resp.StatusCode)

	var body struct {
		OK        bool   `json:"ok"`
		StackID   string `json:"stack_id"`
		Tier      string `json:"tier"`
		ExpiresIn string `json:"expires_in"`
	}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	require.True(t, body.OK)
	assert.Equal(t, "anonymous", body.Tier)
	assert.Equal(t, "6h", body.ExpiresIn)

	var teamID sql.NullString
	var expiresAt sql.NullTime
	require.NoError(t, db.QueryRowContext(context.Background(),
		`SELECT team_id::text, expires_at FROM stacks WHERE slug = $1`, body.StackID,
	).Scan(&teamID, &expiresAt))
	assert.False(t, teamID.Valid, "anonymous stack must have NULL team_id (mig 005)")
	require.True(t, expiresAt.Valid, "anonymous stack must have a non-NULL TTL")
	assert.InDelta(t, (6 * time.Hour).Seconds(), time.Until(expiresAt.Time).Seconds(), 300,
		"anon stack TTL must be ~6h, not the 24h data-resource window")
}

// ── D2/C2.S — create over deployments_apps cap → 402 + agent_action ──────────

// TestStackBlock_D2_OverCap_402WithAgentAction is the matrix D2 / C2.S row:
// hobby allows deployments_apps=1 (plans.yaml). With one active stack already
// present, the next /stacks/new must 402 and carry an agent_action upgrade hint
// (rule 3 — the limit comes from plans.Registry, never a hardcoded literal).
func TestStackBlock_D2_OverCap_402WithAgentAction(t *testing.T) {
	requireTestDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	ensureStackTables(t, db)
	app := newStackTestApp(t, db)

	teamID := testhelpers.MustCreateTeamDB(t, db, "hobby")
	// Seed one active (compute-consuming) stack so the next create trips the cap.
	_, err := db.Exec(`INSERT INTO stacks (team_id, slug, namespace, tier, env, status)
		VALUES ($1::uuid, $2, $3, 'hobby', 'production', 'healthy')`,
		teamID, "blk-cap-"+teamID[:8], "ns-blk-cap-"+teamID[:8])
	require.NoError(t, err)

	jwt := testhelpers.MustSignSessionJWT(t, mustUUIDStr(), teamID, "d2cap@example.com")
	resp := postStackNew(t, app, jwt, testManifestSingleService, map[string][]byte{
		"web": createMinimalTarball(t),
	})
	defer resp.Body.Close()
	require.Equal(t, http.StatusPaymentRequired, resp.StatusCode)

	var body struct {
		OK          bool   `json:"ok"`
		Error       string `json:"error"`
		AgentAction string `json:"agent_action"`
	}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	assert.False(t, body.OK)
	assert.NotEmpty(t, body.AgentAction, "402 over-cap must carry an agent_action upgrade hint")
}

// ── D12 — env merge JSONB + keys_set/keys_deleted/total_after counters ────────

// TestStackBlock_D12_EnvMergeCounters is the matrix D12 row and the regression
// gate for the rule-12 audit-surface fix (stack.go: "keys_set counts only
// actual upserts"). It walks a 4-step sequence and asserts BOTH the response
// counters AND the persisted env_vars at each step:
//
//  1. set 2 keys                         → keys_set=2, deleted=0, total=2
//  2. add 1 + overwrite 1                → keys_set=2, deleted=0, total=3
//  3. delete 1 present + no-op delete 1  → keys_set=0, deleted=1, total=2
//     absent key  (the over-count bug)
//  4. set 1 + delete 1 in same patch     → keys_set=1, deleted=1, total=2
//
// Step 3 is the load-bearing assertion: the pre-fix math len(body.Env)-deletes
// would have reported keys_set=1 for a patch that set NOTHING (one real delete
// + one no-op empty-delete of an absent key). keys_deleted counts only deletes
// that actually removed a present key.
func TestStackBlock_D12_EnvMergeCounters(t *testing.T) {
	requireTestDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	ensureStackTables(t, db)

	teamID := testhelpers.MustCreateTeamDB(t, db, "pro")
	jwt := testhelpers.MustSignSessionJWT(t, mustUUIDStr(), teamID, "d12@example.com")
	app := newStackTestApp(t, db)

	resp := postStackNew(t, app, jwt, testManifestSingleService, map[string][]byte{
		"web": createMinimalTarball(t),
	})
	require.Equal(t, http.StatusAccepted, resp.StatusCode)
	var created struct {
		StackID string `json:"stack_id"`
	}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&created))
	resp.Body.Close()
	slug := created.StackID
	require.NotEmpty(t, slug)
	stackID := stackIDForSlug(t, db, slug)

	// The counters are stamped on the audit_log row (rule 12: the ledger is the
	// truth surface, not the handler's 200 — the HTTP body carries only the
	// merged env). Each PATCH adds one stack.env.updated row; we read the latest
	// after waiting for the Nth row to land (audit insert is fire-and-forget).

	// 1) Set two keys.
	r1, b1 := patchStackEnvBlock(t, app, slug, map[string]string{
		"API_URL":   "https://api.example",
		"LOG_LEVEL": "info",
	}, jwt)
	r1.Body.Close()
	require.Equal(t, http.StatusOK, r1.StatusCode)
	assert.True(t, b1.OK)
	c1 := stackBlockEnvAuditCounters(t, db, stackID, 1)
	assert.Equal(t, 2, c1.KeysSet, "two non-empty upserts")
	assert.Equal(t, 0, c1.KeysDeleted)
	assert.Equal(t, 2, c1.TotalAfter)
	assert.Len(t, readStackEnvVars(t, db, slug), 2)

	// 2) Add one, overwrite one — both are upserts.
	r2, _ := patchStackEnvBlock(t, app, slug, map[string]string{
		"LOG_LEVEL": "debug", // overwrite
		"FEATURE_X": "on",    // new
	}, jwt)
	r2.Body.Close()
	require.Equal(t, http.StatusOK, r2.StatusCode)
	c2 := stackBlockEnvAuditCounters(t, db, stackID, 2)
	assert.Equal(t, 2, c2.KeysSet, "overwrite + new both count as set")
	assert.Equal(t, 0, c2.KeysDeleted)
	assert.Equal(t, 3, c2.TotalAfter)

	// 3) Delete one PRESENT key + no-op delete one ABSENT key. This is the
	//    over-count guard: keys_set MUST be 0 (the pre-fix len(body.Env)-deletes
	//    math would have made it 1), keys_deleted MUST be 1 (only the present key
	//    was actually removed — the absent no-op increments neither).
	r3, _ := patchStackEnvBlock(t, app, slug, map[string]string{
		"FEATURE_X": "", // delete (present)
		"NEVER_SET": "", // no-op delete (absent) — counts as NEITHER
	}, jwt)
	r3.Body.Close()
	require.Equal(t, http.StatusOK, r3.StatusCode)
	c3 := stackBlockEnvAuditCounters(t, db, stackID, 3)
	assert.Equal(t, 0, c3.KeysSet, "an all-empty-value patch sets nothing — pre-fix bug reported 1")
	assert.Equal(t, 1, c3.KeysDeleted, "only the present key counts as deleted; the absent no-op does not")
	assert.Equal(t, 2, c3.TotalAfter)
	got3 := readStackEnvVars(t, db, slug)
	_, hasFeature := got3["FEATURE_X"]
	assert.False(t, hasFeature, "deleted key gone from env_vars")
	assert.Equal(t, "https://api.example", got3["API_URL"], "untouched key survives the merge")
	assert.Equal(t, "debug", got3["LOG_LEVEL"])

	// 4) Mixed set + delete in one patch.
	r4, _ := patchStackEnvBlock(t, app, slug, map[string]string{
		"API_URL":   "",  // delete (present)
		"NEW_TOKEN": "v", // set
	}, jwt)
	r4.Body.Close()
	require.Equal(t, http.StatusOK, r4.StatusCode)
	c4 := stackBlockEnvAuditCounters(t, db, stackID, 4)
	assert.Equal(t, 1, c4.KeysSet, "one real upsert")
	assert.Equal(t, 1, c4.KeysDeleted, "one real delete")
	assert.Equal(t, 2, c4.TotalAfter, "LOG_LEVEL + NEW_TOKEN remain")
}

// TestStackBlock_D12_RequiresAuth confirms the RequireAuth gate on the PATCH
// route — an unauthenticated env merge is a 401, never a silent no-op.
func TestStackBlock_D12_RequiresAuth(t *testing.T) {
	requireTestDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	ensureStackTables(t, db)
	app := newStackTestApp(t, db)

	resp, _ := patchStackEnvBlock(t, app, "stk-anything", map[string]string{"FOO": "bar"}, "")
	resp.Body.Close()
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

// ── D12 — deleting stack rejects env merge under the FOR UPDATE guard ─────────

// TestStackBlock_D12_DeletingStack_Returns409 is the matrix D12 teardown-guard
// row (mig/PR #238). A stack in status='deleting' must reject PATCH env with
// 409 stack_deleting — the authoritative check lives INSIDE MergeStackEnvVars
// under the SELECT … FOR UPDATE lock (NOT a TOCTOU pre-read), so a stack flipped
// to deleting by the teardown worker between GetStackBySlug and the merge tx is
// still caught. The env_vars row must be unchanged by the rejected patch.
func TestStackBlock_D12_DeletingStack_Returns409(t *testing.T) {
	requireTestDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	ensureStackTables(t, db)

	teamID := uuid.MustParse(testhelpers.MustCreateTeamDB(t, db, "pro"))
	jwt := testhelpers.MustSignSessionJWT(t, mustUUIDStr(), teamID.String(), "deleting-blk@example.com")
	// seedStackWithService creates a stack in the given status with one service.
	stack, _ := seedStackWithService(t, db, &teamID, "deleting", "web")

	app := newStackTestApp(t, db)
	resp, body := patchStackEnvBlock(t, app, stack.Slug, map[string]string{"FOO": "bar"}, jwt)
	resp.Body.Close()
	assert.Equal(t, http.StatusConflict, resp.StatusCode)
	assert.Equal(t, "stack_deleting", body.Error)

	// The rejected patch must not have touched env_vars (rolled back in-tx).
	assert.Empty(t, readStackEnvVars(t, db, stack.Slug),
		"a rejected (stack_deleting) patch must leave env_vars untouched")
}
