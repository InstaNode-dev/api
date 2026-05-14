package handlers_test

// audit_export_test.go — handler-layer tests for the W7-C customer-facing
// audit export. Covers:
//
//   * Emit sites: GET /resources/:id, GET /resources, GET /credentials each
//     write the appropriate audit_log row.
//   * /audit endpoint: happy path, tier gate, cursor pagination, filters,
//     redaction, cross-team isolation, admin.* exclusion.
//   * /audit.csv endpoint: shape parity with /audit, isolation parity.
//
// The emits are best-effort goroutines (per the A3 pattern), so most
// assertions poll for up to ~2s for the row to land.

import (
	"context"
	"database/sql"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"instant.dev/internal/crypto"
	"instant.dev/internal/testhelpers"
)

// --- helpers ----------------------------------------------------------------

// seedUserAndJWT creates a user on the given team and returns (userID, jwt).
func seedUserAndJWT(t *testing.T, db *sql.DB, teamID string) (string, string) {
	t.Helper()
	email := testhelpers.UniqueEmail(t)
	var userID string
	require.NoError(t, db.QueryRowContext(context.Background(),
		`INSERT INTO users (team_id, email) VALUES ($1::uuid, $2) RETURNING id::text`,
		teamID, email,
	).Scan(&userID))
	jwt := testhelpers.MustSignSessionJWT(t, userID, teamID, email)
	return userID, jwt
}

// seedPostgresResource inserts an active postgres resource owned by the team
// with an AES-encrypted connection URL and returns the token string.
func seedPostgresResource(t *testing.T, db *sql.DB, teamID string) string {
	t.Helper()
	aesKey, err := crypto.ParseAESKey(testhelpers.TestAESKeyHex)
	require.NoError(t, err)
	encURL, err := crypto.Encrypt(aesKey, "postgres://user:pass@host:5432/db")
	require.NoError(t, err)
	var token string
	require.NoError(t, db.QueryRowContext(context.Background(), `
		INSERT INTO resources (team_id, resource_type, tier, connection_url)
		VALUES ($1::uuid, 'postgres', 'hobby', $2)
		RETURNING token::text
	`, teamID, encURL).Scan(&token))
	return token
}

// pollAuditRow polls audit_log for up to ~2s for a row matching team_id +
// kind. Returns the metadata text and count. Fails the test if no row
// appears.
func pollAuditRow(t *testing.T, db *sql.DB, teamID, kind string) (metaText string, count int) {
	t.Helper()
	for i := 0; i < 40; i++ {
		err := db.QueryRow(`
			SELECT COALESCE(metadata::text, ''), COUNT(*) OVER ()
			  FROM audit_log
			 WHERE team_id = $1::uuid AND kind = $2
			 ORDER BY created_at DESC
			 LIMIT 1`, teamID, kind).Scan(&metaText, &count)
		if err == nil {
			return metaText, count
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("expected at least one audit_log row with team_id=%s kind=%s", teamID, kind)
	return "", 0
}

// countAuditRows returns how many rows match team_id + kind.
func countAuditRows(t *testing.T, db *sql.DB, teamID, kind string) int {
	t.Helper()
	var n int
	require.NoError(t, db.QueryRow(`
		SELECT COUNT(*) FROM audit_log
		 WHERE team_id = $1::uuid AND kind = $2
	`, teamID, kind).Scan(&n))
	return n
}

// --- emit-site tests --------------------------------------------------------

// TestEmit_ResourceGet_WritesResourceReadRow verifies that a successful GET
// /api/v1/resources/:id writes one audit_log row with kind = "resource.read"
// and metadata carrying resource_id / resource_type / accessed_by_user_id.
func TestEmit_ResourceGet_WritesResourceReadRow(t *testing.T) {
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()
	app, cleanApp := testhelpers.NewTestApp(t, db, rdb)
	defer cleanApp()

	teamID := testhelpers.MustCreateTeamDB(t, db, "hobby")
	userID, jwt := seedUserAndJWT(t, db, teamID)
	token := seedPostgresResource(t, db, teamID)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/resources/"+token, nil)
	req.Header.Set("Authorization", "Bearer "+jwt)
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	metaText, _ := pollAuditRow(t, db, teamID, "resource.read")
	assert.Contains(t, metaText, "postgres", "metadata should carry resource_type")
	assert.Contains(t, metaText, userID, "metadata should carry accessed_by_user_id")
}

// TestEmit_ResourceList_WritesOneRowPerCall verifies that GET
// /api/v1/resources writes EXACTLY one audit_log row per call, regardless of
// how many resources are returned. The per-resource resolution lives on the
// GET /:id endpoint; per-row emits on list would flood the table.
func TestEmit_ResourceList_WritesOneRowPerCall(t *testing.T) {
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()
	app, cleanApp := testhelpers.NewTestApp(t, db, rdb)
	defer cleanApp()

	teamID := testhelpers.MustCreateTeamDB(t, db, "hobby")
	_, jwt := seedUserAndJWT(t, db, teamID)
	for i := 0; i < 3; i++ {
		_ = seedPostgresResource(t, db, teamID)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/resources", nil)
	req.Header.Set("Authorization", "Bearer "+jwt)
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	// Poll for the row to land.
	metaText, _ := pollAuditRow(t, db, teamID, "resource.list_by_team")
	assert.Contains(t, metaText, "count_returned",
		"metadata should carry count_returned")

	// Settle then assert exactly one row regardless of N=3 resources.
	time.Sleep(150 * time.Millisecond)
	n := countAuditRows(t, db, teamID, "resource.list_by_team")
	assert.Equal(t, 1, n,
		"GET /resources must emit EXACTLY ONE list_by_team row per call (got %d)", n)
}

// TestEmit_GetCredentials_WritesConnectionURLDecryptedRow verifies that
// the explicit dashboard "show connection string" path (GET
// /resources/:id/credentials) emits a connection_url.decrypted row with
// purpose=customer_reveal.
func TestEmit_GetCredentials_WritesConnectionURLDecryptedRow(t *testing.T) {
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()
	app, cleanApp := testhelpers.NewTestApp(t, db, rdb)
	defer cleanApp()

	teamID := testhelpers.MustCreateTeamDB(t, db, "team")
	_, jwt := seedUserAndJWT(t, db, teamID)
	token := seedPostgresResource(t, db, teamID)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/resources/"+token+"/credentials", nil)
	req.Header.Set("Authorization", "Bearer "+jwt)
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	metaText, _ := pollAuditRow(t, db, teamID, "connection_url.decrypted")
	assert.Contains(t, metaText, "customer_reveal",
		"metadata should carry purpose=customer_reveal")
}

// --- /audit endpoint tests --------------------------------------------------

// TestAudit_HappyPath_ReturnsRowsForTeam — basic round trip. Insert a row,
// hit /audit, get the row back.
func TestAudit_HappyPath_ReturnsRowsForTeam(t *testing.T) {
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()
	app, cleanApp := testhelpers.NewTestApp(t, db, rdb)
	defer cleanApp()

	teamID := testhelpers.MustCreateTeamDB(t, db, "hobby")
	_, jwt := seedUserAndJWT(t, db, teamID)

	// Seed a row directly.
	_, err := db.Exec(`
		INSERT INTO audit_log (team_id, actor, kind, summary)
		VALUES ($1::uuid, 'agent', 'onboarding.claimed', 'seeded row')
	`, teamID)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/audit", nil)
	req.Header.Set("Authorization", "Bearer "+jwt)
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	var body map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	assert.Equal(t, true, body["ok"])
	assert.Equal(t, "hobby", body["tier"])
	assert.Equal(t, float64(30), body["lookback_days"], "hobby lookback = 30d")

	items, _ := body["items"].([]any)
	require.GreaterOrEqual(t, len(items), 1)
	first, _ := items[0].(map[string]any)
	assert.Equal(t, "onboarding.claimed", first["kind"])
}

// TestAudit_TierGate_AnonymousReturns402 — anonymous tier cannot export.
func TestAudit_TierGate_AnonymousReturns402(t *testing.T) {
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()
	app, cleanApp := testhelpers.NewTestApp(t, db, rdb)
	defer cleanApp()

	teamID := testhelpers.MustCreateTeamDB(t, db, "anonymous")
	_, jwt := seedUserAndJWT(t, db, teamID)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/audit", nil)
	req.Header.Set("Authorization", "Bearer "+jwt)
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusPaymentRequired, resp.StatusCode)
	var body map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	assert.Equal(t, "upgrade_required", body["error"])
}

// TestAudit_TierGate_HobbyOldRowFiltered — hobby has 30d lookback. A row
// older than 30d must be filtered out even when no ?since= is passed.
func TestAudit_TierGate_HobbyOldRowFiltered(t *testing.T) {
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()
	app, cleanApp := testhelpers.NewTestApp(t, db, rdb)
	defer cleanApp()

	teamID := testhelpers.MustCreateTeamDB(t, db, "hobby")
	_, jwt := seedUserAndJWT(t, db, teamID)

	// Insert a row stamped 60 days ago — well outside the hobby window.
	_, err := db.Exec(`
		INSERT INTO audit_log (team_id, actor, kind, summary, created_at)
		VALUES ($1::uuid, 'agent', 'onboarding.claimed', 'old row', now() - interval '60 days')
	`, teamID)
	require.NoError(t, err)

	// And a fresh row.
	_, err = db.Exec(`
		INSERT INTO audit_log (team_id, actor, kind, summary)
		VALUES ($1::uuid, 'agent', 'onboarding.claimed', 'fresh row')
	`, teamID)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/audit", nil)
	req.Header.Set("Authorization", "Bearer "+jwt)
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	var body map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	items, _ := body["items"].([]any)
	for _, it := range items {
		m, _ := it.(map[string]any)
		assert.NotEqual(t, "old row", m["summary"],
			"row older than the hobby 30d window must be filtered out")
	}
}

// TestAudit_TierGate_TeamUnlimited — team tier should see the old row.
func TestAudit_TierGate_TeamUnlimited(t *testing.T) {
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()
	app, cleanApp := testhelpers.NewTestApp(t, db, rdb)
	defer cleanApp()

	teamID := testhelpers.MustCreateTeamDB(t, db, "team")
	_, jwt := seedUserAndJWT(t, db, teamID)

	_, err := db.Exec(`
		INSERT INTO audit_log (team_id, actor, kind, summary, created_at)
		VALUES ($1::uuid, 'agent', 'onboarding.claimed', 'ancient row', now() - interval '400 days')
	`, teamID)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/audit", nil)
	req.Header.Set("Authorization", "Bearer "+jwt)
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	var body map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	assert.Equal(t, float64(-1), body["lookback_days"], "team tier returns -1 for unlimited")

	items, _ := body["items"].([]any)
	require.GreaterOrEqual(t, len(items), 1)
	found := false
	for _, it := range items {
		m, _ := it.(map[string]any)
		if m["kind"] == "onboarding.claimed" {
			found = true
		}
	}
	assert.True(t, found, "team tier must see rows of any age")
}

// TestAudit_CrossTeamIsolation_TeamACannotSeeTeamB — security boundary.
func TestAudit_CrossTeamIsolation_TeamACannotSeeTeamB(t *testing.T) {
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()
	app, cleanApp := testhelpers.NewTestApp(t, db, rdb)
	defer cleanApp()

	teamAID := testhelpers.MustCreateTeamDB(t, db, "team")
	teamBID := testhelpers.MustCreateTeamDB(t, db, "team")
	_, jwtA := seedUserAndJWT(t, db, teamAID)

	// Insert a row owned by team B with a distinctive summary so any leak
	// shows up in the assertion below.
	const leakSentinel = "secret-team-b-row-DO-NOT-RETURN"
	_, err := db.Exec(`
		INSERT INTO audit_log (team_id, actor, kind, summary)
		VALUES ($1::uuid, 'agent', 'subscription.upgraded', $2)
	`, teamBID, leakSentinel)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/audit", nil)
	req.Header.Set("Authorization", "Bearer "+jwtA)
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	body, _ := io.ReadAll(resp.Body)
	assert.NotContains(t, string(body), leakSentinel,
		"team A must NEVER see a row stamped to team B")
}

// TestAudit_AdminRowsExcluded — even when explicitly filtered, admin.*
// kinds NEVER return.
func TestAudit_AdminRowsExcluded(t *testing.T) {
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()
	app, cleanApp := testhelpers.NewTestApp(t, db, rdb)
	defer cleanApp()

	teamID := testhelpers.MustCreateTeamDB(t, db, "team")
	_, jwt := seedUserAndJWT(t, db, teamID)

	// Stamp an admin.access row scoped to the team — this is exactly the
	// shape the AdminAuditEmit middleware writes. The customer must NOT
	// be able to read it back.
	const adminSummary = "admin-row-must-not-be-returned"
	_, err := db.Exec(`
		INSERT INTO audit_log (team_id, actor, kind, summary)
		VALUES ($1::uuid, 'operator', 'admin.access', $2)
	`, teamID, adminSummary)
	require.NoError(t, err)

	// Default (no kind filter)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/audit", nil)
	req.Header.Set("Authorization", "Bearer "+jwt)
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	assert.NotContains(t, string(body), adminSummary,
		"admin.access rows must not appear in the customer export (no filter)")

	// Explicit filter must also yield zero
	req = httptest.NewRequest(http.MethodGet, "/api/v1/audit?kind=admin.access", nil)
	req.Header.Set("Authorization", "Bearer "+jwt)
	resp, err = app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()
	var parsed map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&parsed))
	items, _ := parsed["items"].([]any)
	assert.Empty(t, items, "kind=admin.access must return zero items")
}

// TestAudit_Redaction_EmailIsMasked — assert the wire shape masks the
// actor's email AND the unredacted form never appears in the body.
func TestAudit_Redaction_EmailIsMasked(t *testing.T) {
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()
	app, cleanApp := testhelpers.NewTestApp(t, db, rdb)
	defer cleanApp()

	teamID := testhelpers.MustCreateTeamDB(t, db, "team")

	// Create a user with a known-shaped email + stamp an audit row
	// carrying their user_id so the masked-email lookup fires. The local
	// part starts with a stable letter ('a') so the masked output is
	// predictable; the rest is a unique suffix so reruns don't collide
	// on the users_email_key unique constraint.
	knownEmail := "alice." + uuid.NewString()[:8] + "@example.com"
	var userID string
	require.NoError(t, db.QueryRowContext(context.Background(),
		`INSERT INTO users (team_id, email) VALUES ($1::uuid, $2) RETURNING id::text`,
		teamID, knownEmail,
	).Scan(&userID))
	jwt := testhelpers.MustSignSessionJWT(t, userID, teamID, knownEmail)

	_, err := db.Exec(`
		INSERT INTO audit_log (team_id, user_id, actor, kind, summary)
		VALUES ($1::uuid, $2::uuid, 'user', 'resource.read', 'r')
	`, teamID, userID)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/audit", nil)
	req.Header.Set("Authorization", "Bearer "+jwt)
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	bodyStr := string(body)

	assert.NotContains(t, bodyStr, knownEmail,
		"response must NEVER leak the unredacted email — got %q", bodyStr)
	assert.Contains(t, bodyStr, "a***@example.com",
		"response must carry the masked first-char+domain form")
}

// TestAudit_CursorPagination — page through two calls and confirm the
// second page starts where the first ended.
func TestAudit_CursorPagination(t *testing.T) {
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()
	app, cleanApp := testhelpers.NewTestApp(t, db, rdb)
	defer cleanApp()

	teamID := testhelpers.MustCreateTeamDB(t, db, "team")
	_, jwt := seedUserAndJWT(t, db, teamID)

	// Seed 5 rows with distinct created_at via explicit microsecond
	// spacing so the cursor maths is unambiguous.
	base := time.Now().UTC().Add(-1 * time.Hour)
	for i := 0; i < 5; i++ {
		_, err := db.Exec(`
			INSERT INTO audit_log (team_id, actor, kind, summary, created_at)
			VALUES ($1::uuid, 'agent', 'onboarding.claimed', $2, $3)
		`, teamID, fmt.Sprintf("row-%d", i), base.Add(time.Duration(i)*time.Second))
		require.NoError(t, err)
	}

	// Page 1: limit=2 → should return 2 rows, newest first, with cursor.
	req := httptest.NewRequest(http.MethodGet, "/api/v1/audit?limit=2", nil)
	req.Header.Set("Authorization", "Bearer "+jwt)
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()

	var page1 map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&page1))
	items1, _ := page1["items"].([]any)
	require.Len(t, items1, 2)
	cursor, _ := page1["next_cursor"].(string)
	require.NotEmpty(t, cursor, "page 1 must carry next_cursor since it's full")

	// Page 2: ?before=<cursor>
	url2 := "/api/v1/audit?limit=2&before=" + cursor
	req = httptest.NewRequest(http.MethodGet, url2, nil)
	req.Header.Set("Authorization", "Bearer "+jwt)
	resp, err = app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()

	var page2 map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&page2))
	items2, _ := page2["items"].([]any)
	require.Len(t, items2, 2)

	// Sanity: no row should appear in both pages.
	id1a := items1[0].(map[string]any)["id"]
	id1b := items1[1].(map[string]any)["id"]
	id2a := items2[0].(map[string]any)["id"]
	id2b := items2[1].(map[string]any)["id"]
	for _, p2 := range []any{id2a, id2b} {
		assert.NotEqual(t, id1a, p2, "page-2 row must not overlap page 1")
		assert.NotEqual(t, id1b, p2, "page-2 row must not overlap page 1")
	}
}

// TestAudit_KindFilter — exact kind match.
func TestAudit_KindFilter(t *testing.T) {
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()
	app, cleanApp := testhelpers.NewTestApp(t, db, rdb)
	defer cleanApp()

	teamID := testhelpers.MustCreateTeamDB(t, db, "team")
	_, jwt := seedUserAndJWT(t, db, teamID)

	_, err := db.Exec(`
		INSERT INTO audit_log (team_id, actor, kind, summary)
		VALUES
			($1::uuid, 'agent', 'onboarding.claimed', 'a'),
			($1::uuid, 'agent', 'subscription.upgraded', 'b')
	`, teamID)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/audit?kind=onboarding.claimed", nil)
	req.Header.Set("Authorization", "Bearer "+jwt)
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()

	var body map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	items, _ := body["items"].([]any)
	require.NotEmpty(t, items)
	for _, it := range items {
		m, _ := it.(map[string]any)
		assert.Equal(t, "onboarding.claimed", m["kind"])
	}
}

// --- CSV endpoint tests -----------------------------------------------------

// TestAuditCSV_Shape_HeaderAndRows — confirm the CSV has the header row and
// at least one data row.
func TestAuditCSV_Shape_HeaderAndRows(t *testing.T) {
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()
	app, cleanApp := testhelpers.NewTestApp(t, db, rdb)
	defer cleanApp()

	teamID := testhelpers.MustCreateTeamDB(t, db, "team")
	_, jwt := seedUserAndJWT(t, db, teamID)
	_, err := db.Exec(`
		INSERT INTO audit_log (team_id, actor, kind, summary)
		VALUES ($1::uuid, 'agent', 'onboarding.claimed', 'csv row')
	`, teamID)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/audit.csv", nil)
	req.Header.Set("Authorization", "Bearer "+jwt)
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()

	require.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Contains(t, resp.Header.Get("Content-Type"), "text/csv")

	r := csv.NewReader(resp.Body)
	records, err := r.ReadAll()
	require.NoError(t, err)
	require.GreaterOrEqual(t, len(records), 2, "header + at least 1 data row")

	header := records[0]
	assert.Equal(t, []string{
		"id", "kind", "created_at", "actor", "actor_user_id",
		"actor_email_masked", "resource_id", "resource_type",
		"summary", "metadata",
	}, header)

	// Find the seeded row by summary
	found := false
	for _, rec := range records[1:] {
		if len(rec) >= 9 && rec[1] == "onboarding.claimed" && rec[8] == "csv row" {
			found = true
		}
	}
	assert.True(t, found, "CSV must contain the seeded row")
}

// TestAuditCSV_TierGate_AnonymousReturns402 — CSV path enforces the same
// tier gate as the JSON path.
func TestAuditCSV_TierGate_AnonymousReturns402(t *testing.T) {
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()
	app, cleanApp := testhelpers.NewTestApp(t, db, rdb)
	defer cleanApp()

	teamID := testhelpers.MustCreateTeamDB(t, db, "anonymous")
	_, jwt := seedUserAndJWT(t, db, teamID)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/audit.csv", nil)
	req.Header.Set("Authorization", "Bearer "+jwt)
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusPaymentRequired, resp.StatusCode)
}

// TestAuditCSV_CrossTeamIsolation — the CSV stream must NOT carry rows
// stamped to a different team.
func TestAuditCSV_CrossTeamIsolation(t *testing.T) {
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()
	app, cleanApp := testhelpers.NewTestApp(t, db, rdb)
	defer cleanApp()

	teamAID := testhelpers.MustCreateTeamDB(t, db, "team")
	teamBID := testhelpers.MustCreateTeamDB(t, db, "team")
	_, jwtA := seedUserAndJWT(t, db, teamAID)

	const leakSentinel = "team-b-leak-via-csv"
	_, err := db.Exec(`
		INSERT INTO audit_log (team_id, actor, kind, summary)
		VALUES ($1::uuid, 'agent', 'onboarding.claimed', $2)
	`, teamBID, leakSentinel)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/audit.csv", nil)
	req.Header.Set("Authorization", "Bearer "+jwtA)
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	assert.NotContains(t, string(body), leakSentinel,
		"team A must NEVER see team B's row via CSV")
}

// TestAuditCSV_AdminRowsExcluded — admin.* exclusion holds on the CSV path
// just as it does on JSON.
func TestAuditCSV_AdminRowsExcluded(t *testing.T) {
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()
	app, cleanApp := testhelpers.NewTestApp(t, db, rdb)
	defer cleanApp()

	teamID := testhelpers.MustCreateTeamDB(t, db, "team")
	_, jwt := seedUserAndJWT(t, db, teamID)

	const adminSummary = "admin-row-csv-leak"
	_, err := db.Exec(`
		INSERT INTO audit_log (team_id, actor, kind, summary)
		VALUES ($1::uuid, 'operator', 'admin.access', $2)
	`, teamID, adminSummary)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/audit.csv", nil)
	req.Header.Set("Authorization", "Bearer "+jwt)
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	assert.NotContains(t, string(body), adminSummary,
		"admin.access rows must not appear in CSV exports")
}

// TestAuditCSV_StreamsRatherThanBuffers — sanity check: the body is
// chunk-encoded (TransferEncoding: chunked) which is the signal that
// fasthttp's stream writer is engaged. Not a perfect proof but a clear
// regression flag if a future edit replaces the stream call with a
// buffered c.SendString(big).
func TestAuditCSV_StreamsRatherThanBuffers(t *testing.T) {
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()
	app, cleanApp := testhelpers.NewTestApp(t, db, rdb)
	defer cleanApp()

	teamID := testhelpers.MustCreateTeamDB(t, db, "team")
	_, jwt := seedUserAndJWT(t, db, teamID)
	// Seed enough rows that any chunking actually fires across multiple
	// flushes — 50 rows is well past the bufio default but still a fast
	// insert in the test path.
	for i := 0; i < 50; i++ {
		_, err := db.Exec(`
			INSERT INTO audit_log (team_id, actor, kind, summary)
			VALUES ($1::uuid, 'agent', 'onboarding.claimed', $2)
		`, teamID, fmt.Sprintf("row-%d", i))
		require.NoError(t, err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/audit.csv", nil)
	req.Header.Set("Authorization", "Bearer "+jwt)
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()

	// fasthttp set the body via a stream writer — Content-Length is unset
	// on streamed responses (the framework switches to chunked encoding).
	// We can't always observe Transfer-Encoding through Fiber's test
	// adapter cleanly, but a streamed body never carries an explicit
	// Content-Length header.
	assert.Empty(t, resp.Header.Get("Content-Length"),
		"streamed CSV responses must not carry Content-Length (would indicate buffered response)")

	body, _ := io.ReadAll(resp.Body)
	assert.True(t, strings.Count(string(body), "\n") >= 50,
		"50 seeded rows + header should appear in the streamed body")
}
