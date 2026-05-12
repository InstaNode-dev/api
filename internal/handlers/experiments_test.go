package handlers_test

// experiments_test.go — coverage for:
//
//   - GET /auth/me embeds an `experiments` map covering every
//     registered experiment, bucketed deterministically by team_id.
//
//   - POST /api/v1/experiments/converted writes a `kind =
//     experiment.conversion` row into audit_log with the variant
//     and action_taken in metadata.
//
//   - The conversion endpoint rejects (a) unknown experiment names,
//     (b) variants outside the registered set, and (c) variants that
//     don't match what the server itself buckets the caller into.
//
// The tests use the real DB (via testhelpers.SetupTestDB) so the
// audit_log row is verified end-to-end — a unit test on the handler
// alone would miss a JSONB encoding bug.

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"instant.dev/internal/experiments"
	"instant.dev/internal/testhelpers"
)

// TestGetCurrentUser_IncludesExperiments verifies the /auth/me
// response carries an `experiments` map keyed by experiment name,
// containing a registered variant for each known experiment.
func TestGetCurrentUser_IncludesExperiments(t *testing.T) {
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()

	app, cleanApp := testhelpers.NewTestApp(t, db, rdb)
	defer cleanApp()

	teamID := testhelpers.MustCreateTeamDB(t, db, "hobby")
	email := testhelpers.UniqueEmail(t)
	var userID string
	require.NoError(t, db.QueryRowContext(context.Background(),
		`INSERT INTO users (team_id, email) VALUES ($1::uuid, $2) RETURNING id::text`,
		teamID, email,
	).Scan(&userID))

	token := testhelpers.MustSignSessionJWT(t, userID, teamID, email)
	req := httptest.NewRequest(http.MethodGet, "/auth/me", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	var body map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))

	exps, ok := body["experiments"].(map[string]any)
	require.True(t, ok, "experiments field must be a JSON object")

	// UpgradeButton experiment must be present and assigned to a
	// registered variant.
	got, ok := exps[experiments.ExperimentUpgradeButton].(string)
	require.True(t, ok, "experiments.upgrade_button must be a string")

	registered, hasExp := experiments.Get(experiments.ExperimentUpgradeButton)
	require.True(t, hasExp)
	validVariants := map[string]bool{}
	for _, v := range registered.Variants {
		validVariants[v] = true
	}
	assert.Truef(t, validVariants[got],
		"variant %q must be one of the registered variants %v", got, registered.Variants)

	// Cross-check: the server's deterministic Pick for this
	// team_id must produce the exact same variant the response
	// carries. This guards against a regression where /auth/me
	// uses a different identifier than POST /converted (which
	// would make every conversion be rejected as variant_mismatch).
	want := experiments.Pick(experiments.ExperimentUpgradeButton, teamID)
	assert.Equal(t, want, got, "/auth/me variant must match Pick(team_id)")
}

// TestExperimentsConverted_WritesAuditRow verifies the happy path:
// a valid (experiment, variant, action) triplet writes one
// audit_log row with kind = "experiment.conversion" and metadata
// carrying the experiment, variant, and action_taken fields.
func TestExperimentsConverted_WritesAuditRow(t *testing.T) {
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()

	app, cleanApp := testhelpers.NewTestApp(t, db, rdb)
	defer cleanApp()

	teamID := testhelpers.MustCreateTeamDB(t, db, "hobby")
	email := testhelpers.UniqueEmail(t)
	var userID string
	require.NoError(t, db.QueryRowContext(context.Background(),
		`INSERT INTO users (team_id, email) VALUES ($1::uuid, $2) RETURNING id::text`,
		teamID, email,
	).Scan(&userID))

	token := testhelpers.MustSignSessionJWT(t, userID, teamID, email)
	variant := experiments.Pick(experiments.ExperimentUpgradeButton, teamID)
	require.NotEmpty(t, variant, "Pick must return a registered variant")

	payload := map[string]string{
		"experiment": experiments.ExperimentUpgradeButton,
		"variant":    variant,
		"action":     "checkout_started",
	}
	body, _ := json.Marshal(payload)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/experiments/converted", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	// Audit row write is asynchronous (best-effort goroutine).
	// Poll for up to ~2s for it to land.
	var kind, summary string
	var metaJSON []byte
	for i := 0; i < 40; i++ {
		err = db.QueryRowContext(context.Background(),
			`SELECT kind, summary, metadata::text
			   FROM audit_log
			  WHERE team_id = $1::uuid AND kind = 'experiment.conversion'
			  ORDER BY created_at DESC
			  LIMIT 1`, teamID,
		).Scan(&kind, &summary, &metaJSON)
		if err == nil {
			break
		}
		// 50ms * 40 = 2s
		time.Sleep(50 * time.Millisecond)
	}
	require.NoError(t, err, "audit_log row must exist within 2s")
	assert.Equal(t, "experiment.conversion", kind)
	assert.Contains(t, summary, experiments.ExperimentUpgradeButton)

	var meta map[string]string
	require.NoError(t, json.Unmarshal(metaJSON, &meta))
	assert.Equal(t, experiments.ExperimentUpgradeButton, meta["experiment"])
	assert.Equal(t, variant, meta["variant"])
	assert.Equal(t, "checkout_started", meta["action_taken"])
}

// TestExperimentsConverted_RejectsUnknownExperiment guards against
// arbitrary names polluting the audit log.
func TestExperimentsConverted_RejectsUnknownExperiment(t *testing.T) {
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()

	app, cleanApp := testhelpers.NewTestApp(t, db, rdb)
	defer cleanApp()

	teamID := testhelpers.MustCreateTeamDB(t, db, "hobby")
	email := testhelpers.UniqueEmail(t)
	var userID string
	require.NoError(t, db.QueryRowContext(context.Background(),
		`INSERT INTO users (team_id, email) VALUES ($1::uuid, $2) RETURNING id::text`,
		teamID, email,
	).Scan(&userID))

	token := testhelpers.MustSignSessionJWT(t, userID, teamID, email)
	body, _ := json.Marshal(map[string]string{
		"experiment": "not_a_real_experiment",
		"variant":    "control",
		"action":     "checkout_started",
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/experiments/converted", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

// TestExperimentsConverted_RejectsInvalidVariant guards against
// typo'd variant names sneaking in (e.g. "contrl" instead of "control").
func TestExperimentsConverted_RejectsInvalidVariant(t *testing.T) {
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()

	app, cleanApp := testhelpers.NewTestApp(t, db, rdb)
	defer cleanApp()

	teamID := testhelpers.MustCreateTeamDB(t, db, "hobby")
	email := testhelpers.UniqueEmail(t)
	var userID string
	require.NoError(t, db.QueryRowContext(context.Background(),
		`INSERT INTO users (team_id, email) VALUES ($1::uuid, $2) RETURNING id::text`,
		teamID, email,
	).Scan(&userID))

	token := testhelpers.MustSignSessionJWT(t, userID, teamID, email)
	body, _ := json.Marshal(map[string]string{
		"experiment": experiments.ExperimentUpgradeButton,
		"variant":    "contrl_typo",
		"action":     "checkout_started",
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/experiments/converted", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

// TestExperimentsConverted_RejectsVariantMismatch ensures the
// dashboard can't claim it saw a variant the server wouldn't have
// served to this team (stale /auth/me, tampered client, etc.).
func TestExperimentsConverted_RejectsVariantMismatch(t *testing.T) {
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()

	app, cleanApp := testhelpers.NewTestApp(t, db, rdb)
	defer cleanApp()

	teamID := testhelpers.MustCreateTeamDB(t, db, "hobby")
	email := testhelpers.UniqueEmail(t)
	var userID string
	require.NoError(t, db.QueryRowContext(context.Background(),
		`INSERT INTO users (team_id, email) VALUES ($1::uuid, $2) RETURNING id::text`,
		teamID, email,
	).Scan(&userID))

	token := testhelpers.MustSignSessionJWT(t, userID, teamID, email)

	// Find a registered variant the team is NOT bucketed into.
	correct := experiments.Pick(experiments.ExperimentUpgradeButton, teamID)
	exp, _ := experiments.Get(experiments.ExperimentUpgradeButton)
	var wrong string
	for _, v := range exp.Variants {
		if v != correct {
			wrong = v
			break
		}
	}
	require.NotEmpty(t, wrong, "registry must define >1 variant")

	body, _ := json.Marshal(map[string]string{
		"experiment": experiments.ExperimentUpgradeButton,
		"variant":    wrong,
		"action":     "checkout_started",
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/experiments/converted", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

// TestExperimentsConverted_RequiresAuth — no Bearer → 401.
func TestExperimentsConverted_RequiresAuth(t *testing.T) {
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()

	app, cleanApp := testhelpers.NewTestApp(t, db, rdb)
	defer cleanApp()

	body, _ := json.Marshal(map[string]string{
		"experiment": experiments.ExperimentUpgradeButton,
		"variant":    "control",
		"action":     "checkout_started",
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/experiments/converted", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}
