package handlers_test

// deploy_stack_internal_coverage_test.go — coverage push for unexported
// helpers and the server-side goroutine internals of deploy.go + stack.go.
//
// The unexported symbols are reached via the *ForTest wrappers in
// export_test.go (an external test cannot import testhelpers AND be in
// package handlers — that's an import cycle, so we keep these external and
// thunk through export_test.go).
//
// Scope: deploy.go + stack.go ONLY. DB-backed tests skip cleanly when
// TEST_DATABASE_URL is unset.

import (
	"context"
	"database/sql"
	"errors"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"instant.dev/internal/config"
	"instant.dev/internal/handlers"
	"instant.dev/internal/models"
	"instant.dev/internal/plans"
	"instant.dev/internal/providers/compute"
	"instant.dev/internal/testhelpers"
)

func internalCovNeedsDB(t *testing.T) {
	t.Helper()
	if os.Getenv("TEST_DATABASE_URL") == "" {
		t.Skip("TEST_DATABASE_URL not set — skipping internal coverage test")
	}
}

// ── compute provider doubles ─────────────────────────────────────────────────

// covPanicProvider satisfies compute.Provider; every method panics. Used to
// prove a code path short-circuits BEFORE reaching the compute layer.
type covPanicProvider struct{}

func (covPanicProvider) Deploy(context.Context, compute.DeployOptions) (*compute.AppDeployment, error) {
	panic("covPanicProvider.Deploy: not expected")
}
func (covPanicProvider) Status(context.Context, string) (*compute.AppDeployment, error) {
	panic("covPanicProvider.Status: not expected")
}
func (covPanicProvider) Logs(context.Context, string, bool) (io.ReadCloser, error) {
	panic("covPanicProvider.Logs: not expected")
}
func (covPanicProvider) Teardown(context.Context, string) error {
	panic("covPanicProvider.Teardown: not expected")
}
func (covPanicProvider) Redeploy(context.Context, string, []byte, map[string]string) (*compute.AppDeployment, error) {
	panic("covPanicProvider.Redeploy: not expected")
}
func (covPanicProvider) UpdateAccessControl(context.Context, string, bool, []string) error {
	panic("covPanicProvider.UpdateAccessControl: not expected")
}

// covFailProvider's Deploy/Redeploy return a configurable error. It does NOT
// implement BuildLogFetcher, so fetchBuildLogsForAutopsy returns nil
// (fail-soft path).
type covFailProvider struct {
	covPanicProvider
	deployErr error
}

func (f covFailProvider) Deploy(context.Context, compute.DeployOptions) (*compute.AppDeployment, error) {
	return nil, f.deployErr
}
func (f covFailProvider) Redeploy(context.Context, string, []byte, map[string]string) (*compute.AppDeployment, error) {
	return nil, f.deployErr
}
func (covFailProvider) Teardown(context.Context, string) error { return nil }

// ── pure helpers ─────────────────────────────────────────────────────────────

func TestTruncateForAudit(t *testing.T) {
	assert.Equal(t, "short", handlers.TruncateForAuditForTest("short", 10))
	assert.Equal(t, "exactlyten", handlers.TruncateForAuditForTest("exactlyten", 10))
	got := handlers.TruncateForAuditForTest("this is way too long for the cap", 10)
	assert.Equal(t, "this is wa…", got)
	assert.True(t, strings.HasSuffix(got, "…"))
}

func TestGenerateAppID_ShapeAndUniqueness(t *testing.T) {
	a, err := handlers.GenerateAppIDForTest()
	require.NoError(t, err)
	assert.Len(t, a, 8, "app id is 4 random bytes -> 8 hex chars")
	b, err := handlers.GenerateAppIDForTest()
	require.NoError(t, err)
	assert.NotEqual(t, a, b)
}

func TestResourceEnvKey(t *testing.T) {
	cases := []struct {
		rt    string
		index int
		want  string
	}{
		{"postgres", 0, "DATABASE_URL"},
		{"redis", 0, "REDIS_URL"},
		{"mongodb", 0, "MONGO_URL"},
		{"queue", 0, "NATS_URL"},
		{"storage", 0, "STORAGE_URL"},
		{"webhook", 0, "WEBHOOK_URL"},
		{"postgres", 1, "DATABASE_URL_2"},
		{"redis", 2, "REDIS_URL_3"},
	}
	for _, c := range cases {
		assert.Equalf(t, c.want, handlers.ResourceEnvKeyForTest(c.rt, c.index),
			"resourceEnvKey(%q,%d)", c.rt, c.index)
	}
}

func TestParseResourceToken(t *testing.T) {
	valid := uuid.NewString()
	tok, err := handlers.ParseResourceTokenForTest(valid)
	require.NoError(t, err)
	assert.Equal(t, valid, uuid.UUID(tok).String())

	_, err = handlers.ParseResourceTokenForTest("not-a-uuid")
	assert.Error(t, err)
}

func TestRewriteToInternalURL(t *testing.T) {
	rw := handlers.RewriteToInternalURLForTest
	assert.Equal(t, "", rw("", "postgres", "rid"))
	assert.Equal(t, "://bad", rw("://bad", "postgres", "rid"))

	assert.Contains(t, rw("postgres://u:p@public.example.com:5432/db", "postgres", ""),
		"instant-pg-proxy.instant.svc.cluster.local:5432")
	assert.Contains(t, rw("redis://public.example.com:6379", "redis", "ns-1"),
		"redis.ns-1.svc.cluster.local:6379")
	assert.Contains(t, rw("mongodb://public.example.com:27017", "mongodb", "ns-2"),
		"mongo.ns-2.svc.cluster.local:27017")
	assert.Contains(t, rw("nats://public.example.com:4222", "queue", "ns-3"),
		"nats.ns-3.svc.cluster.local:4222")

	// empty provider id -> verbatim for the per-resource backends.
	assert.Equal(t, "redis://public.example.com:6379",
		rw("redis://public.example.com:6379", "redis", ""))
	assert.Equal(t, "mongodb://public:27017", rw("mongodb://public:27017", "mongodb", ""))
	assert.Equal(t, "nats://public:4222", rw("nats://public:4222", "queue", ""))

	// unknown resource type -> verbatim (default branch).
	assert.Equal(t, "https://x.example.com", rw("https://x.example.com", "storage", "rid"))
}

func TestToString(t *testing.T) {
	assert.Equal(t, "", handlers.ToStringForTest(nil))
	id := uuid.New()
	assert.Equal(t, id.String(), handlers.ToStringForTest(&id))
}

// ── deploymentToMapWithDB — failure-object branch ────────────────────────────

func TestDeploymentToMapWithDB_FailureBranch(t *testing.T) {
	internalCovNeedsDB(t)
	db, clean := testhelpers.SetupTestDB(t)
	defer clean()

	teamID := uuid.MustParse(testhelpers.MustCreateTeamDB(t, db, "pro"))
	d := seedInternalDeploy(t, db, teamID, "failed", map[string]string{"FOO": "bar"})

	// failed + nil db -> no failure object, no query.
	_, hasFailure := handlers.DeploymentToMapForTest(d)["failure"]
	assert.False(t, hasFailure, "nil-db path must omit failure object")

	// failed + db but no autopsy row -> field omitted, no panic.
	_, hasFailure = handlers.DeploymentToMapWithDBForTest(d, db)["failure"]
	assert.False(t, hasFailure, "no autopsy row -> failure omitted")

	require.NoError(t, models.UpsertDeploymentAutopsy(context.Background(), db, models.UpsertAutopsyParams{
		DeploymentID: d.ID,
		Reason:       models.FailureReasonBuildFailed,
		Event:        "build_failed",
		LastLines:    []string{"npm ERR! boom"},
		Hint:         models.HintForReason(models.FailureReasonBuildFailed),
	}))
	m := handlers.DeploymentToMapWithDBForTest(d, db)
	failure, ok := m["failure"].(fiber.Map)
	require.True(t, ok, "failure object must be present; got %T", m["failure"])
	assert.Equal(t, models.FailureReasonBuildFailed, failure["reason"])
}

// ── runDeploy — async goroutine internals ────────────────────────────────────

func TestRunDeploy_Success(t *testing.T) {
	internalCovNeedsDB(t)
	db, clean := testhelpers.SetupTestDB(t)
	defer clean()

	teamID := uuid.MustParse(testhelpers.MustCreateTeamDB(t, db, "pro"))
	h := handlers.NewDeployHandler(db, nil, covCfg(), plans.Default())

	d := seedInternalDeploy(t, db, teamID, "building", map[string]string{"FOO": "bar"})
	handlers.RunDeployForTest(h, d, []byte("tarball-bytes"))

	got, err := models.GetDeploymentByID(context.Background(), db, d.ID)
	require.NoError(t, err)
	assert.Equal(t, "healthy", got.Status)
	assert.NotEmpty(t, got.ProviderID)
}

func TestRunDeploy_ComputeFailure_WritesAutopsy(t *testing.T) {
	internalCovNeedsDB(t)
	db, clean := testhelpers.SetupTestDB(t)
	defer clean()

	teamID := uuid.MustParse(testhelpers.MustCreateTeamDB(t, db, "pro"))
	h := handlers.NewDeployHandler(db, nil, covCfg(), plans.Default())
	h.SetComputeProvider(covFailProvider{deployErr: errors.New("kaniko build exploded")})

	d := seedInternalDeploy(t, db, teamID, "building", map[string]string{"FOO": "bar"})
	handlers.RunDeployForTest(h, d, []byte("tarball"))

	got, err := models.GetDeploymentByID(context.Background(), db, d.ID)
	require.NoError(t, err)
	assert.Equal(t, "failed", got.Status)
	assert.Contains(t, got.ErrorMessage, "kaniko build exploded")

	autopsy, err := models.GetLatestDeploymentAutopsy(context.Background(), db, d.ID)
	require.NoError(t, err)
	require.NotNil(t, autopsy)
	assert.Equal(t, models.FailureReasonBuildFailed, autopsy.Reason)
}

func TestRunDeploy_DeadlineClassifiedAsDeadlineExceeded(t *testing.T) {
	internalCovNeedsDB(t)
	db, clean := testhelpers.SetupTestDB(t)
	defer clean()

	teamID := uuid.MustParse(testhelpers.MustCreateTeamDB(t, db, "pro"))
	h := handlers.NewDeployHandler(db, nil, covCfg(), plans.Default())
	h.SetComputeProvider(covFailProvider{deployErr: context.DeadlineExceeded})

	d := seedInternalDeploy(t, db, teamID, "building", map[string]string{"FOO": "bar"})
	handlers.RunDeployForTest(h, d, []byte("tarball"))

	autopsy, err := models.GetLatestDeploymentAutopsy(context.Background(), db, d.ID)
	require.NoError(t, err)
	require.NotNil(t, autopsy)
	assert.Equal(t, models.FailureReasonDeadlineExceeded, autopsy.Reason)
}

func TestRunDeploy_VaultResolveFailure(t *testing.T) {
	internalCovNeedsDB(t)
	db, clean := testhelpers.SetupTestDB(t)
	defer clean()

	teamID := uuid.MustParse(testhelpers.MustCreateTeamDB(t, db, "pro"))
	h := handlers.NewDeployHandler(db, nil, covCfg(), plans.Default())
	// Panic provider — proves the vault failure short-circuits before compute.
	h.SetComputeProvider(covPanicProvider{})

	d := seedInternalDeploy(t, db, teamID, "building",
		map[string]string{"SECRET": "vault://nonexistent-secret-key"})
	handlers.RunDeployForTest(h, d, []byte("tarball"))

	got, err := models.GetDeploymentByID(context.Background(), db, d.ID)
	require.NoError(t, err)
	assert.Equal(t, "failed", got.Status)
}

func TestCaptureAutopsy_DirectWrite(t *testing.T) {
	internalCovNeedsDB(t)
	db, clean := testhelpers.SetupTestDB(t)
	defer clean()

	teamID := uuid.MustParse(testhelpers.MustCreateTeamDB(t, db, "pro"))
	d := seedInternalDeploy(t, db, teamID, "failed", map[string]string{"FOO": "bar"})

	handlers.CaptureAutopsyForTest(context.Background(), db, d.ID,
		models.FailureReasonBuildFailed, "first error", []string{"line1"})
	handlers.CaptureAutopsyForTest(context.Background(), db, d.ID,
		models.FailureReasonDeadlineExceeded, "second error", nil)

	autopsy, err := models.GetLatestDeploymentAutopsy(context.Background(), db, d.ID)
	require.NoError(t, err)
	require.NotNil(t, autopsy)
}

// ── seed + cfg helpers ───────────────────────────────────────────────────────

func covCfg() *config.Config {
	return &config.Config{AESKey: testhelpers.TestAESKeyHex, ComputeProvider: "noop"}
}

func seedInternalDeploy(t *testing.T, db *sql.DB, teamID uuid.UUID, status string, env map[string]string) *models.Deployment {
	t.Helper()
	d, err := models.CreateDeployment(context.Background(), db, models.CreateDeploymentParams{
		TeamID:    teamID,
		AppID:     "int-" + uuid.NewString()[:10],
		Port:      8080,
		Tier:      "pro",
		Env:       "production",
		EnvVars:   env,
		TTLPolicy: models.DeployTTLPolicyPermanent,
	})
	require.NoError(t, err)
	if status != "building" {
		require.NoError(t, models.UpdateDeploymentStatus(context.Background(), db, d.ID, status, ""))
		d.Status = status
	}
	return d
}
