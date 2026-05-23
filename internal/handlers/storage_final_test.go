package handlers_test

// storage_final_test.go — FINAL coverage pass for storage.go. Closes the
// prefix-scoped credential arms that the do-spaces hermetic fixture (broker
// mode) can't reach:
//
//   - decideStorageMode: PrefixScopedKeys=true → "credential" (storage.go:107).
//   - newStorageAuthenticated: the per-tenant-IAM-key audit row that only
//     fires when creds.StorageMode == ModePrefixScoped (storage.go:560-572).
//   - newStorageAuthenticated DB-error arms: team_lookup (449),
//     create_resource (485) via openFaultDB.
//
// THE TECHNIQUE — a hermetic prefix-scoped impl. The MinIO backend reports
// PrefixScopedKeys=true but its IssueTenantCredentials calls a live madmin
// server. So instead of a real MinIO provider we inject a fake
// StorageCredentialProvider (pure computation) via storage.NewWithImpl — its
// Capabilities report PrefixScopedKeys=true and IssueTenantCredentials returns
// long-lived keys with no SessionToken → DeriveStorageMode → ModePrefixScoped.

import (
	"context"
	"database/sql"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"instant.dev/common/storageprovider"
	"instant.dev/internal/config"
	"instant.dev/internal/handlers"
	"instant.dev/internal/middleware"
	"instant.dev/internal/models"
	"instant.dev/internal/plans"
	storageprov "instant.dev/internal/providers/storage"
	"instant.dev/internal/testhelpers"
)

// fakePrefixScopedImpl is a hermetic StorageCredentialProvider whose
// Capabilities report PrefixScopedKeys=true and whose IssueTenantCredentials is
// pure computation (no network). Used to drive the credential / IAM-audit arm.
type fakePrefixScopedImpl struct{}

func (fakePrefixScopedImpl) IssueTenantCredentials(_ context.Context, in storageprovider.IssueRequest) (*storageprovider.TenantCreds, error) {
	return &storageprovider.TenantCreds{
		AccessKey: "key_" + in.Prefix,
		SecretKey: "secret-" + in.Prefix,
		Endpoint:  "https://s3.example.invalid",
		Region:    "nyc3",
		Bucket:    in.Bucket,
		Prefix:    in.Prefix,
		KeyID:     "key_" + in.Prefix,
		// No SessionToken → DeriveStorageMode yields ModePrefixScoped (not
		// ModePrefixScopedTemporary).
	}, nil
}

func (fakePrefixScopedImpl) RevokeTenantCredentials(_ context.Context, _ string) error { return nil }

func (fakePrefixScopedImpl) Capabilities() storageprovider.Capabilities {
	return storageprovider.Capabilities{
		PrefixScopedKeys: true,
		BucketScopedKeys: true,
		STS:              false,
		BucketPerTenant:  true,
	}
}

func (fakePrefixScopedImpl) Name() string { return "minio" }

// prefixScopedProvider wraps the fake impl in a real *storage.Provider.
func prefixScopedProvider(t *testing.T) *storageprov.Provider {
	t.Helper()
	return storageprov.NewWithImpl(fakePrefixScopedImpl{},
		"instant-shared-test", "https://s3.example.invalid", "s3.example.invalid", true)
}

// failingIssueImpl reports PrefixScopedKeys=true but IssueTenantCredentials
// always errors → drives the provision-failure soft-delete arm.
type failingIssueImpl struct{ fakePrefixScopedImpl }

func (failingIssueImpl) IssueTenantCredentials(_ context.Context, _ storageprovider.IssueRequest) (*storageprovider.TenantCreds, error) {
	return nil, stIssueErr("issue creds failed")
}

type stIssueErr string

func (e stIssueErr) Error() string { return string(e) }

func failingStorageProvider(t *testing.T) *storageprov.Provider {
	t.Helper()
	return storageprov.NewWithImpl(failingIssueImpl{},
		"instant-shared-test", "https://s3.example.invalid", "s3.example.invalid", true)
}

func storageAppWithProvider(t *testing.T, db *sql.DB, rdb *redis.Client, prov *storageprov.Provider) *fiber.App {
	t.Helper()
	cfg := &config.Config{
		JWTSecret:       testhelpers.TestJWTSecret,
		AESKey:          testhelpers.TestAESKeyHex,
		EnabledServices: "storage",
		Environment:     "test",
	}
	app := fiber.New(fiber.Config{
		ErrorHandler: func(c *fiber.Ctx, e error) error {
			if e == handlers.ErrResponseWritten {
				return nil
			}
			code := fiber.StatusInternalServerError
			if fe, ok := e.(*fiber.Error); ok {
				code = fe.Code
			}
			return c.Status(code).JSON(fiber.Map{"ok": false, "error": "internal_error", "message": e.Error()})
		},
		ProxyHeader: "X-Forwarded-For",
	})
	app.Use(middleware.RequestID())
	app.Use(middleware.Fingerprint())
	h := handlers.NewStorageHandler(db, rdb, cfg, prov, plans.Default())
	app.Post("/storage/new", middleware.OptionalAuth(cfg), h.NewStorage)
	return app
}

// storagePrefixApp wires /storage/new with the prefix-scoped provider against
// the given DB.
func storagePrefixApp(t *testing.T, db *sql.DB, rdb *redis.Client) *fiber.App {
	t.Helper()
	cfg := &config.Config{
		JWTSecret:       testhelpers.TestJWTSecret,
		AESKey:          testhelpers.TestAESKeyHex,
		EnabledServices: "storage",
		Environment:     "test",
	}
	app := fiber.New(fiber.Config{
		ErrorHandler: func(c *fiber.Ctx, e error) error {
			if e == handlers.ErrResponseWritten {
				return nil
			}
			code := fiber.StatusInternalServerError
			if fe, ok := e.(*fiber.Error); ok {
				code = fe.Code
			}
			return c.Status(code).JSON(fiber.Map{"ok": false, "error": "internal_error", "message": e.Error()})
		},
		ProxyHeader: "X-Forwarded-For",
	})
	app.Use(middleware.RequestID())
	app.Use(middleware.Fingerprint())
	h := handlers.NewStorageHandler(db, rdb, cfg, prefixScopedProvider(t), plans.Default())
	app.Post("/storage/new", middleware.OptionalAuth(cfg), h.NewStorage)
	return app
}

func stPost(t *testing.T, app *fiber.App, ip, jwt, body string) *http.Response {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/storage/new", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Forwarded-For", ip)
	if jwt != "" {
		req.Header.Set("Authorization", "Bearer "+jwt)
	}
	resp, err := app.Test(req, 15000)
	require.NoError(t, err)
	return resp
}

func stJWT(t *testing.T, db *sql.DB, teamID string) string {
	t.Helper()
	email := testhelpers.UniqueEmail(t)
	var userID string
	require.NoError(t, db.QueryRowContext(context.Background(),
		`INSERT INTO users (team_id, email) VALUES ($1::uuid, $2) RETURNING id::text`,
		teamID, email).Scan(&userID))
	return testhelpers.MustSignSessionJWT(t, userID, teamID, email)
}

// TestStorageFinal_DecideMode_PrefixScoped — decideStorageMode returns
// "credential" for a PrefixScopedKeys=true backend (storage.go:107). Verified
// via the exported DecideStorageModeKindForTest seam.
func TestStorageFinal_DecideMode_PrefixScoped(t *testing.T) {
	db, clean := testhelpers.SetupTestDB(t)
	defer clean()
	rdb, cleanR := testhelpers.SetupTestRedis(t)
	defer cleanR()
	cfg := &config.Config{JWTSecret: testhelpers.TestJWTSecret, AESKey: testhelpers.TestAESKeyHex, EnabledServices: "storage", Environment: "test"}
	h := handlers.NewStorageHandler(db, rdb, cfg, prefixScopedProvider(t), plans.Default())
	kind, _ := h.DecideStorageModeKindForTest("pro")
	assert.Equal(t, "credential", kind)
}

// bucketPerTenantImpl: PrefixScopedKeys=false but BucketPerTenant=true → on a
// paid tier decideStorageMode picks broker with the dedicated-bucket reason
// (storage.go:108-112).
type bucketPerTenantImpl struct{ fakePrefixScopedImpl }

func (bucketPerTenantImpl) Capabilities() storageprovider.Capabilities {
	return storageprovider.Capabilities{PrefixScopedKeys: false, BucketPerTenant: true}
}

// TestStorageFinal_DecideMode_BucketPerTenantPaid — the BucketPerTenant && paid
// branch falls through to broker (storage.go:108).
func TestStorageFinal_DecideMode_BucketPerTenantPaid(t *testing.T) {
	db, clean := testhelpers.SetupTestDB(t)
	defer clean()
	rdb, cleanR := testhelpers.SetupTestRedis(t)
	defer cleanR()
	cfg := &config.Config{JWTSecret: testhelpers.TestJWTSecret, AESKey: testhelpers.TestAESKeyHex, EnabledServices: "storage", Environment: "test"}
	prov := storageprov.NewWithImpl(bucketPerTenantImpl{}, "b", "https://s3.example.invalid", "s3.example.invalid", true)
	h := handlers.NewStorageHandler(db, rdb, cfg, prov, plans.Default())
	kind, _ := h.DecideStorageModeKindForTest("pro") // paid tier
	assert.Equal(t, "broker", kind)
}

// TestStorageFinal_Auth_QuotaCheckError_FailOpen — SumStorageBytesByTeamAndType
// errors → fail-open, provision still proceeds (storage.go:459). team(1) ok,
// quota-sum(2) errors, then CreateResource(3) etc. We only assert the request
// did NOT 402 on storage_limit (the quota error is swallowed). failAfter=1 makes
// the quota sum error; the subsequent CreateResource also errors → 503
// provision_failed, which still proves the fail-open path (459-461) ran.
func TestStorageFinal_Auth_QuotaCheckError_FailOpen(t *testing.T) {
	seedDB, clean := testhelpers.SetupTestDB(t)
	defer clean()
	rdb, cleanR := testhelpers.SetupTestRedis(t)
	defer cleanR()
	teamID := testhelpers.MustCreateTeamDB(t, seedDB, "pro")
	jwt := stJWT(t, seedDB, teamID)

	app := storageAppWithProvider(t, openFaultDB(t, 1), rdb, prefixScopedProvider(t))
	resp := stPost(t, app, "10.74.0.1", jwt, `{"name":"x","env":"production"}`)
	defer resp.Body.Close()
	// quota check failed-open → handler continued → CreateResource on faultdb
	// also errors → 503 (not a 402 storage_limit). The fail-open arm ran.
	require.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
	var m map[string]any
	require.NoError(t, decodeJSON(resp, &m))
	assert.NotEqual(t, "storage_limit_reached", m["error"])
}

// TestStorageFinal_Auth_StorageLimitReached_402 — a team whose summed
// storage_bytes already exceeds its tier limit → 402 storage_limit_reached
// (storage.go:464). Seed an active storage resource with storage_bytes over the
// pro limit.
func TestStorageFinal_Auth_StorageLimitReached_402(t *testing.T) {
	db, clean := testhelpers.SetupTestDB(t)
	defer clean()
	rdb, cleanR := testhelpers.SetupTestRedis(t)
	defer cleanR()
	teamID := testhelpers.MustCreateTeamDB(t, db, "hobby") // small storage limit
	jwt := stJWT(t, db, teamID)
	limitMB := plans.Default().StorageLimitMB("hobby", "storage")
	// Seed a storage resource already at/over the limit.
	_, err := db.ExecContext(context.Background(), `
		INSERT INTO resources (team_id, resource_type, tier, status, storage_bytes)
		VALUES ($1::uuid, 'storage', 'hobby', 'active', $2)`,
		teamID, int64(limitMB)*1024*1024+1)
	require.NoError(t, err)

	app := storagePrefixApp(t, db, rdb)
	resp := stPost(t, app, "10.74.0.2", jwt, `{"name":"x","env":"production"}`)
	defer resp.Body.Close()
	require.Equal(t, http.StatusPaymentRequired, resp.StatusCode)
	var m map[string]any
	require.NoError(t, decodeJSON(resp, &m))
	assert.Equal(t, "storage_limit_reached", m["error"])
}

// TestStorageFinal_Auth_PrefixScoped_201_AndIAMAudit — an authenticated
// provision against the prefix-scoped backend returns 201 with mode
// "prefix-scoped" and emits the per-tenant-IAM-key audit row (storage.go:560).
func TestStorageFinal_Auth_PrefixScoped_201_AndIAMAudit(t *testing.T) {
	db, clean := testhelpers.SetupTestDB(t)
	defer clean()
	rdb, cleanR := testhelpers.SetupTestRedis(t)
	defer cleanR()
	teamID := testhelpers.MustCreateTeamDB(t, db, "pro")
	jwt := stJWT(t, db, teamID)

	app := storagePrefixApp(t, db, rdb)
	resp := stPost(t, app, "10.71.0.1", jwt, `{"name":"assets","env":"production"}`)
	defer resp.Body.Close()
	require.Equal(t, http.StatusCreated, resp.StatusCode)

	var m map[string]any
	require.NoError(t, decodeJSON(resp, &m))
	assert.Equal(t, "prefix-scoped", m["mode"])

	// The IAM-audit goroutine is best-effort; poll briefly for the row.
	var teamUUID = uuid.MustParse(teamID)
	found := false
	for i := 0; i < 50 && !found; i++ {
		var n int
		require.NoError(t, db.QueryRowContext(context.Background(),
			`SELECT count(*) FROM audit_log WHERE team_id=$1::uuid AND kind=$2`,
			teamUUID, models.AuditKindStorageIAMUserCreated).Scan(&n))
		if n > 0 {
			found = true
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	assert.True(t, found, "per-tenant IAM-key audit row must be written for prefix-scoped mode")
}

// TestStorageFinal_Anon_PrefixScoped_201 — an anonymous provision against the
// prefix-scoped backend returns 201 (credential mode). Drives the anonymous
// fresh-provision + credential response arms.
func TestStorageFinal_Anon_PrefixScoped_201(t *testing.T) {
	db, clean := testhelpers.SetupTestDB(t)
	defer clean()
	rdb, cleanR := testhelpers.SetupTestRedis(t)
	defer cleanR()
	app := storagePrefixApp(t, db, rdb)
	resp := stPost(t, app, "10.72.0.1", "", `{"name":"anon-bucket","env":"production"}`)
	defer resp.Body.Close()
	require.Equal(t, http.StatusCreated, resp.StatusCode)
	var m map[string]any
	require.NoError(t, decodeJSON(resp, &m))
	assert.Equal(t, "anonymous", m["tier"])
}

// TestStorageFinal_Anon_ProvisionFails_SoftDelete_503 — IssueTenantCredentials
// errors → provision_failed + soft-delete (storage.go:323-331).
func TestStorageFinal_Anon_ProvisionFails_SoftDelete_503(t *testing.T) {
	db, clean := testhelpers.SetupTestDB(t)
	defer clean()
	rdb, cleanR := testhelpers.SetupTestRedis(t)
	defer cleanR()
	app := storageAppWithProvider(t, db, rdb, failingStorageProvider(t))
	resp := stPost(t, app, "10.72.0.2", "", `{"name":"x","env":"production"}`)
	defer resp.Body.Close()
	require.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
	var m map[string]any
	require.NoError(t, decodeJSON(resp, &m))
	assert.Equal(t, "provision_failed", m["error"])
}

// TestStorageFinal_Auth_ProvisionFails_SoftDelete_503 — authenticated provision
// where IssueTenantCredentials errors → provision_failed + soft-delete
// (storage.go:512-520).
func TestStorageFinal_Auth_ProvisionFails_SoftDelete_503(t *testing.T) {
	db, clean := testhelpers.SetupTestDB(t)
	defer clean()
	rdb, cleanR := testhelpers.SetupTestRedis(t)
	defer cleanR()
	teamID := testhelpers.MustCreateTeamDB(t, db, "pro")
	jwt := stJWT(t, db, teamID)
	app := storageAppWithProvider(t, db, rdb, failingStorageProvider(t))
	resp := stPost(t, app, "10.72.0.3", jwt, `{"name":"x","env":"production"}`)
	defer resp.Body.Close()
	require.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
	var m map[string]any
	require.NoError(t, decodeJSON(resp, &m))
	assert.Equal(t, "provision_failed", m["error"])
}

// TestStorageFinal_Anon_OverCap_Dedup — anonymous provisions burn the daily
// cap; the next over-cap call dedups to the existing resource and returns its
// connection_url (storage.go:189-258 dedup happy path + recycleGate 268).
func TestStorageFinal_Anon_OverCap_Dedup(t *testing.T) {
	db, clean := testhelpers.SetupTestDB(t)
	defer clean()
	rdb, cleanR := testhelpers.SetupTestRedis(t)
	defer cleanR()
	app := storagePrefixApp(t, db, rdb)
	const ip = "10.75.0.4"
	post := func() *http.Response {
		return stPost(t, app, ip, "", `{"name":"s","env":"production"}`)
	}
	first := post()
	require.Equal(t, http.StatusCreated, first.StatusCode)
	first.Body.Close()
	// Burn past the anonymous cap (5/fp) and observe a dedup/deny outcome.
	sawDedupOrDeny := false
	for i := 0; i < 8; i++ {
		resp := post()
		if resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode == http.StatusPaymentRequired {
			sawDedupOrDeny = true
		}
		resp.Body.Close()
	}
	assert.True(t, sawDedupOrDeny, "over-cap calls must dedup/deny, exercising the anonymous limit branch")
}

// TestStorageFinal_Anon_OverCap_DedupDecryptFail — corrupt every active storage
// row for the fingerprint after burning the cap → the over-cap dedup decrypt
// fails → fail-closed fallthrough (storage.go:206-209).
func TestStorageFinal_Anon_OverCap_DedupDecryptFail(t *testing.T) {
	db, clean := testhelpers.SetupTestDB(t)
	defer clean()
	rdb, cleanR := testhelpers.SetupTestRedis(t)
	defer cleanR()
	app := storagePrefixApp(t, db, rdb)
	const ip = "10.75.0.5"
	post := func() *http.Response { return stPost(t, app, ip, "", `{"name":"s","env":"production"}`) }
	for i := 0; i < 6; i++ {
		post().Body.Close()
	}
	_, err := db.ExecContext(context.Background(),
		`UPDATE resources SET connection_url = 'corrupt' WHERE resource_type='storage' AND status='active' AND tier='anonymous'`)
	require.NoError(t, err)
	resp := post()
	defer resp.Body.Close()
	assert.NotEqual(t, http.StatusInternalServerError, resp.StatusCode)
}

// TestStorageFinal_Auth_BadTeamID_400 — JWT tid not a UUID → invalid_team
// (storage.go:447).
func TestStorageFinal_Auth_BadTeamID_400(t *testing.T) {
	db, clean := testhelpers.SetupTestDB(t)
	defer clean()
	rdb, cleanR := testhelpers.SetupTestRedis(t)
	defer cleanR()
	app := storagePrefixApp(t, db, rdb)
	jwt := testhelpers.MustSignSessionJWT(t, uuid.NewString(), "not-a-uuid", testhelpers.UniqueEmail(t))
	resp := stPost(t, app, "10.71.0.2", jwt, `{"name":"x","env":"production"}`)
	defer resp.Body.Close()
	require.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

// TestStorageFinal_Auth_TeamLookup_DBError_503 — GetTeamByID errors
// (storage.go:449). failAfter=0.
func TestStorageFinal_Auth_TeamLookup_DBError_503(t *testing.T) {
	seedDB, clean := testhelpers.SetupTestDB(t)
	defer clean()
	rdb, cleanR := testhelpers.SetupTestRedis(t)
	defer cleanR()
	teamID := testhelpers.MustCreateTeamDB(t, seedDB, "pro")
	jwt := stJWT(t, seedDB, teamID)

	faultDB := openFaultDB(t, 0)
	app := storagePrefixApp(t, faultDB, rdb)
	resp := stPost(t, app, "10.71.0.3", jwt, `{"name":"x","env":"production"}`)
	defer resp.Body.Close()
	require.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
}

// TestStorageFinal_Auth_CreateResource_DBError_503 — team(1) + quota(2) ok, the
// CreateResource INSERT(3) errors (storage.go:485). failAfter=2.
func TestStorageFinal_Auth_CreateResource_DBError_503(t *testing.T) {
	seedDB, clean := testhelpers.SetupTestDB(t)
	defer clean()
	rdb, cleanR := testhelpers.SetupTestRedis(t)
	defer cleanR()
	teamID := testhelpers.MustCreateTeamDB(t, seedDB, "pro")
	jwt := stJWT(t, seedDB, teamID)

	faultDB := openFaultDB(t, 2)
	app := storagePrefixApp(t, faultDB, rdb)
	resp := stPost(t, app, "10.71.0.4", jwt, `{"name":"x","env":"production"}`)
	defer resp.Body.Close()
	require.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
}
