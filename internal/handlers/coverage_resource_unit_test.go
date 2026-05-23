package handlers

// coverage_resource_unit_test.go — package-internal unit tests for the pure /
// near-pure helpers in the resource-provisioning handlers that the
// integration suite can't reach without a backend fault: the per-handler
// decrypt helpers, addQueueCredentials, metrics tier-cap helpers,
// nosqlAnonymousLimits / cacheAnonymousLimits, and storeEncryptedURL (with a
// real DB connection opened directly — no testhelpers, to avoid the import
// cycle).
//
// These are `package handlers` (white-box) tests; they construct handlers with
// nil db/rdb where the method under test only reads cfg, and open a real
// *sql.DB for the methods that persist.

import (
	"context"
	"database/sql"
	"os"
	"testing"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	_ "github.com/lib/pq"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	commonqp "instant.dev/common/queueprovider"

	"instant.dev/internal/config"
	"instant.dev/internal/crypto"
	"instant.dev/internal/plans"
)

const unitAESKeyHex = "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"

func unitCfg() *config.Config {
	return &config.Config{
		AESKey:          unitAESKeyHex,
		EnabledServices: "postgres,redis,mongodb,queue,webhook,storage",
		Environment:     "test",
	}
}

func unitReg() *plans.Registry { return plans.Default() }

func mustEncrypt(t *testing.T, plain string) string {
	t.Helper()
	key, err := crypto.ParseAESKey(unitAESKeyHex)
	require.NoError(t, err)
	enc, err := crypto.Encrypt(key, plain)
	require.NoError(t, err)
	return enc
}

// ── per-handler decryptConnectionURL (fail-closed) ──────────────────────────

func TestResourceUnit_DecryptConnectionURL_AllHandlers(t *testing.T) {
	cfg := unitCfg()
	reg := unitReg()
	enc := mustEncrypt(t, "postgres://u:p@h:5432/db")

	dbH := NewDBHandler(nil, nil, cfg, nil, reg)
	cacheH := NewCacheHandler(nil, nil, cfg, nil, reg)
	nosqlH := NewNoSQLHandler(nil, nil, cfg, nil, reg)
	queueH := NewQueueHandler(nil, nil, cfg, nil, reg)

	for name, fn := range map[string]func(string, string) (string, bool){
		"db":    dbH.decryptConnectionURL,
		"cache": cacheH.decryptConnectionURL,
		"nosql": nosqlH.decryptConnectionURL,
		"queue": queueH.decryptConnectionURL,
	} {
		// happy
		got, ok := fn(enc, "rid")
		assert.Truef(t, ok, "%s: happy ok", name)
		assert.Equalf(t, "postgres://u:p@h:5432/db", got, "%s: happy plain", name)
		// empty → ("", true)
		got, ok = fn("", "rid")
		assert.Truef(t, ok, "%s: empty ok", name)
		assert.Emptyf(t, got, "%s: empty plain", name)
		// bad ciphertext → ("", false) fail-closed
		got, ok = fn("not-base64-ciphertext", "rid")
		assert.Falsef(t, ok, "%s: bad ok", name)
		assert.Emptyf(t, got, "%s: bad plain", name)
	}

	// bad AES key → fail-closed for all.
	badCfg := unitCfg()
	badCfg.AESKey = "ZZ"
	dbBad := NewDBHandler(nil, nil, badCfg, nil, reg)
	_, ok := dbBad.decryptConnectionURL(enc, "rid")
	assert.False(t, ok, "bad key must fail closed")
}

// ── webhook decryptWebhookURL (fail-open) ───────────────────────────────────

func TestWebhookUnit_DecryptWebhookURL(t *testing.T) {
	cfg := unitCfg()
	h := NewWebhookHandler(nil, nil, cfg, unitReg())
	enc := mustEncrypt(t, "https://hooks.example.com/recv/abc")

	assert.Equal(t, "https://hooks.example.com/recv/abc", h.decryptWebhookURL(enc, "rid"))
	assert.Equal(t, "", h.decryptWebhookURL("", "rid"))
	// fail-open: bad ciphertext returns the ciphertext unchanged.
	assert.Equal(t, "garbage", h.decryptWebhookURL("garbage", "rid"))

	bad := unitCfg()
	bad.AESKey = "ZZ"
	hb := NewWebhookHandler(nil, nil, bad, unitReg())
	assert.Equal(t, enc, hb.decryptWebhookURL(enc, "rid"), "bad key fail-open returns ciphertext")
}

// ── storage decryptStorageURL ───────────────────────────────────────────────

func TestStorageUnit_DecryptStorageURL(t *testing.T) {
	cfg := unitCfg()
	h := NewStorageHandler(nil, nil, cfg, nil, unitReg())
	enc := mustEncrypt(t, "https://s3.example.com/bucket/prefix/")

	got, ok := h.decryptStorageURL(enc, "rid")
	assert.True(t, ok)
	assert.Equal(t, "https://s3.example.com/bucket/prefix/", got)

	got, ok = h.decryptStorageURL("", "rid")
	assert.True(t, ok)
	assert.Empty(t, got)

	got, ok = h.decryptStorageURL("not-real", "rid")
	assert.False(t, ok)
	assert.Empty(t, got)
}

// ── anonymous-limits map builders ───────────────────────────────────────────

func TestResourceUnit_AnonymousLimits_Builders(t *testing.T) {
	cfg := unitCfg()
	reg := unitReg()

	nosqlH := NewNoSQLHandler(nil, nil, cfg, nil, reg)
	nl := nosqlH.nosqlAnonymousLimits()
	assert.Equal(t, "24h", nl["expires_in"])
	assert.NotNil(t, nl["storage_mb"])

	cacheH := NewCacheHandler(nil, nil, cfg, nil, reg)
	cl := cacheH.cacheAnonymousLimits()
	assert.Equal(t, "24h", cl["expires_in"])
	assert.NotNil(t, cl["memory_mb"])

	storageH := NewStorageHandler(nil, nil, cfg, nil, reg)
	sl := storageH.storageAnonymousLimits()
	assert.Equal(t, "24h", sl["expires_in"])
	assert.NotNil(t, sl["storage_mb"])
}

// ── addQueueCredentials (every flavor) ──────────────────────────────────────

func TestQueueUnit_AddQueueCredentials(t *testing.T) {
	// nil → no-op
	resp := fiber.Map{}
	addQueueCredentials(resp, nil)
	_, has := resp["credentials"]
	assert.False(t, has, "nil creds must not set credentials")

	// legacy_open → no-op
	resp = fiber.Map{}
	addQueueCredentials(resp, &commonqp.TenantCreds{AuthMode: commonqp.AuthModeLegacyOpen})
	_, has = resp["credentials"]
	assert.False(t, has, "legacy_open must not set credentials")

	// isolated with all fields → fully populated credentials map
	resp = fiber.Map{}
	addQueueCredentials(resp, &commonqp.TenantCreds{
		AuthMode:  commonqp.AuthModeIsolated,
		JWT:       "jwt-blob",
		NKey:      "SU-seed",
		CredsFile: "creds-blob",
		Username:  "usr",
		Password:  "pw",
		KeyID:     "k1",
	})
	cm, ok := resp["credentials"].(fiber.Map)
	require.True(t, ok)
	assert.Equal(t, commonqp.AuthModeIsolated, cm["auth_mode"])
	assert.Equal(t, "jwt-blob", cm["nats_jwt"])
	assert.Equal(t, "SU-seed", cm["nats_nkey"])
	assert.Equal(t, "creds-blob", cm["creds_file"])
	assert.Equal(t, "usr", cm["username"])
	assert.Equal(t, "pw", cm["password"])
	assert.Equal(t, "k1", cm["key_id"])
}

// ── metrics tier-cap helpers ────────────────────────────────────────────────

func TestResourceUnit_MetricsTierHumanCap_AllArms(t *testing.T) {
	assert.Equal(t, "1h", metricsTierHumanCap("hobby"))
	assert.Equal(t, "24h", metricsTierHumanCap("pro"))
	assert.Equal(t, "7d", metricsTierHumanCap("growth"))
	assert.Equal(t, "7d", metricsTierHumanCap("team"))
	assert.Equal(t, "1h", metricsTierHumanCap("unknown"))
}

func TestResourceUnit_MetricsTierWindowCap_AllArms(t *testing.T) {
	assert.EqualValues(t, 0, metricsTierWindowCap("anonymous"))
	assert.EqualValues(t, 0, metricsTierWindowCap("free"))
	assert.EqualValues(t, 3600, metricsTierWindowCap("hobby"))
	assert.EqualValues(t, 86400, metricsTierWindowCap("pro"))
	assert.EqualValues(t, 604800, metricsTierWindowCap("growth"))
	assert.EqualValues(t, 604800, metricsTierWindowCap("team"))
	assert.EqualValues(t, 3600, metricsTierWindowCap("mystery"))
}

func TestResourceUnit_MetricsMaxIntAndRound2(t *testing.T) {
	assert.Equal(t, 5, metricsMaxInt(5, 1))
	assert.Equal(t, 9, metricsMaxInt(2, 9))
	assert.Equal(t, 1.23, round2(1.234))
	assert.Equal(t, 1.24, round2(1.235))
}

func TestResourceUnit_AgentActionMetricsWindowTooLarge(t *testing.T) {
	got := newAgentActionMetricsWindowTooLarge("hobby", "1h")
	assert.Contains(t, got, "hobby")
	assert.Contains(t, got, "1h")
}

// ── storeEncryptedURL (needs a real DB) ─────────────────────────────────────

func openUnitDB(t *testing.T) *sql.DB {
	t.Helper()
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		dsn = "postgres://postgres:postgres@127.0.0.1:5432/instant_dev_test?sslmode=disable"
	}
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Skipf("storeEncryptedURL: open db: %v", err)
	}
	if err := db.PingContext(context.Background()); err != nil {
		db.Close()
		t.Skipf("storeEncryptedURL: ping db: %v", err)
	}
	return db
}

func TestWebhookUnit_StoreEncryptedURL(t *testing.T) {
	db := openUnitDB(t)
	defer db.Close()
	cfg := unitCfg()
	h := NewWebhookHandler(db, nil, cfg, unitReg())

	// Seed a resource row to update. The resources table requires a token +
	// resource_type; insert a minimal anonymous webhook row.
	var resourceID uuid.UUID
	err := db.QueryRowContext(context.Background(), `
		INSERT INTO resources (resource_type, tier, status, name)
		VALUES ('webhook', 'anonymous', 'active', 'unit-store-url')
		RETURNING id
	`).Scan(&resourceID)
	if err != nil {
		t.Skipf("seed resource failed (schema unavailable?): %v", err)
	}
	defer db.ExecContext(context.Background(), `DELETE FROM resources WHERE id = $1`, resourceID)

	require.NoError(t, h.storeEncryptedURL(context.Background(), resourceID, "https://hooks.example.com/recv/xyz", "rid"))

	// Verify it round-trips through decryptWebhookURL.
	var enc string
	require.NoError(t, db.QueryRowContext(context.Background(),
		`SELECT connection_url FROM resources WHERE id = $1`, resourceID).Scan(&enc))
	assert.Equal(t, "https://hooks.example.com/recv/xyz", h.decryptWebhookURL(enc, "rid"))

	// bad AES key → storeEncryptedURL returns an error.
	bad := unitCfg()
	bad.AESKey = "ZZ"
	hb := NewWebhookHandler(db, nil, bad, unitReg())
	assert.Error(t, hb.storeEncryptedURL(context.Background(), resourceID, "x", "rid"))
}
