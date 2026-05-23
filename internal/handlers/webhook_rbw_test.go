package handlers_test

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"testing"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"instant.dev/internal/config"
	"instant.dev/internal/crypto"
	"instant.dev/internal/handlers"
	"instant.dev/internal/plans"
	"instant.dev/internal/testhelpers"
)

func newWebhookHandlerForTest(t *testing.T) (*handlers.WebhookHandler, func()) {
	t.Helper()
	db, dbClean := testhelpers.SetupTestDB(t)
	rdb, rClean := testhelpers.SetupTestRedis(t)
	cfg := &config.Config{Environment: "test", AESKey: testhelpers.TestAESKeyHex}
	h := handlers.NewWebhookHandler(db, rdb, cfg, plans.Default())
	return h, func() { dbClean(); rClean() }
}

// TestWebhookMaxStored covers all three arms: unlimited (-1 → 10000), the
// configured-positive value, and the safe floor.
func TestWebhookMaxStored(t *testing.T) {
	h, clean := newWebhookHandlerForTest(t)
	defer clean()
	// team tier → unlimited webhook stored → 10000 cap
	require.Equal(t, int64(10_000), handlers.WebhookMaxStoredForTest(h, "team"))
	// hobby → a finite positive cap (1000 per plans.yaml)
	require.Greater(t, handlers.WebhookMaxStoredForTest(h, "hobby"), int64(0))
	// unknown tier → falls back to anonymous (100) via the int64(n) path
	require.Equal(t, int64(100), handlers.WebhookMaxStoredForTest(h, "no_such_tier"))
}

// TestWebhookMaxStored_FloorArm covers the n<=0 safe-floor branch via a custom
// plans registry whose tier has webhook_requests_stored: 0.
func TestWebhookMaxStored_FloorArm(t *testing.T) {
	limits := `
    limits:
      provisions_per_day: 5
      postgres_storage_mb: 10
      postgres_connections: 2
      redis_memory_mb: 5
      mongodb_storage_mb: 5
      mongodb_connections: 2
      webhook_requests_stored: 0`
	yaml := `
plans:
  anonymous:
    display_name: "Anonymous"
    price_monthly_cents: 0` + limits + `
  zerohook:
    display_name: "ZeroHook"
    price_monthly_cents: 0` + limits + `
`
	dir := t.TempDir()
	path := dir + "/plans.yaml"
	require.NoError(t, os.WriteFile(path, []byte(yaml), 0o600))
	reg, err := plans.Load(path)
	require.NoError(t, err)

	db, dbClean := testhelpers.SetupTestDB(t)
	defer dbClean()
	rdb, rClean := testhelpers.SetupTestRedis(t)
	defer rClean()
	cfg := &config.Config{Environment: "test", AESKey: testhelpers.TestAESKeyHex}
	h := handlers.NewWebhookHandler(db, rdb, cfg, reg)
	require.Equal(t, int64(100), handlers.WebhookMaxStoredForTest(h, "zerohook"), "0-stored tier → safe floor 100")
}

// TestStoreEncryptedURL covers the success path + the update-failure arm
// (closed DB) + the AES-key-parse arm (junk key).
func TestStoreEncryptedURL(t *testing.T) {
	db, dbClean := testhelpers.SetupTestDB(t)
	rdb, rClean := testhelpers.SetupTestRedis(t)
	defer rClean()
	cfg := &config.Config{Environment: "test", AESKey: testhelpers.TestAESKeyHex}
	h := handlers.NewWebhookHandler(db, rdb, cfg, plans.Default())

	team := testhelpers.MustCreateTeamDB(t, db, "pro")
	var resID string
	require.NoError(t, db.QueryRowContext(context.Background(),
		`INSERT INTO resources (team_id, resource_type, tier, status) VALUES ($1::uuid,'webhook','pro','active') RETURNING id::text`,
		team).Scan(&resID))

	// success
	require.NoError(t, handlers.StoreEncryptedURLForTest(h, context.Background(),
		uuid.MustParse(resID), "https://hook.example/x", "req-1"))

	// update-failure: close the pool
	dbClean()
	require.Error(t, handlers.StoreEncryptedURLForTest(h, context.Background(),
		uuid.MustParse(resID), "https://hook.example/y", "req-2"))

	// AES-key-parse failure
	badCfg := &config.Config{Environment: "test", AESKey: "not-hex"}
	rdb2, r2Clean := testhelpers.SetupTestRedis(t)
	defer r2Clean()
	db2, db2Clean := testhelpers.SetupTestDB(t)
	defer db2Clean()
	hBad := handlers.NewWebhookHandler(db2, rdb2, badCfg, plans.Default())
	err := handlers.StoreEncryptedURLForTest(hBad, context.Background(), uuid.New(), "https://x", "req-3")
	require.Error(t, err)
	require.Contains(t, err.Error(), "parse key")
}

// TestDecryptWebhookURL covers empty / bad-key / bad-ciphertext / success.
func TestDecryptWebhookURL(t *testing.T) {
	h, clean := newWebhookHandlerForTest(t)
	defer clean()
	require.Equal(t, "", handlers.DecryptWebhookURLForTest(h, "", "r"))
	// bad ciphertext → returns ciphertext unchanged (fail open)
	require.Equal(t, "garbage", handlers.DecryptWebhookURLForTest(h, "garbage", "r"))
	// success round-trip
	key, _ := crypto.ParseAESKey(testhelpers.TestAESKeyHex)
	enc, _ := crypto.Encrypt(key, "https://hook/abc")
	require.Equal(t, "https://hook/abc", handlers.DecryptWebhookURLForTest(h, enc, "r"))
}

// TestIdempotentReceive covers store + lookup hit + lookup miss + bad-json miss.
func TestIdempotentReceive(t *testing.T) {
	h, clean := newWebhookHandlerForTest(t)
	defer clean()
	ctx := context.Background()
	const token, key = "tok-1", "idem-1"

	// miss before store
	_, ok := handlers.LookupIdempotentReceiveForTest(h, ctx, token, key)
	require.False(t, ok)

	// store then hit
	handlers.StoreIdempotentReceiveForTest(h, ctx, token, key, fiber.Map{"ok": true, "n": 1}, time.Minute)
	got, ok := handlers.LookupIdempotentReceiveForTest(h, ctx, token, key)
	require.True(t, ok)
	require.Equal(t, true, got["ok"])
}

// TestStoreIdempotentReceive_ErrorArms covers the json.Marshal-failure arm
// (an unmarshalable channel value) and the Redis Set-error arm (closed client).
func TestStoreIdempotentReceive_ErrorArms(t *testing.T) {
	h, clean := newWebhookHandlerForTest(t)
	defer clean()
	ctx := context.Background()
	// channel value is not JSON-marshalable → marshal returns early (no panic).
	handlers.StoreIdempotentReceiveForTest(h, ctx, "tok", "k", fiber.Map{"bad": make(chan int)}, time.Minute)

	// closed redis client → Set errors → metric arm. Build a handler whose
	// redis client is closed.
	db, dbClean := testhelpers.SetupTestDB(t)
	defer dbClean()
	rdb, _ := testhelpers.SetupTestRedis(t)
	rdb.Close() // closed → Set errors
	cfg := &config.Config{Environment: "test", AESKey: testhelpers.TestAESKeyHex}
	hClosed := handlers.NewWebhookHandler(db, rdb, cfg, plans.Default())
	handlers.StoreIdempotentReceiveForTest(hClosed, ctx, "tok2", "k2", fiber.Map{"ok": true}, time.Minute)
}

// TestLookupIdempotentReceive_BadJSON covers the json.Unmarshal-failure miss
// arm: a key holding non-JSON bytes returns (nil,false).
func TestLookupIdempotentReceive_BadJSON(t *testing.T) {
	h, clean := newWebhookHandlerForTest(t)
	defer clean()
	ctx := context.Background()
	rdb := handlers.WebhookRedisForTest(h)
	// write raw non-JSON under the exact idempotency key the lookup computes.
	require.NoError(t, rdb.Set(ctx, handlers.WebhookIdempotencyKeyForTest("tok-bad", "k-bad"), "{not-json", time.Minute).Err())
	_, ok := handlers.LookupIdempotentReceiveForTest(h, ctx, "tok-bad", "k-bad")
	require.False(t, ok)
}

// TestDecryptWebhookURL_BadKey covers the aes-key-parse-failure arm: a junk
// AES key makes decrypt fail open, returning the ciphertext unchanged.
func TestDecryptWebhookURL_BadKey(t *testing.T) {
	db, dbClean := testhelpers.SetupTestDB(t)
	defer dbClean()
	rdb, rClean := testhelpers.SetupTestRedis(t)
	defer rClean()
	cfg := &config.Config{Environment: "test", AESKey: "not-a-valid-hex"}
	h := handlers.NewWebhookHandler(db, rdb, cfg, plans.Default())
	require.Equal(t, "ciphertext", handlers.DecryptWebhookURLForTest(h, "ciphertext", "r"))
}

// TestVerifyWebhookHMAC covers every branch: empty header, wrong prefix, bad
// hex, mismatch, and the valid signature.
func TestVerifyWebhookHMAC(t *testing.T) {
	body := []byte(`{"event":"x"}`)
	secret := "shh"
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	valid := "sha256=" + hex.EncodeToString(mac.Sum(nil))

	require.False(t, handlers.VerifyWebhookHMACForTest(secret, body, ""))
	require.False(t, handlers.VerifyWebhookHMACForTest(secret, body, "md5=abc"))
	require.False(t, handlers.VerifyWebhookHMACForTest(secret, body, "sha256=zzznothex"))
	require.False(t, handlers.VerifyWebhookHMACForTest(secret, body, "sha256="+hex.EncodeToString([]byte("wrong"))))
	require.True(t, handlers.VerifyWebhookHMACForTest(secret, body, valid))
}
