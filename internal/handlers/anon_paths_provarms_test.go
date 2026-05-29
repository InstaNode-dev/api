package handlers_test

// anon_paths_provarms_test.go — covers two anonymous-path branches the same-
// type dedup tests miss:
//
//  1. Cross-service daily-cap fallback (P1-A): 5 provisions of type A exhaust
//     the per-fingerprint daily cap; a 6th of type B finds no type-B row but
//     DOES find a type-A row via GetActiveResourceByFingerprint → 429
//     provision_limit_reached (instead of falling through to a fresh provision).
//
//  2. Dedup decrypt-failure fallthrough: when the existing same-type row's
//     stored connection_url can't be decrypted, the handler logs and provisions
//     FRESH rather than returning ciphertext.

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"instant.dev/internal/handlers"
)

// burstToCap sends `n` provisions of `path` from `ip`, each with a distinct
// Idempotency-Key so the handler runs every time.
func burstToCap(t *testing.T, fx grpcProvFixture, path, ip string, n int) {
	t.Helper()
	for i := 0; i < n; i++ {
		resp, body := doProvisionKeyed(t, fx, path, ip, "", uuid.NewString(), map[string]any{"name": "burst"})
		resp.Body.Close()
		require.Truef(t, body.OK, "burst call %d on %s", i+1, path)
	}
}

func TestAnonCrossServiceCapFallback_DBAfterCache(t *testing.T) {
	fake := &fakeProvisioner{}
	fx := setupGRPCProvFixture(t, fake, false)
	ip := "10.210.0.1"
	burstToCap(t, fx, "/cache/new", ip, 5) // exhaust the daily cap with redis

	// 6th provision is a DIFFERENT type (postgres): no postgres row exists for
	// this fingerprint, but a redis row does → cross-service 429.
	resp, body := doProvisionKeyed(t, fx, "/db/new", ip, "", uuid.NewString(), map[string]any{"name": "xservice"})
	defer resp.Body.Close()
	require.Equal(t, http.StatusTooManyRequests, resp.StatusCode)
	assert.Equal(t, "provision_limit_reached", body.Error)
}

func TestAnonCrossServiceCapFallback_QueueAfterCache(t *testing.T) {
	fake := &fakeProvisioner{}
	fx := setupGRPCProvFixture(t, fake, false)
	ip := "10.211.0.1"
	burstToCap(t, fx, "/cache/new", ip, 5)

	resp, body := doProvisionKeyed(t, fx, "/queue/new", ip, "", uuid.NewString(), map[string]any{"name": "xservice-q"})
	defer resp.Body.Close()
	require.Equal(t, http.StatusTooManyRequests, resp.StatusCode)
	assert.Equal(t, "provision_limit_reached", body.Error)
}

func TestAnonCrossServiceCapFallback_NoSQLAfterCache(t *testing.T) {
	fake := &fakeProvisioner{}
	fx := setupGRPCProvFixture(t, fake, false)
	ip := "10.212.0.1"
	burstToCap(t, fx, "/cache/new", ip, 5)

	resp, body := doProvisionKeyed(t, fx, "/nosql/new", ip, "", uuid.NewString(), map[string]any{"name": "xservice-m"})
	defer resp.Body.Close()
	require.Equal(t, http.StatusTooManyRequests, resp.StatusCode)
	assert.Equal(t, "provision_limit_reached", body.Error)
}

// Dedup decrypt-failure fallthrough: provision 5 postgres, corrupt the existing
// row's connection_url to garbage, then a 6th over-cap call hits the dedup
// branch, fails to decrypt, logs, and provisions FRESH (201) rather than
// returning ciphertext.
func TestAnonDedup_DecryptFailure_ProvisionsFresh(t *testing.T) {
	fake := &fakeProvisioner{}
	fx := setupGRPCProvFixture(t, fake, false)
	ip := "10.213.0.1"

	var firstToken string
	for i := 0; i < 5; i++ {
		resp, body := doProvisionKeyed(t, fx, "/db/new", ip, "", uuid.NewString(), map[string]any{"name": "decryptfail"})
		resp.Body.Close()
		require.Equal(t, http.StatusCreated, resp.StatusCode)
		if i == 0 {
			firstToken = body.Token
		}
	}
	require.NotEmpty(t, firstToken)

	// Corrupt every active postgres row's stored connection_url for this
	// fingerprint so the dedup decrypt fails.
	_, err := fx.db.ExecContext(context.Background(), `
		UPDATE resources SET connection_url = 'not-decryptable-ciphertext'
		WHERE resource_type = 'postgres' AND status = 'active' AND team_id IS NULL
		  AND fingerprint = (SELECT fingerprint FROM resources WHERE token = $1::uuid)
	`, firstToken)
	require.NoError(t, err)

	// 6th over-cap call: dedup decrypt fails → fall through → fresh 201.
	resp, body := doProvisionKeyed(t, fx, "/db/new", ip, "", uuid.NewString(), map[string]any{"name": "decryptfail-6"})
	defer resp.Body.Close()
	require.Equal(t, http.StatusCreated, resp.StatusCode, "decrypt-fail dedup must provision fresh, not 200 with ciphertext")
	assert.NotEmpty(t, body.ConnectionURL)
	assert.NotContains(t, body.ConnectionURL, "not-decryptable", "must never return ciphertext")
}

// recycleGate fired via the gRPC fixture (provisioning works) for cache / nosql
// / queue: plant a recycle_seen marker + zero active rows for the fingerprint →
// 402 free_tier_recycle_requires_claim. Covers the recycleGate-true branch in
// each handler (the db variant lives in redis_fault_provarms_test.go).
func recycleGateOnce(t *testing.T, path, ip, resourceType string) {
	t.Helper()
	fake := &fakeProvisioner{}
	fx := setupGRPCProvFixture(t, fake, false)

	// Provision once to learn the fingerprint, then clear active rows + plant
	// the marker so the next call trips the gate.
	resp, body := doProvisionKeyed(t, fx, path, ip, "", uuid.NewString(), map[string]any{"name": "rg-probe"})
	resp.Body.Close()
	require.Equal(t, http.StatusCreated, resp.StatusCode)

	var fp string
	require.NoError(t, fx.db.QueryRowContext(context.Background(),
		`SELECT fingerprint FROM resources WHERE token = $1::uuid`, body.Token).Scan(&fp))
	_, err := fx.db.ExecContext(context.Background(),
		`UPDATE resources SET status = 'deleted' WHERE fingerprint = $1`, fp)
	require.NoError(t, err)
	require.NoError(t, fx.rdb.Set(context.Background(),
		handlers.RecycleSeenKeyPrefix+fp, "1", time.Hour).Err())

	resp2, body2 := doProvisionKeyed(t, fx, path, ip, "", uuid.NewString(), map[string]any{"name": "rg-fire"})
	defer resp2.Body.Close()
	require.Equalf(t, http.StatusPaymentRequired, resp2.StatusCode, "%s recycle gate should 402", resourceType)
	assert.Equal(t, "free_tier_recycle_requires_claim", body2.Error)
}

func TestAnonRecycleGate_Cache(t *testing.T) { recycleGateOnce(t, "/cache/new", "10.214.0.1", "redis") }
func TestAnonRecycleGate_NoSQL(t *testing.T) { recycleGateOnce(t, "/nosql/new", "10.215.0.1", "mongodb") }
func TestAnonRecycleGate_Queue(t *testing.T) { recycleGateOnce(t, "/queue/new", "10.216.0.1", "queue") }

// TestAnonRecycleGate_DB covers the API-7 (QA 2026-05-29) reorder: the recycle
// gate now fires from the EARLIER position in NewDB (before checkProvisionLimit),
// so a fresh fingerprint with a planted recycle marker and zero active rows
// must still 402 free_tier_recycle_requires_claim on the /db/new path. Pinned
// here rather than in redis_fault_provarms_test.go because that test depends
// on a live postgres-customers backend (which the coverage CI job doesn't
// provide); the gRPC fixture's fakeProvisioner is good enough since recycleGate
// fires BEFORE any backend dispatch.
func TestAnonRecycleGate_DB(t *testing.T) {
	fake := &fakeProvisioner{}
	fx := setupGRPCProvFixture(t, fake, false)

	ip := "10.217.0.1"
	// Plant a recycle marker for the fingerprint this IP will produce and
	// ensure zero active rows. We do NOT need to provision first to learn the
	// fingerprint — the middleware computes it the same way every request, so
	// we can plant by replicating the exact fingerprint calc OR by using a
	// throwaway provision to discover it (mirrors recycleGateOnce above).
	resp, body := doProvisionKeyed(t, fx, "/cache/new", ip, "", uuid.NewString(),
		map[string]any{"name": "rg-db-probe"})
	resp.Body.Close()
	require.Equal(t, http.StatusCreated, resp.StatusCode)

	var fp string
	require.NoError(t, fx.db.QueryRowContext(context.Background(),
		`SELECT fingerprint FROM resources WHERE token = $1::uuid`, body.Token).Scan(&fp))
	_, err := fx.db.ExecContext(context.Background(),
		`UPDATE resources SET status = 'deleted' WHERE fingerprint = $1`, fp)
	require.NoError(t, err)
	require.NoError(t, fx.rdb.Set(context.Background(),
		handlers.RecycleSeenKeyPrefix+fp, "1", time.Hour).Err())

	// Next /db/new from the same IP must 402 from the EARLY recycle gate.
	resp2, body2 := doProvisionKeyed(t, fx, "/db/new", ip, "", uuid.NewString(),
		map[string]any{"name": "rg-db-fire"})
	defer resp2.Body.Close()
	require.Equal(t, http.StatusPaymentRequired, resp2.StatusCode,
		"/db/new recycle gate must 402 (early-gate API-7 reorder)")
	assert.Equal(t, "free_tier_recycle_requires_claim", body2.Error)
}

// dedupDecryptFailOnce: provision 5 of a type, corrupt the row's stored
// connection_url, force over-cap, and assert the 6th over-cap call hits the
// dedup branch, fails to decrypt, and provisions FRESH (never returns
// ciphertext). Covers the dedup decrypt-fail fallthrough for cache/nosql/queue.
func dedupDecryptFailOnce(t *testing.T, path, ip, resourceType string) {
	t.Helper()
	fake := &fakeProvisioner{}
	fx := setupGRPCProvFixture(t, fake, false)

	var firstToken string
	for i := 0; i < 5; i++ {
		resp, body := doProvisionKeyed(t, fx, path, ip, "", uuid.NewString(), map[string]any{"name": "ddf"})
		resp.Body.Close()
		require.Equalf(t, http.StatusCreated, resp.StatusCode, "%s call %d", path, i+1)
		if i == 0 {
			firstToken = body.Token
		}
	}
	_, err := fx.db.ExecContext(context.Background(), `
		UPDATE resources SET connection_url = 'not-decryptable'
		WHERE resource_type = $1 AND status = 'active' AND team_id IS NULL
		  AND fingerprint = (SELECT fingerprint FROM resources WHERE token = $2::uuid)
	`, resourceType, firstToken)
	require.NoError(t, err)

	resp, body := doProvisionKeyed(t, fx, path, ip, "", uuid.NewString(), map[string]any{"name": "ddf-6"})
	defer resp.Body.Close()
	require.Equalf(t, http.StatusCreated, resp.StatusCode, "%s decrypt-fail dedup must provision fresh", path)
	assert.NotContains(t, body.ConnectionURL, "not-decryptable")
}

func TestAnonDedupDecryptFail_Cache(t *testing.T) { dedupDecryptFailOnce(t, "/cache/new", "10.217.0.1", "redis") }
func TestAnonDedupDecryptFail_NoSQL(t *testing.T) { dedupDecryptFailOnce(t, "/nosql/new", "10.218.0.1", "mongodb") }
func TestAnonDedupDecryptFail_Queue(t *testing.T) { dedupDecryptFailOnce(t, "/queue/new", "10.219.0.1", "queue") }
