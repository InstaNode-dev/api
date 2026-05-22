package handlers_test

// coverage_provisioner_grpc_faults_test.go — fault-injection + authenticated
// edge-branch coverage for the gRPC-provisioner arms, building on the bufconn
// fake provisioner from coverage_provisioner_grpc_test.go.
//
// Drives:
//   - queue per-tier count cap (402 queue_limit_reached)
//   - queue dedicated tier-gate (402) + dedicated growth success
//   - authenticated gRPC provision error (503) for cache/nosql/queue
//   - anon dedup with a corrupted stored ciphertext (decrypt-fail → fresh)
//   - CreateResource hard failure via a closed *sql.DB (503 provision_failed)

import (
	"context"
	"database/sql"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"instant.dev/internal/testhelpers"
)

// ── Queue per-tier count cap ───────────────────────────────────────────────

func TestGRPCQueue_CountCap_Returns402(t *testing.T) {
	fake := &fakeProvisioner{}
	fx := setupGRPCProvFixture(t, fake, false)
	teamID := testhelpers.MustCreateTeamDB(t, fx.db, "hobby") // queue_count = 3
	jwt := authSessionJWT(t, fx.db, teamID)

	// Provision 3 queues (the hobby cap), each with a distinct idempotency key.
	for i := 0; i < 3; i++ {
		resp, body := doProvisionKeyed(t, fx, "/queue/new", "10.100.0.1", jwt, uuid.NewString(),
			map[string]any{"name": "cap-q"})
		resp.Body.Close()
		require.Equal(t, http.StatusCreated, resp.StatusCode, "queue %d should provision", i+1)
		require.True(t, body.OK)
	}
	// 4th over the cap → 402 queue_limit_reached.
	resp, body := doProvisionKeyed(t, fx, "/queue/new", "10.100.0.1", jwt, uuid.NewString(),
		map[string]any{"name": "cap-q-over"})
	defer resp.Body.Close()
	require.Equal(t, http.StatusPaymentRequired, resp.StatusCode)
	assert.Equal(t, "queue_limit_reached", body.Error)
}

// ── Queue dedicated tier-gate + growth success ─────────────────────────────

func TestGRPCQueue_Dedicated_NonGrowth_Returns402(t *testing.T) {
	fake := &fakeProvisioner{}
	fx := setupGRPCProvFixture(t, fake, false)
	teamID := testhelpers.MustCreateTeamDB(t, fx.db, "pro")
	jwt := authSessionJWT(t, fx.db, teamID)

	resp, body := doProvision(t, fx, "/queue/new", "10.101.0.1", jwt,
		map[string]any{"name": "q-ded", "dedicated": true})
	defer resp.Body.Close()
	require.Equal(t, http.StatusPaymentRequired, resp.StatusCode)
	assert.Equal(t, "upgrade_required", body.Error)
}

func TestGRPCQueue_Dedicated_Growth_Success(t *testing.T) {
	fake := &fakeProvisioner{}
	fx := setupGRPCProvFixture(t, fake, false)
	teamID := testhelpers.MustCreateTeamDB(t, fx.db, "growth")
	jwt := authSessionJWT(t, fx.db, teamID)

	resp, body := doProvision(t, fx, "/queue/new", "10.102.0.1", jwt,
		map[string]any{"name": "q-ded-ok", "dedicated": true})
	defer resp.Body.Close()
	require.Equal(t, http.StatusCreated, resp.StatusCode)
	assert.Equal(t, "growth", body.Tier)
}

// ── Authenticated gRPC provision error → 503 for cache/nosql/queue ─────────

func TestGRPCCache_Authenticated_GRPCError_Returns503(t *testing.T) {
	fake := &fakeProvisioner{failProvision: true}
	fx := setupGRPCProvFixture(t, fake, false)
	teamID := testhelpers.MustCreateTeamDB(t, fx.db, "pro")
	jwt := authSessionJWT(t, fx.db, teamID)

	resp, body := doProvision(t, fx, "/cache/new", "10.103.0.1", jwt, map[string]any{"name": "c-auth-fail"})
	defer resp.Body.Close()
	require.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
	assert.Equal(t, "provision_failed", body.Error)
}

func TestGRPCNoSQL_Authenticated_GRPCError_Returns503(t *testing.T) {
	fake := &fakeProvisioner{failProvision: true}
	fx := setupGRPCProvFixture(t, fake, false)
	teamID := testhelpers.MustCreateTeamDB(t, fx.db, "pro")
	jwt := authSessionJWT(t, fx.db, teamID)

	resp, body := doProvision(t, fx, "/nosql/new", "10.104.0.1", jwt, map[string]any{"name": "m-auth-fail"})
	defer resp.Body.Close()
	require.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
	assert.Equal(t, "provision_failed", body.Error)
}

func TestGRPCQueue_Authenticated_GRPCError_Returns503(t *testing.T) {
	fake := &fakeProvisioner{failProvision: true}
	fx := setupGRPCProvFixture(t, fake, false)
	teamID := testhelpers.MustCreateTeamDB(t, fx.db, "pro")
	jwt := authSessionJWT(t, fx.db, teamID)

	resp, body := doProvision(t, fx, "/queue/new", "10.105.0.1", jwt, map[string]any{"name": "q-auth-fail"})
	defer resp.Body.Close()
	require.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
	assert.Equal(t, "provision_failed", body.Error)
}

// ── Authenticated cache/nosql persist failure (bad AES) → 503 + deprovision ─

func TestGRPCCache_Authenticated_PersistFailure_Returns503(t *testing.T) {
	fake := &fakeProvisioner{}
	fx := setupGRPCProvFixture(t, fake, true) // bad AES key
	teamID := testhelpers.MustCreateTeamDB(t, fx.db, "pro")
	jwt := authSessionJWT(t, fx.db, teamID)

	resp, body := doProvision(t, fx, "/cache/new", "10.106.0.1", jwt, map[string]any{"name": "c-auth-persist"})
	defer resp.Body.Close()
	require.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
	assert.Equal(t, "provision_failed", body.Error)
	assert.GreaterOrEqual(t, fake.deprovisionCount(), 1)
}

func TestGRPCQueue_Authenticated_PersistFailure_Returns503(t *testing.T) {
	fake := &fakeProvisioner{}
	fx := setupGRPCProvFixture(t, fake, true)
	teamID := testhelpers.MustCreateTeamDB(t, fx.db, "pro")
	jwt := authSessionJWT(t, fx.db, teamID)

	resp, body := doProvision(t, fx, "/queue/new", "10.107.0.1", jwt, map[string]any{"name": "q-auth-persist"})
	defer resp.Body.Close()
	require.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
	assert.Equal(t, "provision_failed", body.Error)
	assert.GreaterOrEqual(t, fake.deprovisionCount(), 1)
}

// ── Anon dedup with corrupted stored ciphertext → decrypt-fail → fresh ─────
//
// Seed an active anonymous row whose connection_url is non-empty but NOT valid
// AES ciphertext, set the fingerprint counter over cap, then provision: the
// dedup branch hits decryptConnectionURL → (_, false) and falls through to a
// fresh provision (the gRPC fake supplies a usable URL).

func TestGRPCDB_AnonDedup_DecryptFailure_FallsThrough(t *testing.T) {
	fake := &fakeProvisioner{}
	fx := setupGRPCProvFixture(t, fake, false)

	ip := "10.110.0.1"
	// Provision once so the fingerprint has a real row + the recycle marker.
	resp0, _ := doProvisionKeyed(t, fx, "/db/new", ip, "", uuid.NewString(), map[string]any{"name": "decryptfail-seed"})
	resp0.Body.Close()
	require.Equal(t, http.StatusCreated, resp0.StatusCode)

	// Corrupt the stored connection_url on the most-recent row for this
	// fingerprint so the dedup decrypt fails.
	_, err := fx.db.ExecContext(context.Background(),
		`UPDATE resources SET connection_url = 'not-valid-ciphertext'
		 WHERE fingerprint = (SELECT fingerprint FROM resources WHERE name = 'decryptfail-seed' LIMIT 1)
		   AND resource_type = 'postgres' AND status = 'active'`)
	require.NoError(t, err)

	// Push the fingerprint over the cap (5) so the next call enters the
	// limitExceeded → dedup branch. Distinct idempotency keys per call.
	for i := 0; i < 5; i++ {
		r, _ := doProvisionKeyed(t, fx, "/db/new", ip, "", uuid.NewString(), map[string]any{"name": "decryptfail-fill"})
		r.Body.Close()
	}
	// Over-cap call: dedup decrypt fails on the corrupted row → falls through.
	// The response is either a fresh 201 or a dedup 200 onto a non-corrupted
	// row; either way the connection_url must be usable (never the ciphertext).
	resp, body := doProvisionKeyed(t, fx, "/db/new", ip, "", uuid.NewString(), map[string]any{"name": "decryptfail-final"})
	defer resp.Body.Close()
	require.True(t, body.OK)
	assert.NotEqual(t, "not-valid-ciphertext", body.ConnectionURL)
}

// ── CreateResource hard failure via a closed DB → 503 provision_failed ─────
//
// Closing the *sql.DB after fixture setup makes models.CreateResource fail, so
// the anonymous-path CreateResource error branch (provision_failed) runs.

func TestGRPCDB_Anonymous_CreateResourceFailure_Returns503(t *testing.T) {
	fake := &fakeProvisioner{}
	fx := setupGRPCProvFixture(t, fake, false)

	// Close the platform DB so CreateResource errors.
	require.NoError(t, closeUnderlying(fx.db))

	resp, body := doProvision(t, fx, "/db/new", "10.120.0.1", "", map[string]any{"name": "createfail"})
	defer resp.Body.Close()
	// Either provision_failed (CreateResource err) or another 5xx — assert 503.
	require.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
	assert.NotEmpty(t, body.Error)
}

// closeUnderlying closes the *sql.DB so subsequent queries fail.
func closeUnderlying(db *sql.DB) error { return db.Close() }

// ── Resource Delete via gRPC provisioner (deprovision path) ────────────────
//
// Provision a real (authenticated) resource through the fixture, then DELETE it
// — the Delete handler's default arm calls provisioner.DeprovisionResource
// against the bufconn fake (the non-nil-provisioner branch in resource.go).

func TestGRPCResource_Delete_DeprovisionsViaGRPC(t *testing.T) {
	fake := &fakeProvisioner{}
	fx := setupGRPCProvFixture(t, fake, false)
	teamID := testhelpers.MustCreateTeamDB(t, fx.db, "pro")
	jwt := authSessionJWT(t, fx.db, teamID)

	// Provision an authenticated postgres resource.
	resp, body := doProvision(t, fx, "/db/new", "10.140.0.1", jwt, map[string]any{"name": "del-db"})
	resp.Body.Close()
	require.Equal(t, http.StatusCreated, resp.StatusCode)
	require.NotEmpty(t, body.Token)

	before := fake.deprovisionCount()

	// DELETE /api/v1/resources/:token
	req := httptest.NewRequest(http.MethodDelete, "/api/v1/resources/"+body.Token, nil)
	req.Header.Set("Authorization", "Bearer "+jwt)
	delResp, err := fx.app.Test(req, 15000)
	require.NoError(t, err)
	defer delResp.Body.Close()
	require.Equal(t, http.StatusOK, delResp.StatusCode)
	assert.Greater(t, fake.deprovisionCount(), before,
		"Delete must call provisioner.DeprovisionResource via the gRPC client")
}

func TestGRPCResource_Get_AfterProvision(t *testing.T) {
	fake := &fakeProvisioner{}
	fx := setupGRPCProvFixture(t, fake, false)
	teamID := testhelpers.MustCreateTeamDB(t, fx.db, "pro")
	jwt := authSessionJWT(t, fx.db, teamID)

	resp, body := doProvision(t, fx, "/db/new", "10.141.0.1", jwt, map[string]any{"name": "get-db"})
	resp.Body.Close()
	require.Equal(t, http.StatusCreated, resp.StatusCode)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/resources/"+body.Token, nil)
	req.Header.Set("Authorization", "Bearer "+jwt)
	getResp, err := fx.app.Test(req, 15000)
	require.NoError(t, err)
	defer getResp.Body.Close()
	require.Equal(t, http.StatusOK, getResp.StatusCode)
}

func TestGRPCResource_Delete_CrossTeam_404(t *testing.T) {
	fake := &fakeProvisioner{}
	fx := setupGRPCProvFixture(t, fake, false)
	ownerTeam := testhelpers.MustCreateTeamDB(t, fx.db, "pro")
	ownerJWT := authSessionJWT(t, fx.db, ownerTeam)
	resp, body := doProvision(t, fx, "/db/new", "10.142.0.1", ownerJWT, map[string]any{"name": "xt-db"})
	resp.Body.Close()
	require.Equal(t, http.StatusCreated, resp.StatusCode)

	// A different team tries to delete it → 404 (never confirm existence).
	otherTeam := testhelpers.MustCreateTeamDB(t, fx.db, "pro")
	otherJWT := authSessionJWT(t, fx.db, otherTeam)
	req := httptest.NewRequest(http.MethodDelete, "/api/v1/resources/"+body.Token, nil)
	req.Header.Set("Authorization", "Bearer "+otherJWT)
	delResp, err := fx.app.Test(req, 15000)
	require.NoError(t, err)
	defer delResp.Body.Close()
	require.Equal(t, http.StatusNotFound, delResp.StatusCode)
}

func TestGRPCResource_Delete_BadUUID_400(t *testing.T) {
	fake := &fakeProvisioner{}
	fx := setupGRPCProvFixture(t, fake, false)
	teamID := testhelpers.MustCreateTeamDB(t, fx.db, "pro")
	jwt := authSessionJWT(t, fx.db, teamID)

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/resources/not-a-uuid", nil)
	req.Header.Set("Authorization", "Bearer "+jwt)
	delResp, err := fx.app.Test(req, 15000)
	require.NoError(t, err)
	defer delResp.Body.Close()
	require.Equal(t, http.StatusBadRequest, delResp.StatusCode)
}

func TestGRPCResource_Delete_NotFound_404(t *testing.T) {
	fake := &fakeProvisioner{}
	fx := setupGRPCProvFixture(t, fake, false)
	teamID := testhelpers.MustCreateTeamDB(t, fx.db, "pro")
	jwt := authSessionJWT(t, fx.db, teamID)

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/resources/"+uuid.NewString(), nil)
	req.Header.Set("Authorization", "Bearer "+jwt)
	delResp, err := fx.app.Test(req, 15000)
	require.NoError(t, err)
	defer delResp.Body.Close()
	require.Equal(t, http.StatusNotFound, delResp.StatusCode)
}

// ── DB dedicated growth success + authenticated persist failure ────────────

func TestGRPCDB_Dedicated_Growth_Success(t *testing.T) {
	fake := &fakeProvisioner{}
	fx := setupGRPCProvFixture(t, fake, false)
	teamID := testhelpers.MustCreateTeamDB(t, fx.db, "growth")
	jwt := authSessionJWT(t, fx.db, teamID)

	resp, body := doProvision(t, fx, "/db/new", "10.130.0.1", jwt,
		map[string]any{"name": "db-ded-ok", "dedicated": true})
	defer resp.Body.Close()
	require.Equal(t, http.StatusCreated, resp.StatusCode)
	assert.Equal(t, "growth", body.Tier)
}

func TestGRPCDB_Authenticated_PersistFailure_Returns503(t *testing.T) {
	fake := &fakeProvisioner{}
	fx := setupGRPCProvFixture(t, fake, true) // bad AES key
	teamID := testhelpers.MustCreateTeamDB(t, fx.db, "pro")
	jwt := authSessionJWT(t, fx.db, teamID)

	resp, body := doProvision(t, fx, "/db/new", "10.131.0.1", jwt, map[string]any{"name": "db-auth-persist"})
	defer resp.Body.Close()
	require.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
	assert.Equal(t, "provision_failed", body.Error)
	assert.GreaterOrEqual(t, fake.deprovisionCount(), 1)
}

func TestGRPCNoSQL_Authenticated_PersistFailure_Returns503(t *testing.T) {
	fake := &fakeProvisioner{}
	fx := setupGRPCProvFixture(t, fake, true)
	teamID := testhelpers.MustCreateTeamDB(t, fx.db, "pro")
	jwt := authSessionJWT(t, fx.db, teamID)

	resp, body := doProvision(t, fx, "/nosql/new", "10.132.0.1", jwt, map[string]any{"name": "m-auth-persist"})
	defer resp.Body.Close()
	require.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
	assert.Equal(t, "provision_failed", body.Error)
	assert.GreaterOrEqual(t, fake.deprovisionCount(), 1)
}

// ── Cross-service daily-cap fallback → 429 provision_limit_reached ─────────
//
// Fill the cap with 5 cache provisions (distinct idem keys), then request a DB
// from the SAME fingerprint: over cap, no postgres row exists but a redis row
// does → cross-service fallback fires a 429.

func TestGRPCCrossServiceCap_Returns429(t *testing.T) {
	fake := &fakeProvisioner{}
	fx := setupGRPCProvFixture(t, fake, false)
	ip := "10.133.0.1"
	for i := 0; i < 5; i++ {
		r, _ := doProvisionKeyed(t, fx, "/cache/new", ip, "", uuid.NewString(), map[string]any{"name": "xcap-cache"})
		r.Body.Close()
	}
	// 6th call, postgres, same fingerprint: over cap, no postgres row but a
	// redis row exists → 429 provision_limit_reached.
	resp, body := doProvisionKeyed(t, fx, "/db/new", ip, "", uuid.NewString(), map[string]any{"name": "xcap-db"})
	defer resp.Body.Close()
	require.Equal(t, http.StatusTooManyRequests, resp.StatusCode)
	assert.Equal(t, "provision_limit_reached", body.Error)
}
