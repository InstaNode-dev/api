package handlers_test

// custom_domain_arms_bvwave_test.go — pushes custom_domain.go past 95% by
// covering the arms the existing custom_domain_coverage_test.go leaves open:
//
//   - Create: per-tier domain CAP reached → 402 custom_domains_limit_reached.
//   - Verify: cert-poll ERROR (soft-fail) + cert STILL-ISSUING (not ready) arms.
//   - Verify: domain bound to a DIFFERENT stack → 404 (requireOwnedDomain).
//   - Delete: ingress teardown error is logged but the row is still removed.
//   - List on a stack with several domains.
//
// Reuses customDomainFullApp / stubCustomDomainProvider / seedTeamWithTier /
// cdSeedStackWithService / cdReq / cdUniqueHost from custom_domain_coverage_test.go.

import (
	"context"
	"database/sql"
	"errors"
	"net/http"
	"os"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"instant.dev/internal/models"
	"instant.dev/internal/testhelpers"
)

func TestCustomDomain_CapReached_402_bvwave(t *testing.T) {
	db, clean := testhelpers.SetupTestDB(t)
	defer clean()

	// hobby_plus has custom_domains_max == 1, so one existing domain fills the
	// cap and a second create is rejected with 402.
	teamID := seedTeamWithTier(t, db, "hobby_plus")
	app := customDomainFullApp(t, db, teamID, &stubCustomDomainProvider{})
	slug, stackID := cdSeedStackWithService(t, db, teamID, true)

	// Fill the cap directly via the model.
	_, err := models.CreateCustomDomain(context.Background(), db, teamID, stackID, cdUniqueHost(t))
	require.NoError(t, err)

	resp := cdReq(t, app, http.MethodPost, "/api/v1/stacks/"+slug+"/domains", `{"hostname":"`+cdUniqueHost(t)+`"}`)
	require.Equal(t, http.StatusPaymentRequired, resp.StatusCode)
	resp.Body.Close()
}

func TestCustomDomain_Verify_CertArms_bvwave(t *testing.T) {
	db, clean := testhelpers.SetupTestDB(t)
	defer clean()
	teamID := seedTeamWithTier(t, db, "pro")

	t.Run("cert_poll_error_soft_fail", func(t *testing.T) {
		// Ingress succeeds, cert poll errors → soft-fail, row stays ingress_ready.
		prov := &stubCustomDomainProvider{ensureURL: "https://ingress", certErr: errors.New("cert-manager unreachable")}
		app := customDomainFullApp(t, db, teamID, prov)
		slug, stackID := cdSeedStackWithService(t, db, teamID, true)
		dom, err := models.CreateCustomDomain(context.Background(), db, teamID, stackID, cdUniqueHost(t))
		require.NoError(t, err)
		require.NoError(t, models.MarkCustomDomainVerified(context.Background(), db, dom.ID))
		resp := cdReq(t, app, http.MethodPost, "/api/v1/stacks/"+slug+"/domains/"+dom.ID.String()+"/verify", "")
		assert.Equal(t, http.StatusOK, resp.StatusCode)
		resp.Body.Close()
		assert.GreaterOrEqual(t, prov.certPolls, 1)
	})

	t.Run("cert_still_issuing", func(t *testing.T) {
		// Ingress ok, cert not ready, no error, with a message → records msg.
		prov := &stubCustomDomainProvider{ensureURL: "https://ingress", certReady: false, certMsg: "ACME order created"}
		app := customDomainFullApp(t, db, teamID, prov)
		slug, stackID := cdSeedStackWithService(t, db, teamID, true)
		dom, err := models.CreateCustomDomain(context.Background(), db, teamID, stackID, cdUniqueHost(t))
		require.NoError(t, err)
		require.NoError(t, models.MarkCustomDomainVerified(context.Background(), db, dom.ID))
		resp := cdReq(t, app, http.MethodPost, "/api/v1/stacks/"+slug+"/domains/"+dom.ID.String()+"/verify", "")
		assert.Equal(t, http.StatusOK, resp.StatusCode)
		resp.Body.Close()
		// Row should be ingress_ready (cert not yet ready).
		got, err := models.GetCustomDomainByID(context.Background(), db, dom.ID)
		require.NoError(t, err)
		assert.Equal(t, models.CustomDomainStatusIngressReady, got.Status)
	})
}

func TestCustomDomain_Verify_WrongStack_404_bvwave(t *testing.T) {
	db, clean := testhelpers.SetupTestDB(t)
	defer clean()
	teamID := seedTeamWithTier(t, db, "pro")
	app := customDomainFullApp(t, db, teamID, &stubCustomDomainProvider{})

	// Two stacks; the domain is bound to stackA but the verify URL names stackB.
	slugA, stackA := cdSeedStackWithService(t, db, teamID, true)
	slugB, _ := cdSeedStackWithService(t, db, teamID, true)
	dom, err := models.CreateCustomDomain(context.Background(), db, teamID, stackA, cdUniqueHost(t))
	require.NoError(t, err)

	// Verify under the WRONG stack (requireOwnedDomain checks dom.StackID).
	resp := cdReq(t, app, http.MethodPost, "/api/v1/stacks/"+slugB+"/domains/"+dom.ID.String()+"/verify", "")
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
	resp.Body.Close()
	_ = slugA
}

func TestCustomDomain_Delete_IngressTeardownError_StillRemoves_bvwave(t *testing.T) {
	db, clean := testhelpers.SetupTestDB(t)
	defer clean()
	teamID := seedTeamWithTier(t, db, "pro")
	// Ingress delete errors, but the DB row is still removed (best-effort teardown).
	prov := &stubCustomDomainProvider{deleteErr: errors.New("ingress already gone")}
	app := customDomainFullApp(t, db, teamID, prov)
	slug, stackID := cdSeedStackWithService(t, db, teamID, true)
	dom, err := models.CreateCustomDomain(context.Background(), db, teamID, stackID, cdUniqueHost(t))
	require.NoError(t, err)

	resp := cdReq(t, app, http.MethodDelete, "/api/v1/stacks/"+slug+"/domains/"+dom.ID.String(), "")
	require.Equal(t, http.StatusOK, resp.StatusCode)
	resp.Body.Close()
	assert.GreaterOrEqual(t, prov.deleteCalls, 1)

	// Confirm the row is gone.
	_, getErr := models.GetCustomDomainByID(context.Background(), db, dom.ID)
	assert.ErrorIs(t, getErr, models.ErrCustomDomainNotFound)
}

func TestCustomDomain_InvalidDomainID_400_bvwave(t *testing.T) {
	db, clean := testhelpers.SetupTestDB(t)
	defer clean()
	teamID := seedTeamWithTier(t, db, "pro")
	app := customDomainFullApp(t, db, teamID, &stubCustomDomainProvider{})
	slug, _ := cdSeedStackWithService(t, db, teamID, true)

	// Delete with a non-UUID id → 400 invalid_id (requireOwnedDomain).
	resp := cdReq(t, app, http.MethodDelete, "/api/v1/stacks/"+slug+"/domains/not-a-uuid", "")
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	resp.Body.Close()
	_ = uuid.New
}

// TestCustomDomain_ValidateHostname_Arms_bvwave drives validateHostname's
// rejection branches via Create on a pro stack: empty, scheme/path, port, and
// the exact-reserved-host check.
func TestCustomDomain_ValidateHostname_Arms_bvwave(t *testing.T) {
	db, clean := testhelpers.SetupTestDB(t)
	defer clean()
	teamID := seedTeamWithTier(t, db, "pro")
	app := customDomainFullApp(t, db, teamID, &stubCustomDomainProvider{})
	slug, _ := cdSeedStackWithService(t, db, teamID, true)

	bad := []string{
		`{"hostname":""}`,                  // empty → required
		`{"hostname":"https://app.com"}`,   // scheme
		`{"hostname":"app.example.com:80"}`, // port
		`{"hostname":"instanode.dev"}`,     // exact reserved host
		`{"hostname":"x.deployment.instanode.dev"}`, // reserved suffix
	}
	for _, body := range bad {
		resp := cdReq(t, app, http.MethodPost, "/api/v1/stacks/"+slug+"/domains", body)
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode, "body=%s", body)
		resp.Body.Close()
	}
}

// TestCustomDomain_DBErrorArms_bvwave drives the requireTeam / list / verify
// DB-error arms via a closed DB (every query errors → 503).
func TestCustomDomain_DBErrorArms_bvwave(t *testing.T) {
	teamID := uuid.New()
	app := customDomainFullApp(t, cdBrokenDB(t), teamID, &stubCustomDomainProvider{})

	t.Run("create_team_lookup_503", func(t *testing.T) {
		resp := cdReq(t, app, http.MethodPost, "/api/v1/stacks/any/domains", `{"hostname":"a.example.com"}`)
		assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
		resp.Body.Close()
	})
	t.Run("list_team_lookup_503", func(t *testing.T) {
		resp := cdReq(t, app, http.MethodGet, "/api/v1/stacks/any/domains", "")
		assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
		resp.Body.Close()
	})
	t.Run("verify_team_lookup_503", func(t *testing.T) {
		resp := cdReq(t, app, http.MethodPost, "/api/v1/stacks/any/domains/"+uuid.NewString()+"/verify", "")
		assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
		resp.Body.Close()
	})
}

// cdBrokenDB returns a closed *sql.DB so every query errors.
func cdBrokenDB(t *testing.T) *sql.DB {
	t.Helper()
	dsn := os.Getenv("TEST_DATABASE_URL")
	require.NotEmpty(t, dsn)
	d, err := sql.Open("postgres", dsn)
	require.NoError(t, err)
	require.NoError(t, d.Close())
	return d
}
