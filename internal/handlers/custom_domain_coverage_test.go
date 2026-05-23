package handlers_test

// custom_domain_coverage_test.go — hermetic end-to-end coverage for the
// custom-domain handler (custom_domain.go). The handler is DB + a stubbed
// CustomDomainProvider (interface); no live k8s is needed. The existing
// custom_domain_test.go only exercises the tier-cap arms of Create — this file
// drives List / Verify (ingress + cert + failure arms) / Delete plus the
// validation + ownership helpers, all against the real test DB.

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"instant.dev/internal/config"
	"instant.dev/internal/handlers"
	"instant.dev/internal/middleware"
	"instant.dev/internal/models"
	"instant.dev/internal/plans"
	"instant.dev/internal/testhelpers"
)

// stubCustomDomainProvider implements handlers.CustomDomainProvider with
// programmable outcomes so the ingress / cert arms of Verify are reachable
// without a live cluster.
type stubCustomDomainProvider struct {
	ensureURL    string
	ensureErr    error
	deleteErr    error
	certReady    bool
	certMsg      string
	certErr      error
	ensureCalls  int
	deleteCalls  int
	certPolls    int
}

func (s *stubCustomDomainProvider) EnsureCustomDomainIngress(ctx context.Context, ns, host, svc string, port int) (string, error) {
	s.ensureCalls++
	return s.ensureURL, s.ensureErr
}
func (s *stubCustomDomainProvider) DeleteCustomDomainIngress(ctx context.Context, ns, host, svc string) error {
	s.deleteCalls++
	return s.deleteErr
}
func (s *stubCustomDomainProvider) CertificateReady(ctx context.Context, ns, certName string) (bool, string, error) {
	s.certPolls++
	return s.certReady, s.certMsg, s.certErr
}

func customDomainFullApp(t *testing.T, db *sql.DB, teamID uuid.UUID, prov handlers.CustomDomainProvider) *fiber.App {
	t.Helper()
	app := fiber.New(fiber.Config{
		ErrorHandler: func(c *fiber.Ctx, err error) error {
			if errors.Is(err, handlers.ErrResponseWritten) {
				return nil
			}
			code := fiber.StatusInternalServerError
			if e, ok := err.(*fiber.Error); ok {
				code = e.Code
			}
			return c.Status(code).JSON(fiber.Map{"ok": false, "error": "internal_error", "message": err.Error()})
		},
	})
	app.Use(middleware.RequestID())
	app.Use(func(c *fiber.Ctx) error {
		c.Locals(middleware.LocalKeyTeamID, teamID.String())
		c.Locals(middleware.LocalKeyUserID, uuid.NewString())
		return c.Next()
	})
	cfg := &config.Config{}
	h := handlers.NewCustomDomainHandler(db, cfg, plans.Default(), prov)
	app.Post("/api/v1/stacks/:slug/domains", h.Create)
	app.Get("/api/v1/stacks/:slug/domains", h.List)
	app.Post("/api/v1/stacks/:slug/domains/:id/verify", h.Verify)
	app.Delete("/api/v1/stacks/:slug/domains/:id", h.Delete)
	return app
}

// seedTeamWithTier inserts a team at the given plan tier and returns its UUID.
func seedTeamWithTier(t *testing.T, db *sql.DB, tier string) uuid.UUID {
	t.Helper()
	id := testhelpers.MustCreateTeamDB(t, db, tier)
	return uuid.MustParse(id)
}

// cdSeedStackWithService creates a stack owned by teamID with one exposed
// service, and returns the slug + stack id.
func cdSeedStackWithService(t *testing.T, db *sql.DB, teamID uuid.UUID, expose bool) (slug string, stackID uuid.UUID) {
	t.Helper()
	slug = "cd-" + uuid.NewString()[:8]
	st, err := models.CreateStack(context.Background(), db, models.CreateStackParams{
		TeamID: &teamID, Slug: slug, Tier: "pro", Env: "production",
	})
	require.NoError(t, err)
	_, err = db.Exec(`INSERT INTO stack_services (stack_id, name, status, expose, port)
		VALUES ($1::uuid, 'web', 'healthy', $2, 8080)`, st.ID, expose)
	require.NoError(t, err)
	return slug, st.ID
}

func cdReq(t *testing.T, app *fiber.App, method, path, body string) *http.Response {
	t.Helper()
	var r io.Reader
	if body != "" {
		r = strings.NewReader(body)
	}
	req := httptest.NewRequest(method, path, r)
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	return resp
}

func TestCustomDomain_Create_HappyAndArms(t *testing.T) {
	db, clean := testhelpers.SetupTestDB(t)
	defer clean()
	teamID := seedTeamWithTier(t, db, "pro")
	app := customDomainFullApp(t, db, teamID, &stubCustomDomainProvider{})
	slug, _ := cdSeedStackWithService(t, db, teamID, true)

	// custom_domains.hostname is GLOBALLY unique, so use a per-run-unique
	// hostname to avoid colliding with a leftover row from a prior run or a
	// sibling test in the same package.
	host := cdUniqueHost(t)

	// Happy path.
	resp := cdReq(t, app, http.MethodPost, "/api/v1/stacks/"+slug+"/domains", `{"hostname":"`+host+`"}`)
	require.Equal(t, http.StatusCreated, resp.StatusCode)
	var created struct {
		Domain struct {
			ID     string `json:"id"`
			Status string `json:"status"`
		} `json:"domain"`
	}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&created))
	resp.Body.Close()
	require.NotEmpty(t, created.Domain.ID)
	assert.Equal(t, models.CustomDomainStatusPending, created.Domain.Status)

	// invalid_hostname (reserved suffix).
	resp = cdReq(t, app, http.MethodPost, "/api/v1/stacks/"+slug+"/domains", `{"hostname":"x.instanode.dev"}`)
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	resp.Body.Close()

	// invalid_hostname (no dot).
	resp = cdReq(t, app, http.MethodPost, "/api/v1/stacks/"+slug+"/domains", `{"hostname":"localhost"}`)
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	resp.Body.Close()

	// invalid_body.
	resp = cdReq(t, app, http.MethodPost, "/api/v1/stacks/"+slug+"/domains", `{bad`)
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	resp.Body.Close()

	// hostname_taken (re-create the same hostname).
	resp = cdReq(t, app, http.MethodPost, "/api/v1/stacks/"+slug+"/domains", `{"hostname":"`+host+`"}`)
	assert.Equal(t, http.StatusConflict, resp.StatusCode)
	resp.Body.Close()
}

// cdUniqueHost returns a globally-unique custom-domain hostname for a test run.
func cdUniqueHost(t *testing.T) string {
	t.Helper()
	return "h" + uuid.NewString()[:12] + ".example.com"
}

func TestCustomDomain_Create_UpgradeAndNotOwned(t *testing.T) {
	db, clean := testhelpers.SetupTestDB(t)
	defer clean()

	// Hobby tier → upgrade_required (feature gate).
	hobbyTeam := seedTeamWithTier(t, db, "hobby")
	app := customDomainFullApp(t, db, hobbyTeam, &stubCustomDomainProvider{})
	slug, _ := cdSeedStackWithService(t, db, hobbyTeam, true)
	resp := cdReq(t, app, http.MethodPost, "/api/v1/stacks/"+slug+"/domains", `{"hostname":"a.example.com"}`)
	assert.Equal(t, http.StatusPaymentRequired, resp.StatusCode)
	resp.Body.Close()

	// Pro team requesting a stack it does not own → 404.
	proTeam := seedTeamWithTier(t, db, "pro")
	otherTeam := seedTeamWithTier(t, db, "pro")
	appPro := customDomainFullApp(t, db, proTeam, &stubCustomDomainProvider{})
	foreignSlug, _ := cdSeedStackWithService(t, db, otherTeam, true)
	resp = cdReq(t, appPro, http.MethodPost, "/api/v1/stacks/"+foreignSlug+"/domains", `{"hostname":"b.example.com"}`)
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
	resp.Body.Close()

	// Unknown stack slug → 404.
	resp = cdReq(t, appPro, http.MethodPost, "/api/v1/stacks/nope/domains", `{"hostname":"c.example.com"}`)
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
	resp.Body.Close()
}

func TestCustomDomain_List(t *testing.T) {
	db, clean := testhelpers.SetupTestDB(t)
	defer clean()
	teamID := seedTeamWithTier(t, db, "pro")
	app := customDomainFullApp(t, db, teamID, &stubCustomDomainProvider{})
	slug, stackID := cdSeedStackWithService(t, db, teamID, true)
	_, err := models.CreateCustomDomain(context.Background(), db, teamID, stackID, cdUniqueHost(t))
	require.NoError(t, err)

	resp := cdReq(t, app, http.MethodGet, "/api/v1/stacks/"+slug+"/domains", "")
	require.Equal(t, http.StatusOK, resp.StatusCode)
	var listed struct {
		Total int `json:"total"`
	}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&listed))
	resp.Body.Close()
	assert.Equal(t, 1, listed.Total)
}

func TestCustomDomain_Verify_Arms(t *testing.T) {
	db, clean := testhelpers.SetupTestDB(t)
	defer clean()
	teamID := seedTeamWithTier(t, db, "pro")

	t.Run("pending_txt_missing_returns_200", func(t *testing.T) {
		app := customDomainFullApp(t, db, teamID, &stubCustomDomainProvider{})
		slug, stackID := cdSeedStackWithService(t, db, teamID, true)
		// Use a .invalid TLD so the real resolver fails fast (no TXT record).
		dom, err := models.CreateCustomDomain(context.Background(), db, teamID, stackID, "p"+cdUniqueHost(t)+".invalid")
		require.NoError(t, err)
		resp := cdReq(t, app, http.MethodPost, "/api/v1/stacks/"+slug+"/domains/"+dom.ID.String()+"/verify", "")
		// TXT lookup fails → still 200 with the failure recorded.
		assert.Equal(t, http.StatusOK, resp.StatusCode)
		resp.Body.Close()
	})

	t.Run("verified_no_k8s_terminal", func(t *testing.T) {
		app := customDomainFullApp(t, db, teamID, nil) // nil provider
		slug, stackID := cdSeedStackWithService(t, db, teamID, true)
		dom, err := models.CreateCustomDomain(context.Background(), db, teamID, stackID, cdUniqueHost(t))
		require.NoError(t, err)
		require.NoError(t, models.MarkCustomDomainVerified(context.Background(), db, dom.ID))
		resp := cdReq(t, app, http.MethodPost, "/api/v1/stacks/"+slug+"/domains/"+dom.ID.String()+"/verify", "")
		assert.Equal(t, http.StatusOK, resp.StatusCode)
		resp.Body.Close()
	})

	t.Run("verified_ingress_then_cert_ready", func(t *testing.T) {
		prov := &stubCustomDomainProvider{ensureURL: "https://ingress", certReady: true}
		app := customDomainFullApp(t, db, teamID, prov)
		slug, stackID := cdSeedStackWithService(t, db, teamID, true)
		dom, err := models.CreateCustomDomain(context.Background(), db, teamID, stackID, cdUniqueHost(t))
		require.NoError(t, err)
		require.NoError(t, models.MarkCustomDomainVerified(context.Background(), db, dom.ID))
		resp := cdReq(t, app, http.MethodPost, "/api/v1/stacks/"+slug+"/domains/"+dom.ID.String()+"/verify", "")
		require.Equal(t, http.StatusOK, resp.StatusCode)
		resp.Body.Close()
		assert.GreaterOrEqual(t, prov.ensureCalls, 1)
		assert.GreaterOrEqual(t, prov.certPolls, 1)
		// Row should be cert_ready now.
		got, err := models.GetCustomDomainByID(context.Background(), db, dom.ID)
		require.NoError(t, err)
		assert.Equal(t, models.CustomDomainStatusCertReady, got.Status)
	})

	t.Run("verified_ingress_error_soft_fails", func(t *testing.T) {
		prov := &stubCustomDomainProvider{ensureErr: errors.New("ingress boom")}
		app := customDomainFullApp(t, db, teamID, prov)
		slug, stackID := cdSeedStackWithService(t, db, teamID, true)
		dom, err := models.CreateCustomDomain(context.Background(), db, teamID, stackID, cdUniqueHost(t))
		require.NoError(t, err)
		require.NoError(t, models.MarkCustomDomainVerified(context.Background(), db, dom.ID))
		resp := cdReq(t, app, http.MethodPost, "/api/v1/stacks/"+slug+"/domains/"+dom.ID.String()+"/verify", "")
		assert.Equal(t, http.StatusOK, resp.StatusCode)
		resp.Body.Close()
	})

	t.Run("verified_no_exposed_service_soft_fails", func(t *testing.T) {
		prov := &stubCustomDomainProvider{}
		app := customDomainFullApp(t, db, teamID, prov)
		slug, stackID := cdSeedStackWithService(t, db, teamID, false) // no exposed svc
		dom, err := models.CreateCustomDomain(context.Background(), db, teamID, stackID, cdUniqueHost(t))
		require.NoError(t, err)
		require.NoError(t, models.MarkCustomDomainVerified(context.Background(), db, dom.ID))
		resp := cdReq(t, app, http.MethodPost, "/api/v1/stacks/"+slug+"/domains/"+dom.ID.String()+"/verify", "")
		assert.Equal(t, http.StatusOK, resp.StatusCode)
		resp.Body.Close()
	})

	t.Run("invalid_domain_id", func(t *testing.T) {
		app := customDomainFullApp(t, db, teamID, &stubCustomDomainProvider{})
		slug, _ := cdSeedStackWithService(t, db, teamID, true)
		resp := cdReq(t, app, http.MethodPost, "/api/v1/stacks/"+slug+"/domains/not-a-uuid/verify", "")
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
		resp.Body.Close()
	})

	t.Run("domain_not_found", func(t *testing.T) {
		app := customDomainFullApp(t, db, teamID, &stubCustomDomainProvider{})
		slug, _ := cdSeedStackWithService(t, db, teamID, true)
		resp := cdReq(t, app, http.MethodPost, "/api/v1/stacks/"+slug+"/domains/"+uuid.NewString()+"/verify", "")
		assert.Equal(t, http.StatusNotFound, resp.StatusCode)
		resp.Body.Close()
	})
}

func TestCustomDomain_Delete(t *testing.T) {
	db, clean := testhelpers.SetupTestDB(t)
	defer clean()
	teamID := seedTeamWithTier(t, db, "pro")
	prov := &stubCustomDomainProvider{}
	app := customDomainFullApp(t, db, teamID, prov)
	slug, stackID := cdSeedStackWithService(t, db, teamID, true)
	dom, err := models.CreateCustomDomain(context.Background(), db, teamID, stackID, cdUniqueHost(t))
	require.NoError(t, err)

	resp := cdReq(t, app, http.MethodDelete, "/api/v1/stacks/"+slug+"/domains/"+dom.ID.String(), "")
	require.Equal(t, http.StatusOK, resp.StatusCode)
	resp.Body.Close()
	assert.GreaterOrEqual(t, prov.deleteCalls, 1)

	// Row gone → second delete 404s.
	resp = cdReq(t, app, http.MethodDelete, "/api/v1/stacks/"+slug+"/domains/"+dom.ID.String(), "")
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
	resp.Body.Close()
}
