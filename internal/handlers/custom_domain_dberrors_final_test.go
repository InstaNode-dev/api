package handlers_test

// custom_domain_dberrors_final_test.go — FINAL coverage pass for the
// custom_domain.go DB-error + auth-validation arms the bvwave/coverage slices
// leave open. Uses openFaultDB (staged failAfter) for the mid-handler 503 arms
// and a Locals-controlled app for the requireTeam unauthorized / invalid_team
// arms.

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
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

// cdAppWithLocals builds the custom-domain app with a caller-supplied team-id
// Locals value (may be "" or a non-UUID) so requireTeam's unauthorized /
// invalid_team arms can run.
func cdAppWithLocals(t *testing.T, db *sql.DB, teamIDLocal string, prov handlers.CustomDomainProvider) *fiber.App {
	t.Helper()
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
	})
	app.Use(middleware.RequestID())
	app.Use(func(c *fiber.Ctx) error {
		if teamIDLocal != "" {
			c.Locals(middleware.LocalKeyTeamID, teamIDLocal)
		}
		c.Locals(middleware.LocalKeyUserID, uuid.NewString())
		return c.Next()
	})
	h := handlers.NewCustomDomainHandler(db, &config.Config{}, plans.Default(), prov)
	app.Post("/api/v1/stacks/:slug/domains", h.Create)
	app.Get("/api/v1/stacks/:slug/domains", h.List)
	app.Post("/api/v1/stacks/:slug/domains/:id/verify", h.Verify)
	app.Delete("/api/v1/stacks/:slug/domains/:id", h.Delete)
	return app
}

// requireTeam: no team-id local → unauthorized (custom_domain.go:153).
func TestCDFinal_RequireTeam_Unauthorized_401(t *testing.T) {
	db, clean := testhelpers.SetupTestDB(t)
	defer clean()
	app := cdAppWithLocals(t, db, "", &stubCustomDomainProvider{})
	resp := cdReq(t, app, http.MethodGet, "/api/v1/stacks/any/domains", "")
	defer resp.Body.Close()
	require.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

// requireTeam: non-UUID team-id local → invalid_team (custom_domain.go:158).
func TestCDFinal_RequireTeam_InvalidTeam_400(t *testing.T) {
	db, clean := testhelpers.SetupTestDB(t)
	defer clean()
	app := cdAppWithLocals(t, db, "not-a-uuid", &stubCustomDomainProvider{})
	resp := cdReq(t, app, http.MethodGet, "/api/v1/stacks/any/domains", "")
	defer resp.Body.Close()
	require.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

// requireOwnedStack: GetStackBySlug errors (custom_domain.go:183). team(1)
// succeeds, stack lookup(2) errors. failAfter=1. List path.
func TestCDFinal_RequireOwnedStack_DBError_503(t *testing.T) {
	seedDB, clean := testhelpers.SetupTestDB(t)
	defer clean()
	teamID := seedTeamWithTier(t, seedDB, "pro")

	faultDB := openFaultDB(t, 1)
	app := cdAppWithLocals(t, faultDB, teamID.String(), &stubCustomDomainProvider{})
	resp := cdReq(t, app, http.MethodGet, "/api/v1/stacks/any/domains", "")
	defer resp.Body.Close()
	require.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
	assert.Equal(t, "fetch_failed", cdErrField(t, resp))
}

// List: ListCustomDomainsByStack errors (custom_domain.go:428). team(1) +
// stack(2) succeed (seeded on pooled DB), list(3) errors. failAfter=2.
func TestCDFinal_List_DBError_503(t *testing.T) {
	seedDB, clean := testhelpers.SetupTestDB(t)
	defer clean()
	teamID := seedTeamWithTier(t, seedDB, "pro")
	slug, _ := cdSeedStackWithService(t, seedDB, teamID, true)

	faultDB := openFaultDB(t, 2)
	app := cdAppWithLocals(t, faultDB, teamID.String(), &stubCustomDomainProvider{})
	resp := cdReq(t, app, http.MethodGet, "/api/v1/stacks/"+slug+"/domains", "")
	defer resp.Body.Close()
	require.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
	assert.Equal(t, "list_failed", cdErrField(t, resp))
}

// Create: ListCustomDomainsByTeam (the cap count) errors (custom_domain.go:351).
// team(1) + stack(2) succeed, the count query(3) errors. failAfter=2.
func TestCDFinal_Create_CountFailed_503(t *testing.T) {
	seedDB, clean := testhelpers.SetupTestDB(t)
	defer clean()
	teamID := seedTeamWithTier(t, seedDB, "pro")
	slug, _ := cdSeedStackWithService(t, seedDB, teamID, true)

	faultDB := openFaultDB(t, 2)
	app := cdAppWithLocals(t, faultDB, teamID.String(), &stubCustomDomainProvider{})
	resp := cdReq(t, app, http.MethodPost, "/api/v1/stacks/"+slug+"/domains",
		`{"hostname":"`+cdUniqueHost(t)+`"}`)
	defer resp.Body.Close()
	require.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
	assert.Equal(t, "count_failed", cdErrField(t, resp))
}

// Create: CreateCustomDomain errors (custom_domain.go:395). team(1) + stack(2)
// + count(3) succeed, the INSERT(4) errors. failAfter=3.
func TestCDFinal_Create_CreateFailed_503(t *testing.T) {
	seedDB, clean := testhelpers.SetupTestDB(t)
	defer clean()
	teamID := seedTeamWithTier(t, seedDB, "pro")
	slug, _ := cdSeedStackWithService(t, seedDB, teamID, true)

	faultDB := openFaultDB(t, 3)
	app := cdAppWithLocals(t, faultDB, teamID.String(), &stubCustomDomainProvider{})
	resp := cdReq(t, app, http.MethodPost, "/api/v1/stacks/"+slug+"/domains",
		`{"hostname":"`+cdUniqueHost(t)+`"}`)
	defer resp.Body.Close()
	require.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
	assert.Equal(t, "create_failed", cdErrField(t, resp))
}

// requireOwnedDomain: GetCustomDomainByID errors (custom_domain.go:209). Verify
// path: team(1) + stack(2) succeed, domain lookup(3) errors. failAfter=2.
func TestCDFinal_RequireOwnedDomain_DBError_503(t *testing.T) {
	seedDB, clean := testhelpers.SetupTestDB(t)
	defer clean()
	teamID := seedTeamWithTier(t, seedDB, "pro")
	slug, _ := cdSeedStackWithService(t, seedDB, teamID, true)

	faultDB := openFaultDB(t, 2)
	app := cdAppWithLocals(t, faultDB, teamID.String(), &stubCustomDomainProvider{})
	resp := cdReq(t, app, http.MethodPost,
		"/api/v1/stacks/"+slug+"/domains/"+uuid.NewString()+"/verify", "")
	defer resp.Body.Close()
	require.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
	assert.Equal(t, "fetch_failed", cdErrField(t, resp))
}

// Verify: MarkCustomDomainVerified errors after a TXT match (custom_domain.go:477).
// team(1) + stack(2) + domain-read(3) succeed; the MarkVerified UPDATE(4) errors.
// The TXT seam returns a match so the verify branch is entered. failAfter=3.
func TestCDFinal_Verify_MarkVerifiedFailed_503(t *testing.T) {
	seedDB, clean := testhelpers.SetupTestDB(t)
	defer clean()
	teamID := seedTeamWithTier(t, seedDB, "pro")
	slug, stackID := cdSeedStackWithService(t, seedDB, teamID, true)
	dom, err := models.CreateCustomDomain(context.Background(), seedDB, teamID, stackID, cdUniqueHost(t))
	require.NoError(t, err)

	want := handlers.ExpectedTXTValueForTest(dom.VerificationToken)
	restore := handlers.SetLookupTXTForTest(func(_ context.Context, _ string) ([]string, error) {
		return []string{want}, nil
	})
	defer restore()

	faultDB := openFaultDB(t, 3)
	app := cdAppWithLocals(t, faultDB, teamID.String(), nil)
	resp := cdReq(t, app, http.MethodPost,
		"/api/v1/stacks/"+slug+"/domains/"+dom.ID.String()+"/verify", "")
	defer resp.Body.Close()
	require.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
	assert.Equal(t, "verify_failed", cdErrField(t, resp))
}

// Delete: DeleteCustomDomain errors (custom_domain.go:640). team(1) + stack(2)
// + domain-read(3) succeed (seeded), the DELETE(4) errors. No k8s provider so
// the ingress teardown is skipped. failAfter=3.
func TestCDFinal_Delete_DBError_503(t *testing.T) {
	seedDB, clean := testhelpers.SetupTestDB(t)
	defer clean()
	teamID := seedTeamWithTier(t, seedDB, "pro")
	slug, stackID := cdSeedStackWithService(t, seedDB, teamID, true)
	dom, err := models.CreateCustomDomain(context.Background(), seedDB, teamID, stackID, cdUniqueHost(t))
	require.NoError(t, err)

	faultDB := openFaultDB(t, 3)
	app := cdAppWithLocals(t, faultDB, teamID.String(), nil)
	resp := cdReq(t, app, http.MethodDelete,
		"/api/v1/stacks/"+slug+"/domains/"+dom.ID.String(), "")
	defer resp.Body.Close()
	require.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
	assert.Equal(t, "delete_failed", cdErrField(t, resp))
}

// Verify: primaryStackService returns "no exposed service" → Verify records the
// error and 200s (custom_domain.go:514-521 via svcErr). We seed a stack with
// NO exposed service, mark the domain verified, and wire a cert provider so the
// handler reaches the ingress step.
func TestCDFinal_Verify_NoExposedService_RecordsError(t *testing.T) {
	seedDB, clean := testhelpers.SetupTestDB(t)
	defer clean()
	teamID := seedTeamWithTier(t, seedDB, "pro")
	slug, stackID := cdSeedStackWithService(t, seedDB, teamID, false) // expose=false
	dom, err := models.CreateCustomDomain(context.Background(), seedDB, teamID, stackID, cdUniqueHost(t))
	require.NoError(t, err)
	require.NoError(t, models.MarkCustomDomainVerified(context.Background(), seedDB, dom.ID))

	prov := &stubCustomDomainProvider{ensureURL: "https://ingress"}
	app := cdAppWithLocals(t, seedDB, teamID.String(), prov)
	resp := cdReq(t, app, http.MethodPost,
		"/api/v1/stacks/"+slug+"/domains/"+dom.ID.String()+"/verify", "")
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	// Status stays verified (ingress not created — no exposed service).
	got, err := models.GetCustomDomainByID(context.Background(), seedDB, dom.ID)
	require.NoError(t, err)
	assert.Equal(t, models.CustomDomainStatusVerified, got.Status)
	assert.True(t, got.LastCheckErr.Valid)
}

// List a domain that has verified_at / cert_ready_at / last_check_at /
// last_check_err set → serializeDomain renders all four optional fields
// (custom_domain.go:273-284).
func TestCDFinal_List_SerializeOptionalFields(t *testing.T) {
	seedDB, clean := testhelpers.SetupTestDB(t)
	defer clean()
	teamID := seedTeamWithTier(t, seedDB, "pro")
	slug, stackID := cdSeedStackWithService(t, seedDB, teamID, true)
	dom, err := models.CreateCustomDomain(context.Background(), seedDB, teamID, stackID, cdUniqueHost(t))
	require.NoError(t, err)
	_, err = seedDB.ExecContext(context.Background(), `
		UPDATE custom_domains
		SET verified_at = now(), cert_ready_at = now(), last_check_at = now(),
		    last_check_err = 'some transient error', status = 'cert_ready'
		WHERE id = $1::uuid`, dom.ID)
	require.NoError(t, err)

	app := cdAppWithLocals(t, seedDB, teamID.String(), &stubCustomDomainProvider{})
	resp := cdReq(t, app, http.MethodGet, "/api/v1/stacks/"+slug+"/domains", "")
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	var m map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&m))
	items, _ := m["items"].([]any)
	require.NotEmpty(t, items)
	row, _ := items[0].(map[string]any)
	assert.NotNil(t, row["verified_at"])
	assert.NotNil(t, row["cert_ready_at"])
	assert.NotNil(t, row["last_check_at"])
	assert.Equal(t, "some transient error", row["last_check_err"])
}

// cdErrField extracts the "error" field from a custom-domain JSON error body.
func cdErrField(t *testing.T, resp *http.Response) string {
	t.Helper()
	var m map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&m))
	if s, ok := m["error"].(string); ok {
		return s
	}
	return ""
}
