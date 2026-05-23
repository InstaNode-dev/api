package handlers_test

// custom_domain_final_test.go — FINAL coverage pass for custom_domain.go.
// Closes the two arms the bvwave/coverage slices can't reach without a DNS
// seam + a cert-ready provider:
//
//   - checkTXT TXT-match SUCCESS (custom_domain.go:588-596) → Verify marks the
//     domain verified (476-488). Driven by the package-level lookupTXT seam.
//   - Verify cert→ready transition (555-563): a domain at ingress_ready whose
//     stubbed CertificateReady returns true → MarkCertReady flips it to
//     cert_ready.

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"instant.dev/internal/handlers"
	"instant.dev/internal/models"
	"instant.dev/internal/testhelpers"
)

// TestCustomDomainFinal_Verify_TXTMatch_MarksVerified — a pending domain whose
// TXT record matches → checkTXT returns true → MarkCustomDomainVerified runs,
// then (k8s==nil) the handler returns at the verified state.
func TestCustomDomainFinal_Verify_TXTMatch_MarksVerified(t *testing.T) {
	db, clean := testhelpers.SetupTestDB(t)
	defer clean()
	teamID := seedTeamWithTier(t, db, "pro")
	// No k8s provider → after verification the handler returns at "verified".
	app := customDomainFullApp(t, db, teamID, nil)
	slug, stackID := cdSeedStackWithService(t, db, teamID, true)

	dom, err := models.CreateCustomDomain(context.Background(), db, teamID, stackID, cdUniqueHost(t))
	require.NoError(t, err)

	// Make the DNS seam return the EXACT expected TXT value for this domain.
	want := handlers.ExpectedTXTValueForTest(dom.VerificationToken)
	restore := handlers.SetLookupTXTForTest(func(_ context.Context, _ string) ([]string, error) {
		return []string{"some-other-record", want}, nil
	})
	defer restore()

	resp := cdReq(t, app, http.MethodPost, "/api/v1/stacks/"+slug+"/domains/"+dom.ID.String()+"/verify", "")
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	got, err := models.GetCustomDomainByID(context.Background(), db, dom.ID)
	require.NoError(t, err)
	assert.Equal(t, models.CustomDomainStatusVerified, got.Status,
		"TXT match should flip the row to verified")
}

// TestCustomDomainFinal_Verify_TXTMatch_QuotedRecord — covers the quote-trimmed
// match branch (some resolvers wrap TXT in extra quotes). The record is the
// expected value surrounded by quotes; the handler trims them and matches.
func TestCustomDomainFinal_Verify_TXTMatch_QuotedRecord(t *testing.T) {
	db, clean := testhelpers.SetupTestDB(t)
	defer clean()
	teamID := seedTeamWithTier(t, db, "pro")
	app := customDomainFullApp(t, db, teamID, nil)
	slug, stackID := cdSeedStackWithService(t, db, teamID, true)

	dom, err := models.CreateCustomDomain(context.Background(), db, teamID, stackID, cdUniqueHost(t))
	require.NoError(t, err)

	want := handlers.ExpectedTXTValueForTest(dom.VerificationToken)
	restore := handlers.SetLookupTXTForTest(func(_ context.Context, _ string) ([]string, error) {
		return []string{`"` + want + `"`}, nil
	})
	defer restore()

	resp := cdReq(t, app, http.MethodPost, "/api/v1/stacks/"+slug+"/domains/"+dom.ID.String()+"/verify", "")
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	got, err := models.GetCustomDomainByID(context.Background(), db, dom.ID)
	require.NoError(t, err)
	assert.Equal(t, models.CustomDomainStatusVerified, got.Status)
}

// TestCustomDomainFinal_Verify_CertReady_Transition — a domain already at
// ingress_ready whose stubbed cert poll returns ready=true → MarkCertReady
// flips it to cert_ready (custom_domain.go:556-562). The provider's
// EnsureCustomDomainIngress is a no-op here because the row starts at
// verified, runs the ingress step (ensure succeeds → ingress_ready), then the
// cert step sees ready=true.
func TestCustomDomainFinal_Verify_CertReady_Transition(t *testing.T) {
	db, clean := testhelpers.SetupTestDB(t)
	defer clean()
	teamID := seedTeamWithTier(t, db, "pro")
	prov := &stubCustomDomainProvider{ensureURL: "https://ingress", certReady: true}
	app := customDomainFullApp(t, db, teamID, prov)
	slug, stackID := cdSeedStackWithService(t, db, teamID, true)

	dom, err := models.CreateCustomDomain(context.Background(), db, teamID, stackID, cdUniqueHost(t))
	require.NoError(t, err)
	require.NoError(t, models.MarkCustomDomainVerified(context.Background(), db, dom.ID))

	resp := cdReq(t, app, http.MethodPost, "/api/v1/stacks/"+slug+"/domains/"+dom.ID.String()+"/verify", "")
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	var m map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&m))

	got, err := models.GetCustomDomainByID(context.Background(), db, dom.ID)
	require.NoError(t, err)
	assert.Equal(t, models.CustomDomainStatusCertReady, got.Status,
		"cert ready=true should flip the row to cert_ready")
	assert.GreaterOrEqual(t, prov.certPolls, 1)
}
