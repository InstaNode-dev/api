package handlers_test

// stack_new_arms_coverage_test.go — covers the early validation / quota error
// arms of POST /stacks/new (stack.go New) the happy-path tests don't reach:
// missing-manifest, invalid-manifest, missing-tarball, and the per-tier
// deployment-count cap. Uses the noop-provider newStackTestApp.

import (
	"bytes"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"instant.dev/internal/testhelpers"
)

// multipartManifestOnly builds a multipart body with just a manifest field
// (no tarballs), plus a name field so the mandatory-name contract is satisfied.
func multipartManifestOnly(t *testing.T, manifestYAML string) (*bytes.Buffer, string) {
	t.Helper()
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	fw, err := mw.CreateFormField("manifest")
	require.NoError(t, err)
	_, err = fw.Write([]byte(manifestYAML))
	require.NoError(t, err)
	nf, err := mw.CreateFormField("name")
	require.NoError(t, err)
	_, _ = nf.Write([]byte("test stack"))
	require.NoError(t, mw.Close())
	return &buf, mw.FormDataContentType()
}

func TestStackNew_ValidationArms(t *testing.T) {
	requireTestDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	ensureStackTables(t, db)
	app := newStackTestApp(t, db)

	teamID := testhelpers.MustCreateTeamDB(t, db, "pro")
	jwt := testhelpers.MustSignSessionJWT(t, mustUUIDStr(), teamID, "sn@example.com")

	post := func(buf *bytes.Buffer, ct string) *http.Response {
		req := httptest.NewRequest(http.MethodPost, "/stacks/new", buf)
		req.Header.Set("Content-Type", ct)
		req.Header.Set("Authorization", "Bearer "+jwt)
		req.Header.Set("X-Forwarded-For", "10.61.0.1")
		resp, err := app.Test(req, 10000)
		require.NoError(t, err)
		return resp
	}

	t.Run("missing_manifest", func(t *testing.T) {
		var buf bytes.Buffer
		mw := multipart.NewWriter(&buf)
		nf, _ := mw.CreateFormField("name")
		_, _ = nf.Write([]byte("x"))
		mw.Close()
		resp := post(&buf, mw.FormDataContentType())
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
		resp.Body.Close()
	})

	t.Run("invalid_manifest", func(t *testing.T) {
		buf, ct := multipartManifestOnly(t, "this: is: not: valid: yaml: [")
		resp := post(buf, ct)
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
		resp.Body.Close()
	})

	t.Run("missing_tarball", func(t *testing.T) {
		// Valid manifest naming a service "web", but no tarball file for it.
		buf, ct := multipartManifestOnly(t, "services:\n  web:\n    build: ./web\n    port: 3000\n    expose: true\n")
		resp := post(buf, ct)
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
		resp.Body.Close()
	})
}

func TestStackNew_DeploymentCap_402(t *testing.T) {
	requireTestDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	ensureStackTables(t, db)
	app := newStackTestApp(t, db)

	// hobby allows 1 deployment (plans.yaml deployments_apps). Seed 1 active
	// stack so the next /stacks/new trips the per-tier cap with a 402.
	teamID := testhelpers.MustCreateTeamDB(t, db, "hobby")
	tid := teamID
	_, err := db.Exec(`INSERT INTO stacks (team_id, slug, namespace, tier, env, status)
		VALUES ($1::uuid, $2, $3, 'hobby', 'production', 'healthy')`,
		tid, "cap-"+teamID[:8], "ns-cap-"+teamID[:8])
	require.NoError(t, err)

	jwt := testhelpers.MustSignSessionJWT(t, mustUUIDStr(), teamID, "cap@example.com")
	buf, ct := multipartManifestOnly(t, "services:\n  web:\n    build: ./web\n    port: 3000\n    expose: true\n")
	req := httptest.NewRequest(http.MethodPost, "/stacks/new", buf)
	req.Header.Set("Content-Type", ct)
	req.Header.Set("Authorization", "Bearer "+jwt)
	req.Header.Set("X-Forwarded-For", "10.62.0.1")
	resp, err := app.Test(req, 10000)
	require.NoError(t, err)
	assert.Equal(t, http.StatusPaymentRequired, resp.StatusCode)
	resp.Body.Close()
}
