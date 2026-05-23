package handlers_test

// stack_redeploy_arms_final3_test.go — FINAL serial pass #3. Closes two
// reachable StackHandler.Redeploy arms:
//   - invalid_form: a non-multipart redeploy body → 400          (stack.go:1338)
//   - tarball_open_failed: openMultipartFile seam forced to error (stack.go:1369)

import (
	"errors"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"instant.dev/internal/handlers"
	"instant.dev/internal/testhelpers"
)

// TestStackRedeployFinal3_InvalidForm — a JSON (non-multipart) redeploy body on
// an existing stack → invalid_form 400 (stack.go:1338).
func TestStackRedeployFinal3_InvalidForm(t *testing.T) {
	requireCoverageDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	ensureStackTables2(t, db)

	teamIDStr := testhelpers.MustCreateTeamDB(t, db, "pro")
	teamID := uuid.MustParse(teamIDStr)
	_, slug := seedStack(t, db, &teamID, "healthy")
	jwt := testhelpers.MustSignSessionJWT(t, uuid.NewString(), teamIDStr, "rdform@example.com")
	app, _ := newCoverageStackApp(t, db)

	req := httptest.NewRequest(http.MethodPost, "/stacks/"+slug+"/redeploy", strings.NewReader("not-multipart"))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+jwt)
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

// TestStackRedeployFinal3_TarballOpenFailed — openMultipartFile forced to error
// → tarball_open_failed 400 (stack.go:1369).
func TestStackRedeployFinal3_TarballOpenFailed(t *testing.T) {
	requireCoverageDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	ensureStackTables2(t, db)

	teamIDStr := testhelpers.MustCreateTeamDB(t, db, "pro")
	teamID := uuid.MustParse(teamIDStr)
	_, slug := seedStack(t, db, &teamID, "healthy")
	jwt := testhelpers.MustSignSessionJWT(t, uuid.NewString(), teamIDStr, "rdopen@example.com")
	app, _ := newCoverageStackApp(t, db)

	restore := handlers.SetOpenMultipartFileForTest(func(*multipart.FileHeader) (multipart.File, error) {
		return nil, errors.New("forced open error")
	})
	defer restore()

	manifest := "services:\n  web:\n    build: ./web\n    port: 8080\n    expose: true\n"
	body, ct := stackMultipart(t, manifest, map[string][]byte{"web": newMinimalTarball(t)})
	req := httptest.NewRequest(http.MethodPost, "/stacks/"+slug+"/redeploy", body)
	req.Header.Set("Content-Type", ct)
	req.Header.Set("Authorization", "Bearer "+jwt)
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusBadRequest, resp.StatusCode)
	assert.Equal(t, "tarball_open_failed", decodeErrCode(t, resp))
}
