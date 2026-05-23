package handlers_test

// stack_new_arms_final3_test.go — FINAL serial pass #3. Closes the remaining
// reachable stack.New arms:
//   - optionalStackTeam authErr return (bad team-id in JWT)            (431)
//   - anonymous rate-limit-check Redis-error fail-open warn            (441)
//   - anonymous happy path with a real fingerprint (fingerprint_prefix log + the
//     full anon create branch)                                        (827, anon arms)
//   - manifest warnings note (circular service:// reference)          (840)

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"instant.dev/internal/testhelpers"
)

// TestStackNewFinal3_BadTeamToken_400 — a JWT carrying a non-UUID team_id makes
// optionalStackTeam return an error → stack.New's authErr return (stack.go:431).
func TestStackNewFinal3_BadTeamToken_400(t *testing.T) {
	db, clean := testhelpers.SetupTestDB(t)
	defer clean()
	ensureStackTables(t, db)
	app := stackNewApp(t, db, nil)
	jwt := testhelpers.MustSignSessionJWT(t, uuid.NewString(), "not-a-uuid", testhelpers.UniqueEmail(t))
	resp := postStackNew(t, app, jwt, testManifestSingleService, map[string][]byte{
		"web": createMinimalTarball(t),
	})
	defer resp.Body.Close()
	require.Equal(t, http.StatusBadRequest, resp.StatusCode)
	assert.Equal(t, "invalid_team", decodeErrCode(t, resp))
}

// TestStackNewFinal3_Anon_RateLimitRedisError_FailOpen — an anonymous create
// against a DEAD Redis makes checkStackDeployLimit error; the handler logs a
// warn and FAILS OPEN, continuing to a 202 (stack.go:441-443).
func TestStackNewFinal3_Anon_RateLimitRedisError_FailOpen(t *testing.T) {
	db, clean := testhelpers.SetupTestDB(t)
	defer clean()
	ensureStackTables(t, db)
	// Redis pointed at a closed port → pipeline Exec errors → fail-open warn.
	rdb := redis.NewClient(&redis.Options{Addr: "127.0.0.1:1", DialTimeout: 200 * time.Millisecond})
	t.Cleanup(func() { rdb.Close() })
	app := stackNewApp(t, db, rdb)
	resp := postStackNew(t, app, "", testManifestSingleService, map[string][]byte{
		"web": createMinimalTarball(t),
	})
	defer resp.Body.Close()
	// Fail-open: the Redis error must NOT block the deploy.
	require.NotEqual(t, http.StatusTooManyRequests, resp.StatusCode)
	require.NotEqual(t, http.StatusServiceUnavailable, resp.StatusCode)
	assert.Equal(t, http.StatusAccepted, resp.StatusCode)
}

// TestStackNewFinal3_Anon_HappyPath_FingerprintLog — anonymous create with a
// real fingerprint (stackNewApp registers the Fingerprint middleware) → 202 and
// the anon fingerprint_prefix log arm (stack.go:827) plus the full anon create
// branch.
func TestStackNewFinal3_Anon_HappyPath_FingerprintLog(t *testing.T) {
	db, clean := testhelpers.SetupTestDB(t)
	defer clean()
	ensureStackTables(t, db)
	app := stackNewApp(t, db, nil) // nil rdb → checkStackDeployLimit fails open cleanly
	resp := postStackNew(t, app, "", testManifestSingleService, map[string][]byte{
		"web": createMinimalTarball(t),
	})
	defer resp.Body.Close()
	require.Equal(t, http.StatusAccepted, resp.StatusCode)
}

// TestStackNewFinal3_ManifestWarnings_NotePrefix — a manifest with a circular
// service:// reference produces a Validate warning, so stack.New prepends the
// "N warning(s)" note (stack.go:840).
func TestStackNewFinal3_ManifestWarnings_NotePrefix(t *testing.T) {
	db, clean := testhelpers.SetupTestDB(t)
	defer clean()
	ensureStackTables(t, db)
	app := stackNewApp(t, db, nil)

	// a → b → a circular service:// reference. Validate emits a cycle warning
	// but does NOT error, so the create proceeds with a warnings note.
	const circularManifest = `
services:
  a:
    build: ./a
    port: 8080
    expose: true
    env:
      PEER: service://b
  b:
    build: ./b
    port: 8080
    expose: false
    env:
      PEER: service://a
`
	resp := postStackNew(t, app, "", circularManifest, map[string][]byte{
		"a": createMinimalTarball(t),
		"b": createMinimalTarball(t),
	})
	defer resp.Body.Close()
	require.Equal(t, http.StatusAccepted, resp.StatusCode)
	body := readBodyString(t, resp)
	assert.True(t, strings.Contains(body, "warning"), "note should mention warnings, got: %s", body)
}

// readBodyString drains a response body into a string.
func readBodyString(t *testing.T, resp *http.Response) string {
	t.Helper()
	buf := make([]byte, 0, 1024)
	tmp := make([]byte, 512)
	for {
		n, err := resp.Body.Read(tmp)
		buf = append(buf, tmp[:n]...)
		if err != nil {
			break
		}
	}
	return string(buf)
}
