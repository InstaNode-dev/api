package handlers_test

// auth_residual_coverage_test.go — closes the last residual error branches in
// auth.go that the existing OAuth/magic-link coverage suites left at 0:
//
//   * GitHubCallback (browser)  exchange_failed  (auth.go ~1027)
//   * GoogleCallbackBrowser     exchange_failed  (auth.go ~1113)
//   * GoogleCallbackBrowser     userinfo_failed  (auth.go ~1119)
//   * findOrCreateUserGitHub    new-user markEmailVerified failure (auth.go ~648)
//   * findOrCreateUserGoogle    link error / email-lookup error / teamName
//                               fallback (auth.go ~1168/1183/1189)
//   * FindOrCreateUserByEmail   empty-local-part teamName fallback (auth.go ~814)
//
// All branches are reached through the same seams the sibling files use
// (startFakeOAuth + the state-cookie dance, withIsolatedDB constraint tricks)
// so the production code path runs end-to-end — no behaviour is mocked away.

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"instant.dev/internal/handlers"
	"instant.dev/internal/models"
	"instant.dev/internal/testhelpers"
)

// browserCallback drives the full GitHub/Google browser callback dance: hit
// the Start handler to mint a real state + cookie, then call the callback with
// that state. The fake OAuth server's error knobs decide which branch fires.
func browserCallback(t *testing.T, app interface {
	Test(*http.Request, ...int) (*http.Response, error)
}, startPath, callbackPath string) *http.Response {
	t.Helper()
	startResp, err := app.Test(httptest.NewRequest(http.MethodGet, startPath, nil), 5000)
	require.NoError(t, err)
	cookie := startResp.Header.Get("Set-Cookie")
	loc := startResp.Header.Get("Location")
	startResp.Body.Close()
	state := extractQueryParam(loc, "state")
	require.NotEmpty(t, state)

	req := httptest.NewRequest(http.MethodGet, callbackPath+"?code=c&state="+state, nil)
	req.Header.Set("Cookie", firstCookie(cookie))
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	return resp
}

// GitHub browser callback with a token-exchange error → exchange_failed 401.
func TestAuth_GitHubCallbackBrowser_ExchangeFailed(t *testing.T) {
	startFakeOAuth(t, &fakeOAuthServer{ghTokenErr: true})
	app := buildAuthApp(handlers.NewAuthHandler(nil, oauthCfg()))
	resp := browserCallback(t, app, "/auth/github/start?return_to=https://instanode.dev/x", "/auth/github/callback")
	defer resp.Body.Close()
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	assert.Contains(t, resp.Header.Get("Content-Type"), "text/html")
}

// Google browser callback with no access_token → exchange_failed 401.
func TestAuth_GoogleCallbackBrowser_ExchangeFailed(t *testing.T) {
	startFakeOAuth(t, &fakeOAuthServer{gTokenNoAccess: true})
	app := buildAuthApp(handlers.NewAuthHandler(nil, oauthCfg()))
	resp := browserCallback(t, app, "/auth/google/start?return_to=https://instanode.dev/x", "/auth/google/callback/browser")
	defer resp.Body.Close()
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	assert.Contains(t, resp.Header.Get("Content-Type"), "text/html")
}

// Google browser callback where token-exchange succeeds but /g/userinfo
// returns an empty email → userinfo_failed 401. Exercises the second error
// branch of GoogleCallbackBrowser (distinct from the exchange branch above).
func TestAuth_GoogleCallbackBrowser_UserinfoFailed(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/g/token", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"ya29.ok"}`))
	})
	mux.HandleFunc("/g/userinfo", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"g-xyz","email":""}`)) // missing email → error
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	defer handlers.SetOAuthURLsForTest(srv.URL)()

	app := buildAuthApp(handlers.NewAuthHandler(nil, oauthCfg()))
	resp := browserCallback(t, app, "/auth/google/start?return_to=https://instanode.dev/x", "/auth/google/callback/browser")
	defer resp.Body.Close()
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

// GitHub new-user path where SetEmailVerified fails: a CHECK constraint blocks
// email_verified=true so CreateUser (defaults false) succeeds but the
// best-effort markEmailVerified UPDATE errors. The login still succeeds (the
// flip is swallowed) → 200. Covers the new-user markEmailVerified-error branch
// of findOrCreateUserGitHub.
func TestAuth_GitHub_NewUser_SetEmailVerifiedFailure(t *testing.T) {
	db := withIsolatedDB(t)
	_, err := db.ExecContext(context.Background(),
		`ALTER TABLE users ADD CONSTRAINT no_verify_gh CHECK (email_verified = false)`)
	require.NoError(t, err)

	startFakeOAuth(t, &fakeOAuthServer{ghID: uniqueGHID(), ghEmail: "newgh@example.com"})
	app := buildAuthApp(handlers.NewAuthHandler(db, oauthCfg()))
	resp := oauthPostJSON(t, app, "/auth/github", `{"code":"abc"}`)
	defer resp.Body.Close()
	// markEmailVerified failure is best-effort and swallowed → login still 200.
	assert.Equal(t, http.StatusOK, resp.StatusCode)
}

// Google new-user where g.Name is empty so the teamName falls back to the
// email's local-part (auth.go ~1189). The fake server returns no name field
// for /g/userinfo on the POST /auth/google path, so the team is named after
// the local-part of the email — the previously-uncovered fallback branch.
func TestAuth_Google_NewUser_TeamNameFallback(t *testing.T) {
	db := withIsolatedDB(t)
	// Teams intact → CreateTeam succeeds; the user is created with the
	// local-part fallback team name.
	startFakeOAuth(t, &fakeOAuthServer{gAud: "g-client", gSub: uniqueGHID(), gEmail: "fallbackname@example.com"})
	app := buildAuthApp(handlers.NewAuthHandler(db, oauthCfg()))
	resp := oauthPostJSON(t, app, "/auth/google", `{"id_token":"tok"}`)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)
}

// Google link-by-email where LinkGoogleID errors: pre-create an email-only
// account, then drop the google_id column so the LinkGoogleID UPDATE errors.
// Covers the link-error branch of findOrCreateUserGoogle (auth.go ~1168).
func TestAuth_Google_LinkByEmail_LinkError(t *testing.T) {
	db := withIsolatedDB(t)
	existing := "linkerr@example.com"
	teamID := testhelpers.MustCreateTeamDB(t, db, "hobby")
	_, err := db.ExecContext(context.Background(),
		`INSERT INTO users (team_id, email) VALUES ($1::uuid, $2)`, teamID, existing)
	require.NoError(t, err)
	// Break the column the LinkGoogleID UPDATE writes to so it errors.
	_, err = db.ExecContext(context.Background(), `ALTER TABLE users DROP COLUMN google_id`)
	require.NoError(t, err)

	startFakeOAuth(t, &fakeOAuthServer{gAud: "g-client", gSub: uniqueGHID(), gEmail: existing})
	app := buildAuthApp(handlers.NewAuthHandler(db, oauthCfg()))
	resp := oauthPostJSON(t, app, "/auth/google", `{"id_token":"tok"}`)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
}

// FindOrCreateUserByEmail with an empty local-part: an address like
// "@example.com" lowercases/trims to a non-empty string but Split on '@'
// yields an empty teamName → the `teamName == ""` fallback to "team" runs.
// Called directly (looksLikeEmail would reject it at the HTTP edge, but the
// helper is a public seam other callers reach). Covers auth.go ~814.
func TestAuth_FindOrCreateUserByEmail_EmptyLocalPartTeamName(t *testing.T) {
	db, clean := testhelpers.SetupTestDB(t)
	defer clean()
	h := handlers.NewAuthHandler(db, oauthCfg())

	user, team, err := h.FindOrCreateUserByEmail(context.Background(), "@residual-"+uniqueGHID()+".example.com")
	require.NoError(t, err)
	require.NotNil(t, user)
	require.NotNil(t, team)
	// The local-part was empty so the team falls back to the literal "team".
	assert.Equal(t, "team", strings.ToLower(team.Name.String))
}

// persistMagicLinkSendStatus error branches: create a real magic_links row,
// drop the table, then call the helper directly for both sendErr!=nil
// (MarkMagicLinkSendFailed) and sendErr==nil (MarkMagicLinkSent). Both UPDATEs
// error → the two slog.Error branches run. The helper swallows on failure, so
// the assertion is simply that it does not panic. Covers magic_link.go ~247/256.
func TestMagicLink_PersistSendStatus_BothErrorBranches(t *testing.T) {
	db := withIsolatedDB(t)
	ctx := context.Background()

	plaintext, err := models.GenerateMagicLinkPlaintext()
	require.NoError(t, err)
	row, err := models.CreateMagicLink(ctx, db, "persist@example.com", plaintext, "", 0)
	require.NoError(t, err)

	// Break the table so every Mark* UPDATE errors.
	_, err = db.ExecContext(ctx, `DROP TABLE magic_links CASCADE`)
	require.NoError(t, err)

	// sendErr != nil → MarkMagicLinkSendFailed error branch.
	handlers.PersistMagicLinkSendStatusForTest(ctx, db, row.ID, errors.New("send blew up"), "req-fail")
	// sendErr == nil → MarkMagicLinkSent error branch.
	handlers.PersistMagicLinkSendStatusForTest(ctx, db, row.ID, nil, "req-sent")
	// Arbitrary id, still total / no panic.
	handlers.PersistMagicLinkSendStatusForTest(ctx, db, uuid.New(), nil, "req-rand")
}

// Magic-link Callback consume-race: fire many concurrent Callbacks against the
// SAME token released through a barrier. Exactly one wins ConsumeMagicLink
// (302); the others either re-SELECT after the consume (GetMagicLinkForConsumption
// NotFound → 400) or SELECT before the winner's UPDATE and then find the row
// already consumed (ConsumeMagicLink returns false → the `!consumed` branch,
// magic_link.go ~318). With this many racers the `!consumed` branch is reached
// reliably; the invariant we ASSERT (always true regardless of which losing
// branch fires) is "exactly one 302, all others 400" so the test never flakes.
func TestMagicLink_Callback_ConcurrentConsumeRace(t *testing.T) {
	db, clean := testhelpers.SetupTestDB(t)
	defer clean()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()

	mailer := &stubMailer{}
	app := mlExtraApp(t, db, rdb, mailer)

	// Mint one real, consumable token via Start.
	emailAddr := testhelpers.UniqueEmail(t)
	body := fmt.Sprintf(`{"email":%q,"return_to":"https://instanode.dev/login/callback"}`, emailAddr)
	startReq := httptest.NewRequest(http.MethodPost, "/auth/email/start", strings.NewReader(body))
	startReq.Header.Set("Content-Type", "application/json")
	sresp, err := app.Test(startReq, 5000)
	require.NoError(t, err)
	require.Equal(t, http.StatusAccepted, sresp.StatusCode)
	sresp.Body.Close()
	require.Equal(t, 1, mailer.calls)

	idx := strings.Index(mailer.link, "?t=")
	require.Greater(t, idx, -1)
	plaintext := mailer.link[idx+3:]

	const racers = 16
	var wg sync.WaitGroup
	start := make(chan struct{})
	codes := make([]int, racers)
	for i := 0; i < racers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start // barrier: all goroutines unblock together
			req := httptest.NewRequest(http.MethodGet, "/auth/email/callback?t="+plaintext, nil)
			resp, rerr := app.Test(req, 5000)
			if rerr != nil {
				codes[i] = -1
				return
			}
			codes[i] = resp.StatusCode
			resp.Body.Close()
		}(i)
	}
	close(start)
	wg.Wait()

	won, lost := 0, 0
	for _, c := range codes {
		switch c {
		case http.StatusFound:
			won++
		case http.StatusBadRequest:
			lost++
		default:
			t.Fatalf("unexpected status from a racing Callback: %d", c)
		}
	}
	assert.Equal(t, 1, won, "exactly one racer must win the single-use consume")
	assert.Equal(t, racers-1, lost, "every other racer must be rejected as already-used")
}
