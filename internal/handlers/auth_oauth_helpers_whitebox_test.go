package handlers

// auth_oauth_helpers_whitebox_test.go — white-box unit tests for the low-level
// OAuth HTTP helpers (no DB needed). These reach the decode-error, network-error,
// provider-error, and missing-field branches that the handler-level tests can't
// drive deterministically. Lives in `package handlers` so it can set the
// package URL vars and call the unexported helpers directly.

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"instant.dev/internal/models"
)

// setHelperURLs points every OAuth endpoint var at base for the test.
func setHelperURLs(t *testing.T, base string) {
	t.Helper()
	prev := []*string{
		&githubTokenURL, &githubUserURL, &githubUserEmailURL,
		&googleTokenInfoURL, &googleTokenURL, &googleUserInfoURL,
	}
	saved := make([]string, len(prev))
	for i, p := range prev {
		saved[i] = *p
	}
	t.Cleanup(func() {
		for i, p := range prev {
			*p = saved[i]
		}
	})
	githubTokenURL = base + "/gh/token"
	githubUserURL = base + "/gh/user"
	githubUserEmailURL = base + "/gh/emails"
	googleTokenInfoURL = base + "/g/tokeninfo"
	googleTokenURL = base + "/g/token"
	googleUserInfoURL = base + "/g/userinfo"
}

// --- exchangeGitHubCode ---

// token endpoint returns malformed JSON → token-decode error.
func TestAuth_exchangeGitHubCode_TokenDecodeError(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/gh/token", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("not-json"))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	setHelperURLs(t, srv.URL)

	_, err := exchangeGitHubCode(context.Background(), "id", "secret", "code")
	require.Error(t, err)
}

// token endpoint network failure → token-exchange error.
func TestAuth_exchangeGitHubCode_NetworkError(t *testing.T) {
	setHelperURLs(t, "http://127.0.0.1:1")
	_, err := exchangeGitHubCode(context.Background(), "id", "secret", "code")
	require.Error(t, err)
}

// token OK, /gh/user returns malformed JSON → profile-decode error.
func TestAuth_exchangeGitHubCode_ProfileDecodeError(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/gh/token", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"access_token":"x"}`))
	})
	mux.HandleFunc("/gh/user", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("not-json"))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	setHelperURLs(t, srv.URL)

	_, err := exchangeGitHubCode(context.Background(), "id", "secret", "code")
	require.Error(t, err)
}

// --- verifyGoogleIDToken ---

func TestAuth_verifyGoogleIDToken_NetworkError(t *testing.T) {
	setHelperURLs(t, "http://127.0.0.1:1")
	_, err := verifyGoogleIDToken(context.Background(), "aud", "tok")
	require.Error(t, err)
}

func TestAuth_verifyGoogleIDToken_DecodeError(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/g/tokeninfo", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("not-json"))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	setHelperURLs(t, srv.URL)

	_, err := verifyGoogleIDToken(context.Background(), "aud", "tok")
	require.Error(t, err)
}

func TestAuth_verifyGoogleIDToken_ProviderError(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/g/tokeninfo", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"error_description":"invalid token"}`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	setHelperURLs(t, srv.URL)

	_, err := verifyGoogleIDToken(context.Background(), "aud", "tok")
	require.Error(t, err)
}

// --- exchangeGoogleAuthorizationCode ---

func TestAuth_exchangeGoogleAuthorizationCode_NetworkError(t *testing.T) {
	setHelperURLs(t, "http://127.0.0.1:1")
	_, err := exchangeGoogleAuthorizationCode(context.Background(), "id", "secret", "code", "https://x/cb")
	require.Error(t, err)
}

func TestAuth_exchangeGoogleAuthorizationCode_DecodeError(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/g/token", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("not-json"))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	setHelperURLs(t, srv.URL)

	_, err := exchangeGoogleAuthorizationCode(context.Background(), "id", "secret", "code", "https://x/cb")
	require.Error(t, err)
}

func TestAuth_exchangeGoogleAuthorizationCode_ProviderError(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/g/token", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"error":"invalid_grant","error_description":"bad"}`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	setHelperURLs(t, srv.URL)

	_, err := exchangeGoogleAuthorizationCode(context.Background(), "id", "secret", "code", "https://x/cb")
	require.Error(t, err)
}

// --- fetchGoogleUserInfoOAuth2V2 ---

func TestAuth_fetchGoogleUserInfo_NetworkError(t *testing.T) {
	setHelperURLs(t, "http://127.0.0.1:1")
	_, err := fetchGoogleUserInfoOAuth2V2(context.Background(), "tok")
	require.Error(t, err)
}

func TestAuth_fetchGoogleUserInfo_Non200(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/g/userinfo", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`denied`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	setHelperURLs(t, srv.URL)

	_, err := fetchGoogleUserInfoOAuth2V2(context.Background(), "tok")
	require.Error(t, err)
}

func TestAuth_fetchGoogleUserInfo_DecodeError(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/g/userinfo", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("not-json"))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	setHelperURLs(t, srv.URL)

	_, err := fetchGoogleUserInfoOAuth2V2(context.Background(), "tok")
	require.Error(t, err)
}

func TestAuth_fetchGoogleUserInfo_MissingIDAndEmail(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/g/userinfo", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"id":"","email":""}`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	setHelperURLs(t, srv.URL)

	_, err := fetchGoogleUserInfoOAuth2V2(context.Background(), "tok")
	require.Error(t, err, "missing id must error")

	// id present but email missing → second branch.
	mux2 := http.NewServeMux()
	mux2.HandleFunc("/g/userinfo", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"id":"abc","email":""}`))
	})
	srv2 := httptest.NewServer(mux2)
	defer srv2.Close()
	setHelperURLs(t, srv2.URL)
	_, err = fetchGoogleUserInfoOAuth2V2(context.Background(), "tok")
	require.Error(t, err, "missing email must error")
}

// --- markEmailVerified guard branches (pure, no DB on the guard path) ---

func TestAuth_markEmailVerified_GuardBranches(t *testing.T) {
	// nil user → early return, no panic.
	markEmailVerified(context.Background(), nil, nil)
	// already-verified user → early return without touching the (nil) DB.
	markEmailVerified(context.Background(), nil, &models.User{EmailVerified: true})
	assert.True(t, true)
}

// --- generateOAuthState / generateSessionID happy + shape ---

func TestAuth_generateOAuthState_And_generateSessionID(t *testing.T) {
	s1, err := generateOAuthState()
	require.NoError(t, err)
	assert.Len(t, s1, 32)
	s2, err := generateSessionID()
	require.NoError(t, err)
	assert.Len(t, s2, 32)
}
