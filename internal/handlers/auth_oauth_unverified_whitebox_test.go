package handlers

// auth_oauth_unverified_whitebox_test.go — deterministic coverage for the
// bug-bash #7/#9 account-takeover guard: findOrCreateUserGoogle /
// findOrCreateUserGitHub MUST refuse to link-by-email or seed a new identity
// when the provider did not assert a verified email.
//
// The handler-level tests (auth_oauth_coverage_test.go) drive the body/id_token
// flow, but the BROWSER-callback path (GoogleCallbackBrowser → userinfo v2 →
// findOrCreateUserGoogle) reaches the guard via a code path those tests don't
// exercise, leaving auth.go:1420-1422 uncovered. These white-box tests call the
// upsert helpers directly with EmailVerified=false and a sqlmock'd
// google_id/github_id lookup that misses (→ ErrUserNotFound), so the guard is
// the very next branch — hermetic, no DB container required.

import (
	"context"
	"database/sql"
	"testing"

	sqlmock "github.com/DATA-DOG/go-sqlmock"
	"github.com/stretchr/testify/require"

	"instant.dev/internal/config"
)

func TestFindOrCreateUserGoogle_UnverifiedEmail_Refused_Whitebox(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()
	// GetUserByGoogleID misses → *ErrUserNotFound, so the function falls
	// through to the verified-email guard rather than returning an existing
	// google_id match.
	mock.ExpectQuery(`FROM users WHERE google_id`).
		WithArgs("new-sub").
		WillReturnError(sql.ErrNoRows)

	h := NewAuthHandler(db, &config.Config{})
	_, _, err = h.findOrCreateUserGoogle(context.Background(), &googleUser{
		Sub:           "new-sub",
		Email:         "victim@example.com",
		EmailVerified: false,
	})
	require.ErrorIs(t, err, errOAuthEmailUnverified,
		"a new Google identity on an UNVERIFIED email must be refused (account-takeover guard)")
	require.NoError(t, mock.ExpectationsWereMet())
}

func TestFindOrCreateUserGitHub_UnverifiedEmail_Refused_Whitebox(t *testing.T) {
	// Symmetric guard for GitHub (auth.go:773): fetchGitHubUser only sets
	// gh.Email from a primary+verified /user/emails entry, so an empty Email
	// means "no verified primary email" — link-by-email / new-identity must be
	// refused. GetUserByGitHubID runs first; mock it to miss so we fall through.
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()
	mock.ExpectQuery(`FROM users WHERE github_id`).
		WithArgs("gh-new").
		WillReturnError(sql.ErrNoRows)

	h := NewAuthHandler(db, &config.Config{})
	_, _, gErr := h.findOrCreateUserGitHub(context.Background(), &gitHubUser{
		ID:    "gh-new",
		Email: "", // no verified primary email
	})
	require.ErrorIs(t, gErr, errOAuthEmailUnverified,
		"a new GitHub identity with no verified primary email must be refused")
	require.NoError(t, mock.ExpectationsWereMet())
}
