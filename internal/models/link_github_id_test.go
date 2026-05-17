package models_test

// link_github_id_test.go — P2 bug-hunt coverage (2026-05-17 round 3).
//
// Fix #5: GitHub OAuth previously matched only on github_id and then created a
// fresh team/user — fragmenting the identity of someone who first signed up
// via magic-link or Google. The fix matches by email and attaches the GitHub
// ID via models.LinkGitHubID. This pins that model function:
//   - links github_id when currently NULL
//   - is a no-op (returns error) when github_id is already set
//
// Skips when TEST_DATABASE_URL is unset so the suite runs without Postgres.

import (
	"context"
	"os"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"instant.dev/internal/models"
	"instant.dev/internal/testhelpers"
)

func requireDBLinkGitHub(t *testing.T) {
	t.Helper()
	if os.Getenv("TEST_DATABASE_URL") == "" {
		t.Skip("TEST_DATABASE_URL not set; skipping integration test")
	}
}

func TestLinkGitHubID(t *testing.T) {
	requireDBLinkGitHub(t)
	db, clean := testhelpers.SetupTestDB(t)
	defer clean()

	ctx := context.Background()

	var teamID uuid.UUID
	require.NoError(t, db.QueryRow(
		`INSERT INTO teams (name) VALUES ('link-github-test') RETURNING id`).Scan(&teamID))

	// A user created via magic-link — no github_id yet. This is the account
	// that a later GitHub sign-in with the same email must link to, not fork.
	email := "link-github-" + uuid.NewString() + "@example.com"
	user, err := models.CreateUser(ctx, db, teamID, email, "", "", "owner")
	require.NoError(t, err)
	require.False(t, user.GitHubID.Valid, "fresh magic-link user has no github_id")

	// First link: attaches github_id while it is NULL.
	const ghID = "gh-9001"
	require.NoError(t, models.LinkGitHubID(ctx, db, user.ID, ghID))

	linked, err := models.GetUserByGitHubID(ctx, db, ghID)
	require.NoError(t, err, "user must now be findable by github_id")
	assert.Equal(t, user.ID, linked.ID, "GitHub ID linked to the existing account, not a new one")

	// Second link with a different ID: must fail — github_id is already set.
	// This is the guard that turns a GitHub-ID collision into an explicit
	// error instead of silently overwriting an identity.
	err = models.LinkGitHubID(ctx, db, user.ID, "gh-different")
	assert.Error(t, err, "LinkGitHubID must not overwrite an already-set github_id")
}
