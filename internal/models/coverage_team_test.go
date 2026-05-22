package models

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

func TestTeamUserErrorStrings(t *testing.T) {
	require.Contains(t, (&ErrTeamNotFound{ID: uuid.New()}).Error(), "team")
	require.Contains(t, (&ErrUserNotFound{Email: "a@b.com"}).Error(), "a@b.com")
}

func TestNormalizeEmail(t *testing.T) {
	require.Equal(t, "a@b.com", NormalizeEmail("  A@B.com "))
}

func teamCols() []string {
	return []string{"id", "name", "plan_tier", "stripe_customer_id", "created_at", "default_deployment_ttl_policy"}
}

func teamRow() *sqlmock.Rows {
	return sqlmock.NewRows(teamCols()).AddRow(uuid.New(), nil, "free", nil, time.Now(), "auto_24h")
}

func userCols() []string {
	return []string{"id", "team_id", "email", "role", "github_id", "google_id", "email_verified", "created_at"}
}

func userRow() *sqlmock.Rows {
	return sqlmock.NewRows(userCols()).AddRow(uuid.New(), uuid.New(), "a@b.com", "owner", nil, nil, false, time.Now())
}

func TestCreateTeam_Branches(t *testing.T) {
	ctx := context.Background()
	db, mock := newMock(t)
	mock.ExpectQuery(`INSERT INTO teams`).WillReturnRows(teamRow())
	_, err := CreateTeam(ctx, db, "n")
	require.NoError(t, err)

	db2, mock2 := newMock(t)
	mock2.ExpectQuery(`INSERT INTO teams`).WillReturnError(errors.New("boom"))
	_, err = CreateTeam(ctx, db2, "n")
	require.ErrorContains(t, err, "boom")
}

func TestGetTeamByID_Branches(t *testing.T) {
	ctx := context.Background()
	db, mock := newMock(t)
	mock.ExpectQuery(`FROM teams WHERE id`).WillReturnRows(teamRow())
	_, err := GetTeamByID(ctx, db, uuid.New())
	require.NoError(t, err)

	db2, mock2 := newMock(t)
	mock2.ExpectQuery(`FROM teams WHERE id`).WillReturnError(errNoRows())
	var nf *ErrTeamNotFound
	_, err = GetTeamByID(ctx, db2, uuid.New())
	require.ErrorAs(t, err, &nf)

	db3, mock3 := newMock(t)
	mock3.ExpectQuery(`FROM teams WHERE id`).WillReturnError(errors.New("boom"))
	_, err = GetTeamByID(ctx, db3, uuid.New())
	require.ErrorContains(t, err, "boom")
}

func TestUpdateTeamDefaultDeploymentTTLPolicy_Branches(t *testing.T) {
	ctx := context.Background()
	db, mock := newMock(t)
	mock.ExpectExec(`UPDATE teams SET default_deployment_ttl_policy`).WillReturnResult(sqlmock.NewResult(0, 1))
	require.NoError(t, UpdateTeamDefaultDeploymentTTLPolicy(ctx, db, uuid.New(), "permanent"))

	db2, mock2 := newMock(t)
	mock2.ExpectExec(`UPDATE teams SET default_deployment_ttl_policy`).WillReturnError(errors.New("boom"))
	require.ErrorContains(t, UpdateTeamDefaultDeploymentTTLPolicy(ctx, db2, uuid.New(), "permanent"), "boom")
}

func TestCreateUser_Branches(t *testing.T) {
	ctx := context.Background()
	db, mock := newMock(t)
	mock.ExpectQuery(`INSERT INTO users`).WillReturnRows(userRow())
	_, err := CreateUser(ctx, db, uuid.New(), "A@B.com", "gh", "goog", "owner")
	require.NoError(t, err)

	// empty role default + empty ids + error
	db2, mock2 := newMock(t)
	mock2.ExpectQuery(`INSERT INTO users`).WillReturnError(errors.New("boom"))
	_, err = CreateUser(ctx, db2, uuid.New(), "a@b.com", "", "", "")
	require.ErrorContains(t, err, "boom")
}

func TestSetEmailVerified_Branches(t *testing.T) {
	ctx := context.Background()
	db, mock := newMock(t)
	mock.ExpectExec(`UPDATE users SET email_verified`).WillReturnResult(sqlmock.NewResult(0, 1))
	require.NoError(t, SetEmailVerified(ctx, db, uuid.New()))

	db2, mock2 := newMock(t)
	mock2.ExpectExec(`UPDATE users SET email_verified`).WillReturnError(errors.New("boom"))
	require.ErrorContains(t, SetEmailVerified(ctx, db2, uuid.New()), "boom")
}

// TestUserGetters_Branches exercises the find-by-X helpers that share the
// not-found/error shape.
func TestUserGetters_Branches(t *testing.T) {
	ctx := context.Background()

	// GetPrimaryUserByTeamID
	{
		db, mock := newMock(t)
		mock.ExpectQuery(`WHERE team_id = \$1 AND is_primary = true`).WillReturnRows(userRow())
		_, err := GetPrimaryUserByTeamID(ctx, db, uuid.New())
		require.NoError(t, err)
		db2, mock2 := newMock(t)
		mock2.ExpectQuery(`WHERE team_id = \$1 AND is_primary = true`).WillReturnError(errNoRows())
		_, err = GetPrimaryUserByTeamID(ctx, db2, uuid.New())
		var nf *ErrUserNotFound
		require.ErrorAs(t, err, &nf)
		db3, mock3 := newMock(t)
		mock3.ExpectQuery(`WHERE team_id = \$1 AND is_primary = true`).WillReturnError(errors.New("boom"))
		_, err = GetPrimaryUserByTeamID(ctx, db3, uuid.New())
		require.ErrorContains(t, err, "boom")
	}

	// GetUserByID
	{
		db, mock := newMock(t)
		mock.ExpectQuery(`FROM users WHERE id`).WillReturnRows(userRow())
		_, err := GetUserByID(ctx, db, uuid.New())
		require.NoError(t, err)
		db2, mock2 := newMock(t)
		mock2.ExpectQuery(`FROM users WHERE id`).WillReturnError(errNoRows())
		var nf *ErrUserNotFound
		_, err = GetUserByID(ctx, db2, uuid.New())
		require.ErrorAs(t, err, &nf)
		db3, mock3 := newMock(t)
		mock3.ExpectQuery(`FROM users WHERE id`).WillReturnError(errors.New("boom"))
		_, err = GetUserByID(ctx, db3, uuid.New())
		require.ErrorContains(t, err, "boom")
	}

	// GetUserByEmail
	{
		db, mock := newMock(t)
		mock.ExpectQuery(`WHERE lower\(email\)`).WillReturnRows(userRow())
		_, err := GetUserByEmail(ctx, db, "A@B.com")
		require.NoError(t, err)
		db2, mock2 := newMock(t)
		mock2.ExpectQuery(`WHERE lower\(email\)`).WillReturnError(errNoRows())
		var nf *ErrUserNotFound
		_, err = GetUserByEmail(ctx, db2, "a@b.com")
		require.ErrorAs(t, err, &nf)
		db3, mock3 := newMock(t)
		mock3.ExpectQuery(`WHERE lower\(email\)`).WillReturnError(errors.New("boom"))
		_, err = GetUserByEmail(ctx, db3, "a@b.com")
		require.ErrorContains(t, err, "boom")
	}

	// GetUserByGitHubID
	{
		db, mock := newMock(t)
		mock.ExpectQuery(`WHERE github_id`).WillReturnRows(userRow())
		_, err := GetUserByGitHubID(ctx, db, "gh")
		require.NoError(t, err)
		db2, mock2 := newMock(t)
		mock2.ExpectQuery(`WHERE github_id`).WillReturnError(errNoRows())
		var nf *ErrUserNotFound
		_, err = GetUserByGitHubID(ctx, db2, "gh")
		require.ErrorAs(t, err, &nf)
		db3, mock3 := newMock(t)
		mock3.ExpectQuery(`WHERE github_id`).WillReturnError(errors.New("boom"))
		_, err = GetUserByGitHubID(ctx, db3, "gh")
		require.ErrorContains(t, err, "boom")
	}

	// GetUserByGoogleID
	{
		db, mock := newMock(t)
		mock.ExpectQuery(`WHERE google_id`).WillReturnRows(userRow())
		_, err := GetUserByGoogleID(ctx, db, "goog")
		require.NoError(t, err)
		db2, mock2 := newMock(t)
		mock2.ExpectQuery(`WHERE google_id`).WillReturnError(errNoRows())
		var nf *ErrUserNotFound
		_, err = GetUserByGoogleID(ctx, db2, "goog")
		require.ErrorAs(t, err, &nf)
		db3, mock3 := newMock(t)
		mock3.ExpectQuery(`WHERE google_id`).WillReturnError(errors.New("boom"))
		_, err = GetUserByGoogleID(ctx, db3, "goog")
		require.ErrorContains(t, err, "boom")
	}
}

func TestGetUserByTeamID_Branches(t *testing.T) {
	ctx := context.Background()

	// owner found first query
	db, mock := newMock(t)
	mock.ExpectQuery(`role = 'owner'`).WillReturnRows(userRow())
	_, err := GetUserByTeamID(ctx, db, uuid.New())
	require.NoError(t, err)

	// owner missing -> fallback finds member
	db2, mock2 := newMock(t)
	mock2.ExpectQuery(`role = 'owner'`).WillReturnError(errNoRows())
	mock2.ExpectQuery(`FROM users WHERE team_id = \$1 ORDER BY created_at`).WillReturnRows(userRow())
	_, err = GetUserByTeamID(ctx, db2, uuid.New())
	require.NoError(t, err)

	// both missing -> not found
	db3, mock3 := newMock(t)
	mock3.ExpectQuery(`role = 'owner'`).WillReturnError(errNoRows())
	mock3.ExpectQuery(`FROM users WHERE team_id = \$1 ORDER BY created_at`).WillReturnError(errNoRows())
	var nf *ErrUserNotFound
	_, err = GetUserByTeamID(ctx, db3, uuid.New())
	require.ErrorAs(t, err, &nf)

	// owner query non-nil error
	db4, mock4 := newMock(t)
	mock4.ExpectQuery(`role = 'owner'`).WillReturnError(errors.New("boom"))
	_, err = GetUserByTeamID(ctx, db4, uuid.New())
	require.ErrorContains(t, err, "boom")
}

func TestUpdateRazorpaySubscriptionID_Branches(t *testing.T) {
	ctx := context.Background()
	db, mock := newMock(t)
	mock.ExpectExec(`UPDATE teams SET stripe_customer_id`).WillReturnResult(sqlmock.NewResult(0, 1))
	require.NoError(t, UpdateRazorpaySubscriptionID(ctx, db, uuid.New(), "sub"))
	db2, mock2 := newMock(t)
	mock2.ExpectExec(`UPDATE teams SET stripe_customer_id`).WillReturnError(errors.New("boom"))
	require.ErrorContains(t, UpdateRazorpaySubscriptionID(ctx, db2, uuid.New(), "sub"), "boom")
}

func TestUpdatePlanTier_Branches(t *testing.T) {
	ctx := context.Background()
	db, mock := newMock(t)
	mock.ExpectExec(`UPDATE teams SET plan_tier`).WillReturnResult(sqlmock.NewResult(0, 1))
	require.NoError(t, UpdatePlanTier(ctx, db, uuid.New(), "pro"))
	db2, mock2 := newMock(t)
	mock2.ExpectExec(`UPDATE teams SET plan_tier`).WillReturnError(errors.New("boom"))
	require.ErrorContains(t, UpdatePlanTier(ctx, db2, uuid.New(), "pro"), "boom")
}

func TestUpgradeTeamAllTiersWithSubscription_Branches(t *testing.T) {
	ctx := context.Background()

	// begin error
	db, mock := newMock(t)
	mock.ExpectBegin().WillReturnError(errors.New("beginerr"))
	require.ErrorContains(t, UpgradeTeamAllTiers(ctx, db, uuid.New(), "pro"), "beginerr")

	// team update error
	db2, mock2 := newMock(t)
	mock2.ExpectBegin()
	mock2.ExpectExec(`UPDATE teams SET plan_tier`).WillReturnError(errors.New("upderr"))
	mock2.ExpectRollback()
	require.ErrorContains(t, UpgradeTeamAllTiers(ctx, db2, uuid.New(), "pro"), "upderr")

	// rows-affected error
	db2b, mock2b := newMock(t)
	mock2b.ExpectBegin()
	mock2b.ExpectExec(`UPDATE teams SET plan_tier`).WillReturnResult(sqlmock.NewErrorResult(errors.New("raerr")))
	mock2b.ExpectRollback()
	require.ErrorContains(t, UpgradeTeamAllTiers(ctx, db2b, uuid.New(), "pro"), "raerr")

	// 0 rows -> team not found
	db3, mock3 := newMock(t)
	mock3.ExpectBegin()
	mock3.ExpectExec(`UPDATE teams SET plan_tier`).WillReturnResult(sqlmock.NewResult(0, 0))
	mock3.ExpectRollback()
	var nf *ErrTeamNotFound
	require.ErrorAs(t, UpgradeTeamAllTiers(ctx, db3, uuid.New(), "pro"), &nf)

	// sub_id write error
	db4, mock4 := newMock(t)
	mock4.ExpectBegin()
	mock4.ExpectExec(`UPDATE teams SET plan_tier`).WillReturnResult(sqlmock.NewResult(0, 1))
	mock4.ExpectExec(`UPDATE teams SET stripe_customer_id`).WillReturnError(errors.New("suberr"))
	mock4.ExpectRollback()
	require.ErrorContains(t, UpgradeTeamAllTiersWithSubscription(ctx, db4, uuid.New(), "pro", "sub"), "suberr")

	// resources elevate error
	db5, mock5 := newMock(t)
	mock5.ExpectBegin()
	mock5.ExpectExec(`UPDATE teams SET plan_tier`).WillReturnResult(sqlmock.NewResult(0, 1))
	mock5.ExpectExec(`UPDATE resources`).WillReturnError(errors.New("reserr"))
	mock5.ExpectRollback()
	require.ErrorContains(t, UpgradeTeamAllTiers(ctx, db5, uuid.New(), "pro"), "reserr")

	// deployments elevate error
	db6, mock6 := newMock(t)
	mock6.ExpectBegin()
	mock6.ExpectExec(`UPDATE teams SET plan_tier`).WillReturnResult(sqlmock.NewResult(0, 1))
	mock6.ExpectExec(`UPDATE resources`).WillReturnResult(sqlmock.NewResult(0, 1))
	mock6.ExpectExec(`UPDATE deployments`).WillReturnError(errors.New("deperr"))
	mock6.ExpectRollback()
	require.ErrorContains(t, UpgradeTeamAllTiers(ctx, db6, uuid.New(), "pro"), "deperr")

	// stacks elevate error
	db7, mock7 := newMock(t)
	mock7.ExpectBegin()
	mock7.ExpectExec(`UPDATE teams SET plan_tier`).WillReturnResult(sqlmock.NewResult(0, 1))
	mock7.ExpectExec(`UPDATE resources`).WillReturnResult(sqlmock.NewResult(0, 1))
	mock7.ExpectExec(`UPDATE deployments`).WillReturnResult(sqlmock.NewResult(0, 1))
	mock7.ExpectExec(`UPDATE stacks`).WillReturnError(errors.New("stkerr"))
	mock7.ExpectRollback()
	require.ErrorContains(t, UpgradeTeamAllTiers(ctx, db7, uuid.New(), "pro"), "stkerr")

	// commit error
	db8, mock8 := newMock(t)
	mock8.ExpectBegin()
	mock8.ExpectExec(`UPDATE teams SET plan_tier`).WillReturnResult(sqlmock.NewResult(0, 1))
	mock8.ExpectExec(`UPDATE resources`).WillReturnResult(sqlmock.NewResult(0, 1))
	mock8.ExpectExec(`UPDATE deployments`).WillReturnResult(sqlmock.NewResult(0, 1))
	mock8.ExpectExec(`UPDATE stacks`).WillReturnResult(sqlmock.NewResult(0, 1))
	mock8.ExpectCommit().WillReturnError(errors.New("commiterr"))
	require.ErrorContains(t, UpgradeTeamAllTiers(ctx, db8, uuid.New(), "pro"), "commiterr")

	// happy with subscription id
	db9, mock9 := newMock(t)
	mock9.ExpectBegin()
	mock9.ExpectExec(`UPDATE teams SET plan_tier`).WillReturnResult(sqlmock.NewResult(0, 1))
	mock9.ExpectExec(`UPDATE teams SET stripe_customer_id`).WillReturnResult(sqlmock.NewResult(0, 1))
	mock9.ExpectExec(`UPDATE resources`).WillReturnResult(sqlmock.NewResult(0, 1))
	mock9.ExpectExec(`UPDATE deployments`).WillReturnResult(sqlmock.NewResult(0, 1))
	mock9.ExpectExec(`UPDATE stacks`).WillReturnResult(sqlmock.NewResult(0, 1))
	mock9.ExpectCommit()
	require.NoError(t, UpgradeTeamAllTiersWithSubscription(ctx, db9, uuid.New(), "pro", "sub"))
}

func TestGetTeamByRazorpaySubscriptionID_Branches(t *testing.T) {
	ctx := context.Background()
	db, mock := newMock(t)
	mock.ExpectQuery(`WHERE stripe_customer_id`).WillReturnRows(teamRow())
	_, err := GetTeamByRazorpaySubscriptionID(ctx, db, "sub")
	require.NoError(t, err)

	db2, mock2 := newMock(t)
	mock2.ExpectQuery(`WHERE stripe_customer_id`).WillReturnError(errNoRows())
	var nf *ErrTeamNotFound
	_, err = GetTeamByRazorpaySubscriptionID(ctx, db2, "sub")
	require.ErrorAs(t, err, &nf)

	db3, mock3 := newMock(t)
	mock3.ExpectQuery(`WHERE stripe_customer_id`).WillReturnError(errors.New("boom"))
	_, err = GetTeamByRazorpaySubscriptionID(ctx, db3, "sub")
	require.ErrorContains(t, err, "boom")
}

func TestLinkGitHubID_Branches(t *testing.T) {
	ctx := context.Background()
	db, mock := newMock(t)
	mock.ExpectExec(`UPDATE users SET github_id`).WillReturnResult(sqlmock.NewResult(0, 1))
	require.NoError(t, LinkGitHubID(ctx, db, uuid.New(), "gh"))

	db2, mock2 := newMock(t)
	mock2.ExpectExec(`UPDATE users SET github_id`).WillReturnError(errors.New("boom"))
	require.ErrorContains(t, LinkGitHubID(ctx, db2, uuid.New(), "gh"), "boom")

	db3, mock3 := newMock(t)
	mock3.ExpectExec(`UPDATE users SET github_id`).WillReturnResult(sqlmock.NewResult(0, 0))
	require.ErrorContains(t, LinkGitHubID(ctx, db3, uuid.New(), "gh"), "not updated")

	db4, mock4 := newMock(t)
	mock4.ExpectExec(`UPDATE users SET github_id`).WillReturnResult(sqlmock.NewErrorResult(errors.New("raerr")))
	require.ErrorContains(t, LinkGitHubID(ctx, db4, uuid.New(), "gh"), "raerr")
}

func TestLinkGoogleID_Branches(t *testing.T) {
	ctx := context.Background()
	db, mock := newMock(t)
	mock.ExpectExec(`UPDATE users SET google_id`).WillReturnResult(sqlmock.NewResult(0, 1))
	require.NoError(t, LinkGoogleID(ctx, db, uuid.New(), "goog"))

	db2, mock2 := newMock(t)
	mock2.ExpectExec(`UPDATE users SET google_id`).WillReturnError(errors.New("boom"))
	require.ErrorContains(t, LinkGoogleID(ctx, db2, uuid.New(), "goog"), "boom")

	db3, mock3 := newMock(t)
	mock3.ExpectExec(`UPDATE users SET google_id`).WillReturnResult(sqlmock.NewResult(0, 0))
	require.ErrorContains(t, LinkGoogleID(ctx, db3, uuid.New(), "goog"), "not updated")

	db4, mock4 := newMock(t)
	mock4.ExpectExec(`UPDATE users SET google_id`).WillReturnResult(sqlmock.NewErrorResult(errors.New("raerr")))
	require.ErrorContains(t, LinkGoogleID(ctx, db4, uuid.New(), "goog"), "raerr")
}
