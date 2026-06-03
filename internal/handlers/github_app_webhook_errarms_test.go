package handlers

// github_app_webhook_errarms_test.go — sqlmock white-box coverage for the
// defensive error arms in handleInstallation/handlePush that a real-DB
// integration test can't reach (the DB op succeeds normally there): the
// installation delete/suspend/unsuspend slog.Warn arms, the generic
// enqueue-error arm, and the last-deploy-update slog.Warn arm. Reuses
// whSignBody/whPost from github_app_webhook_whitebox_test.go.

import (
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"

	"instant.dev/internal/config"
)

func newErrArmApp(t *testing.T) (*fiber.App, sqlmock.Sqlmock, func()) {
	t.Helper()
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	h := NewGitHubAppWebhookHandler(db, nil, &config.Config{
		GitHubAppEnabled:       true,
		GitHubAppWebhookSecret: "whsec",
	}, nil)
	app := fiber.New()
	app.Post("/wh", h.Receive)
	return app, mock, func() { _ = db.Close() }
}

// installation op errors → slog.Warn arm, still 200 (covers delete/suspend/unsuspend).
func TestGitHubAppWebhook_InstallationOpErrors(t *testing.T) {
	cases := []struct {
		action   string
		expectFn func(sqlmock.Sqlmock)
	}{
		{"deleted", func(m sqlmock.Sqlmock) {
			m.ExpectExec(`DELETE FROM github_installations`).WillReturnError(errors.New("boom"))
		}},
		{"suspend", func(m sqlmock.Sqlmock) {
			m.ExpectExec(`UPDATE github_installations SET suspended_at`).WillReturnError(errors.New("boom"))
		}},
		{"unsuspend", func(m sqlmock.Sqlmock) {
			m.ExpectExec(`UPDATE github_installations SET suspended_at`).WillReturnError(errors.New("boom"))
		}},
	}
	for _, tc := range cases {
		t.Run(tc.action, func(t *testing.T) {
			app, mock, done := newErrArmApp(t)
			defer done()
			tc.expectFn(mock)
			body := []byte(`{"action":"` + tc.action + `","installation":{"id":42,"account":{"login":"acme"}}}`)
			resp := whPost(t, app, body, "installation", whSignBody("whsec", body), "")
			if resp.StatusCode != http.StatusOK {
				t.Errorf("%s op error must still 200, got %d", tc.action, resp.StatusCode)
			}
		})
	}
}

// pushMatchExpectations stages the installation + connection lookups so a push
// reaches the enqueue step with exactly one matching connection.
func pushMatchExpectations(mock sqlmock.Sqlmock, team uuid.UUID, connID uuid.UUID, installID int64) {
	mock.ExpectQuery(`FROM github_installations WHERE installation_id`).
		WillReturnRows(sqlmock.NewRows([]string{
			"installation_id", "team_id", "account_login", "suspended_at", "created_at", "updated_at",
		}).AddRow(installID, team, "acme", nil, time.Now(), time.Now()))
	mock.ExpectQuery(`FROM app_github_connections WHERE github_repo`).
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "app_id", "team_id", "github_repo", "branch", "webhook_secret",
			"installation_id", "created_at", "last_deploy_at", "last_commit_sha",
		}).AddRow(connID, uuid.New(), team, "owner/repo", "main", "sec", installID, time.Now(), nil, nil))
}

// pushBody42 is a valid push payload for installation_id 42 with a 40-hex SHA.
func pushBody42() []byte {
	return []byte(`{"repository":{"full_name":"owner/repo"},"ref":"refs/heads/main","after":"a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0","installation":{"id":42}}`)
}

// enqueue returns a generic (non-rate-limit) error → error arm, 202 enqueued:0.
func TestGitHubAppWebhook_Push_EnqueueError(t *testing.T) {
	app, mock, done := newErrArmApp(t)
	defer done()
	team := uuid.New()
	pushMatchExpectations(mock, team, uuid.New(), 42)
	// CountAndEnqueueGitHubDeployLocked: BeginTx fails → generic error (not rate-limited).
	mock.ExpectBegin().WillReturnError(errors.New("begin boom"))

	resp := whPost(t, app, pushBody42(), "push", whSignBody("whsec", pushBody42()), "")
	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("want 202 (matched but enqueue errored), got %d", resp.StatusCode)
	}
}

// enqueue succeeds but UpdateGitHubConnectionLastDeploy errors → slog.Warn arm,
// still counts as enqueued, 202.
func TestGitHubAppWebhook_Push_LastDeployUpdateError(t *testing.T) {
	app, mock, done := newErrArmApp(t)
	defer done()
	team := uuid.New()
	connID := uuid.New()
	pushMatchExpectations(mock, team, connID, 42)
	// Full successful enqueue tx.
	mock.ExpectBegin()
	mock.ExpectQuery(`SELECT id FROM app_github_connections WHERE id = .* FOR UPDATE`).
		WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(connID))
	mock.ExpectQuery(`SELECT COUNT\(\*\) FROM pending_github_deploys`).
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(0))
	mock.ExpectQuery(`INSERT INTO pending_github_deploys`).
		WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(uuid.New()))
	mock.ExpectCommit()
	// last-deploy bump fails → warn arm.
	mock.ExpectExec(`UPDATE app_github_connections`).WillReturnError(errors.New("update boom"))

	resp := whPost(t, app, pushBody42(), "push", whSignBody("whsec", pushBody42()), "")
	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("want 202, got %d", resp.StatusCode)
	}
}
