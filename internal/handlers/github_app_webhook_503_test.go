package handlers

// github_app_webhook_503_test.go — covers handlePush's connection-lookup error
// arm (FindConnectionsByRepoBranch fails after the installation lookup
// succeeds → 503). Driven with sqlmock so the two sequential queries can return
// row-then-error deterministically (impossible to stage with a single real DB).
// Reuses whSignBody / whPost from github_app_webhook_whitebox_test.go.

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

func TestGitHubAppWebhook_Push_ConnectionLookupError_503(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()

	// 1) installation lookup succeeds (not suspended).
	mock.ExpectQuery(`FROM github_installations WHERE installation_id`).
		WillReturnRows(sqlmock.NewRows([]string{
			"installation_id", "team_id", "account_login", "suspended_at", "created_at", "updated_at",
		}).AddRow(int64(42), uuid.New(), "acme", nil, time.Now(), time.Now()))
	// 2) connection lookup errors → handler returns 503.
	mock.ExpectQuery(`FROM app_github_connections WHERE github_repo`).
		WillReturnError(errors.New("connection lookup boom"))

	h := NewGitHubAppWebhookHandler(db, nil, &config.Config{
		GitHubAppEnabled:       true,
		GitHubAppWebhookSecret: "whsec",
	}, nil)
	app := fiber.New()
	app.Post("/wh", h.Receive)

	body := []byte(`{"repository":{"full_name":"owner/repo"},"ref":"refs/heads/main","after":"a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0","installation":{"id":42}}`)
	resp := whPost(t, app, body, "push", whSignBody("whsec", body), "")
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("connection lookup error must 503, got %d", resp.StatusCode)
	}
}
