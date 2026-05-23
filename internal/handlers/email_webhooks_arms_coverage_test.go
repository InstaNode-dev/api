package handlers_test

// email_webhooks_arms_coverage_test.go — covers the remaining Brevo inbound
// webhook arms (email_webhooks.go) the existing suite leaves at ~77%:
// invalid-payload (bad JSON), missing-email skip, and the DB-insert-failure
// fail-open arm. All via sqlmock — no live DB needed.

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"instant.dev/internal/config"
	"instant.dev/internal/handlers"
)

func TestEmailWebhook_Brevo_InvalidPayload_400(t *testing.T) {
	db, _, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()
	cfg := &config.Config{BrevoWebhookSecret: testBrevoSecret}
	h := handlers.NewEmailWebhookHandler(db, cfg)
	app := emailWebhookApp(t, h)

	payload := []byte(`{not valid json`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/email/webhook/brevo", bytes.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Sib-Signature", signBrevo(t, testBrevoSecret, payload))
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	resp.Body.Close()
}

func TestEmailWebhook_Brevo_MissingEmail_SkipNoInsert(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()
	// No INSERT expected — missing email short-circuits to 200 skip.
	cfg := &config.Config{BrevoWebhookSecret: testBrevoSecret}
	h := handlers.NewEmailWebhookHandler(db, cfg)
	app := emailWebhookApp(t, h)

	payload := []byte(`{"event":"hard_bounce","email":""}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/email/webhook/brevo", bytes.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Sib-Signature", signBrevo(t, testBrevoSecret, payload))
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	resp.Body.Close()
	assert.NoError(t, mock.ExpectationsWereMet(), "missing-email path must not touch DB")
}

func TestEmailWebhook_Brevo_InsertFails_FailOpen200(t *testing.T) {
	db, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherRegexp))
	require.NoError(t, err)
	defer db.Close()
	mock.ExpectQuery(`INSERT INTO email_events`).
		WillReturnError(assertAnError())
	cfg := &config.Config{BrevoWebhookSecret: testBrevoSecret}
	h := handlers.NewEmailWebhookHandler(db, cfg)
	app := emailWebhookApp(t, h)

	payload := []byte(`{"event":"hard_bounce","email":"x@example.com","reason":"r","message-id":"<m@x>"}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/email/webhook/brevo", bytes.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Sib-Signature", signBrevo(t, testBrevoSecret, payload))
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	// DB blip → still 200 (fail-open so Brevo doesn't retry-storm).
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	resp.Body.Close()
}

func assertAnError() error { return errSentinel }

var errSentinel = &sentinelErr{}

type sentinelErr struct{}

func (*sentinelErr) Error() string { return "simulated db failure" }
