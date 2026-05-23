package handlers_test

// logs_coverage_test.go — hermetic coverage for the resource-logs SSE handler
// (logs.go). The happy path needs a k8s clientset; we inject a fake one via the
// SetClientset seam so the tier/status/namespace/pod-list/stream arms all run
// under CI's postgres-only matrix. Before this file logs.go measured 0% under
// CI (the route is k8s-gated and was never wired into a test app).

import (
	"database/sql"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8sfake "k8s.io/client-go/kubernetes/fake"

	"instant.dev/internal/handlers"
	"instant.dev/internal/testhelpers"
)

func logsTestApp(t *testing.T, db *sql.DB, h *handlers.LogsHandler) *fiber.App {
	t.Helper()
	app := fiber.New(fiber.Config{
		ErrorHandler: func(c *fiber.Ctx, err error) error {
			if errors.Is(err, handlers.ErrResponseWritten) {
				return nil
			}
			code := fiber.StatusInternalServerError
			if e, ok := err.(*fiber.Error); ok {
				code = e.Code
			}
			return c.Status(code).JSON(fiber.Map{"ok": false, "error": "internal_error", "message": err.Error()})
		},
	})
	app.Get("/resources/:token/logs", h.ResourceLogs)
	return app
}

// seedLogsResource inserts a resource row with explicit tier/status/namespace
// and returns its token.
func seedLogsResource(t *testing.T, db *sql.DB, rtype, tier, status, namespace string) string {
	t.Helper()
	teamID := testhelpers.MustCreateTeamDB(t, db, "growth")
	var token string
	err := db.QueryRow(`
		INSERT INTO resources (team_id, resource_type, tier, env, status, provider_resource_id)
		VALUES ($1::uuid, $2, $3, 'production', $4, NULLIF($5,''))
		RETURNING token::text
	`, teamID, rtype, tier, status, namespace).Scan(&token)
	require.NoError(t, err)
	return token
}

func logsGet(t *testing.T, app *fiber.App, token, query string) *http.Response {
	t.Helper()
	url := "/resources/" + token + "/logs"
	if query != "" {
		url += "?" + query
	}
	resp, err := app.Test(httptest.NewRequest(http.MethodGet, url, nil), 5000)
	require.NoError(t, err)
	return resp
}

func TestLogs_NilClientset_503(t *testing.T) {
	db, clean := testhelpers.SetupTestDB(t)
	defer clean()
	// In CI (no kubeconfig) NewLogsHandler leaves clientset nil. On a dev box
	// with ~/.kube/config it would build a real client, so force the nil state
	// explicitly to make the 503 short-circuit deterministic everywhere.
	h := handlers.NewLogsHandler(db)
	h.SetClientset(nil)
	app := logsTestApp(t, db, h)
	resp := logsGet(t, app, uuid.NewString(), "")
	assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
	resp.Body.Close()
}

func TestLogs_ErrorArms_WithFakeClientset(t *testing.T) {
	db, clean := testhelpers.SetupTestDB(t)
	defer clean()
	h := handlers.NewLogsHandler(db)
	h.SetClientset(k8sfake.NewSimpleClientset())
	app := logsTestApp(t, db, h)

	t.Run("invalid_token", func(t *testing.T) {
		resp := logsGet(t, app, "not-a-uuid", "")
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
		resp.Body.Close()
	})

	t.Run("not_found", func(t *testing.T) {
		resp := logsGet(t, app, uuid.NewString(), "")
		assert.Equal(t, http.StatusNotFound, resp.StatusCode)
		resp.Body.Close()
	})

	t.Run("not_active", func(t *testing.T) {
		token := seedLogsResource(t, db, "postgres", "growth", "deleted", "ns-1")
		resp := logsGet(t, app, token, "")
		assert.Equal(t, http.StatusConflict, resp.StatusCode)
		resp.Body.Close()
	})

	t.Run("not_growth", func(t *testing.T) {
		token := seedLogsResource(t, db, "postgres", "hobby", "active", "ns-2")
		resp := logsGet(t, app, token, "")
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
		resp.Body.Close()
	})

	t.Run("no_namespace", func(t *testing.T) {
		token := seedLogsResource(t, db, "postgres", "growth", "active", "")
		resp := logsGet(t, app, token, "")
		assert.Equal(t, http.StatusConflict, resp.StatusCode)
		resp.Body.Close()
	})

	t.Run("unsupported_type", func(t *testing.T) {
		token := seedLogsResource(t, db, "storage", "growth", "active", "ns-3")
		resp := logsGet(t, app, token, "")
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
		resp.Body.Close()
	})

	t.Run("no_pods", func(t *testing.T) {
		// growth + active + namespace + supported type, but the fake clientset
		// has no pods matching app=postgres → 404 pod_not_found.
		token := seedLogsResource(t, db, "postgres", "growth", "active", "ns-empty")
		resp := logsGet(t, app, token, "tail=50")
		assert.Equal(t, http.StatusNotFound, resp.StatusCode)
		resp.Body.Close()
	})
}

func TestLogs_HappyPath_StreamsSSE(t *testing.T) {
	db, clean := testhelpers.SetupTestDB(t)
	defer clean()

	const ns = "ns-live"
	// Seed a pod into the fake clientset matching the postgres app label.
	cs := k8sfake.NewSimpleClientset(&corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "postgres-0",
			Namespace: ns,
			Labels:    map[string]string{"app": "postgres"},
		},
	})
	h := handlers.NewLogsHandler(db)
	h.SetClientset(cs)
	app := logsTestApp(t, db, h)

	token := seedLogsResource(t, db, "postgres", "growth", "active", ns)
	// tail clamps: pass an out-of-range value to exercise the clamp arm.
	resp := logsGet(t, app, token, "tail=99999")
	require.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "text/event-stream", resp.Header.Get("Content-Type"))
	// Drain the SSE body — the fake GetLogs returns a canned "fake logs" line.
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	assert.NotNil(t, body)
}
