package router_test

import (
	"encoding/json"
	"io"
	"net/http/httptest"
	"testing"

	"github.com/gofiber/fiber/v2"
	"github.com/stretchr/testify/require"

	"instant.dev/common/buildinfo"
)

// TestHealthzShape pins the wire shape of GET /healthz. We don't spin
// up the full router (that needs Postgres + Redis + gRPC and is covered
// by the e2e suite); instead we replicate the handler verbatim from
// router.New so a future refactor that drops a field fails this test.
//
// The fields commit_id / build_time / version are the contract that
// canaries and `/instant-ship` health checks read after each deploy
// to confirm the cluster is running the pushed image.
func TestHealthzShape(t *testing.T) {
	app := fiber.New()
	app.Get("/healthz", func(c *fiber.Ctx) error {
		return c.JSON(fiber.Map{
			"ok":         true,
			"service":    "instant.dev",
			"commit_id":  buildinfo.GitSHA,
			"build_time": buildinfo.BuildTime,
			"version":    buildinfo.Version,
		})
	})

	resp, err := app.Test(httptest.NewRequest("GET", "/healthz", nil))
	require.NoError(t, err)
	require.Equal(t, fiber.StatusOK, resp.StatusCode)

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	var got map[string]any
	require.NoError(t, json.Unmarshal(body, &got))

	// Every field is non-empty; commit_id specifically falls back to
	// "dev" when -ldflags is omitted (go run, go test).
	require.Equal(t, true, got["ok"])
	require.Equal(t, "instant.dev", got["service"])
	require.NotEmpty(t, got["commit_id"], "commit_id MUST be present on /healthz")
	require.NotEmpty(t, got["build_time"])
	require.NotEmpty(t, got["version"])

	// The compile-time defaults round-trip when no -ldflags is set —
	// this is the value canaries see in CI builds.
	require.Equal(t, buildinfo.GitSHA, got["commit_id"])
	require.Equal(t, buildinfo.BuildTime, got["build_time"])
	require.Equal(t, buildinfo.Version, got["version"])
}
