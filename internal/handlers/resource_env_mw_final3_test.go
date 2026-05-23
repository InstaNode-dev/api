package handlers_test

// resource_env_mw_final3_test.go — FINAL serial pass #3. Covers all three arms
// of ResourceEnvByTokenForMiddleware (env_policy_helpers.go):
//   - non-UUID :id → ("", nil)               (line 32)
//   - token not found → ("", nil) fail-open   (line 38)
//   - real resource → (env, nil) happy        (line 40)

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"instant.dev/internal/handlers"
	"instant.dev/internal/testhelpers"
)

func TestResourceEnvByTokenMWFinal3_Arms(t *testing.T) {
	db, clean := testhelpers.SetupTestDB(t)
	defer clean()
	teamID := testhelpers.MustCreateTeamDB(t, db, "pro")

	// Seed a real resource so the happy arm returns its env.
	var token string
	require.NoError(t, db.QueryRowContext(context.Background(),
		`INSERT INTO resources (team_id, resource_type, tier, env, status)
		 VALUES ($1::uuid, 'postgres', 'pro', 'staging', 'active')
		 RETURNING token::text`, teamID).Scan(&token))

	app := fiber.New()
	app.Get("/r/:id", func(c *fiber.Ctx) error {
		env, err := handlers.ResourceEnvByTokenForMiddleware(c, db)
		if err != nil {
			return c.Status(http.StatusInternalServerError).SendString("err")
		}
		return c.SendString(env)
	})

	get := func(id string) (int, string) {
		resp, err := app.Test(httptest.NewRequest(http.MethodGet, "/r/"+id, nil), 5000)
		require.NoError(t, err)
		defer resp.Body.Close()
		buf := make([]byte, 256)
		n, _ := resp.Body.Read(buf)
		return resp.StatusCode, string(buf[:n])
	}

	// bad UUID → "" (line 32).
	_, body := get("not-a-uuid")
	assert.Empty(t, body)

	// not found → "" fail-open (line 38).
	_, body = get(uuid.NewString())
	assert.Empty(t, body)

	// real resource → its env (line 40).
	_, body = get(token)
	assert.Equal(t, "staging", body)
}
