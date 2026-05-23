package middleware_test

// coverage_push3_ext_test.go — black-box top-up: PopulateTeamRole DB-error
// (non-ErrNoRows) branch, which logs a warning and falls through to Next().

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	sqlmock "github.com/DATA-DOG/go-sqlmock"
	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"instant.dev/internal/middleware"
)

func TestPopulateTeamRole_QueryErrorIsTolerated(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()
	middleware.SetRoleLookupDB(db)
	defer middleware.SetRoleLookupDB(nil)

	uid := uuid.NewString()
	tid := uuid.NewString()
	// A real DB error (NOT sql.ErrNoRows) → logs warn + Next(), no role local.
	mock.ExpectQuery("SELECT role FROM users").
		WithArgs(uid, tid).
		WillReturnError(errors.New("connection reset by peer"))

	app := fiber.New()
	app.Use(func(c *fiber.Ctx) error {
		c.Locals(middleware.LocalKeyUserID, uid)
		c.Locals(middleware.LocalKeyTeamID, tid)
		return c.Next()
	})
	app.Use(middleware.PopulateTeamRole())
	app.Get("/role", func(c *fiber.Ctx) error {
		assert.Empty(t, middleware.GetTeamRole(c), "role unset on DB error (fail-open)")
		return c.SendStatus(fiber.StatusOK)
	})
	resp, err := app.Test(httptest.NewRequest(http.MethodGet, "/role", nil), 3000)
	require.NoError(t, err)
	resp.Body.Close()
	assert.NoError(t, mock.ExpectationsWereMet())
}
