package handlers_test

// provision_helper_provarms_test.go — pin the remaining uncovered branches of
// the small pure helpers in provision_helper.go / family_bulk_twin.go that the
// HTTP-level suites don't exercise to 100%.

import (
	"database/sql"
	"testing"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/stretchr/testify/assert"
	"github.com/valyala/fasthttp"

	"instant.dev/internal/handlers"
)

func TestFormatDuration_AllBranches(t *testing.T) {
	cases := []struct {
		d    time.Duration
		want string
	}{
		{-time.Second, "less than a minute"},
		{0, "less than a minute"},
		{30 * time.Second, "0m"},      // < 1m rounds to 0m (m branch)
		{45 * time.Minute, "45m"},     // minutes only
		{2 * time.Hour, "2h"},         // hours only, no minutes
		{90 * time.Minute, "1h 30m"},  // hours + minutes
		{25 * time.Hour, "25h"},       // > 24h, no remainder
		{26*time.Hour + 5*time.Minute, "26h 5m"},
	}
	for _, tc := range cases {
		assert.Equalf(t, tc.want, handlers.FormatDurationForTest(tc.d), "formatDuration(%v)", tc.d)
	}
}

func TestNullStrOrEmpty(t *testing.T) {
	assert.Equal(t, "", handlers.NullStrOrEmptyForTest(sql.NullString{Valid: false}))
	assert.Equal(t, "", handlers.NullStrOrEmptyForTest(sql.NullString{String: "ignored", Valid: false}))
	assert.Equal(t, "hello", handlers.NullStrOrEmptyForTest(sql.NullString{String: "hello", Valid: true}))
}

// newTestCtx returns a throwaway *fiber.Ctx + a release func for unit-testing
// helpers that take a context but don't depend on request state.
func newTestCtx(t *testing.T) (*fiber.Ctx, func()) {
	t.Helper()
	app := fiber.New()
	fctx := &fasthttp.RequestCtx{}
	c := app.AcquireCtx(fctx)
	return c, func() { app.ReleaseCtx(c) }
}

func TestSanitizeNameForRequest_CleanName(t *testing.T) {
	c, release := newTestCtx(t)
	defer release()
	got, err := handlers.SanitizeNameForRequestForTest(c, "My App DB")
	assert.NoError(t, err)
	assert.Equal(t, "My App DB", got)
}

func TestSanitizeNameForRequest_InvalidUTF8_WritesError(t *testing.T) {
	c, release := newTestCtx(t)
	defer release()
	// Invalid UTF-8 byte sequence → sanitizeName returns errInvalidUTF8Name →
	// sanitizeNameForRequest writes a 400 invalid_name response + returns
	// ErrResponseWritten.
	_, err := handlers.SanitizeNameForRequestForTest(c, "bad\xff\xfename")
	assert.Error(t, err)
	assert.Equal(t, fiber.StatusBadRequest, c.Response().StatusCode())
}
