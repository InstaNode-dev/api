package middleware_test

// idempotency_inflight_test.go — BugBash 2026-06-02 #21 regression.
//
// The middleware used to do GET(miss) → run handler → SET, with no atomic
// reservation between the GET and the SET. Two requests carrying the same
// Idempotency-Key (or the same body-fingerprint) that raced in that window
// both saw redis.Nil and both ran the handler — double-creating real
// backend resources for the authenticated provision paths that have no other
// per-burst dedup gate.
//
// The fix writes an in-flight reservation marker (SETNX) the instant a miss
// begins running the handler. A concurrent same-key request reads the marker
// and returns 409 idempotency_key_in_progress instead of re-running the
// handler. These tests hold request A inside the handler (blocked on a
// channel) so request B is guaranteed to observe A's live reservation.

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/gofiber/fiber/v2"
	"github.com/stretchr/testify/assert"

	"instant.dev/internal/middleware"
	"instant.dev/internal/testhelpers"
)

// newBlockingInflightApp builds a Fiber app whose POST /test handler signals
// `entered` once it begins and then blocks on `release`, so a test can hold
// one request in flight. ran counts handler invocations.
func newBlockingInflightApp(t *testing.T, ran *int32, entered, release chan struct{}) (*fiber.App, func()) {
	t.Helper()
	rdb, cleanup := testhelpers.SetupTestRedis(t)
	app := fiber.New()
	app.Use(middleware.Fingerprint())
	app.Post("/test", middleware.Idempotency(rdb, "inflight.endpoint"), func(c *fiber.Ctx) error {
		atomic.AddInt32(ran, 1)
		entered <- struct{}{}
		<-release
		return c.Status(fiber.StatusCreated).JSON(fiber.Map{"ok": true})
	})
	return app, cleanup
}

// fireBlocking sends a request that will block in the handler, returning its
// response on the done channel once released.
func fireBlocking(app *fiber.App, ip, key, body string, done chan *http.Response) {
	req := httptest.NewRequest(http.MethodPost, "/test", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Forwarded-For", ip)
	if key != "" {
		req.Header.Set("Idempotency-Key", key)
	}
	resp, _ := app.Test(req, 10000)
	done <- resp
}

// TestIdempotency_ExplicitKey_ConcurrentInFlight_Returns409 — a second request
// carrying the same Idempotency-Key while the first is still running the
// handler gets 409 idempotency_key_in_progress and does NOT re-run the handler.
func TestIdempotency_ExplicitKey_ConcurrentInFlight_Returns409(t *testing.T) {
	var ran int32
	entered := make(chan struct{})
	release := make(chan struct{})
	app, clean := newBlockingInflightApp(t, &ran, entered, release)
	defer clean()

	ip := uniqueTestIP("inflight-explicit")
	key := "inflight-key-" + ip
	body := `{"x":1}`

	aDone := make(chan *http.Response, 1)
	go fireBlocking(app, ip, key, body, aDone)
	<-entered // A is in the handler; its reservation marker is live in Redis.

	// B: same key, arrives mid-flight → 409 in_progress, handler not re-run.
	respB := postWithIdem(t, app, "/test", ip, key, body)
	assert.Equal(t, http.StatusConflict, respB.StatusCode)
	bodyB := readBody(t, respB)
	assert.Contains(t, bodyB, "idempotency_key_in_progress")
	assert.Contains(t, bodyB, "request_id")

	close(release) // let A finish.
	respA := <-aDone
	assert.Equal(t, http.StatusCreated, respA.StatusCode)
	respA.Body.Close()
	assert.Equal(t, int32(1), atomic.LoadInt32(&ran),
		"handler must run exactly once despite the concurrent same-key duplicate")
}

// TestIdempotency_Fingerprint_ConcurrentInFlight_Returns409 — the same race on
// the no-header body-fingerprint path: a concurrent identical-body request
// observes the in-flight marker and 409s instead of double-running.
func TestIdempotency_Fingerprint_ConcurrentInFlight_Returns409(t *testing.T) {
	var ran int32
	entered := make(chan struct{})
	release := make(chan struct{})
	app, clean := newBlockingInflightApp(t, &ran, entered, release)
	defer clean()

	ip := uniqueTestIP("inflight-fp")
	body := `{"x":1}`

	aDone := make(chan *http.Response, 1)
	go fireBlocking(app, ip, "", body, aDone) // no key → fingerprint path
	<-entered

	// B: no key, identical body + ip + route → same fingerprint → 409.
	respB := postWithIdem(t, app, "/test", ip, "", body)
	assert.Equal(t, http.StatusConflict, respB.StatusCode)
	bodyB := readBody(t, respB)
	assert.Contains(t, bodyB, "idempotency_key_in_progress")
	assert.Equal(t, "fingerprint", respB.Header.Get("X-Idempotency-Source"))

	close(release)
	respA := <-aDone
	assert.Equal(t, http.StatusCreated, respA.StatusCode)
	respA.Body.Close()
	assert.Equal(t, int32(1), atomic.LoadInt32(&ran),
		"handler must run exactly once despite the concurrent same-fingerprint duplicate")
}
