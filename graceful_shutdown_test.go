package main

// graceful_shutdown_test.go — MR-P0-7 regression guard (BugBash 2026-05-20).
//
// Before this fix, `app.Listen(":"+cfg.Port)` blocked with no signal handler:
// SIGTERM (every rolling deploy, every HPA scale-down, every node drain) RST'd
// every in-flight request including multi-minute provisions. The fix wraps the
// Listen in runServerWithGracefulShutdown, which traps SIGTERM and calls
// app.ShutdownWithTimeout to drain.
//
// This test asserts the drain contract: an in-flight request still completes
// after SIGTERM arrives, and the helper returns nil for a clean shutdown.

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"instant.dev/internal/handlers"
	"instant.dev/internal/router"
)

// pickFreePort returns a TCP port number currently free on localhost. Lets
// the test bind a real listener so we can exercise Fiber's network drain
// path, not just a mock — graceful shutdown semantics live in the listener,
// not in a fake.
func pickFreePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	port := l.Addr().(*net.TCPAddr).Port
	require.NoError(t, l.Close())
	return port
}

// TestRunServerWithGracefulShutdown_DrainsInflight is the MR-P0-7 guard.
// A request mid-flight when SIGTERM arrives MUST complete successfully, and
// runServerWithGracefulShutdown MUST return nil for a clean drain.
//
// Without the fix (bare app.Listen), the process dies on SIGTERM and the
// in-flight request sees a connection reset — captured here as a transport
// error from http.DefaultClient.Do.
func TestRunServerWithGracefulShutdown_DrainsInflight(t *testing.T) {
	port := pickFreePort(t)
	app := fiber.New(fiber.Config{DisableStartupMessage: true})

	// "started" tells the main goroutine "the handler is running — fire SIGTERM
	// NOW." The handler then waits a beat before responding so the SIGTERM
	// lands while the request is in-flight, which is the exact MR-P0-7 surface.
	started := make(chan struct{}, 1)
	const handlerDelay = 400 * time.Millisecond
	app.Get("/slow", func(c *fiber.Ctx) error {
		started <- struct{}{}
		time.Sleep(handlerDelay)
		return c.SendString("drained-ok")
	})

	// Run the helper in a goroutine — same shape main() uses.
	srvErr := make(chan error, 1)
	go func() {
		srvErr <- runServerWithGracefulShutdown(app, fmt.Sprintf("127.0.0.1:%d", port), 5*time.Second, router.ShutdownHooks{})
	}()

	// Wait for the listener to bind. Tight retry loop with a generous cap so
	// CI's cold-start jitter doesn't false-flag this test.
	require.Eventually(t, func() bool {
		conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 100*time.Millisecond)
		if err != nil {
			return false
		}
		_ = conn.Close()
		return true
	}, 3*time.Second, 25*time.Millisecond, "server never bound to :%d", port)

	// Fire the slow request in the background.
	respCh := make(chan *http.Response, 1)
	errCh := make(chan error, 1)
	go func() {
		req, err := http.NewRequestWithContext(context.Background(), http.MethodGet,
			fmt.Sprintf("http://127.0.0.1:%d/slow", port), nil)
		if err != nil {
			errCh <- err
			return
		}
		resp, err := (&http.Client{Timeout: 10 * time.Second}).Do(req)
		if err != nil {
			errCh <- err
			return
		}
		respCh <- resp
	}()

	// Wait until the handler is actually running.
	select {
	case <-started:
	case <-time.After(3 * time.Second):
		t.Fatalf("handler never started — the test setup is broken, not the SUT")
	}

	// Send SIGTERM to our own process. runServerWithGracefulShutdown is
	// subscribed via signal.NotifyContext and should fire its
	// ShutdownWithTimeout path, draining the in-flight /slow handler.
	require.NoError(t, syscall.Kill(os.Getpid(), syscall.SIGTERM))

	// The in-flight request MUST complete successfully — that is the drain.
	var resp *http.Response
	select {
	case resp = <-respCh:
	case err := <-errCh:
		t.Fatalf("in-flight request did NOT drain after SIGTERM — got transport error %v "+
			"(this is the exact MR-P0-7 regression: app.Listen with no signal handler)", err)
	case <-time.After(8 * time.Second):
		t.Fatal("in-flight request never completed within drain window — graceful shutdown is broken")
	}
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode,
		"the in-flight request must complete with the handler's status, not a reset/error")
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	assert.Equal(t, "drained-ok", string(body),
		"the in-flight handler must run to completion — the drain is what makes MR-P0-7 fixed")

	// The helper itself must return nil for a clean shutdown.
	select {
	case sErr := <-srvErr:
		assert.NoError(t, sErr, "runServerWithGracefulShutdown must return nil on clean SIGTERM-triggered drain")
	case <-time.After(5 * time.Second):
		t.Fatal("runServerWithGracefulShutdown never returned after the drain completed")
	}
}


// TestRunServerWithGracefulShutdown_MarksReadinessDraining — the
// MR-P0-7 readiness contract: on SIGTERM the helper MUST flip
// hooks.Readyz.MarkDraining BEFORE Fiber's ShutdownWithTimeout closes
// the listener. Without this, the kubelet's readinessProbe keeps
// returning 200 right up to SIGKILL and the Service keeps routing new
// traffic to a pod that is about to stop accepting connections.
func TestRunServerWithGracefulShutdown_MarksReadinessDraining(t *testing.T) {
	port := pickFreePort(t)
	app := fiber.New(fiber.Config{DisableStartupMessage: true})
	app.Get("/ping", func(c *fiber.Ctx) error { return c.SendString("ok") })

	readyzH := &handlers.ReadyzHandler{}
	require.False(t, readyzH.IsDraining(), "fresh ReadyzHandler must not start in draining state")

	srvErr := make(chan error, 1)
	go func() {
		srvErr <- runServerWithGracefulShutdown(
			app,
			fmt.Sprintf("127.0.0.1:%d", port),
			3*time.Second,
			router.ShutdownHooks{Readyz: readyzH},
		)
	}()

	require.Eventually(t, func() bool {
		conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 100*time.Millisecond)
		if err != nil {
			return false
		}
		_ = conn.Close()
		return true
	}, 3*time.Second, 25*time.Millisecond, "server never bound to :%d", port)

	require.NoError(t, syscall.Kill(os.Getpid(), syscall.SIGTERM))

	require.Eventually(t, readyzH.IsDraining,
		2*time.Second, 10*time.Millisecond,
		"hooks.Readyz.MarkDraining was never called — readinessProbe will keep returning 200 (MR-P0-7 regression)")

	select {
	case sErr := <-srvErr:
		assert.NoError(t, sErr, "clean SIGTERM drain must return nil")
	case <-time.After(8 * time.Second):
		t.Fatal("runServerWithGracefulShutdown never returned after the drain")
	}
	assert.True(t, readyzH.IsDraining(), "drain flag is single-shot, never un-flipped")
}

// TestRunServerWithGracefulShutdown_TimeoutKillsStuckRequest — the
// MR-P0-7 timeout contract: a request that never returns MUST NOT
// block the helper past shutdownTimeout. ShutdownWithTimeout returns a
// non-nil error which the helper surfaces, so the process exits in
// bounded time instead of being SIGKILLed by the kubelet.
func TestRunServerWithGracefulShutdown_TimeoutKillsStuckRequest(t *testing.T) {
	port := pickFreePort(t)
	app := fiber.New(fiber.Config{DisableStartupMessage: true})

	stuck := make(chan struct{})
	defer close(stuck)
	requestStarted := make(chan struct{}, 1)
	app.Get("/stuck", func(c *fiber.Ctx) error {
		select {
		case requestStarted <- struct{}{}:
		default:
		}
		<-stuck
		return nil
	})

	const tinyTimeout = 500 * time.Millisecond
	srvErr := make(chan error, 1)
	go func() {
		srvErr <- runServerWithGracefulShutdown(
			app,
			fmt.Sprintf("127.0.0.1:%d", port),
			tinyTimeout,
			router.ShutdownHooks{},
		)
	}()

	require.Eventually(t, func() bool {
		conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 100*time.Millisecond)
		if err != nil {
			return false
		}
		_ = conn.Close()
		return true
	}, 3*time.Second, 25*time.Millisecond, "server never bound to :%d", port)

	clientCtx, cancelClient := context.WithCancel(context.Background())
	defer cancelClient()
	go func() {
		req, _ := http.NewRequestWithContext(clientCtx, http.MethodGet,
			fmt.Sprintf("http://127.0.0.1:%d/stuck", port), nil)
		_, _ = http.DefaultClient.Do(req)
	}()

	select {
	case <-requestStarted:
	case <-time.After(2 * time.Second):
		t.Fatal("stuck handler never started — setup is broken, not the SUT")
	}

	start := time.Now()
	require.NoError(t, syscall.Kill(os.Getpid(), syscall.SIGTERM))

	select {
	case sErr := <-srvErr:
		elapsed := time.Since(start)
		assert.Error(t, sErr,
			"stuck request must surface ShutdownWithTimeout's non-nil return so operators can grep server.graceful_shutdown_failed")
		// readinessDrainGrace (3s) + tinyTimeout (0.5s) + slack ≤ ~6s.
		assert.Less(t, elapsed, 6*time.Second,
			"helper took %s — timeout path is broken; a real pod would be SIGKILLed", elapsed)
	case <-time.After(10 * time.Second):
		t.Fatal("runServerWithGracefulShutdown blocked past shutdownTimeout — the kubelet would SIGKILL this pod")
	}
}

// Compile-time guard against a regression that removes the helper or changes
// its signature in a way that would silently bypass the MR-P0-7 fix.
var _ = func(app *fiber.App) error {
	return runServerWithGracefulShutdown(app, ":0", time.Second, router.ShutdownHooks{})
}

// sync.WaitGroup import-guard so a future test that adds goroutines can rely
// on the package without re-juggling imports.
var _ sync.WaitGroup
