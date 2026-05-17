package handlers

// auth_oauth_state_test.go — P1-K coverage (bug hunt 2026-05-17 round 2).
//
// The OAuth `state` token used to be validated only against a cookie, making
// it replayable inside its 5-minute window. registerOAuthState +
// consumeOAuthState make it single-use via an atomic Redis GETDEL.
//
// Internal-package test so it can drive the unexported helpers directly.

import (
	"context"
	"testing"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
)

// TestConsumeOAuthState_SingleUse is the core P1-K guarantee: the first
// consume of a registered state succeeds; an immediate replay fails.
func TestConsumeOAuthState_SingleUse(t *testing.T) {
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("miniredis: %v", err)
	}
	defer mr.Close()
	h := &AuthHandler{rdb: redis.NewClient(&redis.Options{Addr: mr.Addr()})}
	ctx := context.Background()

	const state = "deadbeefcafebabe"
	h.registerOAuthState(ctx, state)

	if !h.consumeOAuthState(ctx, state) {
		t.Fatal("first consume of a registered state must succeed")
	}
	if h.consumeOAuthState(ctx, state) {
		t.Fatal("replayed consume of an already-used state must fail (P1-K)")
	}
}

// TestConsumeOAuthState_UnregisteredRejected verifies a state that was never
// registered (forged, or replayed after expiry) is rejected.
func TestConsumeOAuthState_UnregisteredRejected(t *testing.T) {
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("miniredis: %v", err)
	}
	defer mr.Close()
	h := &AuthHandler{rdb: redis.NewClient(&redis.Options{Addr: mr.Addr()})}

	if h.consumeOAuthState(context.Background(), "never-registered") {
		t.Fatal("an unregistered state must be rejected")
	}
}

// TestConsumeOAuthState_FailsOpenWithoutRedis verifies the fail-open contract:
// with no Redis client (unit tests / no-Redis dev) consume returns true so the
// cookie check still gates — a Redis outage must not become a sign-in outage.
func TestConsumeOAuthState_FailsOpenWithoutRedis(t *testing.T) {
	h := &AuthHandler{} // rdb == nil
	if !h.consumeOAuthState(context.Background(), "anything") {
		t.Fatal("with nil Redis, consume must fail open (return true)")
	}
	// registerOAuthState must also be a safe no-op.
	h.registerOAuthState(context.Background(), "anything")
}

// TestConsumeOAuthState_ConcurrentReplayOnlyOneWins guards the TOCTOU edge:
// two concurrent consumes of the same state — exactly one must win because
// GETDEL is atomic.
func TestConsumeOAuthState_ConcurrentReplayOnlyOneWins(t *testing.T) {
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("miniredis: %v", err)
	}
	defer mr.Close()
	h := &AuthHandler{rdb: redis.NewClient(&redis.Options{Addr: mr.Addr()})}
	ctx := context.Background()

	const state = "concurrentstatetoken"
	h.registerOAuthState(ctx, state)

	results := make(chan bool, 2)
	for i := 0; i < 2; i++ {
		go func() { results <- h.consumeOAuthState(ctx, state) }()
	}
	wins := 0
	for i := 0; i < 2; i++ {
		if <-results {
			wins++
		}
	}
	if wins != 1 {
		t.Fatalf("exactly one concurrent consume must win, got %d", wins)
	}
}
