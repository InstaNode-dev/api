//go:build e2e

package e2e

// w11_idempotency_e2e_test.go — black-box coverage for W11 Fix 2
// (X-Idempotent-Replay header + idempotency-vs-fingerprint-dedup
// precedence, 2026-05-14).
//
// Contracts under test:
//
//  1. Same Idempotency-Key + same body from the same fingerprint:
//     second response MUST carry `X-Idempotent-Replay: true` AND return
//     the cached body (including the same token). The first response
//     MUST NOT carry the header.
//
//  2. Same Idempotency-Key + DIFFERENT body: 409 with structured error
//     `idempotency_key_conflict`. Already covered by the middleware unit
//     test; re-asserted here at the HTTP boundary so a per-route wiring
//     misconfig (e.g. middleware accidentally moved AFTER the handler)
//     would fail loudly.
//
//  3. NO Idempotency-Key + same fingerprint: handler's per-fingerprint
//     dedup still works, but X-Idempotent-Replay is NEVER set. This is
//     the precedence inverse — the header is reserved exclusively for
//     the idempotency middleware so upstream agents can branch on it.
//
// Target endpoint: /cache/new (most reliably enabled). Idempotency
// middleware wiring is identical across all provisioning endpoints —
// see internal/router/router.go.

import (
	"net/http"
	"strings"
	"testing"

	"github.com/google/uuid"
)

// TestE2E_W11_Idempotency_ReplaysWithHeader drives the core replay flow:
// two POST /cache/new calls from the same fingerprint with the same
// Idempotency-Key + same body MUST yield the SAME token AND the second
// response MUST carry `X-Idempotent-Replay: true`.
//
// Precedence: even if fingerprint dedup would return the same token
// (it's the same /24), the cached entry replays verbatim — including
// the header — which fingerprint dedup alone cannot produce. The header
// is the differentiator an upstream agent can branch on.
func TestE2E_W11_Idempotency_ReplaysWithHeader(t *testing.T) {
	ip := uniqueIP(t)
	idemKey := "w11-replay-" + uuid.NewString()
	body := map[string]any{"name": "w11-idem-test"}

	// First call: fresh provision, no replay header.
	resp1 := post(t, "/cache/new", body,
		"X-Forwarded-For", ip,
		"Idempotency-Key", idemKey,
	)
	if resp1.StatusCode == http.StatusServiceUnavailable {
		readBody(t, resp1)
		t.Skip("/cache/new service not enabled")
	}
	if resp1.StatusCode != http.StatusCreated {
		t.Fatalf("call 1: want 201, got %d\n%s", resp1.StatusCode, readBody(t, resp1))
	}
	if r := resp1.Header.Get("X-Idempotent-Replay"); r != "" {
		t.Errorf("call 1 MUST NOT set X-Idempotent-Replay; got %q", r)
	}
	var first provisionNewResponse
	decodeJSON(t, resp1, &first)
	if first.Token == "" {
		t.Fatalf("call 1: token missing\n%v", first)
	}

	// Second call: same key + same body. Middleware short-circuits with
	// the cached response and `X-Idempotent-Replay: true`.
	resp2 := post(t, "/cache/new", body,
		"X-Forwarded-For", ip,
		"Idempotency-Key", idemKey,
	)
	defer resp2.Body.Close()

	if resp2.StatusCode != http.StatusCreated {
		t.Fatalf("call 2: want 201 (cached replay), got %d", resp2.StatusCode)
	}
	if r := resp2.Header.Get("X-Idempotent-Replay"); r != "true" {
		t.Errorf("call 2 MUST set X-Idempotent-Replay: true; got %q", r)
	}
	var second provisionNewResponse
	decodeJSON(t, resp2, &second)
	if second.Token != first.Token {
		t.Errorf("replay MUST return the same token; got %q want %q",
			second.Token, first.Token)
	}
}

// TestE2E_W11_Idempotency_DifferentBody_Returns409 pins the
// "same key, different body" → 409 contract at the HTTP boundary.
// Without this guard an agent could silently mutate a payload on retry
// and get a totally different resource under the same key — a class of
// "race condition with myself" bug that's hard to debug.
func TestE2E_W11_Idempotency_DifferentBody_Returns409(t *testing.T) {
	ip := uniqueIP(t)
	idemKey := "w11-conflict-" + uuid.NewString()

	// First body
	resp1 := post(t, "/cache/new", map[string]any{"name": "first"},
		"X-Forwarded-For", ip,
		"Idempotency-Key", idemKey,
	)
	if resp1.StatusCode == http.StatusServiceUnavailable {
		readBody(t, resp1)
		t.Skip("/cache/new service not enabled")
	}
	if resp1.StatusCode != http.StatusCreated {
		t.Fatalf("call 1: want 201, got %d\n%s", resp1.StatusCode, readBody(t, resp1))
	}
	readBody(t, resp1)

	// Same key, different body → 409.
	resp2 := post(t, "/cache/new", map[string]any{"name": "second-different-payload"},
		"X-Forwarded-For", ip,
		"Idempotency-Key", idemKey,
	)
	body2 := readBody(t, resp2)
	if resp2.StatusCode != http.StatusConflict {
		t.Fatalf("call 2 (different body): want 409, got %d\n%s", resp2.StatusCode, body2)
	}
	if !strings.Contains(body2, "idempotency_key_conflict") {
		t.Errorf("409 body must carry structured error 'idempotency_key_conflict'; got\n%s", body2)
	}
}

// TestE2E_W11_FingerprintDedup_NoIdempotencyKey_StillWorks pins the
// inverse direction: when NO Idempotency-Key is sent, the handler's
// per-fingerprint dedup branch is still the authoritative path. Two
// sequential calls from the same /24 may return the same token
// (fingerprint dedup) but MUST NOT set X-Idempotent-Replay — that header
// is reserved for the idempotency middleware's cache hits, not for
// fingerprint dedup. Locks the "no key ⇒ fingerprint dedup; key ⇒
// idempotency" precedence contract from both sides.
func TestE2E_W11_FingerprintDedup_NoIdempotencyKey_StillWorks(t *testing.T) {
	ip := uniqueIP(t)

	resp1 := post(t, "/cache/new", nil, "X-Forwarded-For", ip)
	if resp1.StatusCode == http.StatusServiceUnavailable {
		readBody(t, resp1)
		t.Skip("/cache/new service not enabled")
	}
	if resp1.StatusCode != http.StatusCreated {
		t.Fatalf("call 1: want 201, got %d\n%s", resp1.StatusCode, readBody(t, resp1))
	}
	if r := resp1.Header.Get("X-Idempotent-Replay"); r != "" {
		t.Errorf("call 1 (no idem key) MUST NOT set X-Idempotent-Replay; got %q", r)
	}
	var first provisionNewResponse
	decodeJSON(t, resp1, &first)

	// Call 2 from the same /24 — fingerprint dedup may return the same
	// resource depending on cluster state. The contract under test is
	// that the header stays absent.
	resp2 := post(t, "/cache/new", nil, "X-Forwarded-For", ip)
	defer resp2.Body.Close()
	if resp2.StatusCode != http.StatusCreated && resp2.StatusCode != http.StatusOK {
		// Anonymous dedup path returns 200, fresh provision returns 201.
		// Either is acceptable here — the assertion is on the header.
		t.Logf("call 2: status=%d (informational; either 200 or 201 is acceptable)", resp2.StatusCode)
	}
	if r := resp2.Header.Get("X-Idempotent-Replay"); r != "" {
		t.Errorf("call 2 (no idem key, fingerprint dedup) MUST NOT set X-Idempotent-Replay; got %q", r)
	}
}
