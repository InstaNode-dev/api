//go:build loadtest && e2e

// Package e2e — LOAD & CHAOS HARNESS
//
// This file is behind the `loadtest` build constraint so it NEVER runs in
// the normal `go test ./... -short` PR/deploy gate (no tag) nor the standard
// E2E gate (`-tags e2e` only). It compiles ONLY under `-tags 'e2e loadtest'`
// — it reuses the e2e helper layer (baseURL, post, uniqueIP, ...) which is
// itself `//go:build e2e`, so both tags are required. `make loadtest` /
// `make chaostest` pass both. The deploy gate passes neither, so this never
// runs in CI.
//
// ─── WHAT THIS HARNESS DOES ───────────────────────────────────────────────────
//
//	1. Concurrency / load — N goroutines hammering every provisioning
//	   endpoint simultaneously. Asserts: no duplicate tokens, no 5xx,
//	   reports latency percentiles + throughput.
//	2. Fingerprint dedup under burst — confirms the 5/day cap holds and
//	   the 6th call returns the existing token, under concurrency.
//	3. Rate-limit under burst — fires past the limit, asserts clean 429s
//	   (never 5xx, never silent drops).
//
// ─── THE 402 RECYCLE-GATE PROBLEM, AND HOW WE HANDLE IT ───────────────────────
//
// Prod anonymous provisioning from a fingerprint that has provisioned before
// hits the `free_tier_recycle_requires_claim` 402 gate (see
// internal/handlers/provision_helper.go recycleGate). A naive load test from
// one machine would just get a wall of 402s.
//
// This harness handles it deliberately with TWO load lanes:
//
//	LANE A — AUTHENTICATED LOAD (the real concurrency/throughput test).
//	  When a Bearer session JWT is present, provisioning routes through
//	  newCacheAuthenticated/...Authenticated which bypasses the recycle
//	  gate entirely (cache.go:99). We claim ONE free-tier team up front,
//	  mint a session JWT, and drive all concurrency load through it.
//	  Free tier => zero cost, no Razorpay, no card.
//
//	LANE B — THE 402 GATE ITSELF AS ASSERTED BEHAVIOR.
//	  We also load-test the anonymous path and assert the gate responds
//	  cleanly under burst: every blocked call must return a well-formed
//	  402 envelope (error code + claim_url), never a 5xx, never a silent
//	  drop. The gate is a real prod surface; its behavior under load
//	  matters.
//
// ─── COST SAFETY ──────────────────────────────────────────────────────────────
//
//   - Free tier ONLY. No /db/new pro pods, no Razorpay, no deploy (kaniko).
//   - Every provisioned resource is registered in a ledger and torn down:
//     a deferred per-resource delete AND batch sweeps every BatchSweepEvery
//     provisions AND a final full sweep. The harness asserts a zero-leak
//     ledger before it exits.
//
// ─── HOW TO RUN ───────────────────────────────────────────────────────────────
//
//	make loadtest    # load lanes A + B
//	make chaostest   # safe pod-kill chaos pass
//
// Required env:
//
//	E2E_BASE_URL          live API root, e.g. https://api.instanode.dev
//	E2E_JWT_SECRET        JWT_SECRET from the k8s secret (Lane A authed path)
//
// Optional:
//
//	LOAD_CONCURRENCY      goroutines per wave              (default 20)
//	LOAD_TARGET_NS        k8s namespace of instant-api     (default instant)
package e2e

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/google/uuid"
)

// ─── Tunables ─────────────────────────────────────────────────────────────────

// loadConcurrency is the number of goroutines fired per load wave.
func loadConcurrency() int {
	if v := os.Getenv("LOAD_CONCURRENCY"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			return n
		}
	}
	return 20
}

// BatchSweepEvery — after this many resources accumulate in the ledger, the
// harness deletes them in a batch so cost/footprint never spikes during a
// long run.
const BatchSweepEvery = 25

// ─── Resource ledger — the cost-safety backbone ───────────────────────────────

// ledgerEntry is one provisioned resource the harness must tear down.
type ledgerEntry struct {
	token   string // resource token, used as the DELETE id
	kind    string // "redis" | "postgres" | "mongodb" | "queue" | "storage" | "webhook"
	deleted bool
}

// resourceLedger tracks every resource the harness provisions and guarantees
// teardown. Design:
//
//   - add() is called immediately after every successful provision.
//   - sweep() deletes every not-yet-deleted entry; called in batches during
//     a run and once finally in t.Cleanup.
//   - leaks() returns entries still alive after the final sweep — the
//     harness asserts this is empty.
//
// Concurrency-safe: load waves add() from many goroutines at once.
type resourceLedger struct {
	mu      sync.Mutex
	entries []*ledgerEntry
	jwt     string // session JWT used to authorize DELETEs
}

func newResourceLedger(sessionJWT string) *resourceLedger {
	return &resourceLedger{jwt: sessionJWT}
}

func (l *resourceLedger) add(token, kind string) {
	if token == "" {
		return
	}
	l.mu.Lock()
	l.entries = append(l.entries, &ledgerEntry{token: token, kind: kind})
	l.mu.Unlock()
}

// count returns total tracked and still-alive counts.
func (l *resourceLedger) count() (total, alive int) {
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, e := range l.entries {
		total++
		if !e.deleted {
			alive++
		}
	}
	return
}

// deleteResource issues an authenticated DELETE for a single resource token.
// Returns the HTTP status. 200/204 => gone; 404 => already gone (also fine).
func (l *resourceLedger) deleteResource(token string) (int, error) {
	req, err := http.NewRequest(http.MethodDelete, baseURL()+"/api/v1/resources/"+token, nil)
	if err != nil {
		return 0, err
	}
	if l.jwt != "" {
		req.Header.Set("Authorization", "Bearer "+l.jwt)
	}
	resp, err := client.Do(req)
	if err != nil {
		return 0, err
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	return resp.StatusCode, nil
}

// sweep tears down every not-yet-deleted ledger entry. Best-effort with one
// retry per resource; logs per-entry outcome. Returns count successfully
// deleted in this sweep.
func (l *resourceLedger) sweep(t *testing.T) int {
	t.Helper()
	l.mu.Lock()
	pending := make([]*ledgerEntry, 0, len(l.entries))
	for _, e := range l.entries {
		if !e.deleted {
			pending = append(pending, e)
		}
	}
	l.mu.Unlock()

	if len(pending) == 0 {
		return 0
	}

	swept := 0
	for _, e := range pending {
		var lastCode int
		var lastErr error
		ok := false
		for attempt := 0; attempt < 2; attempt++ {
			code, err := l.deleteResource(e.token)
			lastCode, lastErr = code, err
			if err == nil && (code == 200 || code == 204 || code == 404) {
				ok = true
				break
			}
			time.Sleep(300 * time.Millisecond)
		}
		l.mu.Lock()
		e.deleted = ok
		l.mu.Unlock()
		if ok {
			swept++
		} else {
			t.Errorf("LEDGER LEAK RISK: token=%s kind=%s last_code=%d err=%v",
				e.token, e.kind, lastCode, lastErr)
		}
	}
	t.Logf("ledger sweep: deleted %d/%d resources", swept, len(pending))
	return swept
}

// leaks returns the tokens still alive after the final sweep.
func (l *resourceLedger) leaks() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	var out []string
	for _, e := range l.entries {
		if !e.deleted {
			out = append(out, e.kind+":"+e.token)
		}
	}
	return out
}

// serverSideReconcile is the cleanup BACKSTOP. The in-memory ledger only
// tracks resources whose provision RESPONSE the client actually received —
// but a client-deadline timeout (Finding F1) can leave the server still
// provisioning, so the resource is created AFTER the client gave up and is
// never ledger-tracked. This method asks the server for ground truth: it
// lists every still-active resource the team owns via GET /api/v1/resources
// and deletes each by its `token` (the DELETE route keys on token, not the
// separate `id` field). Returns (found, deleted). A correct run ends with
// found==deleted and a subsequent call returning found==0.
func (l *resourceLedger) serverSideReconcile(t *testing.T) (found, deleted int) {
	t.Helper()
	if l.jwt == "" {
		return 0, 0
	}
	listResp := get(t, "/api/v1/resources", "Authorization", "Bearer "+l.jwt)
	body, _ := io.ReadAll(listResp.Body)
	_ = listResp.Body.Close()
	var list struct {
		Items []struct {
			Token  string `json:"token"`
			Status string `json:"status"`
			Type   string `json:"resource_type"`
		} `json:"items"`
	}
	if json.Unmarshal(body, &list) != nil {
		return 0, 0
	}
	for _, it := range list.Items {
		if it.Status != "active" || it.Token == "" {
			continue
		}
		found++
		code, err := l.deleteResource(it.Token)
		if err == nil && (code == 200 || code == 204 || code == 404) {
			deleted++
		} else {
			t.Errorf("RECONCILE LEAK: token=%s type=%s code=%d err=%v",
				it.Token, it.Type, code, err)
		}
	}
	if found > 0 {
		t.Logf("server-side reconcile: %d active resources found on team, %d deleted "+
			"(catches timeout-orphans the in-memory ledger never saw)", found, deleted)
	} else {
		t.Logf("server-side reconcile: team has 0 active resources — ledger complete")
	}
	return found, deleted
}

// maybeBatchSweep deletes accumulated resources mid-run so the live footprint
// never exceeds ~BatchSweepEvery resources at once.
func (l *resourceLedger) maybeBatchSweep(t *testing.T) {
	_, alive := l.count()
	if alive >= BatchSweepEvery {
		t.Logf("batch sweep triggered (%d alive >= %d)", alive, BatchSweepEvery)
		l.sweep(t)
	}
}

// ─── Latency / outcome recorder ───────────────────────────────────────────────

// outcome is one observed request result.
//
// status==0 means no HTTP response was received. Two distinct causes, kept
// separate because they mean very different things:
//
//   - timedOut: the CLIENT's context deadline fired while the server was
//     still processing. This is a LATENCY finding, not a server crash —
//     the server very likely completed the work after the client gave up.
//   - err && !timedOut: a genuine transport-layer failure (connection
//     reset / refused) with no deadline involved — a true silent drop.
type outcome struct {
	status   int
	latency  time.Duration
	token    string
	err      bool
	timedOut bool
}

// loadStats aggregates outcomes across a wave for percentile reporting.
type loadStats struct {
	mu        sync.Mutex
	outcomes  []outcome
	codeCount map[int]int
}

func newLoadStats() *loadStats {
	return &loadStats{codeCount: map[int]int{}}
}

func (s *loadStats) record(o outcome) {
	s.mu.Lock()
	s.outcomes = append(s.outcomes, o)
	s.codeCount[o.status]++
	s.mu.Unlock()
}

// timeouts returns the count of CLIENT-deadline timeouts (latency finding).
func (s *loadStats) timeouts() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for _, o := range s.outcomes {
		if o.timedOut {
			n++
		}
	}
	return n
}

// trueDrops returns the count of genuine transport-layer failures — a
// status==0 outcome that was NOT a client-deadline timeout.
func (s *loadStats) trueDrops() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for _, o := range s.outcomes {
		if o.status == 0 && o.err && !o.timedOut {
			n++
		}
	}
	return n
}

// percentiles returns p50, p95, p99, and max latency over all recorded
// outcomes (including failures — a failure that took 30s still matters).
func (s *loadStats) percentiles() (p50, p95, p99, max time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.outcomes) == 0 {
		return
	}
	lat := make([]time.Duration, len(s.outcomes))
	for i, o := range s.outcomes {
		lat[i] = o.latency
	}
	sort.Slice(lat, func(i, j int) bool { return lat[i] < lat[j] })
	pick := func(p float64) time.Duration {
		idx := int(p * float64(len(lat)-1))
		return lat[idx]
	}
	return pick(0.50), pick(0.95), pick(0.99), lat[len(lat)-1]
}

// fivexx returns the count of 5xx responses observed.
func (s *loadStats) fivexx() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for code, c := range s.codeCount {
		if code >= 500 && code <= 599 {
			n += c
		}
	}
	return n
}

// report logs a human-readable summary of the wave.
func (s *loadStats) report(t *testing.T, label string, wall time.Duration) {
	s.mu.Lock()
	total := len(s.outcomes)
	codes := make([]int, 0, len(s.codeCount))
	for c := range s.codeCount {
		codes = append(codes, c)
	}
	sort.Ints(codes)
	s.mu.Unlock()

	p50, p95, p99, max := s.percentiles()
	tput := 0.0
	if wall > 0 {
		tput = float64(total) / wall.Seconds()
	}
	t.Logf("── LOAD WAVE: %s ──", label)
	t.Logf("   requests=%d  wall=%s  throughput=%.1f req/s", total, wall.Round(time.Millisecond), tput)
	t.Logf("   latency  p50=%s  p95=%s  p99=%s  max=%s",
		p50.Round(time.Millisecond), p95.Round(time.Millisecond),
		p99.Round(time.Millisecond), max.Round(time.Millisecond))
	for _, c := range codes {
		t.Logf("   status %d: %d", c, s.codeCount[c])
	}
}

// ─── Authenticated session bootstrap (Lane A) ─────────────────────────────────

// loadSession is a claimed free-tier team + a session JWT, the vehicle for
// authenticated load that bypasses the recycle gate at zero cost.
type loadSession struct {
	teamID     string
	email      string
	sessionJWT string
}

// bootstrapLoadSession provisions one anonymous resource, claims it with a
// fresh email (creating a free-tier team), and mints a session JWT. All
// subsequent authenticated load uses this single team — every resource it
// provisions stays on the free tier.
//
// If the anonymous provision itself hits the 402 recycle gate (this machine's
// fingerprint has provisioned before), bootstrap cannot proceed and the
// authenticated lane is skipped — Lane B still runs and asserts the gate.
func bootstrapLoadSession(t *testing.T) (*loadSession, bool) {
	t.Helper()
	if os.Getenv("E2E_JWT_SECRET") == "" {
		t.Log("E2E_JWT_SECRET not set — authenticated load lane unavailable")
		return nil, false
	}

	ip := uniqueIP(t)
	resp := post(t, "/cache/new", map[string]any{"name": "loadtest-bootstrap"},
		"X-Forwarded-For", ip)
	body := readBody(t, resp)
	if resp.StatusCode == 402 {
		t.Logf("bootstrap anonymous provision hit 402 recycle gate — "+
			"authenticated lane skipped, gate-lane (Lane B) still runs. body=%s", body)
		return nil, false
	}
	if resp.StatusCode != 201 {
		t.Logf("bootstrap anonymous provision: want 201, got %d body=%s",
			resp.StatusCode, body)
		return nil, false
	}
	var prov provisionNewResponse
	if err := json.Unmarshal([]byte(body), &prov); err != nil {
		t.Logf("bootstrap: decode provision: %v", err)
		return nil, false
	}
	jwtTok := extractJWTFromNote(t, prov.Note)
	email := uniqueEmail()
	claimResp := post(t, "/claim", map[string]any{
		"jwt":       jwtTok,
		"email":     email,
		"team_name": "loadtest-" + uuid.NewString()[:8],
	})
	if claimResp.StatusCode != 201 {
		t.Logf("bootstrap claim: want 201, got %d body=%s",
			claimResp.StatusCode, readBody(t, claimResp))
		return nil, false
	}
	var claim claimResponse
	decodeJSON(t, claimResp, &claim)

	secret := os.Getenv("E2E_JWT_SECRET")
	now := time.Now().Unix()
	claims := jwt.MapClaims{
		"uid":   claim.UserID,
		"tid":   claim.TeamID,
		"email": email,
		"jti":   uuid.NewString(),
		"iat":   now,
		"exp":   now + 3600,
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := tok.SignedString([]byte(secret))
	if err != nil {
		t.Logf("bootstrap: sign session JWT: %v", err)
		return nil, false
	}
	t.Logf("bootstrap: claimed free-tier team %s, session JWT minted", claim.TeamID)
	return &loadSession{teamID: claim.TeamID, email: email, sessionJWT: signed}, true
}

// ─── Authenticated provision (Lane A primitive) ───────────────────────────────

// provEndpoint is one provisioning endpoint under load.
type provEndpoint struct {
	path string
	kind string
}

// freeServiceEndpoints are the free-tier-safe provisioning endpoints. /db/new
// is included — on the free tier it is a shared-Postgres CREATE DATABASE, not
// a dedicated pod, so it carries no per-pod cost. /deploy/new is deliberately
// EXCLUDED: it triggers a real kaniko build (cost) and the free tier allows 0
// deploy apps anyway.
var freeServiceEndpoints = []provEndpoint{
	{"/cache/new", "redis"},
	{"/db/new", "postgres"},
	{"/nosql/new", "mongodb"},
	{"/queue/new", "queue"},
	{"/storage/new", "storage"},
	{"/webhook/new", "webhook"},
}

// provisionAuthed fires one authenticated provision and records the outcome.
// Authenticated => routes through the *Authenticated handler, bypassing the
// recycle gate. Registers the resulting token in the ledger for teardown.
func provisionAuthed(sess *loadSession, ledger *resourceLedger, ep provEndpoint, stats *loadStats) {
	bodyMap := map[string]any{"name": "lt-" + uuid.NewString()[:8]}
	raw, _ := json.Marshal(bodyMap)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		baseURL()+ep.path, strings.NewReader(string(raw)))
	if err != nil {
		stats.record(outcome{status: 0, err: true})
		return
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+sess.sessionJWT)

	start := time.Now()
	resp, err := client.Do(req)
	lat := time.Since(start)
	if err != nil {
		stats.record(outcome{status: 0, latency: lat, err: true})
		return
	}
	respBody, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()

	o := outcome{status: resp.StatusCode, latency: lat}
	if resp.StatusCode == 201 {
		var pv struct {
			Token string `json:"token"`
		}
		if json.Unmarshal(respBody, &pv) == nil && pv.Token != "" {
			o.token = pv.Token
			ledger.add(pv.Token, ep.kind)
		}
	}
	stats.record(o)
}

// extractJWTLoose pulls the `?t=` JWT out of a note string. Unlike the e2e
// helper extractJWTFromNote it never calls t.Fatalf — safe to call from a
// goroutine. Returns "" when no JWT is present.
func extractJWTLoose(note string) string {
	const marker = "?t="
	idx := strings.Index(note, marker)
	if idx == -1 {
		return ""
	}
	raw := note[idx+len(marker):]
	if sp := strings.IndexAny(raw, " \t\n\""); sp != -1 {
		raw = raw[:sp]
	}
	return raw
}

// ─── Lane-B anonymous-resource teardown ───────────────────────────────────────
//
// Anonymous resources have no team and cannot be deleted via the
// authenticated DELETE /api/v1/resources/:id (it requires team ownership).
// They are designed to auto-expire on a 24h TTL — that is the platform's own
// teardown mechanism and the ultimate backstop.
//
// To NOT rely solely on TTL, the harness actively tears Lane-B resources
// down: every anonymous provision response carries an onboarding JWT in
// `note`. POST /claim with that JWT moves the resources THAT JWT NAMES into a
// fresh throwaway team; each is then deletable via the authenticated DELETE.
// If E2E_JWT_SECRET is unset (cannot mint the session JWT to authorize the
// DELETEs) the harness falls back to the 24h TTL and says so.
//
// PARTIAL SINCE 2026-08-13: this used to reclaim the WHOLE burst from one JWT,
// because /claim swept every resource sharing the caller's fingerprint. That
// sweep was a cross-tenant ownership hole (SHA256(/24 + ASN) buckets strangers
// behind one NAT together) and was removed — see
// api/internal/handlers/onboarding.go. A single captured JWT now reclaims only
// its own token (plus anything chained onto it via X-Instant-Upgrade-Token,
// which this concurrent burst does not thread). The remainder of the burst
// falls back to the 24h TTL, which the caller already logs. Reclaiming the
// full burst again would mean chaining the header through the goroutines.
//
// teardownAnonymousFingerprint claims the resources named by `fpJWT` and
// deletes them. Returns (claimed, deleted, ok).
func teardownAnonymousFingerprint(t *testing.T, fpJWT string) (claimed, deleted int, ok bool) {
	t.Helper()
	if fpJWT == "" {
		return 0, 0, false
	}
	if os.Getenv("E2E_JWT_SECRET") == "" {
		t.Logf("Lane-B teardown: E2E_JWT_SECRET unset — cannot mint session JWT to "+
			"authorize DELETEs; %d anonymous resources fall back to 24h-TTL auto-expiry",
			0)
		return 0, 0, false
	}

	// List the fingerprint's resources via GET /start?t=<jwt> before claiming.
	startResp := getNoRedirect(t, "/start?t="+fpJWT)
	_, _ = io.Copy(io.Discard, startResp.Body)
	_ = startResp.Body.Close()

	email := uniqueEmail()
	claimResp := post(t, "/claim", map[string]any{
		"jwt":       fpJWT,
		"email":     email,
		"team_name": "lt-cleanup-" + uuid.NewString()[:8],
	})
	if claimResp.StatusCode != 201 {
		body := readBody(t, claimResp)
		t.Logf("Lane-B teardown: claim returned %d (resources fall back to 24h TTL): %s",
			claimResp.StatusCode, body)
		return 0, 0, false
	}
	var claim claimResponse
	decodeJSON(t, claimResp, &claim)

	secret := os.Getenv("E2E_JWT_SECRET")
	now := time.Now().Unix()
	sc := jwt.MapClaims{
		"uid": claim.UserID, "tid": claim.TeamID, "email": email,
		"jti": uuid.NewString(), "iat": now, "exp": now + 3600,
	}
	signed, err := jwt.NewWithClaims(jwt.SigningMethodHS256, sc).SignedString([]byte(secret))
	if err != nil {
		t.Logf("Lane-B teardown: sign session JWT failed: %v", err)
		return 0, 0, false
	}

	// List all resources now owned by the throwaway team and delete each.
	listResp := get(t, "/api/v1/resources", "Authorization", "Bearer "+signed)
	listBody, _ := io.ReadAll(listResp.Body)
	_ = listResp.Body.Close()
	var list struct {
		Items []struct {
			Token string `json:"token"`
		} `json:"items"`
	}
	_ = json.Unmarshal(listBody, &list)
	claimed = len(list.Items)

	ledger := &resourceLedger{jwt: signed}
	for _, it := range list.Items {
		if it.Token == "" {
			continue
		}
		code, derr := ledger.deleteResource(it.Token)
		if derr == nil && (code == 200 || code == 204 || code == 404) {
			deleted++
		} else {
			t.Logf("Lane-B teardown: delete %s -> code=%d err=%v", it.Token, code, derr)
		}
	}
	t.Logf("Lane-B teardown: claimed fingerprint into team %s, deleted %d/%d resources",
		claim.TeamID, deleted, claimed)
	return claimed, deleted, deleted == claimed
}

// ════════════════════════════════════════════════════════════════════════════
// TEST 1 — CONCURRENT MULTI-AGENT PROVISIONING (Lane A, authenticated)
// ════════════════════════════════════════════════════════════════════════════

// TestLoad_ConcurrentProvisioning_AllEndpoints fires LOAD_CONCURRENCY
// goroutines, each provisioning across all six free-tier endpoints, against
// the authenticated path. Asserts:
//   - zero 5xx responses
//   - zero duplicate tokens
//   - reports latency percentiles + throughput
//   - every provisioned resource is torn down (verified-empty ledger)
func TestLoad_ConcurrentProvisioning_AllEndpoints(t *testing.T) {
	sess, ok := bootstrapLoadSession(t)
	if !ok {
		t.Skip("authenticated load lane unavailable (see log) — run Lane B gate test instead")
	}
	ledger := newResourceLedger(sess.sessionJWT)

	// Final teardown + zero-leak assertion. t.Cleanup runs LIFO and after
	// every subtest, so this is the last thing the test does.
	//
	// Two-stage teardown:
	//  1. ledger.sweep      — delete everything the in-memory ledger tracked.
	//  2. serverSideReconcile — ask the server for ground truth and delete
	//     anything the ledger missed (timeout-orphans from Finding F1: a
	//     client-deadline timeout leaves the server still provisioning, so
	//     the resource is created after the client stops watching).
	// Then a second reconcile MUST report 0 — that is the verified-empty
	// proof, not just "the ledger says it's empty".
	t.Cleanup(func() {
		ledger.sweep(t)
		ledger.serverSideReconcile(t)
		if leaks := ledger.leaks(); len(leaks) > 0 {
			t.Errorf("CLEANUP FAILED — %d ledger-tracked resources not deleted: %v",
				len(leaks), leaks)
		}
		// Ground-truth re-check: the team must own ZERO active resources.
		residual, _ := ledger.serverSideReconcile(t)
		if residual > 0 {
			t.Errorf("CLEANUP FAILED — %d active resources still on team after "+
				"two reconcile passes", residual)
		} else {
			total, _ := ledger.count()
			t.Logf("CLEANUP VERIFIED — ledger empty AND server reports 0 active "+
				"resources on team; %d ledger-tracked resources torn down", total)
		}
	})

	conc := loadConcurrency()
	stats := newLoadStats()
	var provisioned int64

	wallStart := time.Now()
	var wg sync.WaitGroup
	wg.Add(conc)
	for g := 0; g < conc; g++ {
		go func() {
			defer wg.Done()
			for _, ep := range freeServiceEndpoints {
				provisionAuthed(sess, ledger, ep, stats)
				atomic.AddInt64(&provisioned, 1)
			}
		}()
	}
	wg.Wait()
	wall := time.Since(wallStart)

	// Mid/late batch sweep so footprint never lingers.
	ledger.maybeBatchSweep(t)

	stats.report(t, fmt.Sprintf("authenticated provisioning · %d goroutines × %d endpoints",
		conc, len(freeServiceEndpoints)), wall)

	// ── ASSERT: no 5xx ──
	if n := stats.fivexx(); n > 0 {
		t.Errorf("BREAKING POINT: %d 5xx responses under %d-way concurrency", n, conc)
	}

	// ── ASSERT: no duplicate tokens ──
	stats.mu.Lock()
	seen := map[string]int{}
	for _, o := range stats.outcomes {
		if o.token != "" {
			seen[o.token]++
		}
	}
	stats.mu.Unlock()
	dupes := 0
	for tok, c := range seen {
		if c > 1 {
			dupes++
			t.Errorf("DUPLICATE TOKEN under concurrency: %s issued %d times", tok, c)
		}
	}
	if dupes == 0 {
		t.Logf("token uniqueness: OK — %d distinct tokens, zero collisions", len(seen))
	}
}

// ════════════════════════════════════════════════════════════════════════════
// TEST 2 — FINGERPRINT DEDUP UNDER BURST (Lane B, anonymous)
// ════════════════════════════════════════════════════════════════════════════

// TestLoad_FingerprintDedup_UnderBurst fires many concurrent anonymous
// provisions from a SINGLE /24 subnet (one fingerprint) and verifies the
// dedup / daily-cap behavior under concurrency.
//
// HARD assertions (a failure here is a crash-class breaking point):
//   - ZERO 5xx — the dedup path must never crash.
//   - ZERO transport-layer drops — no silently lost requests.
//   - Every status is one of 201 / 402 / 429 — no surprise codes.
//
// SOFT assertion (a failure here is a documented concurrency FINDING, not a
// crash): distinct 201 tokens from one fingerprint should stay <= the
// ProvisionLimit("anonymous") daily cap of 5. The anonymous limit check
// (handlers/provision_helper.go checkProvisionLimit + cache.go) is a classic
// check-then-act: checkProvisionLimit does an atomic INCR, but the
// limit-exceeded branch then does a SEPARATE DB lookup
// (GetActiveResourceByFingerprintType) for an existing resource to
// dedup-return. Under a burst, the count>5 requests run that lookup BEFORE
// the count<=5 requests have committed their rows — the lookup finds
// nothing and the code falls through to provision a fresh resource. The cap
// leaks. This test is designed to surface exactly that race.
//
// This is a Lane-B test: no auth required; it asserts gate/dedup behavior
// rather than raw throughput.
func TestLoad_FingerprintDedup_UnderBurst(t *testing.T) {
	// One fixed /24 — every request shares one fingerprint.
	subnet := uniqueSubnet(t)
	const burst = 30

	stats := newLoadStats()
	// fpJWT captures one onboarding JWT from a 201 response so the test can
	// claim+delete the resource that JWT names (rather than relying purely on
	// the 24h TTL). See teardownAnonymousFingerprint for why this is partial
	// coverage of the burst since the claim-by-fingerprint fix.
	var fpJWT string
	var fpJWTMu sync.Mutex

	// Cleanup: claim what the captured JWT names into a throwaway team & delete.
	t.Cleanup(func() {
		fpJWTMu.Lock()
		jwtTok := fpJWT
		fpJWTMu.Unlock()
		if jwtTok == "" {
			t.Log("dedup cleanup: no 201 issued (all gated) — nothing to tear down")
			return
		}
		claimed, deleted, ok := teardownAnonymousFingerprint(t, jwtTok)
		if !ok && claimed > deleted {
			t.Logf("dedup cleanup: %d/%d deleted — remainder falls back to 24h TTL",
				deleted, claimed)
		}
	})

	var wg sync.WaitGroup
	wg.Add(burst)
	wallStart := time.Now()
	for i := 0; i < burst; i++ {
		i := i
		go func() {
			defer wg.Done()
			ip := subnet.IP(i%254 + 1)
			ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
			defer cancel()
			bodyMap := map[string]any{"name": "lt-dedup-" + uuid.NewString()[:6]}
			raw, _ := json.Marshal(bodyMap)
			req, _ := http.NewRequestWithContext(ctx, http.MethodPost,
				baseURL()+"/cache/new", strings.NewReader(string(raw)))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("X-Forwarded-For", ip)
			if tok := e2eTestToken(); tok != "" {
				req.Header.Set("X-E2E-Test-Token", tok)
				req.Header.Set("X-E2E-Source-IP", ip)
			}
			start := time.Now()
			resp, err := client.Do(req)
			lat := time.Since(start)
			if err != nil {
				stats.record(outcome{
					status:   0,
					latency:  lat,
					err:      true,
					timedOut: ctx.Err() == context.DeadlineExceeded,
				})
				return
			}
			rb, _ := io.ReadAll(resp.Body)
			_ = resp.Body.Close()
			o := outcome{status: resp.StatusCode, latency: lat}
			if resp.StatusCode == 201 {
				var pv struct {
					Token string `json:"token"`
					Note  string `json:"note"`
				}
				if json.Unmarshal(rb, &pv) == nil {
					o.token = pv.Token
					if pv.Note != "" {
						fpJWTMu.Lock()
						if fpJWT == "" {
							if jwtTok := extractJWTLoose(pv.Note); jwtTok != "" {
								fpJWT = jwtTok
							}
						}
						fpJWTMu.Unlock()
					}
				}
			}
			stats.record(o)
		}()
	}
	wg.Wait()
	stats.report(t, fmt.Sprintf("anonymous dedup burst · %d req · 1 fingerprint", burst),
		time.Since(wallStart))

	// ── ASSERT: no 5xx ──
	if n := stats.fivexx(); n > 0 {
		t.Errorf("BREAKING POINT: dedup path returned %d 5xx under burst", n)
	}

	// ── ASSERT: no TRUE transport-layer drops (timeouts are a separate, softer
	//    latency finding — see below) ──
	if drops := stats.trueDrops(); drops > 0 {
		t.Errorf("BREAKING POINT: %d genuine transport-layer drops (connection reset/"+
			"refused, no client deadline involved)", drops)
	}
	// ── FINDING: client-deadline timeouts. The server did NOT drop these —
	//    the 60s client deadline fired while provisioning was still running.
	//    A latency finding, not a crash. ──
	if to := stats.timeouts(); to > 0 {
		t.Errorf("FINDING — LATENCY CLIFF: %d/%d anonymous provisions exceeded the "+
			"60s client deadline under a %d-way burst. Server still processing; not "+
			"a drop. The anonymous provision path serializes under concurrency. "+
			"See report S5 / Finding F1.", to, burst, burst)
	}

	// ── ASSERT: every NON-zero status is 201 / 402 / 429 (no surprises) ──
	stats.mu.Lock()
	for code, c := range stats.codeCount {
		switch code {
		case 0, 201, 402, 429:
			// 0 already classified above (timeout vs drop); rest are expected.
		default:
			t.Errorf("UNEXPECTED status %d (×%d) on anonymous dedup burst", code, c)
		}
	}
	// ── ASSERT: distinct 201 tokens bounded by the 5/day dedup cap ──
	tokens := map[string]bool{}
	for _, o := range stats.outcomes {
		if o.token != "" {
			tokens[o.token] = true
		}
	}
	stats.mu.Unlock()
	if len(tokens) > 5 {
		t.Errorf("FINDING — DAILY-CAP TOCTOU: %d distinct tokens minted from ONE "+
			"fingerprint under a %d-way burst; ProvisionLimit(\"anonymous\") cap is 5. "+
			"The limit-exceeded branch's dedup lookup races the in-flight provisions "+
			"and falls through to a fresh provision. Sequential callers still cap "+
			"correctly — this leak is concurrency-only. See report S5 / Finding F2.",
			len(tokens), burst)
	} else {
		t.Logf("dedup under burst: OK — %d distinct tokens (<= 5/day cap), %d total requests",
			len(tokens), burst)
	}
}

// ════════════════════════════════════════════════════════════════════════════
// TEST 3 — RATE-LIMIT / RECYCLE-GATE UNDER BURST (Lane B, anonymous)
// ════════════════════════════════════════════════════════════════════════════

// TestLoad_RecycleGate_UnderBurst hammers the anonymous endpoint past any
// per-fingerprint limit and asserts the platform sheds load CLEANLY:
//
//   - Blocked requests return a well-formed 402 (recycle gate) or 429
//     (rate limit) — a real, parseable error envelope.
//   - ZERO 5xx — load shedding must never look like a crash.
//   - ZERO transport-layer failures — no silently dropped connections.
//   - Every 402 carries the documented error code + claim_url so an agent
//     can act on it. This is the contract the recycle gate promises.
func TestLoad_RecycleGate_UnderBurst(t *testing.T) {
	subnet := uniqueSubnet(t)
	const burst = 40

	type gateResult struct {
		status   int
		latency  time.Duration
		errCode  string
		claimURL string
		transErr bool // status==0 — see timedOut to classify
		timedOut bool // client deadline fired (latency finding, not a drop)
	}
	results := make([]gateResult, burst)

	// Capture an onboarding JWT from any 201 so the test tears down every
	// anonymous resource it created on this fingerprint.
	var fpJWT string
	var fpJWTMu sync.Mutex
	t.Cleanup(func() {
		fpJWTMu.Lock()
		jwtTok := fpJWT
		fpJWTMu.Unlock()
		if jwtTok == "" {
			t.Log("recycle-gate cleanup: no 201 issued — nothing to tear down")
			return
		}
		teardownAnonymousFingerprint(t, jwtTok)
	})

	var wg sync.WaitGroup
	wg.Add(burst)
	wallStart := time.Now()
	for i := 0; i < burst; i++ {
		i := i
		go func() {
			defer wg.Done()
			ip := subnet.IP(i%254 + 1)
			ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
			defer cancel()
			raw, _ := json.Marshal(map[string]any{"name": "lt-gate-" + uuid.NewString()[:6]})
			req, _ := http.NewRequestWithContext(ctx, http.MethodPost,
				baseURL()+"/cache/new", strings.NewReader(string(raw)))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("X-Forwarded-For", ip)
			if tok := e2eTestToken(); tok != "" {
				req.Header.Set("X-E2E-Test-Token", tok)
				req.Header.Set("X-E2E-Source-IP", ip)
			}
			start := time.Now()
			resp, err := client.Do(req)
			lat := time.Since(start)
			if err != nil {
				results[i] = gateResult{
					status:   0,
					latency:  lat,
					transErr: true,
					timedOut: ctx.Err() == context.DeadlineExceeded,
				}
				return
			}
			rb, _ := io.ReadAll(resp.Body)
			_ = resp.Body.Close()
			r := gateResult{status: resp.StatusCode, latency: lat}
			var env struct {
				Error    string `json:"error"`
				ClaimURL string `json:"claim_url"`
				Note     string `json:"note"`
			}
			_ = json.Unmarshal(rb, &env)
			r.errCode = env.Error
			r.claimURL = env.ClaimURL
			if resp.StatusCode == 201 && env.Note != "" {
				fpJWTMu.Lock()
				if fpJWT == "" {
					if jwtTok := extractJWTLoose(env.Note); jwtTok != "" {
						fpJWT = jwtTok
					}
				}
				fpJWTMu.Unlock()
			}
			results[i] = r
		}()
	}
	wg.Wait()
	wall := time.Since(wallStart)

	// Tally.
	codeCount := map[int]int{}
	var fivexx, timedOut, trueDrop, malformed402 int
	var lat []time.Duration
	for _, r := range results {
		codeCount[r.status]++
		lat = append(lat, r.latency)
		if r.status >= 500 && r.status <= 599 {
			fivexx++
		}
		if r.transErr && r.timedOut {
			timedOut++
		}
		if r.transErr && !r.timedOut {
			trueDrop++
		}
		if r.status == 402 && (r.errCode == "" || r.claimURL == "") {
			malformed402++
		}
	}
	sort.Slice(lat, func(i, j int) bool { return lat[i] < lat[j] })
	p95 := lat[int(0.95*float64(len(lat)-1))]

	t.Logf("── LOAD WAVE: recycle-gate / rate-limit burst · %d req ──", burst)
	t.Logf("   wall=%s  p95=%s  throughput=%.1f req/s",
		wall.Round(time.Millisecond), p95.Round(time.Millisecond),
		float64(burst)/wall.Seconds())
	codes := make([]int, 0, len(codeCount))
	for c := range codeCount {
		codes = append(codes, c)
	}
	sort.Ints(codes)
	for _, c := range codes {
		t.Logf("   status %d: %d", c, codeCount[c])
	}

	// ── ASSERTIONS ──
	//
	// HARD breaking points (crash-class):
	if fivexx > 0 {
		t.Errorf("BREAKING POINT: %d × 5xx under burst — load shedding looked like "+
			"a crash. A 5xx is NOT clean load shedding; 402/429 are. See report S5 / "+
			"Finding F3.", fivexx)
	}
	if trueDrop > 0 {
		t.Errorf("BREAKING POINT: %d genuine transport-layer drops (connection reset/"+
			"refused, no client deadline) — silently lost requests", trueDrop)
	}
	if malformed402 > 0 {
		t.Errorf("CONTRACT VIOLATION: %d × 402 missing error code or claim_url — "+
			"agent cannot recover", malformed402)
	}
	// SOFT finding (latency, not a crash):
	if timedOut > 0 {
		t.Errorf("FINDING — LATENCY CLIFF: %d/%d requests exceeded the 60s client "+
			"deadline under a %d-way burst — server still processing, not a drop. "+
			"The anonymous provision path serializes under concurrency. See report "+
			"S5 / Finding F1.", timedOut, burst, burst)
	}
	// Bookkeeping: every request must be classified.
	clean := codeCount[201] + codeCount[402] + codeCount[429]
	if clean+timedOut+trueDrop+fivexx != burst {
		t.Errorf("BOOKKEEPING: %d clean + %d timeout + %d drop + %d 5xx != %d total",
			clean, timedOut, trueDrop, fivexx, burst)
	}
	if fivexx == 0 && trueDrop == 0 && timedOut == 0 {
		t.Logf("load-shedding under burst: CLEAN — all %d requests got 201/402/429, "+
			"zero 5xx, zero drops, zero timeouts, all 402s well-formed", burst)
	}
}
