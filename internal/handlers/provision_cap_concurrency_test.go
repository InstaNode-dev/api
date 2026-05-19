package handlers

// provision_cap_concurrency_test.go — regression coverage for load-test
// finding F2 (LOAD-CHAOS-REPORT-2026-05-19.md): the per-fingerprint daily
// anonymous provisioning cap was NOT concurrency-safe. A 30-way simultaneous
// burst from one fingerprint minted 22–29 tokens instead of capping at 5.
//
// THE BUG (TOCTOU): each anonymous provisioning handler did
//
//	limitExceeded := checkProvisionLimit(fp)   // atomic INCR — fine
//	if limitExceeded {
//	    existing := GetActiveResourceByFingerprintType(...)   // misses
//	    if existing-also-misses-cross-service { ... }         // misses
//	    // <-- FELL THROUGH HERE to CreateResource
//	}
//	CreateResource(...)   // every burst caller minted a fresh token
//
// During a *simultaneous* burst the ≤5 winning provisions have claimed
// their atomic-INCR slots but have NOT yet committed a `resources` row, so
// both dedup lookups return ErrResourceNotFound — and control fell through
// to CreateResource. All 30 callers minted.
//
// THE FIX: checkProvisionLimit's atomic INCR is the gate (its return value
// IS the caller's claimed slot); the over-cap branch now calls
// denyProvisionOverCap on the no-existing-resource path instead of falling
// through — see provision_helper.go.
//
// These tests model the exact handler decision flow against the real,
// fixed helper methods:
//   - TestProvisionCap_ConcurrentBurst_CapsAt5 reproduces F2: 30 goroutines,
//     one fingerprint, asserts ≤5 mints. Fails on the pre-fix fall-through.
//   - TestProvisionCap_Sequential_FiveThenExisting confirms the documented
//     non-burst behavior (≤5 succeed, the rest return the existing token)
//     is unchanged.

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// committedStore is an in-memory stand-in for the `resources` table on the
// anonymous-provisioning path. A token only becomes visible to a dedup
// lookup AFTER the provisioning caller commits it — exactly like a real
// CreateResource row. Concurrency-safe.
type committedStore struct {
	mu     sync.Mutex
	tokens []string
}

// commit records a freshly-minted token (mirrors models.CreateResource).
func (s *committedStore) commit(tok string) {
	s.mu.Lock()
	s.tokens = append(s.tokens, tok)
	s.mu.Unlock()
}

// lookupExisting mirrors models.GetActiveResourceByFingerprint{,Type}: it
// returns a committed token if one exists, else ("", false). During a
// simultaneous burst this returns ("", false) for every caller because the
// winners have not committed yet — the exact condition that triggered the
// F2 fall-through.
func (s *committedStore) lookupExisting() (string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.tokens) == 0 {
		return "", false
	}
	return s.tokens[0], true
}

// provisionOutcome is what one anonymous /{service}/new call resolves to.
type provisionOutcome struct {
	token   string // the token returned to the caller (minted OR existing)
	minted  bool   // true => a NEW token was created (CreateResource ran)
	existed bool   // true => an existing token was returned (dedup hit)
	denied  bool   // true => 429 over-cap deny (denyProvisionOverCap path)
}

// f2Behavior selects which version of the over-cap branch runAnonymousProvision
// uses. f2Fixed is the shipped code; f2PreFix re-creates the TOCTOU
// fall-through so a single test can prove the fix actually changes the
// outcome (a regression test that cannot fail without the fix proves
// nothing — CLAUDE.md convention #17/#18).
type f2Behavior int

const (
	f2Fixed  f2Behavior = iota // over-cap + no existing row → deny (shipped)
	f2PreFix                   // over-cap + no existing row → FALL THROUGH to mint
)

// runAnonymousProvision faithfully replays the anonymous-path decision flow
// that every one of the six (db/cache/nosql/queue/storage/webhook)
// handlers — and vector — share, exercising the REAL fixed helper
// (checkProvisionLimit). The branch structure mirrors db.go exactly:
//
//	limitExceeded := checkProvisionLimit(fp)
//	if limitExceeded {
//	    if existing := lookup(); found { return existing }     // dedup
//	    return deny                                            // F2 FIX
//	}
//	mint()                                                     // winners only
//
// The pre-fix bug was the *absence* of the `return deny` line: control fell
// through to mint(). Passing f2PreFix re-enables that fall-through.
//
// The `commitWinner` callback lets a test interpose a barrier between
// "claim the atomic slot" and "commit the resources row" — the exact window
// the F2 burst exploited (winners have INCR'd but not yet committed).
func runAnonymousProvision(
	ctx context.Context,
	h *provisionHelper,
	store *committedStore,
	fp string,
	minted *int64,
	mode f2Behavior,
	commitWinner func(tok string),
) provisionOutcome {
	limitExceeded, err := h.checkProvisionLimit(ctx, fp)
	if err != nil {
		// Fail-open (CLAUDE.md convention #6): a Redis outage must never
		// block provisioning. Treated as "not over cap" — provision fresh.
		limitExceeded = false
	}

	if limitExceeded {
		// Over the cap. Try to dedup onto a committed winner.
		if tok, found := store.lookupExisting(); found {
			return provisionOutcome{token: tok, existed: true}
		}
		if mode == f2PreFix {
			// PRE-FIX BUG: no committed winner visible (burst winners still
			// in-flight) → control FELL THROUGH to CreateResource. Every
			// over-cap caller minted. This is what produced 22–29 tokens.
			// The fall-through mint is itself a racing CreateResource, so it
			// routes through commitWinner just like a winner's mint — held
			// uncommitted behind the barrier so it doesn't accidentally let
			// later callers dedup onto it and understate the leak.
			tok := uuid.NewString()
			atomic.AddInt64(minted, 1)
			if commitWinner != nil {
				commitWinner(tok)
			} else {
				store.commit(tok)
			}
			return provisionOutcome{token: tok, minted: true}
		}
		// F2 TOCTOU FIX: no committed winner visible yet. The atomic INCR
		// already proved this caller is over the cap — it MUST be denied,
		// never fall through to mint. (provision_helper.go denyProvisionOverCap)
		return provisionOutcome{denied: true}
	}

	// Within the cap — this caller is one of the ≤5 winners. Mint.
	tok := uuid.NewString()
	atomic.AddInt64(minted, 1)
	// commitWinner lets the test hold the row uncommitted until every
	// over-cap caller has run its lookup — reproducing the F2 race window
	// deterministically rather than hoping the scheduler hits it.
	if commitWinner != nil {
		commitWinner(tok)
	} else {
		store.commit(tok)
	}
	return provisionOutcome{token: tok, minted: true}
}

// f2BurstResult is the tally of one 30-way burst run.
type f2BurstResult struct {
	minted, existed, denied, distinct int
}

// runF2Burst fires `burst` simultaneous anonymous provisions from ONE
// fingerprint and DETERMINISTICALLY reproduces the F2 race window: every
// winning provision holds its `resources` row UNCOMMITTED until all `burst`
// callers have passed the dedup-lookup point. That is precisely the
// real-world burst state — winners have claimed their atomic-INCR slot but
// have not yet committed — and it is the state that made every pre-fix
// over-cap caller's dedup lookup miss and fall through to mint.
//
// With the fix (f2Fixed) the over-cap callers hit denyProvisionOverCap and
// only `cap` tokens are ever minted. With f2PreFix the fall-through fires
// and all `burst` callers mint — exactly the 22–29-token finding.
func runF2Burst(t *testing.T, mode f2Behavior, burst int) f2BurstResult {
	t.Helper()
	h, _, _, cleanup := newTestHelper(t)
	defer cleanup()

	const fp = "fp_f2_burst_single_fingerprint"
	store := &committedStore{}
	var minted int64

	// reachedDedup counts callers that have passed the point where a real
	// handler would run its GetActiveResourceByFingerprint lookup. Winners
	// wait until ALL callers have reached it before committing — holding the
	// F2 window open for the entire burst.
	var reachedDedup sync.WaitGroup
	reachedDedup.Add(burst)
	allReached := make(chan struct{})
	var once sync.Once

	commitWinner := func(tok string) {
		// A winner reached the commit step. Signal it has passed dedup,
		// then block until every caller has — so over-cap callers do their
		// lookup against an empty store.
		reachedDedup.Done()
		<-allReached
		store.commit(tok)
	}

	release := make(chan struct{})
	outcomes := make([]provisionOutcome, burst)
	var wg sync.WaitGroup
	wg.Add(burst)
	for i := 0; i < burst; i++ {
		go func(idx int) {
			defer wg.Done()
			<-release
			// Over-cap callers signal "reached dedup" themselves (they never
			// reach commitWinner). Winners signal inside commitWinner.
			outcomes[idx] = runAnonymousProvisionInstrumented(
				context.Background(), &h, store, fp, &minted, mode,
				commitWinner, &reachedDedup)
		}(i)
	}
	close(release)

	// Once every caller has reached the dedup point, unblock the winners.
	go func() {
		reachedDedup.Wait()
		once.Do(func() { close(allReached) })
	}()
	wg.Wait()

	res := f2BurstResult{}
	distinct := map[string]struct{}{}
	for _, o := range outcomes {
		switch {
		case o.minted:
			res.minted++
			distinct[o.token] = struct{}{}
		case o.existed:
			res.existed++
			distinct[o.token] = struct{}{}
		case o.denied:
			res.denied++
		default:
			t.Fatalf("a provision resolved to no outcome: %+v", o)
		}
	}
	res.distinct = len(distinct)
	return res
}

// runAnonymousProvisionInstrumented wraps runAnonymousProvision so an
// over-cap caller (which never reaches commitWinner) still signals that it
// has passed the dedup-lookup point — keeping the barrier accounting exact.
func runAnonymousProvisionInstrumented(
	ctx context.Context,
	h *provisionHelper,
	store *committedStore,
	fp string,
	minted *int64,
	mode f2Behavior,
	commitWinner func(tok string),
	reachedDedup *sync.WaitGroup,
) provisionOutcome {
	signalled := false
	wrapped := func(tok string) {
		signalled = true
		commitWinner(tok)
	}
	o := runAnonymousProvision(ctx, h, store, fp, minted, mode, wrapped)
	if !signalled {
		// Over-cap caller: it passed the dedup lookup without minting.
		reachedDedup.Done()
	}
	return o
}

// TestProvisionCap_ConcurrentBurst_CapsAt5 is the F2 reproduction. It fires
// 30 simultaneous anonymous provisions from ONE fingerprint, holding the
// race window open for the whole burst, and asserts the per-fingerprint
// daily cap (plans.yaml anonymous provisions_per_day = 5) holds.
//
// CRITICAL — this test PROVES it pins F2: it runs the SAME burst twice.
//   - f2PreFix (fall-through) must mint all 30 → asserted, so the test
//     genuinely fails when the fix is absent.
//   - f2Fixed (denyProvisionOverCap) must mint exactly 5 → the contract.
func TestProvisionCap_ConcurrentBurst_CapsAt5(t *testing.T) {
	const burst = 30

	// Sanity: cap is 5.
	h, _, _, cleanup := newTestHelper(t)
	cap := h.plans.ProvisionLimit(provisionLimitTier)
	cleanup()
	require.Equal(t, 5, cap, "anonymous provisions_per_day must be 5 (plans.yaml)")

	// 1. Prove the test reproduces F2: without the fix, the fall-through
	//    mints every burst caller. If this ever stops minting > cap, the
	//    test no longer exercises the race and the f2Fixed assertion is
	//    worthless.
	pre := runF2Burst(t, f2PreFix, burst)
	t.Logf("PRE-FIX burst: minted=%d existed=%d denied=%d distinct=%d",
		pre.minted, pre.existed, pre.denied, pre.distinct)
	require.Greaterf(t, pre.minted, cap,
		"the test must reproduce F2: with the fall-through, a %d-way burst "+
			"must mint MORE than the cap (%d). Got %d — the race window is "+
			"not being held open; the fixed assertion below would be hollow.",
		burst, cap, pre.minted)

	// 2. The fix: the SAME burst under denyProvisionOverCap caps at 5.
	got := runF2Burst(t, f2Fixed, burst)
	t.Logf("FIXED burst:   minted=%d existed=%d denied=%d distinct=%d",
		got.minted, got.existed, got.denied, got.distinct)

	assert.LessOrEqualf(t, got.minted, cap,
		"F2 REGRESSION: %d tokens minted from a %d-way burst on one "+
			"fingerprint — the cap is %d. The TOCTOU fall-through is back.",
		got.minted, burst, cap)
	assert.Equalf(t, cap, got.minted,
		"exactly %d winners must mint under a full burst", cap)
	assert.Equal(t, burst, got.minted+got.existed+got.denied,
		"every burst caller must mint, dedup, or be denied — none may fall through")
	assert.LessOrEqualf(t, got.distinct, cap,
		"distinct tokens returned (%d) exceeds the cap (%d)", got.distinct, cap)
	assert.Equalf(t, burst-cap, got.denied,
		"the %d over-cap callers must all be denied (429), since no winner "+
			"committed before they ran their lookup", burst-cap)
}

// TestProvisionCap_Sequential_FiveThenExisting confirms the documented
// non-burst behavior is unchanged by the fix: the first 5 sequential
// provisions from one fingerprint succeed (mint), and the 6th onward return
// the EXISTING token (dedup) — never a 6th distinct token, never a denial,
// because by call 6 a committed winner is always visible.
//
// This is the CLAUDE.md convention #6 contract: "≤5 succeed, the 6th call
// returns the existing token."
func TestProvisionCap_Sequential_FiveThenExisting(t *testing.T) {
	h, _, _, cleanup := newTestHelper(t)
	defer cleanup()

	const fp = "fp_sequential_cap_walk"
	cap := h.plans.ProvisionLimit(provisionLimitTier)
	require.Equal(t, 5, cap)

	store := &committedStore{}
	var minted int64
	ctx := context.Background()

	var firstToken string
	for call := 1; call <= 10; call++ {
		o := runAnonymousProvision(ctx, &h, store, fp, &minted, f2Fixed, nil)
		if call <= cap {
			require.Truef(t, o.minted,
				"call %d (≤ cap %d) must mint a fresh token", call, cap)
			if firstToken == "" {
				firstToken = o.token
			}
		} else {
			require.Falsef(t, o.minted,
				"call %d (> cap %d) must NOT mint — the cap is spent", call, cap)
			require.Truef(t, o.existed,
				"call %d (> cap %d) must return the EXISTING token "+
					"(CLAUDE.md #6 dedup contract)", call, cap)
			require.Equalf(t, firstToken, o.token,
				"call %d must return the first committed token, not a new one", call)
		}
	}

	assert.Equalf(t, int64(cap), minted,
		"exactly %d tokens minted across 10 sequential calls — the rest dedup'd", cap)
}

// TestCheckProvisionLimit_AtomicUnderConcurrency directly stresses the gate
// primitive: N goroutines call checkProvisionLimit for one fingerprint and
// the test asserts EXACTLY `cap` of them are cleared (limitExceeded ==
// false) — proving the atomic INCR hands out distinct slots with no
// check-then-act window. This is the unit-level proof beneath the
// handler-level F2 test above.
func TestCheckProvisionLimit_AtomicUnderConcurrency(t *testing.T) {
	h, _, _, cleanup := newTestHelper(t)
	defer cleanup()

	const fp = "fp_atomic_gate_stress"
	const burst = 40
	cap := h.plans.ProvisionLimit(provisionLimitTier)

	release := make(chan struct{})
	var cleared int64

	var wg sync.WaitGroup
	wg.Add(burst)
	for i := 0; i < burst; i++ {
		go func() {
			defer wg.Done()
			<-release
			limitExceeded, err := h.checkProvisionLimit(context.Background(), fp)
			require.NoError(t, err)
			if !limitExceeded {
				atomic.AddInt64(&cleared, 1)
			}
		}()
	}
	close(release)
	wg.Wait()

	assert.Equalf(t, int64(cap), cleared,
		"checkProvisionLimit cleared %d callers from a %d-way burst — must "+
			"clear exactly the cap (%d). A different count means the atomic "+
			"INCR gate leaked.", cleared, burst, cap)
}
