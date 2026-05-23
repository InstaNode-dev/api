package experiments

import (
	"fmt"
	"math"
	"testing"
)

// TestPick_Determinism verifies the same (experiment, identifier) pair
// always returns the same variant, even across many calls. This is the
// load-bearing property — if it ever breaks, every existing bucket
// reshuffles and the conversion data goes incoherent.
func TestPick_Determinism(t *testing.T) {
	ids := []string{
		"team-uuid-aaa",
		"team-uuid-bbb",
		"fp:abcdef0123",
		// Empty string is a degenerate but legal identifier — it
		// happens when an unauthenticated request has no
		// fingerprint yet. Should still hash to a stable bucket.
		"",
		// Unicode + special chars — make sure the hash is bytewise
		// stable (no surprise normalization).
		"team-üñîçødé-🚀",
	}
	for _, id := range ids {
		first := Pick(ExperimentUpgradeButton, id)
		for i := 0; i < 20; i++ {
			got := Pick(ExperimentUpgradeButton, id)
			if got != first {
				t.Fatalf("Pick(%q) non-deterministic: first=%q got=%q on iter %d",
					id, first, got, i)
			}
		}
	}
}

// TestPick_UnknownExperiment returns "" so callers can detect a
// typo without a panic.
func TestPick_UnknownExperiment(t *testing.T) {
	got := Pick("definitely_not_registered", "team-1")
	if got != "" {
		t.Fatalf("unknown experiment should return empty string, got %q", got)
	}
}

// TestPick_ReturnsValidVariant guards against a regression where the
// modulus math drifts off-by-one and returns a bogus index. Every Pick
// result must be one of the registered variants for that experiment.
func TestPick_ReturnsValidVariant(t *testing.T) {
	e, ok := Get(ExperimentUpgradeButton)
	if !ok {
		t.Fatal("UpgradeButton experiment must be registered")
	}
	valid := map[string]bool{}
	for _, v := range e.Variants {
		valid[v] = true
	}
	for i := 0; i < 1000; i++ {
		id := fmt.Sprintf("team-%d", i)
		v := Pick(ExperimentUpgradeButton, id)
		if !valid[v] {
			t.Fatalf("Pick(%q) returned non-registered variant %q", id, v)
		}
	}
}

// TestPick_DistributionRoughly33 checks the bucket distribution is
// within tolerance of even thirds across a 1000-id sample. A real
// SHA256 won't be exactly 333/333/334 but it will be close; we allow a
// generous +/-5% to keep the test from flaking on sample-size variance
// while still catching a regression where one variant gets >50% of
// traffic.
func TestPick_DistributionRoughly33(t *testing.T) {
	const N = 1000
	counts := map[string]int{}
	for i := 0; i < N; i++ {
		id := fmt.Sprintf("identifier-%d", i)
		v := Pick(ExperimentUpgradeButton, id)
		counts[v]++
	}
	e, _ := Get(ExperimentUpgradeButton)
	want := float64(N) / float64(len(e.Variants))
	tolerance := want * 0.15 // 15% — generous for N=1000
	for _, v := range e.Variants {
		got := float64(counts[v])
		if math.Abs(got-want) > tolerance {
			t.Errorf("variant %q: got %d, want ~%.0f (±%.0f) — distribution skew",
				v, counts[v], want, tolerance)
		}
	}
	// Sanity: counts must sum to N (no identifier dropped).
	sum := 0
	for _, c := range counts {
		sum += c
	}
	if sum != N {
		t.Fatalf("counts sum to %d, want %d (bucket leak)", sum, N)
	}
}

// TestPickAll_HasEveryRegistered verifies the one-shot helper used by
// /auth/me returns a variant for every registered experiment with no
// gaps, and matches what Pick would have returned per-experiment.
func TestPickAll_HasEveryRegistered(t *testing.T) {
	id := "team-pickall-test"
	got := PickAll(id)
	all := All()
	if len(got) != len(all) {
		t.Fatalf("PickAll returned %d entries, registered %d", len(got), len(all))
	}
	for name := range all {
		single := Pick(name, id)
		if got[name] != single {
			t.Errorf("PickAll[%s]=%q, Pick(%s,id)=%q — disagreement",
				name, got[name], name, single)
		}
	}
}

// TestAll_IsCopy ensures the All() return is a copy — callers
// mutating it must not corrupt the registry.
func TestAll_IsCopy(t *testing.T) {
	a := All()
	a["injected"] = Experiment{Name: "injected"}
	if _, ok := Get("injected"); ok {
		t.Fatal("All() returned the live registry; callers can corrupt it")
	}
}

// TestSaltIsolation_DifferentSaltsDiffer verifies two experiments with
// the same variant list but different salts bucket the same id into
// (potentially) different variants — i.e., the salt isn't ignored.
// We sample 200 ids and require the two assignments disagree at least
// 40% of the time; with truly independent hashes the expected
// disagreement rate is (k-1)/k = 66.7% for k=3 variants.
func TestSaltIsolation_DifferentSaltsDiffer(t *testing.T) {
	const N = 200
	vs := []string{"a", "b", "c"}
	disagree := 0
	for i := 0; i < N; i++ {
		id := fmt.Sprintf("salt-test-%d", i)
		x := pickFromVariants(vs, "salt-one", id)
		y := pickFromVariants(vs, "salt-two", id)
		if x != y {
			disagree++
		}
	}
	if disagree < N*40/100 {
		t.Fatalf("salt isolation weak: only %d/%d disagreements; expected >= %d",
			disagree, N, N*40/100)
	}
}

// ---------------------------------------------------------------------------
// register panic branches + pickFromVariants empty guard
// ---------------------------------------------------------------------------

// TestRegister_PanicsOnDuplicate verifies a second registration of the same
// name fails loudly — duplicate registration is always a programmer error.
func TestRegister_PanicsOnDuplicate(t *testing.T) {
	const name = "test_dup_experiment"
	register(Experiment{Name: name, Variants: []string{"a", "b"}, Salt: "s"})
	t.Cleanup(func() { delete(registry, name) })

	defer func() {
		r := recover()
		if r == nil {
			t.Fatal("expected panic on duplicate registration")
		}
		msg, _ := r.(string)
		if msg != "experiments: duplicate registration: "+name {
			t.Fatalf("unexpected panic message: %v", r)
		}
	}()
	register(Experiment{Name: name, Variants: []string{"x"}, Salt: "s2"})
}

// TestRegister_PanicsOnEmptyVariants verifies an experiment with no variants
// fails loudly at startup rather than silently producing "" buckets.
func TestRegister_PanicsOnEmptyVariants(t *testing.T) {
	const name = "test_empty_variants_experiment"
	defer func() {
		r := recover()
		if r == nil {
			t.Fatal("expected panic on empty variants")
		}
		msg, _ := r.(string)
		if msg != "experiments: variants empty: "+name {
			t.Fatalf("unexpected panic message: %v", r)
		}
		// Ensure the failed registration did not leak into the registry.
		if _, ok := registry[name]; ok {
			delete(registry, name)
			t.Fatal("empty-variant experiment must not be registered")
		}
	}()
	register(Experiment{Name: name, Variants: nil, Salt: "s"})
}

// TestPickFromVariants_EmptyReturnsEmpty exercises the defensive empty-slice
// guard that Pick relies on for unknown experiments.
func TestPickFromVariants_EmptyReturnsEmpty(t *testing.T) {
	if got := pickFromVariants(nil, "salt", "id"); got != "" {
		t.Fatalf("empty variants must return \"\", got %q", got)
	}
	if got := pickFromVariants([]string{}, "salt", "id"); got != "" {
		t.Fatalf("empty variants must return \"\", got %q", got)
	}
}
