// Package experiments holds the server-side variant selector for A/B tests.
//
// Design goals:
//
//   - Deterministic per-identifier bucketing — the same caller always
//     lands in the same variant for a given experiment, so analytics can
//     be reconstructed retroactively from the audit log alone (no extra
//     "assignment" row needed).
//
//   - Salt = experiment name. This keeps two experiments running in
//     parallel statistically independent even when bucketed by the same
//     identifier (e.g. a team_id seeing both UpgradeButton and a future
//     PricingHeadline experiment lands in uncorrelated buckets).
//
//   - Zero external state. The "registry" is a compile-time map; the
//     bucket function is a pure SHA256(identifier + salt) mod N. No DB
//     round-trip, no Redis, no cache invalidation story to maintain.
//
// The first experiment registered here is UpgradeButton — the dashboard
// reads its variant out of GET /auth/me's `experiments` field and
// renders one of three button label/color combinations. Conversion is
// recorded via POST /api/v1/experiments/converted writing an audit_log
// row, which is the only assignment-time signal we keep.
package experiments

import (
	"crypto/sha256"
	"encoding/binary"
)

// Experiment names — used as both the registry key and the salt input
// to Pick. Exported as constants so callers (handlers, tests, the
// dashboard's audit-event filter) reference the same string.
const (
	// ExperimentUpgradeButton — A/B test the upgrade CTA label and
	// color across {control, urgent, value}. P1 of the pricing
	// experiments track.
	ExperimentUpgradeButton = "upgrade_button"
)

// Variant strings for the UpgradeButton experiment. Exported so tests
// + the dashboard can assert against the same labels without
// stringly-typed drift.
const (
	VariantControl = "control"
	VariantUrgent  = "urgent"
	VariantValue   = "value"
)

// Experiment describes a single A/B test. Variants are listed in a
// stable order — Pick maps the SHA256 modulus onto this slice, so
// reordering variants reshuffles existing users. Don't reorder a live
// experiment; add new variants at the tail.
type Experiment struct {
	Name     string
	Variants []string
	// Salt is appended to the identifier before hashing. By
	// convention this equals Name so two experiments stay
	// independent even when sharing one identifier. Kept as a
	// separate field so a future experiment can override (e.g.
	// "re-bucket everyone after a fix" by rotating the salt).
	Salt string
}

// registry holds every experiment the server knows about. Populated in
// init() so callers can iterate it without locking. Read-only after
// startup.
var registry = map[string]Experiment{}

func init() {
	register(Experiment{
		Name:     ExperimentUpgradeButton,
		Variants: []string{VariantControl, VariantUrgent, VariantValue},
		Salt:     ExperimentUpgradeButton,
	})
}

// register adds an experiment to the registry. Panics on duplicate
// name — duplicate registration is always a programmer error and
// should fail loudly at startup rather than silently overwrite.
func register(e Experiment) {
	if _, ok := registry[e.Name]; ok {
		panic("experiments: duplicate registration: " + e.Name)
	}
	if len(e.Variants) == 0 {
		panic("experiments: variants empty: " + e.Name)
	}
	registry[e.Name] = e
}

// All returns the registered experiments. Used by the /auth/me
// handler to bucket the caller into every active experiment in one
// pass. The returned map is a copy so callers can't mutate the
// registry through it.
func All() map[string]Experiment {
	out := make(map[string]Experiment, len(registry))
	for k, v := range registry {
		out[k] = v
	}
	return out
}

// Get returns an experiment by name. The second return value is false
// when the name is unknown; callers should treat that as "no
// experiment running" and skip the bucket step.
func Get(name string) (Experiment, bool) {
	e, ok := registry[name]
	return e, ok
}

// Pick returns the variant for (experiment, identifier). It's
// deterministic: the same input always returns the same variant. An
// unknown experiment returns "" — callers must check.
//
// Identifier can be any stable string per-caller — team_id for
// claimed users, fingerprint for anonymous. Mixing them in one
// experiment is fine; the modulus distribution is the same.
func Pick(experiment, identifier string) string {
	e, ok := registry[experiment]
	if !ok {
		return ""
	}
	return pickFromVariants(e.Variants, e.Salt, identifier)
}

// pickFromVariants is the pure hashing core, factored out so tests
// can exercise it with custom variant lists / salts without mutating
// the global registry.
func pickFromVariants(variants []string, salt, identifier string) string {
	if len(variants) == 0 {
		return ""
	}
	h := sha256.Sum256([]byte(identifier + "|" + salt))
	// Use the first 8 bytes as a uint64 — 64 bits of entropy is
	// vastly more than enough to evenly distribute across small N
	// variant counts, and avoids a big.Int allocation.
	n := binary.BigEndian.Uint64(h[:8])
	idx := int(n % uint64(len(variants)))
	return variants[idx]
}

// PickAll buckets the identifier into every registered experiment in
// one call. Used by GET /auth/me to embed an `experiments` map in
// the response so the dashboard needs one round trip to learn every
// active assignment.
func PickAll(identifier string) map[string]string {
	out := make(map[string]string, len(registry))
	for name, e := range registry {
		out[name] = pickFromVariants(e.Variants, e.Salt, identifier)
	}
	return out
}
