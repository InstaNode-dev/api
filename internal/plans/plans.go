// Package plans re-exports the shared plan registry from instant.dev/common/plans.
package plans

import commonplans "instant.dev/common/plans"

// Registry is an in-memory index of all plan and promotion definitions.
type Registry = commonplans.Registry

// Plan re-exports the fully resolved configuration for one pricing tier
// so handlers in this module don't need to import the shared package
// directly. capabilities.go uses this to receive the registry's Plan map
// from Registry.All() and read DisplayName / PriceMonthly / BillingPeriod
// without an extra import line.
type Plan = commonplans.Plan

// Load reads and parses a plans YAML file and returns a validated Registry.
func Load(path string) (*Registry, error) { return commonplans.Load(path) }

// Default returns a Registry built from embedded defaults.
func Default() *Registry { return commonplans.Default() }

// CanonicalTier strips the "_yearly" suffix from a plan name and returns the
// base tier (e.g. "pro_yearly" -> "pro"). Re-exported from common/plans so
// handlers in this module don't need to import the shared package directly.
func CanonicalTier(tier string) string { return commonplans.CanonicalTier(tier) }

// Rank returns the totally-ordered rank of the given plan tier. Higher rank
// = more capacity (anonymous=0, free=1, hobby=2, hobby_plus=3, pro=4,
// growth=5, team=6 — anchored to plans.yaml pricing, pro $49 < growth $99).
// Unknown tiers return -1 — callers MUST guard against the sentinel when
// comparing two ranks (a negative rank means "no transition direction").
//
// Re-exported from common/plans so api handlers don't need to import the
// shared package directly. The yearly variants are NOT auto-normalised —
// pass them through CanonicalTier first if you want "pro_yearly" to rank
// the same as "pro".
func Rank(tier string) int { return commonplans.Rank(tier) }
