// Package plans re-exports the shared plan registry from instant.dev/common/plans.
package plans

import commonplans "instant.dev/common/plans"

// Registry is an in-memory index of all plan and promotion definitions.
type Registry = commonplans.Registry

// Load reads and parses a plans YAML file and returns a validated Registry.
func Load(path string) (*Registry, error) { return commonplans.Load(path) }

// Default returns a Registry built from embedded defaults.
func Default() *Registry { return commonplans.Default() }

// CanonicalTier strips the "_yearly" suffix from a plan name and returns the
// base tier (e.g. "pro_yearly" -> "pro"). Re-exported from common/plans so
// handlers in this module don't need to import the shared package directly.
func CanonicalTier(tier string) string { return commonplans.CanonicalTier(tier) }
