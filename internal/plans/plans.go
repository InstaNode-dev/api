// Package plans re-exports the shared plan registry from instant.dev/common/plans.
package plans

import commonplans "instant.dev/common/plans"

// Registry is an in-memory index of all plan and promotion definitions.
type Registry = commonplans.Registry

// Load reads and parses a plans YAML file and returns a validated Registry.
func Load(path string) (*Registry, error) { return commonplans.Load(path) }

// Default returns a Registry built from embedded defaults.
func Default() *Registry { return commonplans.Default() }
