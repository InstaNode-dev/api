package manifest

import (
	"fmt"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// Manifest is the parsed and validated instant.yaml.
type Manifest struct {
	Services map[string]*ServiceDef
}

// ServiceDef describes a single service in the stack.
type ServiceDef struct {
	Build  string            // relative path to build context (must contain Dockerfile)
	Port   int               // default 8080 if unspecified
	Expose bool              // if true: creates k8s Ingress
	Needs  []string          // resource tokens (validated by handler, not parser)
	Env    map[string]string // after Resolve(): service:// replaced with http://name:port
}

// ParseWarning is a non-fatal issue found during validation or resolution.
type ParseWarning struct {
	Message string
}

// rawManifest is the internal struct used for YAML unmarshaling.
type rawManifest struct {
	Services map[string]*rawServiceDef `yaml:"services"`
}

// rawServiceDef mirrors ServiceDef with yaml struct tags.
type rawServiceDef struct {
	Build  string            `yaml:"build"`
	Port   int               `yaml:"port"`
	Expose bool              `yaml:"expose"`
	Needs  []string          `yaml:"needs"`
	Env    map[string]string `yaml:"env"`
}

// Parse reads and unmarshals an instant.yaml manifest.
// Returns error if YAML is malformed or services block is empty.
func Parse(data []byte) (*Manifest, error) {
	var raw rawManifest
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("manifest: invalid YAML: %w", err)
	}

	if len(raw.Services) == 0 {
		return nil, fmt.Errorf("manifest has no services defined")
	}

	m := &Manifest{
		Services: make(map[string]*ServiceDef, len(raw.Services)),
	}

	for name, rsvc := range raw.Services {
		if name == "" {
			return nil, fmt.Errorf("manifest: service name must not be empty")
		}
		if rsvc == nil {
			rsvc = &rawServiceDef{}
		}
		port := rsvc.Port
		if port == 0 {
			port = 8080
		}
		m.Services[name] = &ServiceDef{
			Build:  rsvc.Build,
			Port:   port,
			Expose: rsvc.Expose,
			Needs:  rsvc.Needs,
			Env:    rsvc.Env,
		}
	}

	return m, nil
}

// Validate checks all service:// env var references.
// Returns error if any service:// ref points to a service not defined in the manifest.
// Circular refs (A->B->A) are allowed (k8s DNS resolves lazily); they produce a ParseWarning.
func (m *Manifest) Validate() ([]ParseWarning, error) {
	// Build set of known service names.
	known := make(map[string]bool, len(m.Services))
	for name := range m.Services {
		known[name] = true
	}

	var warnings []ParseWarning

	// DFS-based cycle detection.
	// visited tracks nodes whose entire subtree has been explored.
	// inStack tracks nodes currently on the DFS path.
	visited := make(map[string]bool)
	inStack := make(map[string]bool)
	cycleWarned := make(map[string]bool) // deduplicate cycle warnings

	// adjacency: service name → list of service:// refs it makes
	adj := make(map[string][]string, len(m.Services))
	for svcName, svc := range m.Services {
		for key, val := range svc.Env {
			if !strings.HasPrefix(val, "service://") {
				continue
			}
			ref := strings.TrimPrefix(val, "service://")
			if !known[ref] {
				return nil, fmt.Errorf("service %q: env %s: references unknown service %q", svcName, key, ref)
			}
			adj[svcName] = append(adj[svcName], ref)
		}
	}

	// DFS — detect cycles and emit warnings.
	var dfs func(node string) bool
	dfs = func(node string) bool {
		if inStack[node] {
			return true // cycle detected
		}
		if visited[node] {
			return false
		}
		inStack[node] = true
		for _, neighbor := range adj[node] {
			if dfs(neighbor) {
				// Build a human-readable warning for this edge.
				key := node + "→" + neighbor
				if !cycleWarned[key] {
					cycleWarned[key] = true
					warnings = append(warnings, ParseWarning{
						Message: fmt.Sprintf("circular service reference detected: %s → %s", node, neighbor),
					})
				}
			}
		}
		inStack[node] = false
		visited[node] = true
		return false
	}

	for name := range m.Services {
		dfs(name)
	}

	return warnings, nil
}

// Resolve replaces all service://name values in env blocks with http://name:port.
// Port comes from the referenced service's Port field (default 8080).
// Must call Validate() first to ensure all refs exist.
// Modifies m.Services[*].Env in place.
func (m *Manifest) Resolve() error {
	// Build port map.
	portMap := make(map[string]int, len(m.Services))
	for name, svc := range m.Services {
		portMap[name] = svc.Port
	}

	for _, svc := range m.Services {
		for key, val := range svc.Env {
			if !strings.HasPrefix(val, "service://") {
				continue
			}
			refName := strings.TrimPrefix(val, "service://")
			port, ok := portMap[refName]
			if !ok {
				return fmt.Errorf("manifest: resolve: service %q not found in manifest; call Validate() first", refName)
			}
			svc.Env[key] = fmt.Sprintf("http://%s:%d", refName, port)
		}
	}

	return nil
}

// ServiceNames returns a sorted slice of all service names in the manifest.
func (m *Manifest) ServiceNames() []string {
	names := make([]string, 0, len(m.Services))
	for name := range m.Services {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}
