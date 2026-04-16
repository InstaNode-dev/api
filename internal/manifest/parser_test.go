package manifest

import (
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// TestParse
// ---------------------------------------------------------------------------

func TestParse(t *testing.T) {
	type testCase struct {
		name       string
		input      []byte
		wantErr    bool
		assertions func(t *testing.T, m *Manifest)
	}

	cases := []testCase{
		{
			name: "valid two-service manifest",
			input: []byte(`
services:
  api:
    build: ./api
    port: 8080
    expose: true
    needs:
      - postgres-abc123
      - redis-xyz789
    env:
      LOG_LEVEL: debug
      WORKER_URL: service://worker
  worker:
    build: ./worker
    port: 9000
    expose: false
    needs:
      - postgres-abc123
    env:
      QUEUE_SIZE: "100"
`),
			wantErr: false,
			assertions: func(t *testing.T, m *Manifest) {
				t.Helper()
				if len(m.Services) != 2 {
					t.Fatalf("expected 2 services, got %d", len(m.Services))
				}

				api, ok := m.Services["api"]
				if !ok {
					t.Fatal("expected service 'api' to exist")
				}
				if api.Build != "./api" {
					t.Errorf("api.Build: got %q, want %q", api.Build, "./api")
				}
				if api.Port != 8080 {
					t.Errorf("api.Port: got %d, want 8080", api.Port)
				}
				if !api.Expose {
					t.Error("api.Expose: got false, want true")
				}
				if len(api.Needs) != 2 {
					t.Errorf("api.Needs: got %d items, want 2", len(api.Needs))
				}
				if api.Env["LOG_LEVEL"] != "debug" {
					t.Errorf("api.Env[LOG_LEVEL]: got %q, want %q", api.Env["LOG_LEVEL"], "debug")
				}
				if api.Env["WORKER_URL"] != "service://worker" {
					t.Errorf("api.Env[WORKER_URL]: got %q, want %q", api.Env["WORKER_URL"], "service://worker")
				}

				worker, ok := m.Services["worker"]
				if !ok {
					t.Fatal("expected service 'worker' to exist")
				}
				if worker.Build != "./worker" {
					t.Errorf("worker.Build: got %q, want %q", worker.Build, "./worker")
				}
				if worker.Port != 9000 {
					t.Errorf("worker.Port: got %d, want 9000", worker.Port)
				}
				if worker.Expose {
					t.Error("worker.Expose: got true, want false")
				}
				if worker.Env["QUEUE_SIZE"] != "100" {
					t.Errorf("worker.Env[QUEUE_SIZE]: got %q, want %q", worker.Env["QUEUE_SIZE"], "100")
				}
			},
		},
		{
			name:    "empty services block",
			input:   []byte(`services: {}`),
			wantErr: true,
		},
		{
			name:    "nil services block",
			input:   []byte(`services:`),
			wantErr: true,
		},
		{
			name:    "malformed YAML — unclosed bracket",
			input:   []byte(`services: {api: {build: ./api`),
			wantErr: true,
		},
		{
			name:    "malformed YAML — bad indentation tab",
			input:   []byte("services:\n  api:\n\t\tbuild: ./api"),
			wantErr: true,
		},
		{
			name: "service with no port defaults to 8080",
			input: []byte(`
services:
  api:
    build: ./api
`),
			wantErr: false,
			assertions: func(t *testing.T, m *Manifest) {
				t.Helper()
				api := m.Services["api"]
				if api == nil {
					t.Fatal("expected service 'api' to exist")
				}
				if api.Port != 8080 {
					t.Errorf("expected default port 8080, got %d", api.Port)
				}
			},
		},
		{
			name: "service with port explicitly set to 3000",
			input: []byte(`
services:
  frontend:
    build: ./frontend
    port: 3000
`),
			wantErr: false,
			assertions: func(t *testing.T, m *Manifest) {
				t.Helper()
				fe := m.Services["frontend"]
				if fe == nil {
					t.Fatal("expected service 'frontend' to exist")
				}
				if fe.Port != 3000 {
					t.Errorf("expected port 3000, got %d", fe.Port)
				}
			},
		},
		{
			name: "expose defaults to false when not set",
			input: []byte(`
services:
  api:
    build: ./api
`),
			wantErr: false,
			assertions: func(t *testing.T, m *Manifest) {
				t.Helper()
				api := m.Services["api"]
				if api == nil {
					t.Fatal("expected service 'api' to exist")
				}
				if api.Expose {
					t.Error("expected Expose to be false when not set")
				}
			},
		},
		{
			name: "env map is nil when not specified",
			input: []byte(`
services:
  api:
    build: ./api
    port: 8080
`),
			wantErr: false,
			assertions: func(t *testing.T, m *Manifest) {
				t.Helper()
				api := m.Services["api"]
				if api == nil {
					t.Fatal("expected service 'api' to exist")
				}
				if len(api.Env) != 0 {
					t.Errorf("expected nil/empty env map, got %v", api.Env)
				}
			},
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			m, err := Parse(tc.input)
			if tc.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tc.assertions != nil {
				tc.assertions(t, m)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// TestValidate
// ---------------------------------------------------------------------------

func TestValidate(t *testing.T) {
	type testCase struct {
		name         string
		manifest     *Manifest
		wantErr      bool
		errContains  string
		wantWarnings int // minimum number of warnings expected
	}

	cases := []testCase{
		{
			name: "valid refs — no warnings",
			manifest: &Manifest{
				Services: map[string]*ServiceDef{
					"api": {
						Port: 8080,
						Env:  map[string]string{"WORKER_URL": "service://worker"},
					},
					"worker": {
						Port: 8080,
						Env:  map[string]string{},
					},
				},
			},
			wantErr:      false,
			wantWarnings: 0,
		},
		{
			name: "missing service ref returns error",
			manifest: &Manifest{
				Services: map[string]*ServiceDef{
					"api": {
						Port: 8080,
						Env:  map[string]string{"MISSING_URL": "service://nonexistent"},
					},
				},
			},
			wantErr:     true,
			errContains: "references unknown service",
		},
		{
			name: "circular ref A→B→A produces warning",
			manifest: &Manifest{
				Services: map[string]*ServiceDef{
					"serviceA": {
						Port: 8080,
						Env:  map[string]string{"B_URL": "service://serviceB"},
					},
					"serviceB": {
						Port: 8080,
						Env:  map[string]string{"A_URL": "service://serviceA"},
					},
				},
			},
			wantErr:      false,
			wantWarnings: 1,
		},
		{
			name: "self-reference produces warning",
			manifest: &Manifest{
				Services: map[string]*ServiceDef{
					"api": {
						Port: 8080,
						Env:  map[string]string{"SELF_URL": "service://api"},
					},
				},
			},
			wantErr:      false,
			wantWarnings: 1,
		},
		{
			name: "no service refs — clean",
			manifest: &Manifest{
				Services: map[string]*ServiceDef{
					"api": {
						Port: 8080,
						Env:  map[string]string{"LOG_LEVEL": "debug", "PORT": "8080"},
					},
					"worker": {
						Port: 9000,
						Env:  nil,
					},
				},
			},
			wantErr:      false,
			wantWarnings: 0,
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			warnings, err := tc.manifest.Validate()
			if tc.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				if tc.errContains != "" && !strings.Contains(err.Error(), tc.errContains) {
					t.Errorf("error %q does not contain %q", err.Error(), tc.errContains)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(warnings) < tc.wantWarnings {
				t.Errorf("expected at least %d warning(s), got %d: %v", tc.wantWarnings, len(warnings), warnings)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// TestResolve
// ---------------------------------------------------------------------------

func TestResolve(t *testing.T) {
	type testCase struct {
		name     string
		manifest *Manifest
		wantErr  bool
		check    func(t *testing.T, m *Manifest)
	}

	cases := []testCase{
		{
			name: "service://worker resolved to http://worker:8080",
			manifest: &Manifest{
				Services: map[string]*ServiceDef{
					"api": {
						Port: 8080,
						Env:  map[string]string{"WORKER_URL": "service://worker"},
					},
					"worker": {
						Port: 8080,
						Env:  map[string]string{},
					},
				},
			},
			wantErr: false,
			check: func(t *testing.T, m *Manifest) {
				t.Helper()
				got := m.Services["api"].Env["WORKER_URL"]
				want := "http://worker:8080"
				if got != want {
					t.Errorf("WORKER_URL: got %q, want %q", got, want)
				}
			},
		},
		{
			name: "service://api with port 3000 resolved correctly",
			manifest: &Manifest{
				Services: map[string]*ServiceDef{
					"frontend": {
						Port: 8080,
						Env:  map[string]string{"API_URL": "service://api"},
					},
					"api": {
						Port: 3000,
						Env:  map[string]string{},
					},
				},
			},
			wantErr: false,
			check: func(t *testing.T, m *Manifest) {
				t.Helper()
				got := m.Services["frontend"].Env["API_URL"]
				want := "http://api:3000"
				if got != want {
					t.Errorf("API_URL: got %q, want %q", got, want)
				}
			},
		},
		{
			name: "non-service:// env values unchanged",
			manifest: &Manifest{
				Services: map[string]*ServiceDef{
					"api": {
						Port: 8080,
						Env: map[string]string{
							"LOG_LEVEL":  "debug",
							"QUEUE_SIZE": "100",
							"WORKER_URL": "service://worker",
						},
					},
					"worker": {
						Port: 8080,
						Env:  map[string]string{},
					},
				},
			},
			wantErr: false,
			check: func(t *testing.T, m *Manifest) {
				t.Helper()
				env := m.Services["api"].Env
				if env["LOG_LEVEL"] != "debug" {
					t.Errorf("LOG_LEVEL: got %q, want %q", env["LOG_LEVEL"], "debug")
				}
				if env["QUEUE_SIZE"] != "100" {
					t.Errorf("QUEUE_SIZE: got %q, want %q", env["QUEUE_SIZE"], "100")
				}
				// service:// ref should be resolved
				if strings.HasPrefix(env["WORKER_URL"], "service://") {
					t.Errorf("WORKER_URL still has service:// prefix after Resolve: %q", env["WORKER_URL"])
				}
			},
		},
		{
			name: "unknown ref returns error",
			manifest: &Manifest{
				Services: map[string]*ServiceDef{
					"api": {
						Port: 8080,
						Env:  map[string]string{"BAD": "service://ghost"},
					},
				},
			},
			wantErr: true,
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			err := tc.manifest.Resolve()
			if tc.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tc.check != nil {
				tc.check(t, tc.manifest)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// TestServiceNames
// ---------------------------------------------------------------------------

func TestServiceNames(t *testing.T) {
	m := &Manifest{
		Services: map[string]*ServiceDef{
			"worker":  {Port: 8080},
			"api":     {Port: 8080},
			"db-init": {Port: 8080},
		},
	}
	names := m.ServiceNames()
	want := []string{"api", "db-init", "worker"}
	if len(names) != len(want) {
		t.Fatalf("ServiceNames: got %v, want %v", names, want)
	}
	for i, n := range names {
		if n != want[i] {
			t.Errorf("ServiceNames[%d]: got %q, want %q", i, n, want[i])
		}
	}
}

// ---------------------------------------------------------------------------
// TestParseAndResolveIntegration
// ---------------------------------------------------------------------------

func TestParseAndResolveIntegration(t *testing.T) {
	input := []byte(`
services:
  api:
    build: ./api
    port: 8080
    expose: true
    needs:
      - postgres-abc123
      - redis-xyz789
    env:
      LOG_LEVEL: info
      WORKER_URL: service://worker
      DB_INIT_URL: service://db-init

  worker:
    build: ./worker
    port: 9000
    expose: false
    needs:
      - postgres-abc123
    env:
      QUEUE_SIZE: "50"
      API_URL: service://api

  db-init:
    build: ./db-init
    port: 5432
    expose: false
    needs:
      - postgres-abc123
    env:
      MIGRATIONS_DIR: /migrations
`)

	// 1. Parse
	m, err := Parse(input)
	if err != nil {
		t.Fatalf("Parse: unexpected error: %v", err)
	}

	// Check service count
	if len(m.Services) != 3 {
		t.Fatalf("expected 3 services, got %d", len(m.Services))
	}

	// Sorted names
	names := m.ServiceNames()
	wantNames := []string{"api", "db-init", "worker"}
	for i, n := range names {
		if n != wantNames[i] {
			t.Errorf("ServiceNames[%d]: got %q, want %q", i, n, wantNames[i])
		}
	}

	// Expose flags
	if !m.Services["api"].Expose {
		t.Error("api.Expose: want true, got false")
	}
	if m.Services["worker"].Expose {
		t.Error("worker.Expose: want false, got true")
	}
	if m.Services["db-init"].Expose {
		t.Error("db-init.Expose: want false, got true")
	}

	// Ports
	if m.Services["api"].Port != 8080 {
		t.Errorf("api.Port: got %d, want 8080", m.Services["api"].Port)
	}
	if m.Services["worker"].Port != 9000 {
		t.Errorf("worker.Port: got %d, want 9000", m.Services["worker"].Port)
	}
	if m.Services["db-init"].Port != 5432 {
		t.Errorf("db-init.Port: got %d, want 5432", m.Services["db-init"].Port)
	}

	// 2. Validate — no errors expected (no missing refs, only valid cross-refs)
	warnings, err := m.Validate()
	if err != nil {
		t.Fatalf("Validate: unexpected error: %v", err)
	}
	// api refs worker and db-init; worker refs api — that's a cycle, expect warning
	// but no hard error
	t.Logf("Validate produced %d warning(s): %v", len(warnings), warnings)

	// 3. Resolve
	if err := m.Resolve(); err != nil {
		t.Fatalf("Resolve: unexpected error: %v", err)
	}

	// After resolve: check all env vars
	apiEnv := m.Services["api"].Env
	if apiEnv["LOG_LEVEL"] != "info" {
		t.Errorf("api LOG_LEVEL: got %q, want %q", apiEnv["LOG_LEVEL"], "info")
	}
	if apiEnv["WORKER_URL"] != "http://worker:9000" {
		t.Errorf("api WORKER_URL: got %q, want %q", apiEnv["WORKER_URL"], "http://worker:9000")
	}
	if apiEnv["DB_INIT_URL"] != "http://db-init:5432" {
		t.Errorf("api DB_INIT_URL: got %q, want %q", apiEnv["DB_INIT_URL"], "http://db-init:5432")
	}

	workerEnv := m.Services["worker"].Env
	if workerEnv["QUEUE_SIZE"] != "50" {
		t.Errorf("worker QUEUE_SIZE: got %q, want %q", workerEnv["QUEUE_SIZE"], "50")
	}
	if workerEnv["API_URL"] != "http://api:8080" {
		t.Errorf("worker API_URL: got %q, want %q", workerEnv["API_URL"], "http://api:8080")
	}

	dbInitEnv := m.Services["db-init"].Env
	if dbInitEnv["MIGRATIONS_DIR"] != "/migrations" {
		t.Errorf("db-init MIGRATIONS_DIR: got %q, want %q", dbInitEnv["MIGRATIONS_DIR"], "/migrations")
	}

	// 4. No service:// prefixes remain anywhere after Resolve
	for svcName, svc := range m.Services {
		for key, val := range svc.Env {
			if strings.HasPrefix(val, "service://") {
				t.Errorf("after Resolve, service %q env %s still has service:// prefix: %q", svcName, key, val)
			}
		}
	}
}
