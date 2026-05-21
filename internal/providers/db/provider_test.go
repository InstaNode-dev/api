package db

// Tests for the public Provider facade in provider.go. The Provider type
// is a tiny dispatcher in front of a Backend; the goal here is to prove
// the right backend is selected by `New` and that every method on
// Provider forwards faithfully to the underlying Backend.

import (
	"context"
	"errors"
	"testing"

	"instant.dev/internal/config"
)

// stubBackend is a minimal Backend test-double. It records the arguments
// each method was called with and returns canned responses. Useful for
// asserting Provider.X delegates to backend.X without standing up a real
// Postgres / HTTP server.
type stubBackend struct {
	gotToken    string
	gotTier     string
	gotExts     []string
	gotPRID     string
	provCreds   *Credentials
	provErr     error
	storageSize int64
	storageErr  error
	deprovErr   error
}

func (s *stubBackend) Provision(_ context.Context, token, tier string) (*Credentials, error) {
	s.gotToken, s.gotTier, s.gotExts = token, tier, nil
	return s.provCreds, s.provErr
}
func (s *stubBackend) ProvisionWithExtensions(_ context.Context, token, tier string, exts []string) (*Credentials, error) {
	s.gotToken, s.gotTier, s.gotExts = token, tier, exts
	return s.provCreds, s.provErr
}
func (s *stubBackend) StorageBytes(_ context.Context, token, prid string) (int64, error) {
	s.gotToken, s.gotPRID = token, prid
	return s.storageSize, s.storageErr
}
func (s *stubBackend) Deprovision(_ context.Context, token, prid string) error {
	s.gotToken, s.gotPRID = token, prid
	return s.deprovErr
}

// TestNew_PicksLocalByDefault — empty / unknown backend strings default
// to the LocalBackend (the production agent-API behaviour); only the
// literal "neon" selects the Neon HTTP backend.
func TestNew_PicksLocalByDefault(t *testing.T) {
	cases := []struct {
		name string
		cfg  *config.Config
		wantLocal bool
	}{
		{"empty_default_local", &config.Config{PostgresProvisionBackend: ""}, true},
		{"explicit_local", &config.Config{PostgresProvisionBackend: "local"}, true},
		{"unknown_falls_back_to_local", &config.Config{PostgresProvisionBackend: "bogus"}, true},
		{"neon_selects_neon", &config.Config{PostgresProvisionBackend: "neon", NeonAPIKey: "k", NeonRegionID: "aws-us-east-1"}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := New(tc.cfg, "")
			if p == nil || p.backend == nil {
				t.Fatalf("New: returned nil backend")
			}
			_, isLocal := p.backend.(*LocalBackend)
			_, isNeon := p.backend.(*NeonBackend)
			if tc.wantLocal && !isLocal {
				t.Fatalf("want LocalBackend, got %T", p.backend)
			}
			if !tc.wantLocal && !isNeon {
				t.Fatalf("want NeonBackend, got %T", p.backend)
			}
		})
	}
}

// TestProvider_ForwardsToBackend — the four Provider methods must
// faithfully delegate to the configured Backend. We swap in a stub and
// assert (a) arguments arrive as-passed, (b) returns propagate as-is,
// (c) errors propagate as-is.
func TestProvider_ForwardsToBackend(t *testing.T) {
	creds := &Credentials{URL: "postgres://x@h/y", DatabaseName: "y", Username: "x"}
	wantErr := errors.New("boom")
	s := &stubBackend{
		provCreds:   creds,
		storageSize: 12345,
		storageErr:  nil,
		provErr:     nil,
		deprovErr:   wantErr,
	}
	p := &Provider{backend: s}

	t.Run("Provision", func(t *testing.T) {
		got, err := p.Provision(context.Background(), "tok-1", "pro")
		if err != nil || got != creds {
			t.Fatalf("Provision: got=%v err=%v", got, err)
		}
		if s.gotToken != "tok-1" || s.gotTier != "pro" || s.gotExts != nil {
			t.Fatalf("Provision: backend got token=%q tier=%q exts=%v", s.gotToken, s.gotTier, s.gotExts)
		}
	})

	t.Run("ProvisionWithExtensions", func(t *testing.T) {
		got, err := p.ProvisionWithExtensions(context.Background(), "tok-2", "team", []string{"vector"})
		if err != nil || got != creds {
			t.Fatalf("ProvisionWithExtensions: got=%v err=%v", got, err)
		}
		if s.gotToken != "tok-2" || s.gotTier != "team" || len(s.gotExts) != 1 || s.gotExts[0] != "vector" {
			t.Fatalf("ProvisionWithExtensions: backend got token=%q tier=%q exts=%v", s.gotToken, s.gotTier, s.gotExts)
		}
	})

	t.Run("StorageBytes", func(t *testing.T) {
		n, err := p.StorageBytes(context.Background(), "tok-3", "prid-3")
		if err != nil || n != 12345 {
			t.Fatalf("StorageBytes: n=%d err=%v", n, err)
		}
		if s.gotToken != "tok-3" || s.gotPRID != "prid-3" {
			t.Fatalf("StorageBytes: backend got token=%q prid=%q", s.gotToken, s.gotPRID)
		}
	})

	t.Run("Deprovision_PropagatesError", func(t *testing.T) {
		err := p.Deprovision(context.Background(), "tok-4", "prid-4")
		if !errors.Is(err, wantErr) {
			t.Fatalf("Deprovision: want %v got %v", wantErr, err)
		}
		if s.gotToken != "tok-4" || s.gotPRID != "prid-4" {
			t.Fatalf("Deprovision: backend got token=%q prid=%q", s.gotToken, s.gotPRID)
		}
	})
}
