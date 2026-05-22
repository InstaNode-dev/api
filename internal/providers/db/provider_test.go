package db

import (
	"context"
	"testing"

	"instant.dev/internal/config"
)

// TestProviderNew_SelectsBackend verifies the factory picks local vs neon by
// cfg.PostgresProvisionBackend and that the thin delegating wrappers call
// through to the chosen backend.
func TestProviderNew_SelectsBackend(t *testing.T) {
	local := New(&config.Config{PostgresProvisionBackend: "local"}, "postgres://u:p@h:5432/d")
	if _, ok := local.backend.(*LocalBackend); !ok {
		t.Fatalf("local backend type = %T", local.backend)
	}
	neon := New(&config.Config{PostgresProvisionBackend: "neon", NeonAPIKey: "k"}, "")
	if _, ok := neon.backend.(*NeonBackend); !ok {
		t.Fatalf("neon backend type = %T", neon.backend)
	}
	// Unknown backend falls through to local.
	def := New(&config.Config{PostgresProvisionBackend: "wat"}, "")
	if _, ok := def.backend.(*LocalBackend); !ok {
		t.Fatalf("default backend type = %T", def.backend)
	}
}

// fakeBackend records which delegating method ran.
type fakeBackend struct{ called string }

func (f *fakeBackend) Provision(_ context.Context, _, _ string) (*Credentials, error) {
	f.called = "Provision"
	return &Credentials{}, nil
}
func (f *fakeBackend) ProvisionWithExtensions(_ context.Context, _, _ string, _ []string) (*Credentials, error) {
	f.called = "ProvisionWithExtensions"
	return &Credentials{}, nil
}
func (f *fakeBackend) StorageBytes(_ context.Context, _, _ string) (int64, error) {
	f.called = "StorageBytes"
	return 7, nil
}
func (f *fakeBackend) Deprovision(_ context.Context, _, _ string) error {
	f.called = "Deprovision"
	return nil
}

func TestProviderDelegation(t *testing.T) {
	fb := &fakeBackend{}
	p := &Provider{backend: fb}
	ctx := context.Background()

	if _, err := p.Provision(ctx, "t", "tier"); err != nil || fb.called != "Provision" {
		t.Fatalf("Provision delegation: called=%q err=%v", fb.called, err)
	}
	if _, err := p.ProvisionWithExtensions(ctx, "t", "tier", []string{"vector"}); err != nil || fb.called != "ProvisionWithExtensions" {
		t.Fatalf("ProvisionWithExtensions delegation: called=%q err=%v", fb.called, err)
	}
	if n, err := p.StorageBytes(ctx, "t", "rid"); err != nil || n != 7 || fb.called != "StorageBytes" {
		t.Fatalf("StorageBytes delegation: called=%q n=%d err=%v", fb.called, n, err)
	}
	if err := p.Deprovision(ctx, "t", "rid"); err != nil || fb.called != "Deprovision" {
		t.Fatalf("Deprovision delegation: called=%q err=%v", fb.called, err)
	}
}
