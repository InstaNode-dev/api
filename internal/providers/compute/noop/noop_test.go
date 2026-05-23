package noop

import (
	"context"
	"io"
	"testing"

	"instant.dev/internal/providers/compute"
)

// TestNoop_New verifies that New returns a non-nil NoopProvider implementing
// the compute.Provider interface.
func TestNoop_New(t *testing.T) {
	p := New()
	if p == nil {
		t.Fatal("New returned nil")
	}
	var _ compute.Provider = p
}

// TestNoop_Deploy verifies the placeholder response shape returned by Deploy.
func TestNoop_Deploy(t *testing.T) {
	p := New()
	got, err := p.Deploy(context.Background(), compute.DeployOptions{
		AppID: "abc123",
		Tier:  "hobby",
	})
	if err != nil {
		t.Fatalf("Deploy: %v", err)
	}
	if got == nil {
		t.Fatal("Deploy returned nil deployment")
	}
	if got.ProviderID != "noop-abc123" {
		t.Errorf("ProviderID = %q; want %q", got.ProviderID, "noop-abc123")
	}
	if got.Status != "healthy" {
		t.Errorf("Status = %q; want healthy", got.Status)
	}
	if got.AppURL == "" {
		t.Error("AppURL is empty; want a placeholder URL")
	}
	if got.UpdatedAt.IsZero() {
		t.Error("UpdatedAt is zero")
	}
}

// TestNoop_Status verifies Status returns the providerID echoed back.
func TestNoop_Status(t *testing.T) {
	p := New()
	got, err := p.Status(context.Background(), "noop-xyz")
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if got == nil {
		t.Fatal("Status returned nil")
	}
	if got.ProviderID != "noop-xyz" {
		t.Errorf("ProviderID = %q; want noop-xyz", got.ProviderID)
	}
	if got.Status != "healthy" {
		t.Errorf("Status = %q; want healthy", got.Status)
	}
}

// TestNoop_Logs verifies Logs returns a readable, empty stream.
func TestNoop_Logs(t *testing.T) {
	p := New()
	for _, follow := range []bool{false, true} {
		r, err := p.Logs(context.Background(), "noop-x", follow)
		if err != nil {
			t.Fatalf("Logs(follow=%v): %v", follow, err)
		}
		if r == nil {
			t.Fatalf("Logs(follow=%v): nil reader", follow)
		}
		b, err := io.ReadAll(r)
		if err != nil {
			t.Errorf("ReadAll: %v", err)
		}
		if len(b) != 0 {
			t.Errorf("Logs body = %q; want empty", string(b))
		}
		_ = r.Close()
	}
}

// TestNoop_Teardown verifies Teardown is a no-op returning nil.
func TestNoop_Teardown(t *testing.T) {
	p := New()
	if err := p.Teardown(context.Background(), "noop-x"); err != nil {
		t.Errorf("Teardown: %v", err)
	}
}

// TestNoop_Redeploy verifies the placeholder response from Redeploy.
func TestNoop_Redeploy(t *testing.T) {
	p := New()
	got, err := p.Redeploy(context.Background(), "noop-x", []byte("tar"), map[string]string{"FOO": "bar"})
	if err != nil {
		t.Fatalf("Redeploy: %v", err)
	}
	if got == nil {
		t.Fatal("Redeploy returned nil")
	}
	if got.ProviderID != "noop-x" {
		t.Errorf("ProviderID = %q; want noop-x", got.ProviderID)
	}
	if got.Status != "healthy" {
		t.Errorf("Status = %q; want healthy", got.Status)
	}
}

// TestNoop_UpdateAccessControl verifies UpdateAccessControl is a no-op.
func TestNoop_UpdateAccessControl(t *testing.T) {
	p := New()
	if err := p.UpdateAccessControl(context.Background(), "appid", true, []string{"1.2.3.4/32"}); err != nil {
		t.Errorf("UpdateAccessControl(private=true): %v", err)
	}
	if err := p.UpdateAccessControl(context.Background(), "appid", false, nil); err != nil {
		t.Errorf("UpdateAccessControl(private=false): %v", err)
	}
}

// ── Stack provider ──────────────────────────────────────────────────────────

// TestNoop_NewStack verifies the stack constructor.
func TestNoop_NewStack(t *testing.T) {
	sp := NewStack()
	if sp == nil {
		t.Fatal("NewStack returned nil")
	}
	var _ compute.StackProvider = sp
}

// TestNoop_DeployStack verifies onUpdate + onImageBuilt are called for every
// service, that the synthetic image ref is used when ImageRef is empty, and
// that the supplied ImageRef is preserved otherwise.
func TestNoop_DeployStack(t *testing.T) {
	sp := NewStack()

	updates := map[string][]string{}
	images := map[string]string{}
	onUpdate := func(name, status, _, _ string) {
		updates[name] = append(updates[name], status)
	}
	onImageBuilt := func(name, ref string) { images[name] = ref }

	opts := compute.StackDeployOptions{
		StackID: "stk1",
		Tier:    "hobby",
		Services: []compute.StackServiceDef{
			{Name: "web"},
			{Name: "api", ImageRef: "ghcr.io/x/y@sha256:abc"},
		},
	}
	if err := sp.DeployStack(context.Background(), opts, onUpdate, onImageBuilt); err != nil {
		t.Fatalf("DeployStack: %v", err)
	}

	// Each service must transition building → deploying → healthy.
	want := []string{"building", "deploying", "healthy"}
	for _, name := range []string{"web", "api"} {
		got := updates[name]
		if len(got) != len(want) {
			t.Errorf("[%s] updates = %v; want %v", name, got, want)
			continue
		}
		for i, s := range want {
			if got[i] != s {
				t.Errorf("[%s] update %d = %q; want %q", name, i, got[i], s)
			}
		}
	}

	// Synthetic ref when ImageRef is empty.
	if got := images["web"]; got != "noop://stk1/web" {
		t.Errorf("web image ref = %q; want %q", got, "noop://stk1/web")
	}
	// Pass-through when set.
	if got := images["api"]; got != "ghcr.io/x/y@sha256:abc" {
		t.Errorf("api image ref = %q; want %q", got, "ghcr.io/x/y@sha256:abc")
	}
}

// TestNoop_DeployStack_NilImageBuilt verifies the nil onImageBuilt callback
// is tolerated.
func TestNoop_DeployStack_NilImageBuilt(t *testing.T) {
	sp := NewStack()
	err := sp.DeployStack(context.Background(),
		compute.StackDeployOptions{
			StackID:  "stk2",
			Services: []compute.StackServiceDef{{Name: "x"}},
		},
		func(string, string, string, string) {},
		nil,
	)
	if err != nil {
		t.Fatalf("DeployStack with nil onImageBuilt: %v", err)
	}
}

// TestNoop_TeardownStack verifies the no-op contract.
func TestNoop_TeardownStack(t *testing.T) {
	sp := NewStack()
	if err := sp.TeardownStack(context.Background(), "instant-stack-stk1"); err != nil {
		t.Errorf("TeardownStack: %v", err)
	}
}

// TestNoop_ServiceLogs verifies the empty-reader contract.
func TestNoop_ServiceLogs(t *testing.T) {
	sp := NewStack()
	for _, follow := range []bool{false, true} {
		r, err := sp.ServiceLogs(context.Background(), "instant-stack-x", "web", follow)
		if err != nil {
			t.Fatalf("ServiceLogs(follow=%v): %v", follow, err)
		}
		if r == nil {
			t.Fatalf("ServiceLogs(follow=%v): nil reader", follow)
		}
		b, err := io.ReadAll(r)
		if err != nil {
			t.Errorf("ReadAll: %v", err)
		}
		if string(b) == "" {
			t.Error("ServiceLogs body is empty; want a placeholder string")
		}
		_ = r.Close()
	}
}

// TestNoop_RedeployStack verifies onUpdate + onImageBuilt are called for every
// service in the same way as DeployStack.
func TestNoop_RedeployStack(t *testing.T) {
	sp := NewStack()

	updates := map[string][]string{}
	images := map[string]string{}
	onUpdate := func(name, status, _, _ string) {
		updates[name] = append(updates[name], status)
	}
	onImageBuilt := func(name, ref string) { images[name] = ref }

	svcs := []compute.StackServiceDef{
		{Name: "web"},
		{Name: "api", ImageRef: "ghcr.io/x/y@sha256:def"},
	}
	if err := sp.RedeployStack(context.Background(), "instant-stack-rd1", svcs, onUpdate, onImageBuilt); err != nil {
		t.Fatalf("RedeployStack: %v", err)
	}

	for _, name := range []string{"web", "api"} {
		if len(updates[name]) != 3 {
			t.Errorf("[%s] update count = %d; want 3", name, len(updates[name]))
		}
	}
	if got := images["web"]; got != "noop://instant-stack-rd1/web" {
		t.Errorf("web image ref = %q; want %q", got, "noop://instant-stack-rd1/web")
	}
	if got := images["api"]; got != "ghcr.io/x/y@sha256:def" {
		t.Errorf("api image ref = %q; want %q", got, "ghcr.io/x/y@sha256:def")
	}
}

// TestNoop_RedeployStack_NilImageBuilt verifies a nil onImageBuilt is
// tolerated by Redeploy.
func TestNoop_RedeployStack_NilImageBuilt(t *testing.T) {
	sp := NewStack()
	err := sp.RedeployStack(context.Background(), "instant-stack-x",
		[]compute.StackServiceDef{{Name: "web"}},
		func(string, string, string, string) {},
		nil,
	)
	if err != nil {
		t.Fatalf("RedeployStack with nil onImageBuilt: %v", err)
	}
}
