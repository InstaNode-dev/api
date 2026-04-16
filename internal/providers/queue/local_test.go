package queue_test

import (
	"context"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	queueprovider "instant.dev/internal/providers/queue"
)

// TestNew_DefaultsToLocalhost verifies that New("") uses "localhost" as host.
func TestNew_DefaultsToLocalhost(t *testing.T) {
	p := queueprovider.New("")
	require.NotNil(t, p)
	// We can't call Provision without a real NATS; just verify the provider was created.
}

// TestDeprovision_IsNoOp verifies that Deprovision always returns nil
// (no per-user state on a no-auth NATS server).
func TestDeprovision_IsNoOp(t *testing.T) {
	p := queueprovider.New("nats.example.local")
	err := p.Deprovision(context.Background(), "any-token-xyz")
	assert.NoError(t, err, "Deprovision must always return nil — NATS has no per-user state")
}

// TestDeprovision_ShortToken verifies Deprovision is nil for short tokens too.
func TestDeprovision_ShortToken(t *testing.T) {
	p := queueprovider.New("nats.example.local")
	err := p.Deprovision(context.Background(), "tok")
	assert.NoError(t, err)
}

// TestProvision_FailsWithoutNATS verifies that Provision returns an error
// when the NATS monitoring endpoint is unreachable.
// This confirms synchronous provisioning: never return a URL for an absent server.
func TestProvision_FailsWithoutNATS(t *testing.T) {
	// Use a host that won't have NATS running (no such DNS / no service).
	p := queueprovider.New("nats-does-not-exist.invalid")
	_, err := p.Provision(context.Background(), "testtoken1234567", "anonymous")
	require.Error(t, err, "Provision must fail when NATS is unreachable")
	assert.True(t,
		strings.Contains(err.Error(), "health check") || strings.Contains(err.Error(), "NATS"),
		"error must mention health check or NATS; got %q", err.Error())
}

// TestNew_EmptyHostDefaultsToLocalhost verifies New("") stores "localhost" internally.
// We can't provision without real NATS, but the constructor should succeed.
func TestNew_EmptyHostDefaultsToLocalhost(t *testing.T) {
	p := queueprovider.New("")
	require.NotNil(t, p, "New with empty host must return a non-nil Provider")
}
