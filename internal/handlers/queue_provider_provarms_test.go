package handlers_test

// queue_provider_provarms_test.go — drives buildQueueProvider's backend-
// selection branches without standing up a real NATS server.
//
// buildQueueProvider is the boot-time wiring helper called from
// NewQueueHandler. The test app constructs the handler (so the legacy_open
// fallback runs at construction), but the explicit-backend, nats-when-seed,
// and Factory-error branches are never reached by the HTTP-level tests. These
// direct calls cover each arm.

import (
	"context"
	"testing"

	"github.com/nats-io/nkeys"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	natsqp "instant.dev/common/queueprovider/nats"
	"instant.dev/internal/config"
	"instant.dev/internal/handlers"
	"instant.dev/internal/natsresolver"
)

// TestBuildQueueProvider_DefaultNoSeed_FallsBackToLegacyOpen — empty
// QueueBackend AND empty operator seed → the legacy_open shim, which enforces
// nothing (all-false capabilities).
func TestBuildQueueProvider_DefaultNoSeed_FallsBackToLegacyOpen(t *testing.T) {
	cfg := &config.Config{
		QueueBackend:     "",
		NATSOperatorSeed: "",
		NATSHost:         "nats.test",
		NATSPublicHost:   "nats.instanode.dev",
	}
	qp, err := handlers.BuildQueueProviderForTest(cfg)
	require.NoError(t, err)
	require.NotNil(t, qp)
	assert.Equal(t, "legacy_open", qp.Name())
	caps := qp.Capabilities()
	assert.False(t, caps.PerTenantAccounts, "legacy_open enforces nothing")
	assert.False(t, caps.SubjectScopedAuth)
}

// TestBuildQueueProvider_DefaultWithSeed_SelectsNATS — empty QueueBackend but
// a valid operator seed present → the "nats" backend is selected and builds.
//
// An operator seed also means real account claims will be minted, so the
// system-account resolver publisher must come up too; the constructor seam is
// stubbed here so no NATS server is needed.
func TestBuildQueueProvider_DefaultWithSeed_SelectsNATS(t *testing.T) {
	kp, err := nkeys.CreateOperator()
	require.NoError(t, err)
	seed, err := kp.Seed()
	require.NoError(t, err)

	restore := handlers.SwapResolverPusherFactoryForTest(
		func(natsresolver.Config) (natsqp.ResolverPusher, error) { return stubResolverPusher{}, nil })
	defer restore()

	cfg := &config.Config{
		QueueBackend:         "",
		NATSOperatorSeed:     string(seed),
		NATSHost:             "nats.test",
		NATSPublicHost:       "nats.instanode.dev",
		NATSSystemAccountKey: "",
		NATSSystemUserJWT:    "eyJ0eXAiOiJKV1QifQ.sys.user",
		NATSSystemUserSeed:   "SUAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
	}
	qp, err := handlers.BuildQueueProviderForTest(cfg)
	require.NoError(t, err)
	require.NotNil(t, qp)
	assert.Equal(t, "nats", qp.Name())
}

// stubResolverPusher is an accept-everything resolver publisher for the
// backend-selection tests, which are not about push behaviour.
type stubResolverPusher struct{}

func (stubResolverPusher) PushAccountClaim(context.Context, string, string) error { return nil }

// TestBuildQueueProvider_SeedWithoutSystemCreds_Errors — the regression guard
// for the bug this wiring fixes. An operator seed with no SYS user credentials
// means account claims can never be pushed to nats-server, so every issued
// credential would be rejected at CONNECT. buildQueueProvider must refuse to
// return a provider rather than let the caller degrade to legacy_open.
func TestBuildQueueProvider_SeedWithoutSystemCreds_Errors(t *testing.T) {
	kp, err := nkeys.CreateOperator()
	require.NoError(t, err)
	seed, err := kp.Seed()
	require.NoError(t, err)

	cfg := &config.Config{
		QueueBackend:     "nats",
		NATSOperatorSeed: string(seed),
		NATSHost:         "nats.test",
		NATSPublicHost:   "nats.instanode.dev",
		// NATSSystemUserJWT / NATSSystemUserSeed deliberately unset.
	}
	qp, err := handlers.BuildQueueProviderForTest(cfg)
	require.Error(t, err)
	assert.Nil(t, qp)
	assert.ErrorIs(t, err, natsresolver.ErrPushFailed)
	assert.Contains(t, err.Error(), "NATS_SYSTEM_USER_JWT")
}

// TestBuildQueueProvider_ExplicitLegacyOpen — explicit backend overrides the
// seed-based default selection.
func TestBuildQueueProvider_ExplicitLegacyOpen(t *testing.T) {
	kp, err := nkeys.CreateOperator()
	require.NoError(t, err)
	seed, _ := kp.Seed()

	cfg := &config.Config{
		QueueBackend:     "legacy_open",
		NATSOperatorSeed: string(seed), // present but ignored — explicit backend wins
		NATSHost:         "nats.test",
		NATSPublicHost:   "nats.instanode.dev",
	}
	qp, err := handlers.BuildQueueProviderForTest(cfg)
	require.NoError(t, err)
	assert.Equal(t, "legacy_open", qp.Name())
}

// TestBuildQueueProvider_UnknownBackend_Errors — an unrecognised QueueBackend
// surfaces the Factory's ErrUnknownBackend so NewQueueHandler can fall back to
// the legacy_open shim defensively.
func TestBuildQueueProvider_UnknownBackend_Errors(t *testing.T) {
	cfg := &config.Config{
		QueueBackend:   "bogus-not-a-backend",
		NATSHost:       "nats.test",
		NATSPublicHost: "nats.instanode.dev",
	}
	qp, err := handlers.BuildQueueProviderForTest(cfg)
	require.Error(t, err)
	assert.Nil(t, qp)
}

// TestBuildQueueProvider_BadSeed_Errors — backend=nats with an unparseable
// operator seed surfaces the auth-failure error from the nats constructor.
func TestBuildQueueProvider_BadSeed_Errors(t *testing.T) {
	cfg := &config.Config{
		QueueBackend:     "nats",
		NATSOperatorSeed: "not-a-valid-nkey-seed",
		NATSHost:         "nats.test",
		NATSPublicHost:   "nats.instanode.dev",
	}
	qp, err := handlers.BuildQueueProviderForTest(cfg)
	require.Error(t, err)
	assert.Nil(t, qp)
}
