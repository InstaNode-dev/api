package handlers

// queue_provider.go — wires the QueueHandler to the common/queueprovider
// abstraction (MR-P0-5 — NATS per-tenant isolation, 2026-05-20).
//
// The QueueHandler delegates credential issuance to a queueprovider.QueueCre-
// dentialProvider selected at boot via env vars (QUEUE_BACKEND + NATS_OPERATOR_SEED).
//
// During the staged cutover:
//   - the "nats" provider returns AuthMode=legacy_open creds when no operator
//     seed is configured — letting api deploy BEFORE the operator runs `nsc
//     generate` and applies the nats-operator Secret.
//   - once the operator seed is configured, every new /queue/new mints a real
//     per-tenant account JWT + user NKey via the provider.
//
// Minting is only half the job. A tenant account JWT the running nats-server
// has never seen is rejected at CONNECT with "Authorization Violation", so the
// nats provider's ResolverPusher seam must be filled with a real
// system-account publisher — internal/natsresolver — or every isolated
// credential is dead on arrival. attachResolverPusher below is that wiring,
// and it fails LOUDLY: when the operator seed says "issue isolated creds" but
// the resolver push cannot be set up, buildQueueProvider errors instead of
// quietly degrading to legacy_open. A silent degrade is what shipped the bug.
//
// The provider lives at handler-scope (one per process); IssueTenantCredentials
// is concurrency-safe per the queueprovider contract.

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"

	"instant.dev/common/queueprovider"
	// register every backend by side-effect import — same pattern as
	// storageprovider wiring in router.go. The nats backend is imported by
	// name (not blank) because attachResolverPusher needs its ResolverPusher
	// interface type for the setter type-assertion.
	_ "instant.dev/common/queueprovider/kafka"
	_ "instant.dev/common/queueprovider/legacyopen"
	natsqp "instant.dev/common/queueprovider/nats"
	_ "instant.dev/common/queueprovider/rabbitmq"

	"instant.dev/internal/config"
	"instant.dev/internal/natsresolver"
)

const (
	// queueBackendNATS is the operator-mode backend that mints per-tenant
	// account JWTs.
	queueBackendNATS = "nats"
	// queueBackendLegacyOpen is the pre-cutover unauthenticated shim.
	queueBackendLegacyOpen = "legacy_open"
	// natsClientPort is the broker port for both tenant and system-account
	// connections.
	natsClientPort = 4222
	// natsPlainScheme is the URL scheme used for the in-cluster
	// system-account connection. Operators needing TLS set NATS_SYSTEM_URL.
	natsPlainScheme = "nats"
)

// resolverPusherSetter is the sub-interface of *natsqp.Provider that accepts a
// ResolverPusher. queueprovider.Factory returns an interface, and only the
// nats backend implements this method — legacy_open / rabbitmq / kafka have no
// resolver, so the type-assertion below simply misses for them (never panics).
type resolverPusherSetter interface {
	SetResolverPusher(natsqp.ResolverPusher)
}

// newResolverPusher is the construction seam for the system-account pusher.
// Production aliases natsresolver.New; tests substitute a stub so the
// attach/skip/fail arms can be driven without a NATS server.
var newResolverPusher = func(cfg natsresolver.Config) (natsqp.ResolverPusher, error) {
	return natsresolver.New(cfg)
}

// buildQueueProvider constructs the queueprovider.QueueCredentialProvider from
// cfg. Falls back to the legacy_open shim when QUEUE_BACKEND is unset AND no
// operator seed is configured, so deploys before the operator-key generation
// keep working unchanged. Logs the resolved backend + capabilities at INFO
// so operators can verify isolation is actually in effect.
func buildQueueProvider(cfg *config.Config) (queueprovider.QueueCredentialProvider, error) {
	backend := cfg.QueueBackend
	if backend == "" {
		// Pre-cutover defaults: when neither QUEUE_BACKEND nor operator seed
		// is set, fall back to legacy_open so the cluster keeps serving
		// (un-isolated) traffic until the operator keys are generated. After
		// the operator seed is wired, the same code mints isolated creds.
		if cfg.NATSOperatorSeed == "" {
			backend = queueBackendLegacyOpen
		} else {
			backend = queueBackendNATS
		}
	}
	qpCfg := queueprovider.Config{
		Backend:                    backend,
		Host:                       cfg.NATSHost,
		PublicHost:                 cfg.NATSPublicHost,
		Port:                       natsClientPort,
		UseTLS:                     cfg.NATSUseTLS,
		NATSOperatorSeed:           cfg.NATSOperatorSeed,
		NATSSystemAccountPublicKey: cfg.NATSSystemAccountKey,
		// SubjectTemplate left empty → provider uses its default "tenant_<token>."
	}
	qp, err := queueprovider.Factory(qpCfg)
	if err != nil {
		return nil, err
	}
	if err := attachResolverPusher(cfg, qp); err != nil {
		return nil, err
	}
	caps := qp.Capabilities()
	slog.Info("queue.provider_initialised",
		"backend", qp.Name(),
		"per_tenant_accounts", caps.PerTenantAccounts,
		"subject_scoped_auth", caps.SubjectScopedAuth,
		"stream_isolation", caps.StreamIsolation,
		"operator_seed_set", cfg.NATSOperatorSeed != "",
	)
	return qp, nil
}

// attachResolverPusher gives the nats provider a real
// $SYS.REQ.CLAIMS.UPDATE publisher.
//
// Three outcomes, and only one of them is an error:
//   - backend has no resolver (legacy_open / rabbitmq / kafka) → nothing to do.
//   - nats backend with no operator seed → the provider returns legacy_open
//     creds and never mints an account claim, so there is nothing to push.
//   - nats backend WITH an operator seed → isolated credentials will be
//     minted, and they only work if the claim reaches the server. A pusher
//     that cannot be built or cannot connect is a hard error: returning nil
//     here would leave the provider on its no-op pusher and hand customers
//     credentials that fail at CONNECT.
func attachResolverPusher(cfg *config.Config, qp queueprovider.QueueCredentialProvider) error {
	setter, ok := qp.(resolverPusherSetter)
	if !ok {
		return nil
	}
	if cfg.NATSOperatorSeed == "" {
		slog.Warn("queue.resolver_pusher_skipped_no_operator_seed",
			"backend", qp.Name(),
			"detail", "NATS_OPERATOR_SEED unset — /queue/new serves legacy_open credentials")
		return nil
	}
	url := natsSystemURL(cfg)
	pusher, err := newResolverPusher(natsresolver.Config{
		URL:      url,
		UserJWT:  cfg.NATSSystemUserJWT,
		UserSeed: cfg.NATSSystemUserSeed,
	})
	if err != nil {
		return fmt.Errorf("queue: NATS_OPERATOR_SEED is set so /queue/new mints per-tenant "+
			"account JWTs, but the %s publisher could not be started — those credentials "+
			"would be rejected by nats-server. Set NATS_SYSTEM_USER_JWT + NATS_SYSTEM_USER_SEED "+
			"and make %s reachable: %w", natsresolver.ClaimsUpdateSubject, url, err)
	}
	setter.SetResolverPusher(pusher)
	slog.Info("queue.resolver_pusher_attached",
		"backend", qp.Name(),
		"url", url,
		"subject", natsresolver.ClaimsUpdateSubject)
	return nil
}

// natsSystemURL resolves the URL for the system-account connection.
// NATS_SYSTEM_URL wins when set (that is the escape hatch for TLS or an
// out-of-cluster endpoint); otherwise it is derived from NATS_HOST.
func natsSystemURL(cfg *config.Config) string {
	if u := strings.TrimSpace(cfg.NATSSystemURL); u != "" {
		return u
	}
	return fmt.Sprintf("%s://%s:%d", natsPlainScheme, cfg.NATSHost, natsClientPort)
}

// isolationUnavailable reports whether a credential-issuance error means the
// per-tenant isolation path is broken — i.e. the account claim never reached
// the resolver. Such an error must fail the provision (503) rather than
// degrade to a legacy_open response, because the connection URL in that
// response is unusable against an auth_required server.
func isolationUnavailable(err error) bool {
	return err != nil && errors.Is(err, natsresolver.ErrPushFailed)
}

// unavailableCredProvider stands in for the nats provider when isolation is
// CONFIGURED but could not be initialised. It never issues a credential; every
// call returns an ErrPushFailed-wrapped error so /queue/new answers 503
// instead of returning an unauthenticated URL that the server will reject.
type unavailableCredProvider struct{ cause error }

func (u unavailableCredProvider) IssueTenantCredentials(_ context.Context, _ queueprovider.IssueRequest) (*queueprovider.TenantCreds, error) {
	return nil, fmt.Errorf("%w: queue isolation is configured but unavailable: %v",
		natsresolver.ErrPushFailed, u.cause)
}

func (u unavailableCredProvider) RevokeTenantCredentials(_ context.Context, _ string) error {
	return nil
}

func (u unavailableCredProvider) Capabilities() queueprovider.Capabilities {
	return queueprovider.Capabilities{
		PerTenantAccounts: true,
		SubjectScopedAuth: true,
		StreamIsolation:   true,
	}
}

func (u unavailableCredProvider) Name() string { return "nats-unavailable" }
