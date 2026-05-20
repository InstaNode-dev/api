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
// The provider lives at handler-scope (one per process); IssueTenantCredentials
// is concurrency-safe per the queueprovider contract.

import (
	"log/slog"

	"instant.dev/common/queueprovider"
	// register every backend by side-effect import — same pattern as
	// storageprovider wiring in router.go.
	_ "instant.dev/common/queueprovider/kafka"
	_ "instant.dev/common/queueprovider/legacyopen"
	_ "instant.dev/common/queueprovider/nats"
	_ "instant.dev/common/queueprovider/rabbitmq"

	"instant.dev/internal/config"
)

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
			backend = "legacy_open"
		} else {
			backend = "nats"
		}
	}
	qpCfg := queueprovider.Config{
		Backend:                    backend,
		Host:                       cfg.NATSHost,
		PublicHost:                 cfg.NATSPublicHost,
		Port:                       4222,
		UseTLS:                     cfg.NATSUseTLS,
		NATSOperatorSeed:           cfg.NATSOperatorSeed,
		NATSSystemAccountPublicKey: cfg.NATSSystemAccountKey,
		// SubjectTemplate left empty → provider uses its default "tenant_<token>."
	}
	qp, err := queueprovider.Factory(qpCfg)
	if err != nil {
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
