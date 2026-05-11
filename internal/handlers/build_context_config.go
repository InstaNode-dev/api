package handlers

import (
	"instant.dev/internal/config"
	"instant.dev/internal/providers/compute/k8s"
)

// buildContextConfigFromCfg shapes the K8s BuildContextConfig from the global
// config. Returns a zero value when MinIO is not configured — the K8sProvider
// then falls back to the legacy Secret-based delivery (1 MiB cap).
//
// The build-context bucket is named separately from the customer-facing
// MinIO bucket ("instant-shared") so we can apply different lifecycle rules:
// build contexts are TTL'd within hours; customer objects persist.
func buildContextConfigFromCfg(cfg *config.Config) k8s.BuildContextConfig {
	if cfg.MinioEndpoint == "" {
		return k8s.BuildContextConfig{}
	}
	return k8s.BuildContextConfig{
		Endpoint:   cfg.MinioEndpoint,
		AccessKey:  cfg.MinioRootUser,
		SecretKey:  cfg.MinioRootPassword,
		BucketName: "instant-build-contexts",
		UseSSL:     false, // in-cluster MinIO is plaintext
	}
}
