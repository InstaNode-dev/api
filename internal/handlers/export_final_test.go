package handlers

// export_final_test.go — white-box re-exports for the FINAL handlers coverage
// pass. Each symbol is checked against the existing export_*_test.go files
// (export_billing/bvwave/provarms/rbw/residual/vecwave) to avoid redeclaration.

import (
	"context"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"

	"instant.dev/internal/config"
	"instant.dev/internal/models"
)

// DerefUUIDForTest re-exports twin.go's package-private derefUUID. The nil
// branch is unreachable through the HTTP handler (ProvisionForTwin is always
// called with a non-nil &rootID), so it's covered as a pure unit here.
func DerefUUIDForTest(p *uuid.UUID) string { return derefUUID(p) }

// SetLookupTXTForTest swaps custom_domain.go's package-level lookupTXT seam so
// the TXT-match success path runs without real DNS. Returns a restore func.
func SetLookupTXTForTest(fn func(ctx context.Context, name string) ([]string, error)) (restore func()) {
	prev := lookupTXT
	lookupTXT = fn
	return func() { lookupTXT = prev }
}

// ExpectedTXTValueForTest re-exports expectedTXTValue so a test can build the
// exact TXT record the verifier looks for.
func ExpectedTXTValueForTest(token string) string { return expectedTXTValue(token) }

// StackOwnerCheckForTest re-exports stack.go's package-private stackOwnerCheck
// so the anonymous/authenticated mismatch arms can be unit-tested directly.
func StackOwnerCheckForTest(c *fiber.Ctx, stack *models.Stack, team *models.Team) error {
	return stackOwnerCheck(c, stack, team)
}

// CheckStackDeployLimitForTest re-exports StackHandler.checkStackDeployLimit so
// the Redis-pipeline-error arm can be driven with a closed Redis client.
func (h *StackHandler) CheckStackDeployLimitForTest(ctx context.Context, fp string) (bool, error) {
	return h.checkStackDeployLimit(ctx, fp)
}

// ── agent_action.go empty-arg default-branch coverage ────────────────────────
// These re-exports drive the `if x == "" { x = "..." }` default branches that
// the happy-path callers (always passing a non-empty value) leave open.

func AAEnvPolicyDeniedForTest(env, action, allowedRoles, callerRole string) string {
	return newAgentActionEnvPolicyDenied(env, action, allowedRoles, callerRole)
}
func AAOwnerRequiredForTest(callerRole string) string { return newAgentActionOwnerRequired(callerRole) }
func AABindingNoEnvTwinForTest(rootID, resourceName, env string) string {
	return newAgentActionBindingNoEnvTwin(rootID, resourceName, env)
}
func AAPromoteApprovalSentForTest(toEnv, recipientEmail string) string {
	return newAgentActionPromoteApprovalSent(toEnv, recipientEmail)
}
func AADeletionPendingForTest(maskedEmail string, ttlMinutes int) string {
	return newAgentActionDeletionPendingConfirmation(maskedEmail, ttlMinutes)
}

// MaskSourceIPForTest re-exports webhook_security_helpers.maskSourceIP so the
// IPv4:port-strip, parse-fail, and IPv6-/48 branches can be unit-covered.
func MaskSourceIPForTest(raw string) string { return maskSourceIP(raw) }

// BuildContextConfigFromCfgForTest re-exports buildContextConfigFromCfg so its
// MinIO-configured branch (the populated-BuildContextConfig path) can be
// covered alongside the existing empty-MinIO default.
func BuildContextConfigFromCfgForTest(cfg *config.Config) (endpoint, bucket string) {
	bc := buildContextConfigFromCfg(cfg)
	return bc.Endpoint, bc.BucketName
}
