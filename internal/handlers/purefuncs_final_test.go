package handlers_test

// purefuncs_final_test.go — FINAL coverage pass for the small pure-function
// default-branch arms that the happy-path callers leave open: the agent_action
// empty-arg defaults, maskSourceIP's IPv4:port / parse-fail / IPv6 branches,
// and buildContextConfigFromCfg's MinIO-configured branch.

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"

	"instant.dev/internal/config"
	"instant.dev/internal/handlers"
)

func TestPureFinal_AgentAction_EmptyArgDefaults(t *testing.T) {
	// Each builder has an `if x == "" { x = "unknown" }` default branch the
	// happy-path callers never hit.
	assert.Contains(t, handlers.AAEnvPolicyDeniedForTest("production", "deploy", "owner", ""), "unknown")
	assert.Contains(t, handlers.AAOwnerRequiredForTest(""), "unknown")
	// Non-empty inputs hit the no-default arm too.
	assert.Contains(t, handlers.AAEnvPolicyDeniedForTest("staging", "delete", "admin", "member"), "member")
	assert.Contains(t, handlers.AAOwnerRequiredForTest("member"), "member")
}

func TestPureFinal_AgentAction_BindingAndPromoteAndDeletion(t *testing.T) {
	// These builders have a conditional inner branch (empty name / recipient /
	// masked email). Exercise both arms.
	assert.NotEmpty(t, handlers.AABindingNoEnvTwinForTest("root-1", "", "staging"))
	assert.NotEmpty(t, handlers.AABindingNoEnvTwinForTest("root-1", "my-db", "staging"))
	assert.NotEmpty(t, handlers.AAPromoteApprovalSentForTest("production", ""))
	assert.NotEmpty(t, handlers.AAPromoteApprovalSentForTest("production", "ops@example.com"))
	assert.NotEmpty(t, handlers.AADeletionPendingForTest("", 30))
	assert.NotEmpty(t, handlers.AADeletionPendingForTest("o***@example.com", 30))
}

func TestPureFinal_MaskSourceIP_Branches(t *testing.T) {
	// Empty → "".
	assert.Equal(t, "", handlers.MaskSourceIPForTest(""))
	// IPv4:port → stripped + masked to /24.
	assert.Equal(t, "203.0.113.0/24", handlers.MaskSourceIPForTest("203.0.113.45:54321"))
	// Bare IPv4 → /24.
	assert.Equal(t, "198.51.100.0/24", handlers.MaskSourceIPForTest("198.51.100.7"))
	// Unparseable → "".
	assert.Equal(t, "", handlers.MaskSourceIPForTest("not-an-ip"))
	// IPv6 → /48 mask.
	got := handlers.MaskSourceIPForTest("2001:db8:1234:5678::1")
	assert.True(t, strings.HasSuffix(got, "/48"), "IPv6 should be masked to /48, got %q", got)
	// Bracketed IPv6:port.
	assert.NotEmpty(t, handlers.MaskSourceIPForTest("[2001:db8::1]:8080"))
}

func TestPureFinal_BuildContextConfig_MinIOConfigured(t *testing.T) {
	// Empty MinIO → zero-value (already covered elsewhere).
	ep, _ := handlers.BuildContextConfigFromCfgForTest(&config.Config{})
	assert.Equal(t, "", ep)
	// MinIO configured → populated BuildContextConfig.
	ep2, bucket := handlers.BuildContextConfigFromCfgForTest(&config.Config{
		MinioEndpoint:     "minio.test:9000",
		MinioRootUser:     "root",
		MinioRootPassword: "rootpass",
	})
	assert.Equal(t, "minio.test:9000", ep2)
	assert.Equal(t, "instant-build-contexts", bucket)
}
