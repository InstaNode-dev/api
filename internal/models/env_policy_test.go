package models

// env_policy_test.go — Pure unit tests for EnvPolicy.Allowed +
// ValidateEnvPolicy. No DB. The middleware-level + handler-level tests live
// in internal/handlers/env_policy_test.go.

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEnvPolicy_Allowed_EmptyPolicy(t *testing.T) {
	// The critical invariant: a nil policy + an empty policy both allow.
	var nilPolicy EnvPolicy
	assert.True(t, nilPolicy.Allowed("production", "deploy", "viewer"),
		"nil EnvPolicy must allow every action by every role")
	emptyPolicy := EnvPolicy{}
	assert.True(t, emptyPolicy.Allowed("production", "deploy", "viewer"),
		"empty EnvPolicy must allow every action by every role")
}

func TestEnvPolicy_Allowed_EnvNotInPolicy(t *testing.T) {
	policy := EnvPolicy{
		"production": {"deploy": []string{"owner"}},
	}
	assert.True(t, policy.Allowed("staging", "deploy", "developer"),
		"env not present in policy must allow")
}

func TestEnvPolicy_Allowed_ActionNotInPolicy(t *testing.T) {
	policy := EnvPolicy{
		"production": {"deploy": []string{"owner"}},
	}
	assert.True(t, policy.Allowed("production", "delete_resource", "developer"),
		"action not present for the env must allow")
}

func TestEnvPolicy_Allowed_EmptyRoleList(t *testing.T) {
	policy := EnvPolicy{
		"production": {"deploy": []string{}},
	}
	assert.True(t, policy.Allowed("production", "deploy", "viewer"),
		"empty role list for the action must allow (documented design)")
}

func TestEnvPolicy_Allowed_RolePresent(t *testing.T) {
	policy := EnvPolicy{
		"production": {"deploy": []string{"owner", "admin"}},
	}
	assert.True(t, policy.Allowed("production", "deploy", "owner"))
	assert.True(t, policy.Allowed("production", "deploy", "admin"))
	assert.True(t, policy.Allowed("production", "deploy", "OWNER"), "role match is case-insensitive")
}

func TestEnvPolicy_Allowed_RoleAbsent(t *testing.T) {
	policy := EnvPolicy{
		"production": {"deploy": []string{"owner"}},
	}
	assert.False(t, policy.Allowed("production", "deploy", "developer"),
		"role not in allowlist must be denied")
	assert.False(t, policy.Allowed("production", "deploy", ""),
		"empty role must be denied when allowlist is non-empty")
}

func TestValidateEnvPolicy_EmptyInput(t *testing.T) {
	p, err := ValidateEnvPolicy(nil)
	require.NoError(t, err)
	assert.Empty(t, p)

	p, err = ValidateEnvPolicy([]byte{})
	require.NoError(t, err)
	assert.Empty(t, p)
}

func TestValidateEnvPolicy_HappyPath(t *testing.T) {
	in := []byte(`{"production":{"deploy":["owner"],"vault_write":["owner","admin"]}}`)
	p, err := ValidateEnvPolicy(in)
	require.NoError(t, err)
	assert.Equal(t, []string{"owner"}, p["production"]["deploy"])
	assert.Equal(t, []string{"owner", "admin"}, p["production"]["vault_write"])
}

func TestValidateEnvPolicy_LowercaseNormalisation(t *testing.T) {
	in := []byte(`{"production":{"deploy":["Owner","ADMIN"," developer "]}}`)
	p, err := ValidateEnvPolicy(in)
	require.NoError(t, err)
	assert.Equal(t, []string{"owner", "admin", "developer"}, p["production"]["deploy"])
}

func TestValidateEnvPolicy_UnknownAction_Rejected(t *testing.T) {
	in := []byte(`{"production":{"deplay":["owner"]}}`)
	_, err := ValidateEnvPolicy(in)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "deplay")
}

func TestValidateEnvPolicy_InvalidEnvName_Rejected(t *testing.T) {
	// Spaces are not allowed after lowercasing — the lowercasing pass
	// only fixes letter case; structural invalid characters still trip
	// envNameValid.
	in := []byte(`{"prod env":{"deploy":["owner"]}}`)
	_, err := ValidateEnvPolicy(in)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "prod env")
}

// Uppercase env names ARE accepted and lowercased on the way in — this is
// a UX nicety, not a bug. The PUT endpoint test reproduces the same
// behaviour at the HTTP boundary (TestEnvPolicy_PutMalformedJSON_400
// uses uppercase to confirm rejection of structural issues, but lowercase
// is the canonical persisted form).
func TestValidateEnvPolicy_UppercaseEnv_Lowercased(t *testing.T) {
	in := []byte(`{"PRODUCTION":{"deploy":["owner"]}}`)
	p, err := ValidateEnvPolicy(in)
	require.NoError(t, err)
	_, ok := p["production"]
	assert.True(t, ok, "uppercase env name must be lowercased to 'production'")
}

func TestValidateEnvPolicy_InvalidRoleName_Rejected(t *testing.T) {
	in := []byte(`{"production":{"deploy":["owner!@#"]}}`)
	_, err := ValidateEnvPolicy(in)
	require.Error(t, err)
}

func TestValidateEnvPolicy_TooLarge_Rejected(t *testing.T) {
	big := make([]byte, envPolicyMaxBytes+1)
	for i := range big {
		big[i] = 'a'
	}
	_, err := ValidateEnvPolicy(big)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "too large")
}

func TestValidateEnvPolicy_DuplicateRolesDeduped(t *testing.T) {
	in := []byte(`{"production":{"deploy":["owner","owner","admin","owner"]}}`)
	p, err := ValidateEnvPolicy(in)
	require.NoError(t, err)
	assert.Equal(t, []string{"owner", "admin"}, p["production"]["deploy"])
}
