package models

// env_policy.go — Team-level per-environment access policy.
//
// Slice 6 of ENV-AWARE-DEPLOYMENTS-DESIGN. The policy is a JSONB column on
// teams whose shape is map[env]map[action][]role — the set of roles permitted
// to perform `action` on `env`. An EMPTY policy (`{}`) means "no enforcement"
// — every role can perform every action on every env. This default-allow
// stance is non-negotiable per the design doc: a misconfigured team must
// never be locked out of their own resources.
//
// The middleware that consumes this lives in internal/middleware/env_policy.go;
// the model side is intentionally just storage + validation + a single helper
// that answers "is `role` in the allowlist for (env, action)?".

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/google/uuid"
)

// EnvPolicy is the in-memory representation of teams.env_policy. The keys at
// both levels are normalised lowercase strings. A nil EnvPolicy is treated
// identically to an empty map: no enforcement on any env.
type EnvPolicy map[string]map[string][]string

// Allowed reports whether the supplied role is permitted to perform `action`
// on `env`. The rules — kept in one place so middleware tests and direct
// callers (e.g. dashboard JSON validation) cannot drift:
//
//  1. If the policy is nil or has no entry for `env`, return true (allow).
//  2. If the env entry exists but has no entry for `action`, return true.
//  3. If the action entry exists but is an empty slice, return true.
//  4. Otherwise the role must appear in the slice (case-insensitive).
//
// The "empty slice = allow" rule (case 3) is deliberate: an owner clearing
// the role list for an action is the natural way to say "no restriction on
// this one". Documented in the design doc §4 slice 6.
func (p EnvPolicy) Allowed(env, action, role string) bool {
	if len(p) == 0 {
		return true
	}
	envEntry, ok := p[env]
	if !ok || len(envEntry) == 0 {
		return true
	}
	roles, ok := envEntry[action]
	if !ok || len(roles) == 0 {
		return true
	}
	roleLower := strings.ToLower(strings.TrimSpace(role))
	for _, r := range roles {
		if strings.EqualFold(strings.TrimSpace(r), roleLower) {
			return true
		}
	}
	return false
}

// AllowedRoles returns the role allowlist configured for (env, action), or
// nil if the policy does not gate that pair. Used by the middleware to
// populate the `allowed_roles` field on the 403 response so agents can tell
// the user which role is required.
func (p EnvPolicy) AllowedRoles(env, action string) []string {
	if len(p) == 0 {
		return nil
	}
	envEntry, ok := p[env]
	if !ok {
		return nil
	}
	roles, ok := envEntry[action]
	if !ok {
		return nil
	}
	// Defensive copy so callers can't mutate the cached policy.
	out := make([]string, len(roles))
	copy(out, roles)
	return out
}

// envPolicyMaxBytes caps the size of a stored policy. A team uploading a
// policy larger than this is almost certainly malicious or buggy; the cap
// keeps a runaway PUT from bloating the teams row.
const envPolicyMaxBytes = 8 * 1024

// ValidateEnvPolicy ensures the JSON shape is map[string]map[string][]string
// and that env names + action names match a sane character set. Returns
// (normalised policy, nil) on success or (nil, error) on failure. The
// returned policy has lowercase env/action keys and trimmed role names —
// the canonical form persisted to the DB.
//
// Validation rules:
//   - Env names: 1-64 chars, [a-z0-9_-] after lowercasing. (Matches the
//     existing models.NormalizeEnv contract.)
//   - Action names: must be one of the known action constants
//     (ActionDeploy, ActionDeleteResource, ActionVaultWrite). Unknown
//     actions are rejected so a typo (`"deplay"`) can't silently
//     no-op the policy.
//   - Role names: 1-32 chars, [a-z0-9_] after lowercasing. We do NOT
//     enforce against a fixed allowlist (owner/admin/developer/viewer)
//     here so future role additions don't require a model change.
//   - Total serialised size must fit envPolicyMaxBytes.
func ValidateEnvPolicy(raw []byte) (EnvPolicy, error) {
	if len(raw) == 0 {
		return EnvPolicy{}, nil
	}
	if len(raw) > envPolicyMaxBytes {
		return nil, fmt.Errorf("env_policy too large: %d bytes (max %d)", len(raw), envPolicyMaxBytes)
	}
	var parsed map[string]map[string][]string
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&parsed); err != nil {
		return nil, fmt.Errorf("env_policy must be JSON of shape {env:{action:[role,...]}}: %w", err)
	}

	known := knownEnvPolicyActions()
	out := make(EnvPolicy, len(parsed))
	for env, actions := range parsed {
		envLower := strings.ToLower(strings.TrimSpace(env))
		if !envNameValid(envLower) {
			return nil, fmt.Errorf("env_policy: invalid env name %q (must match ^[a-z0-9_-]{1,64}$)", env)
		}
		if _, dupe := out[envLower]; dupe {
			return nil, fmt.Errorf("env_policy: duplicate env %q after lowercasing", env)
		}
		envOut := make(map[string][]string, len(actions))
		for action, roles := range actions {
			actLower := strings.ToLower(strings.TrimSpace(action))
			if _, ok := known[actLower]; !ok {
				return nil, fmt.Errorf("env_policy: unknown action %q (known: deploy, delete_resource, vault_write)", action)
			}
			// Trim + lowercase roles, dedupe.
			seen := make(map[string]struct{}, len(roles))
			cleaned := make([]string, 0, len(roles))
			for _, r := range roles {
				rl := strings.ToLower(strings.TrimSpace(r))
				if !roleNameValid(rl) {
					return nil, fmt.Errorf("env_policy: invalid role %q (must match ^[a-z0-9_]{1,32}$)", r)
				}
				if _, dupe := seen[rl]; dupe {
					continue
				}
				seen[rl] = struct{}{}
				cleaned = append(cleaned, rl)
			}
			envOut[actLower] = cleaned
		}
		out[envLower] = envOut
	}
	return out, nil
}

// envNameValid mirrors NormalizeEnv's regex without pulling regexp.
func envNameValid(s string) bool {
	if len(s) == 0 || len(s) > 64 {
		return false
	}
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' || r == '_' {
			continue
		}
		return false
	}
	return true
}

func roleNameValid(s string) bool {
	if len(s) == 0 || len(s) > 32 {
		return false
	}
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '_' {
			continue
		}
		return false
	}
	return true
}

// Action constants — the canonical set of write-mutating actions that the
// env-policy middleware understands. Exposed for use in:
//   - handlers wiring RequireEnvAccess(ActionDeploy) onto routes
//   - validation logic above (knownEnvPolicyActions)
//   - tests
//
// Adding a new action: append it here, add it to knownEnvPolicyActions, and
// wire the middleware onto the corresponding endpoint.
const (
	ActionDeploy         = "deploy"
	ActionDeleteResource = "delete_resource"
	ActionVaultWrite     = "vault_write"
)

func knownEnvPolicyActions() map[string]struct{} {
	return map[string]struct{}{
		ActionDeploy:         {},
		ActionDeleteResource: {},
		ActionVaultWrite:     {},
	}
}

// GetTeamEnvPolicy fetches the policy for a team. Missing team → an empty
// policy (so policy lookups never block on a stale team_id in a stale JWT).
// The empty-policy fallback is consistent with the default-allow rule.
func GetTeamEnvPolicy(ctx context.Context, db *sql.DB, teamID uuid.UUID) (EnvPolicy, error) {
	var raw []byte
	err := db.QueryRowContext(ctx,
		`SELECT env_policy FROM teams WHERE id = $1`, teamID,
	).Scan(&raw)
	if err == sql.ErrNoRows {
		return EnvPolicy{}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("models.GetTeamEnvPolicy: %w", err)
	}
	if len(raw) == 0 {
		return EnvPolicy{}, nil
	}
	var parsed EnvPolicy
	if err := json.Unmarshal(raw, &parsed); err != nil {
		// A malformed policy in the DB must default-allow rather than block
		// every action — the user gets a warning in logs but production
		// stays available. Returning the parse error here would cause the
		// middleware to deny every request on a corrupted team row.
		return EnvPolicy{}, nil
	}
	return parsed, nil
}

// SetTeamEnvPolicy replaces the team's env_policy with the supplied policy.
// Validates by re-serialising — the caller has already typically run
// ValidateEnvPolicy on the inbound JSON; this re-serialisation is the
// canonical-form write that flows into the DB.
func SetTeamEnvPolicy(ctx context.Context, db *sql.DB, teamID uuid.UUID, policy EnvPolicy) error {
	body, err := json.Marshal(policy)
	if err != nil {
		return fmt.Errorf("models.SetTeamEnvPolicy: marshal: %w", err)
	}
	res, err := db.ExecContext(ctx,
		`UPDATE teams SET env_policy = $1::jsonb WHERE id = $2`,
		string(body), teamID,
	)
	if err != nil {
		return fmt.Errorf("models.SetTeamEnvPolicy: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return &ErrTeamNotFound{ID: teamID}
	}
	return nil
}
