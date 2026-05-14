package middleware

// env_policy.go — Per-env access policy middleware (slice 6 of
// ENV-AWARE-DEPLOYMENTS-DESIGN).
//
// RequireEnvAccess(action) returns a Fiber handler that:
//   - looks up the authenticated team's env_policy JSONB row
//   - reads the env scope from the request (query "?env=" first, then JSON
//     body field "env" or "to", then "development" as a safe default
//     — flipped from "production" by migration 026)
//   - reads the authenticated user's team role (populated by
//     PopulateTeamRole upstream)
//   - rejects with 403 + agent_action when role is not in the allowlist
//
// The DEFAULT-ALLOW rule is critical: when the team's env_policy is empty
// `{}`, or the env has no entry, or the action has no entry, the middleware
// MUST pass the request through unchanged. A misconfigured-team-locked-out
// failure mode is unacceptable — see the design doc §4 slice 6.
//
// Wiring: install AFTER RequireAuth + PopulateTeamRole. The role lookup uses
// the same DB handle PopulateTeamRole was wired with (set via
// SetRoleLookupDB at startup).

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
)

// envPolicyDB is the package-level DB handle used by RequireEnvAccess to read
// teams.env_policy. Distinct from roleLookupDB because policy lookups are
// keyed by team_id only (no user join) and the timeout is shorter — we
// trade some duplication for the freedom to tune the two independently.
var (
	envPolicyMu sync.RWMutex
	envPolicyDB *sql.DB
)

// SetEnvPolicyDB registers the platform DB handle used to look up team env
// policies. Wired in router.go alongside SetRoleLookupDB. A nil DB disables
// policy enforcement (middleware short-circuits to allow on lookup failure
// rather than locking out every user during DB downtime — fail-open by
// design, same as the rate-limit middleware).
func SetEnvPolicyDB(db *sql.DB) {
	envPolicyMu.Lock()
	defer envPolicyMu.Unlock()
	envPolicyDB = db
}

func getEnvPolicyDB() *sql.DB {
	envPolicyMu.RLock()
	defer envPolicyMu.RUnlock()
	return envPolicyDB
}

// envPolicyAction constants. Must stay in sync with models.Action* (the
// model-side constants are the source of truth; these are duplicated here
// to avoid a middleware→models import cycle, same pattern as RBAC Role*).
const (
	EnvPolicyActionDeploy         = "deploy"
	EnvPolicyActionDeleteResource = "delete_resource"
	EnvPolicyActionVaultWrite     = "vault_write"
)

// envPolicyDefaultEnv is the env name used when neither the query string nor
// the request body declares one. Matches resolveEnv's "empty → development"
// default in handlers/provision_helper.go (flipped from "production" by
// migration 026 — see models.EnvDefault).
const envPolicyDefaultEnv = "development"

// envPolicyLookupTimeout caps the DB call to read teams.env_policy. Kept
// short because this middleware runs on every gated request — slow lookups
// must not pile up under load.
const envPolicyLookupTimeout = 500 * time.Millisecond

// envPolicyExtractor describes the optional callback used to derive the env
// scope from request state that the middleware can't read on its own (e.g.
// the env stored on a resource row, looked up by URL param :id).
//
// The default behaviour reads c.Query("env") / body "env" / body "to" /
// "production". For DELETE /resources/:id we need the env from the resource
// row — that case overrides via WithEnvLookup.
type envPolicyOption struct {
	envLookup func(c *fiber.Ctx) (string, error)
}

// EnvPolicyOption tunes RequireEnvAccess for a specific endpoint.
type EnvPolicyOption func(*envPolicyOption)

// WithEnvLookup overrides the default request-derived env extraction. The
// lookup runs on every gated request, after auth but before the policy
// check. Errors propagate as 503 (so a transient DB outage doesn't
// mistakenly deny — fail-open).
func WithEnvLookup(fn func(c *fiber.Ctx) (string, error)) EnvPolicyOption {
	return func(o *envPolicyOption) { o.envLookup = fn }
}

// RequireEnvAccess returns a Fiber middleware that gates the request on the
// authenticated user's role being permitted by the team's env_policy for
// the supplied action. Must run after RequireAuth + PopulateTeamRole.
//
// The middleware's contract on failure modes (each "fail" mode chosen to
// MINIMISE the risk of locking real users out):
//   - No DB handle wired → allow (treat as "policy disabled")
//   - DB lookup error → allow (logged via slog if a logger is present)
//   - Malformed policy JSON in the DB → allow (models.GetTeamEnvPolicy
//     normalises this)
//   - Empty policy → allow
//   - Env not in policy → allow
//   - Action not in policy for this env → allow
//   - Empty role list for this action → allow
//   - Role in list → allow
//   - Role NOT in list → 403 + structured body
//
// The structured 403 body always carries:
//   - error: "env_policy_denied" (stable keyword agents can branch on)
//   - env, action, role: what was checked
//   - allowed_roles: the list the policy specifies
//   - agent_action: prose the agent surfaces verbatim to the user
func RequireEnvAccess(action string, opts ...EnvPolicyOption) fiber.Handler {
	o := envPolicyOption{envLookup: defaultEnvLookup}
	for _, fn := range opts {
		fn(&o)
	}
	return func(c *fiber.Ctx) error {
		teamIDStr := GetTeamID(c)
		if teamIDStr == "" {
			// Upstream RequireAuth should have rejected — but if we got
			// here without a team id, fail open. Letting the downstream
			// handler return its own 401 is the right behaviour.
			return c.Next()
		}
		teamID, err := uuid.Parse(teamIDStr)
		if err != nil {
			return c.Next()
		}
		db := getEnvPolicyDB()
		if db == nil {
			return c.Next()
		}

		env, err := o.envLookup(c)
		if err != nil {
			// Lookup error → fail open. The handler will surface its own
			// 404/500 if the request is malformed; we don't want to layer
			// a confusing 403 on top.
			return c.Next()
		}
		if env == "" {
			env = envPolicyDefaultEnv
		}
		env = strings.ToLower(env)

		policy, err := loadEnvPolicy(c.UserContext(), db, teamID)
		if err != nil {
			// DB error → fail open.
			return c.Next()
		}
		if len(policy) == 0 {
			return c.Next()
		}
		envEntry, ok := policy[env]
		if !ok || len(envEntry) == 0 {
			return c.Next()
		}
		allowed, ok := envEntry[action]
		if !ok || len(allowed) == 0 {
			return c.Next()
		}

		role := GetTeamRole(c)
		roleLower := strings.ToLower(strings.TrimSpace(role))
		for _, r := range allowed {
			if strings.EqualFold(strings.TrimSpace(r), roleLower) {
				return c.Next()
			}
		}

		// Build the agent_action prose via the named builder. Extracted
		// from an inline fmt.Sprintf so the contract-review grep
		// (`grep "agent_action" internal/middleware`) surfaces every
		// middleware-level agent_action string in one place, alongside
		// unauthorizedAgentAction (auth.go) and adminForbiddenAgentAction
		// (admin.go). The middleware can't import handlers/agent_action.go
		// (cycle), so the builder lives in this package — same pattern as
		// the other two middleware-level constants.
		agentAction := envPolicyDeniedAgentAction(env, formatAllowedRoles(allowed), action, role)
		return c.Status(fiber.StatusForbidden).JSON(fiber.Map{
			"ok":                  false,
			"error":               "env_policy_denied",
			"message":             "env_policy denies " + action + " on env=" + env + " for role=" + role,
			"request_id":          GetRequestID(c),
			"retry_after_seconds": nil,
			"env":                 env,
			"action":              action,
			"role":                role,
			"allowed_roles":       allowed,
			"agent_action":        agentAction,
		})
	}
}

// loadEnvPolicy reads teams.env_policy and JSON-decodes it. Mirrors
// models.GetTeamEnvPolicy but lives here to avoid the middleware→models
// import cycle (handlers depend on middleware; models is depended on by
// handlers; if middleware imported models we'd close the loop).
func loadEnvPolicy(parent context.Context, db *sql.DB, teamID uuid.UUID) (map[string]map[string][]string, error) {
	ctx, cancel := context.WithTimeout(parent, envPolicyLookupTimeout)
	defer cancel()
	var raw []byte
	err := db.QueryRowContext(ctx, `SELECT env_policy FROM teams WHERE id = $1`, teamID).Scan(&raw)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if len(raw) == 0 {
		return nil, nil
	}
	var parsed map[string]map[string][]string
	if err := json.Unmarshal(raw, &parsed); err != nil {
		// Malformed JSON → treat as empty so we default-allow rather than
		// lock out the team on corrupt state.
		return nil, nil
	}
	return parsed, nil
}

// defaultEnvLookup reads the env scope from, in order:
//  1. c.Query("env")
//  2. JSON body field "env"
//  3. JSON body field "to" (used by /promote and /vault/copy)
//
// Falls back to "" so the caller substitutes envPolicyDefaultEnv. Body
// parsing is best-effort — a malformed body short-circuits to "" and the
// downstream handler will reject with its own 400.
func defaultEnvLookup(c *fiber.Ctx) (string, error) {
	if q := strings.TrimSpace(c.Query("env")); q != "" {
		return q, nil
	}
	body := c.Body()
	if len(body) == 0 {
		return "", nil
	}
	// Only attempt JSON parse when the content-type plausibly says JSON.
	// Multipart forms (POST /deploy/new) carry the env scope in a form
	// field, which we read via WithEnvLookup for that route.
	ct := strings.ToLower(c.Get("Content-Type"))
	if !strings.Contains(ct, "json") {
		return "", nil
	}
	var probe struct {
		Env string `json:"env"`
		To  string `json:"to"`
	}
	if err := json.Unmarshal(body, &probe); err != nil {
		return "", nil
	}
	if probe.Env != "" {
		return probe.Env, nil
	}
	if probe.To != "" {
		return probe.To, nil
	}
	return "", nil
}

// envPolicyDeniedAgentAction is the canonical agent_action sentence served
// on every 403 from RequireEnvAccess. Mirrors the U3 contract shape used by
// handlers/agent_action.go::newAgentActionEnvPolicyDenied:
//
//   - opens with "Tell the user"
//   - names the specific reason (env + required role + action)
//   - exact next action ("have a team owner run the prompt")
//   - full https://instanode.dev/... URL
//
// Duplicated here (rather than imported from handlers) because middleware is
// depended on by handlers, not the other way around — a cross-import would
// close a cycle. Same justification as unauthorizedAgentAction (auth.go) and
// adminForbiddenAgentAction (admin.go). The handlers builder is the source
// of truth; if the prose changes, update both.
//
// The contract test (handlers.TestAgentActionContract) can't reach into
// middleware without an import cycle. The shape (Tell the user / specific
// reason / next action / https URL) MUST stay in sync with the handlers
// builder by hand — covered by env_policy_test.go assertions on the 403
// response body.
func envPolicyDeniedAgentAction(env, allowedRoles, action, callerRole string) string {
	agentRole := callerRole
	if agentRole == "" {
		agentRole = "unknown"
	}
	return fmt.Sprintf(
		"Tell the user the %s env requires the %s role to %s. Their role is %s — have a team owner run the prompt at https://instanode.dev/app/team or adjust the env-policy.",
		env, allowedRoles, action, agentRole,
	)
}

// formatAllowedRoles renders ["owner"] as "owner", ["owner","developer"] as
// "owner or developer", and longer lists with Oxford comma. Used in the
// agent_action prose.
func formatAllowedRoles(roles []string) string {
	switch len(roles) {
	case 0:
		return "<none>"
	case 1:
		return roles[0]
	case 2:
		return roles[0] + " or " + roles[1]
	}
	out := strings.Builder{}
	for i, r := range roles {
		if i == len(roles)-1 {
			out.WriteString("or ")
			out.WriteString(r)
			continue
		}
		out.WriteString(r)
		out.WriteString(", ")
	}
	return out.String()
}
