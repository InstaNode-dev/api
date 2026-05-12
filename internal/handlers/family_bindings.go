package handlers

// family_bindings.go — Slice 4 of env-aware deployments.
//
// Adds "family:<family_root_id>" syntax to POST /deploy/new resource_bindings.
// At deploy time the resolver walks the resource family (via
// models.GetResourceFamily) for the supplied root id, picks the member whose
// env matches the deploy's env, and substitutes that member's decrypted
// connection_url. One deploy manifest works across all envs.
//
// Design choices:
//
//  • Resolution happens BEFORE the deployments row is persisted. That keeps
//    the handler's 4xx surface (400 bad UUID, 403 cross-team, 404 unknown
//    root, 409 no env-twin) in front of the user, instead of failing silently
//    inside the async runDeploy goroutine. This is the opposite of vault://
//    resolution which intentionally runs late (inside runDeploy) so vault
//    rotations apply on redeploy. Family bindings, by contrast, name a
//    specific physical resource and should fail fast.
//
//  • Backward compat: a value that is a raw UUID string (no "family:" prefix)
//    is resolved as a direct resource token lookup. This matches the spec
//    test #6 ("raw token binding still works").
//
//  • A value that is neither a UUID nor "family:<uuid>" is rejected with
//    400 invalid_binding. We do NOT pass arbitrary literal strings through —
//    if the caller wants to inject a literal env var, they should use the
//    env_vars field (not resource_bindings). Keeping the resource_bindings
//    map type-pure prevents agents from accidentally injecting a literal
//    "family:bogus" into the pod env.
//
//  • Feature flag: when cfg.FamilyBindingsEnabled is false, the "family:"
//    prefix is NOT recognised. Such values fall into the UUID-parsing path
//    and fail with 400 invalid_binding (deterministic disable — the deploy
//    cannot accidentally proceed with an unresolved family ref).

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"strings"

	"github.com/google/uuid"
	"instant.dev/internal/crypto"
	"instant.dev/internal/models"
)

// FamilyBindingPrefix marks a resource_bindings value as a family-root id
// reference rather than a raw resource token. See package docs.
const FamilyBindingPrefix = "family:"

// BindingErrorKind classifies a resolveResourceBindings failure so the HTTP
// handler can map each to the right status + agent_action.
type BindingErrorKind string

const (
	BindingErrInvalidUUID    BindingErrorKind = "invalid_uuid"    // 400
	BindingErrInvalidBinding BindingErrorKind = "invalid_binding" // 400 — neither family: nor UUID
	BindingErrNotFound       BindingErrorKind = "not_found"       // 404 — UUID parsed, no row
	BindingErrCrossTeam      BindingErrorKind = "cross_team"      // 403
	BindingErrNoEnvTwin      BindingErrorKind = "no_env_twin"     // 409 — family exists, env sibling missing
	BindingErrLookupFailed   BindingErrorKind = "lookup_failed"   // 503 — db error
)

// BindingError carries the structured failure shape used by the deploy
// handler when resource_bindings cannot be resolved. The handler inspects
// .Kind to pick the HTTP status and .ResourceName / .Env / .RootID to build
// the agent_action sentence.
type BindingError struct {
	Kind         BindingErrorKind
	EnvVarKey    string // e.g. "DATABASE_URL"
	RawValue     string // the offending binding value, e.g. "family:abc-..."
	RootID       string // family root id, if known
	ResourceName string // name of the family's root resource, if known
	Env          string // deploy env we tried to find a twin in
	Detail       string // free-form supplement (db error message etc.)
}

func (e *BindingError) Error() string {
	return fmt.Sprintf("resource_bindings[%s]=%q: %s — %s",
		e.EnvVarKey, e.RawValue, e.Kind, e.Detail)
}

// resolveResourceBindings turns a map of resource_bindings (where each value
// is either "family:<uuid>" or a raw resource-token UUID) into a map of
// env-var → decrypted connection URL.
//
// On any failure it returns nil + a *BindingError naming the offending key.
// All resources must belong to teamID; cross-team refs return BindingErrCrossTeam.
//
// teamID is required (this endpoint is auth-only). env is the deploy's env
// scope (already normalized upstream).
func resolveResourceBindings(
	ctx context.Context,
	db *sql.DB,
	aesKeyHex string,
	teamID uuid.UUID,
	env string,
	bindings map[string]string,
	familyEnabled bool,
) (map[string]string, *BindingError) {
	if len(bindings) == 0 {
		return map[string]string{}, nil
	}

	aesKey, keyErr := crypto.ParseAESKey(aesKeyHex)
	if keyErr != nil {
		return nil, &BindingError{
			Kind:   BindingErrLookupFailed,
			Detail: "AES key parse failed: " + keyErr.Error(),
		}
	}

	out := make(map[string]string, len(bindings))
	for k, raw := range bindings {
		// Reserved underscore-prefixed keys are dropped (matches env_vars rules
		// in deploy.go). Don't fail — just skip.
		if strings.HasPrefix(k, "_") {
			continue
		}
		isFamily := familyEnabled && strings.HasPrefix(raw, FamilyBindingPrefix)
		var idStr string
		if isFamily {
			idStr = strings.TrimPrefix(raw, FamilyBindingPrefix)
		} else {
			idStr = raw
		}
		parsedID, parseErr := uuid.Parse(idStr)
		if parseErr != nil {
			kind := BindingErrInvalidUUID
			detail := "value must be a UUID or family:<uuid> form"
			if !isFamily && strings.HasPrefix(raw, FamilyBindingPrefix) {
				// family: prefix used, but flag disabled
				detail = "family bindings are disabled by FAMILY_BINDINGS_ENABLED=false"
				kind = BindingErrInvalidBinding
			}
			return nil, &BindingError{
				Kind:      kind,
				EnvVarKey: k,
				RawValue:  raw,
				Detail:    detail,
			}
		}

		var member *models.Resource
		if isFamily {
			// family: prefix. Walk the family for the supplied root id,
			// then pick the member matching the deploy's env.
			members, ferr := models.GetResourceFamily(ctx, db, parsedID)
			if ferr != nil {
				return nil, &BindingError{
					Kind:      BindingErrLookupFailed,
					EnvVarKey: k,
					RawValue:  raw,
					RootID:    parsedID.String(),
					Detail:    ferr.Error(),
				}
			}
			if len(members) == 0 {
				return nil, &BindingError{
					Kind:      BindingErrNotFound,
					EnvVarKey: k,
					RawValue:  raw,
					RootID:    parsedID.String(),
					Detail:    "no resource with that family-root id",
				}
			}
			// Authorisation: every member of the family must belong to the
			// caller's team. (They will all share a team_id by construction,
			// but check the root row first for a precise 403.)
			root := members[0]
			if !root.TeamID.Valid || root.TeamID.UUID != teamID {
				return nil, &BindingError{
					Kind:         BindingErrCrossTeam,
					EnvVarKey:    k,
					RawValue:     raw,
					RootID:       parsedID.String(),
					ResourceName: nameOrType(root),
					Detail:       "family root belongs to a different team",
				}
			}
			for _, r := range members {
				if r.Env == env && r.Status != "deleted" {
					member = r
					break
				}
			}
			if member == nil {
				return nil, &BindingError{
					Kind:         BindingErrNoEnvTwin,
					EnvVarKey:    k,
					RawValue:     raw,
					RootID:       parsedID.String(),
					ResourceName: nameOrType(root),
					Env:          env,
					Detail:       fmt.Sprintf("family has no member in env=%s", env),
				}
			}
		} else {
			// Raw UUID = direct resource-token lookup. Backward compat with the
			// pre-slice-4 binding style.
			res, lerr := models.GetResourceByToken(ctx, db, parsedID)
			if lerr != nil {
				var notFound *models.ErrResourceNotFound
				if errors.As(lerr, &notFound) {
					return nil, &BindingError{
						Kind:      BindingErrNotFound,
						EnvVarKey: k,
						RawValue:  raw,
						Detail:    "no resource with that token",
					}
				}
				return nil, &BindingError{
					Kind:      BindingErrLookupFailed,
					EnvVarKey: k,
					RawValue:  raw,
					Detail:    lerr.Error(),
				}
			}
			if res.Status == "deleted" {
				return nil, &BindingError{
					Kind:      BindingErrNotFound,
					EnvVarKey: k,
					RawValue:  raw,
					Detail:    "resource is deleted",
				}
			}
			if !res.TeamID.Valid || res.TeamID.UUID != teamID {
				return nil, &BindingError{
					Kind:         BindingErrCrossTeam,
					EnvVarKey:    k,
					RawValue:     raw,
					ResourceName: nameOrType(res),
					Detail:       "resource belongs to a different team",
				}
			}
			member = res
		}

		// Decrypt the connection URL. Mirror the fail-open posture used in
		// stack.go (key rotation safety): a decrypt failure logs a warning
		// and uses the ciphertext rather than blocking the deploy. The
		// alternative (hard fail) would brick existing apps on every key
		// rotation.
		if !member.ConnectionURL.Valid || member.ConnectionURL.String == "" {
			return nil, &BindingError{
				Kind:         BindingErrLookupFailed,
				EnvVarKey:    k,
				RawValue:     raw,
				ResourceName: nameOrType(member),
				Detail:       "resource has no connection_url (not yet provisioned)",
			}
		}
		plain, dErr := crypto.Decrypt(aesKey, member.ConnectionURL.String)
		if dErr != nil {
			slog.Warn("deploy.family_bindings.decrypt_failed",
				"env_var", k, "resource_id", member.ID, "error", dErr)
			plain = member.ConnectionURL.String
		}
		// Rewrite to the cluster-internal FQDN so the deployed pod can reach
		// the resource without hairpinning through the LoadBalancer. Same
		// rewrite stack.go applies for `needs:` entries.
		prid := member.ProviderResourceID.String
		if prid == "" || prid == "local:0" {
			prid = "instant-customer-" + member.Token.String()
		}
		plain = rewriteToInternalURLForDeploy(plain, member.ResourceType, prid)
		out[k] = plain
	}
	return out, nil
}

// rewriteToInternalURLForDeploy is the deploy-side wrapper around
// rewriteToInternalURL. Kept as a thin alias so future env-specific tweaks
// (e.g. honoring a deploy.Env-aware DNS suffix) don't bleed back into the
// stack handler.
func rewriteToInternalURLForDeploy(publicURL, resourceType, providerResourceID string) string {
	return rewriteToInternalURL(publicURL, resourceType, providerResourceID)
}

// nameOrType returns a printable label for the resource — its name if set,
// else its type. Used in agent_action sentences.
func nameOrType(r *models.Resource) string {
	if r.Name.Valid && r.Name.String != "" {
		return r.Name.String
	}
	return r.ResourceType
}

// mapBindingError translates a *BindingError into the HTTP status, error
// code, message, and agent_action that the deploy handler returns. Kept
// alongside the error definition so adding a new BindingErrorKind requires
// a single edit here (rather than scattered switches in deploy.go).
func mapBindingError(e *BindingError) (status int, code, message, agentAction string) {
	keyLabel := e.EnvVarKey
	if keyLabel == "" {
		keyLabel = "<unknown>"
	}
	switch e.Kind {
	case BindingErrInvalidUUID:
		return 400, "invalid_resource_binding",
			fmt.Sprintf("resource_bindings[%s] is not a valid UUID or family:<uuid>", keyLabel),
			newAgentActionBindingInvalidUUID(keyLabel, e.RawValue)
	case BindingErrInvalidBinding:
		return 400, "invalid_resource_binding",
			fmt.Sprintf("resource_bindings[%s]: %s", keyLabel, e.Detail),
			AgentActionBindingFamilyDisabled
	case BindingErrNotFound:
		return 404, "resource_binding_not_found",
			fmt.Sprintf("resource_bindings[%s]: no resource found for %q", keyLabel, e.RawValue),
			newAgentActionBindingNotFound(keyLabel)
	case BindingErrCrossTeam:
		return 403, "resource_binding_forbidden",
			fmt.Sprintf("resource_bindings[%s]: resource belongs to another team", keyLabel),
			newAgentActionBindingCrossTeam(keyLabel)
	case BindingErrNoEnvTwin:
		return 409, "no_env_twin",
			fmt.Sprintf("resource_bindings[%s]: family for %q has no member in env=%s", keyLabel, nameOrEmpty(e.ResourceName, e.RootID), e.Env),
			newAgentActionBindingNoEnvTwin(e.RootID, e.ResourceName, e.Env)
	default: // BindingErrLookupFailed
		return 503, "resource_binding_lookup_failed",
			fmt.Sprintf("resource_bindings[%s] resolution failed: %s", keyLabel, e.Detail),
			AgentActionBindingLookupFailed
	}
}

// nameOrEmpty returns name when non-empty, else fallback. Local helper so
// mapBindingError doesn't re-implement the trivial fall-through inline.
func nameOrEmpty(name, fallback string) string {
	if name == "" {
		return fallback
	}
	return name
}

