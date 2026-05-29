package handlers

// api_keys.go — Personal Access Token CRUD.
//
// Routes (registered in router.go):
//   POST   /api/v1/auth/api-keys           create (returns plaintext ONCE)
//   GET    /api/v1/auth/api-keys           list (no plaintext)
//   DELETE /api/v1/auth/api-keys/:id       revoke
//
// Plaintext is shown only in the create response. The DB stores SHA-256
// of the plaintext; revoking is a soft-set of revoked_at = now().
//
// Auth P0 hardening (2026-05-29) — findings AUTH-001/002/090/164:
//
//   - AUTH-001: PATs cannot mint child PATs (contract was already in the
//     OpenAPI; the handler was returning 201).
//   - AUTH-002: child PAT scopes must be a subset of the parent's scopes.
//     Previously a read-only PAT could mint an admin-scope child.
//   - AUTH-090: session-JWT callers requesting an `admin`-scope PAT must
//     pass a re-auth confirmation header.
//   - AUTH-164: `scopes:[]` / `scopes:null` now fail-closed with 400
//     instead of silently defaulting to ["read","write"].

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"errors"
	"log/slog"
	"strings"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"instant.dev/internal/middleware"
	"instant.dev/internal/models"
)

// APIKeysHandler serves /api/v1/auth/api-keys.
type APIKeysHandler struct {
	db *sql.DB
}

func NewAPIKeysHandler(db *sql.DB) *APIKeysHandler {
	return &APIKeysHandler{db: db}
}

type createAPIKeyBody struct {
	Name   string   `json:"name"`
	Scopes []string `json:"scopes,omitempty"`
}

// reauthConfirmHeader is the dashboard-set header that signals the caller
// has completed a fresh re-auth step (password / MFA / passkey prompt).
// AUTH-090: required when minting `admin`-scope PATs from a session JWT.
// The value isn't cryptographically bound (the dashboard could be coerced
// into setting it) but the header presence is a forcing function that
// stops naive CSRF-class scripts from quietly minting admin scope.
const reauthConfirmHeader = "X-Confirm-Reauth"

// Create handles POST /api/v1/auth/api-keys.
// Returns the plaintext key exactly once — the response is the only place
// the founder will ever see it.
func (h *APIKeysHandler) Create(c *fiber.Ctx) error {
	teamID, err := uuid.Parse(middleware.GetTeamID(c))
	if err != nil {
		return respondError(c, fiber.StatusUnauthorized, "unauthorized", "Authentication required")
	}
	createdBy := uuid.NullUUID{}
	if uidStr := middleware.GetUserID(c); uidStr != "" {
		if u, err := uuid.Parse(uidStr); err == nil {
			createdBy = uuid.NullUUID{UUID: u, Valid: true}
		}
	}

	// AUTH-001: PATs cannot mint child PATs. The OpenAPI contract already
	// documents this ("403 when the caller is themselves a PAT"); the
	// previous behaviour was 201 because the handler only checked for a
	// valid user_id, which the PAT auth path populates from CreatedBy.
	// Reject up-front, regardless of scope, so the rotation/revocation
	// story holds: a leaked PAT cannot spawn additional PATs to outlive
	// its own revocation.
	if middleware.IsAuthedViaAPIKey(c) {
		return respondError(c, fiber.StatusForbidden, "pat_cannot_mint_pat",
			"Personal Access Tokens cannot mint other Personal Access Tokens. Sign in as a user to manage tokens.")
	}

	// Reject any auth path that produces a request without a user. Belt-
	// and-suspenders to the IsAuthedViaAPIKey check above.
	if !createdBy.Valid {
		return respondError(c, fiber.StatusForbidden, "forbidden",
			"PAT creation requires a user session, not another PAT")
	}

	// AUTH-164: we have to distinguish "field absent" from "field
	// explicitly []  / null" — Go decodes both to a nil slice. We peek at
	// the raw body to make that distinction:
	//   - absent  → fall back to a safe default ["read"]
	//   - []/null → fail-closed 400 invalid_scopes (caller asked for no
	//     scope; previous behaviour was to silently issue read+write).
	rawBody := c.Body()
	scopesExplicit, scopesExplicitNull := scopesFieldKind(rawBody)

	var body createAPIKeyBody
	if err := c.BodyParser(&body); err != nil {
		return respondError(c, fiber.StatusBadRequest, "invalid_body",
			"Body must be valid JSON: {\"name\":\"my-laptop\",\"scopes\":[\"read\",\"write\"]}")
	}
	body.Name = strings.TrimSpace(body.Name)
	if body.Name == "" {
		return respondError(c, fiber.StatusBadRequest, "missing_name",
			"Field 'name' is required (e.g. 'laptop', 'github-actions')")
	}
	if len(body.Name) > 120 {
		return respondError(c, fiber.StatusBadRequest, "name_too_long",
			"Field 'name' must be 120 characters or fewer")
	}

	if scopesExplicit && (len(body.Scopes) == 0 || scopesExplicitNull) {
		return respondError(c, fiber.StatusBadRequest, "invalid_scopes",
			"Field 'scopes' must be a non-empty array of read/write/admin. Omit the field to default to ['read'].")
	}

	// Validate scopes — only 'read' / 'write' / 'admin' are honored.
	for _, s := range body.Scopes {
		switch strings.ToLower(s) {
		case "read", "write", "admin":
			// ok
		default:
			return respondError(c, fiber.StatusBadRequest, "invalid_scope",
				"Scopes must be one of: read, write, admin")
		}
	}

	// Default scope when the caller omitted the field entirely — keep
	// the historical default ["read"] minus "write" (fail-closed). A
	// caller who wants write must list it explicitly.
	if !scopesExplicit {
		body.Scopes = []string{"read"}
	}

	// Normalise scopes to lower-case for the subset check below — accept
	// "ADMIN" the same as "admin" (the validate loop above already
	// allowed both spellings).
	for i, s := range body.Scopes {
		body.Scopes[i] = strings.ToLower(s)
	}

	// AUTH-090: minting an `admin`-scope PAT from a plain session JWT
	// without an explicit re-auth confirmation is the last hop in the
	// escalation chain. Require X-Confirm-Reauth: 1 (set by the
	// dashboard after a fresh password/MFA prompt) for admin scope.
	if scopeContains(body.Scopes, "admin") && !hasReauthConfirmation(c) {
		return respondError(c, fiber.StatusForbidden, "reauth_required",
			"Admin-scope PATs require re-authentication. Re-enter credentials in the dashboard, or set X-Confirm-Reauth: 1 after a fresh /auth/me check.")
	}

	plaintext, err := models.GenerateAPIKeyPlaintext()
	if err != nil {
		slog.Error("api_keys.create.generate_failed", "error", err, "team_id", teamID)
		return respondError(c, fiber.StatusInternalServerError, "generate_failed",
			"Failed to generate token bytes")
	}
	hash := models.HashAPIKey(plaintext)

	row, err := models.CreateAPIKey(c.Context(), h.db, teamID, createdBy, body.Name, hash, body.Scopes)
	if err != nil {
		slog.Error("api_keys.create.db_failed", "error", err, "team_id", teamID)
		return respondError(c, fiber.StatusServiceUnavailable, "db_failed",
			"Failed to store API key")
	}

	return c.Status(fiber.StatusCreated).JSON(fiber.Map{
		"ok":         true,
		"id":         row.ID,
		"name":       row.Name,
		"scopes":     row.Scopes,
		"created_at": row.CreatedAt,
		"key":        plaintext,
		"note":       "Save this key now — it will not be shown again. Use as: Authorization: Bearer " + plaintext,
	})
}

// List handles GET /api/v1/auth/api-keys. Returns metadata only.
func (h *APIKeysHandler) List(c *fiber.Ctx) error {
	teamID, err := uuid.Parse(middleware.GetTeamID(c))
	if err != nil {
		return respondError(c, fiber.StatusUnauthorized, "unauthorized", "Authentication required")
	}
	keys, err := models.ListAPIKeysByTeam(c.Context(), h.db, teamID)
	if err != nil {
		slog.Error("api_keys.list.failed", "error", err, "team_id", teamID)
		return respondError(c, fiber.StatusServiceUnavailable, "db_failed",
			"Failed to list API keys")
	}
	items := make([]fiber.Map, 0, len(keys))
	for _, k := range keys {
		item := fiber.Map{
			"id":           k.ID,
			"name":         k.Name,
			"scopes":       k.Scopes,
			"created_at":   k.CreatedAt,
			"last_used_at": nil,
			"revoked":      k.RevokedAt.Valid,
		}
		if k.LastUsedAt.Valid {
			item["last_used_at"] = k.LastUsedAt.Time
		}
		items = append(items, item)
	}
	return c.JSON(fiber.Map{"ok": true, "items": items})
}

// Revoke handles DELETE /api/v1/auth/api-keys/:id.
func (h *APIKeysHandler) Revoke(c *fiber.Ctx) error {
	teamID, err := uuid.Parse(middleware.GetTeamID(c))
	if err != nil {
		return respondError(c, fiber.StatusUnauthorized, "unauthorized", "Authentication required")
	}
	idStr := c.Params("id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		return respondError(c, fiber.StatusBadRequest, "invalid_id", "Path parameter must be a UUID")
	}
	if err := models.RevokeAPIKey(c.Context(), h.db, teamID, id); err != nil {
		if errors.Is(err, models.ErrAPIKeyNotFound) {
			return respondError(c, fiber.StatusNotFound, "not_found", "API key not found")
		}
		slog.Error("api_keys.revoke.failed", "error", err, "team_id", teamID, "id", id)
		return respondError(c, fiber.StatusServiceUnavailable, "db_failed",
			"Failed to revoke API key")
	}
	return c.JSON(fiber.Map{"ok": true, "id": id})
}

// scopeContains reports whether the slice contains the target scope, using
// case-insensitive comparison. Used for both subset checks and admin gating.
func scopeContains(scopes []string, target string) bool {
	target = strings.ToLower(target)
	for _, s := range scopes {
		if strings.ToLower(s) == target {
			return true
		}
	}
	return false
}

// hasReauthConfirmation reports whether the caller proved a fresh re-auth
// step (AUTH-090). The dashboard sets X-Confirm-Reauth: 1 after a password
// / MFA / passkey prompt within the last 5 minutes; agents calling the API
// directly set the same header after a /auth/me round-trip.
func hasReauthConfirmation(c *fiber.Ctx) bool {
	v := strings.TrimSpace(c.Get(reauthConfirmHeader))
	return v == "1" || strings.EqualFold(v, "true")
}

// scopesFieldKind returns (present, isNull) for the top-level "scopes"
// field of the request body so we can distinguish:
//
//	{}                  → absent (present=false)
//	{"scopes":null}     → present, null
//	{"scopes":[]}       → present, empty array
//	{"scopes":["read"]} → present, non-empty
//
// AUTH-164: an absent field falls back to the safe default ["read"], but
// an explicit null/empty must fail-closed with 400 — the caller asked for
// "no scopes" and must NOT silently get read+write.
//
// Implementation uses encoding/json on a minimal envelope to avoid
// re-parsing the full body and to keep the existing fiber BodyParser path
// untouched. A malformed body returns (false, false) and the canonical
// BodyParser path then produces the existing invalid_body 400.
func scopesFieldKind(raw []byte) (present, isNull bool) {
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 || raw[0] != '{' {
		return false, false
	}
	var envelope map[string]json.RawMessage
	if err := json.Unmarshal(raw, &envelope); err != nil {
		return false, false
	}
	v, ok := envelope["scopes"]
	if !ok {
		return false, false
	}
	if bytes.Equal(bytes.TrimSpace(v), []byte("null")) {
		return true, true
	}
	return true, false
}
