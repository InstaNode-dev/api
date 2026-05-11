package handlers

// vault.go — per-team encrypted secret storage.
//
// Endpoints (all require team JWT, registered behind RequireAuth in router.go):
//   PUT    /api/v1/vault/:env/:key            body {"value":"..."}  → 201 {key,version}
//   GET    /api/v1/vault/:env/:key[?version=N]                       → 200 {key,value,version}
//   GET    /api/v1/vault/:env                                        → 200 {keys:[...]}     (no values)
//   DELETE /api/v1/vault/:env/:key                                   → 204 (hard delete: removes ALL versions)
//   POST   /api/v1/vault/:env/:key/rotate     body {"value":"..."}   → 201 {key,version}     (alias for PUT)
//
// Encryption: AES-256-GCM, key from cfg.AESKey (64-char hex). Stored as raw bytes
// in vault_secrets.encrypted_value (BYTEA). The base64 wrapper produced by
// crypto.Encrypt is decoded before insert and re-encoded for tamper checks.
//
// Isolation: every query is scoped by team_id pulled from the session JWT.
// Foreign reads return 404 — never 403 — so existence of a secret in another
// team is never observable. There is no "list all" endpoint and no value
// is ever returned by the list-keys path.
//
// Audit: every mutation (PUT/DELETE/rotate) and every successful GET writes a
// row to vault_audit_log. Audit failures are logged but never block the request.
//
// DELETE semantics: hard delete of ALL versions for (team,env,key). Chosen over
// tombstone-row to keep access checks simple and the hot table small. The audit
// log preserves the action durably.

import (
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"strings"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"instant.dev/internal/config"
	"instant.dev/internal/crypto"
	"instant.dev/internal/middleware"
	"instant.dev/internal/models"
	"instant.dev/internal/plans"
)

// vaultDefaultEnv is the env path segment treated as the default production environment.
const vaultDefaultEnv = "production"

// vaultMaxKeyLen bounds keys to a sane length. Unix env-var conventions cap at
// names of this size on most shells; matching keeps later /deploy injection sane.
const vaultMaxKeyLen = 256

// vaultMaxValueBytes caps plaintext value size pre-encryption. 1 MiB is plenty
// for typical secrets (DB URLs, API tokens, TLS bundles) without enabling abuse.
const vaultMaxValueBytes = 1 << 20 // 1 MiB

// vaultErrInternal / vaultErrInvalidBody / etc. — keep error codes as named consts
// so callers can match on them and we don't sprinkle string literals through handlers.
const (
	vaultErrInvalidBody    = "invalid_body"
	vaultErrInvalidKey     = "invalid_key"
	vaultErrInvalidEnv     = "invalid_env"
	vaultErrInvalidValue   = "invalid_value"
	vaultErrUnauthorized   = "unauthorized"
	vaultErrNotFound       = "not_found"
	vaultErrInternal       = "internal_error"
	vaultErrPersist        = "persist_failed"
	vaultErrNotAvailable   = "vault_not_available"
	vaultErrQuotaExceeded  = "vault_quota_exceeded"
	vaultErrEnvNotAllowed  = "vault_env_not_allowed"
)

// VaultHandler serves vault endpoints. All endpoints require an authenticated team.
type VaultHandler struct {
	db    *sql.DB
	cfg   *config.Config
	plans *plans.Registry
}

// NewVaultHandler constructs a VaultHandler.
func NewVaultHandler(db *sql.DB, cfg *config.Config, reg *plans.Registry) *VaultHandler {
	return &VaultHandler{db: db, cfg: cfg, plans: reg}
}

// vaultBody is the request body for PUT /api/v1/vault/:env/:key and the rotate alias.
type vaultBody struct {
	Value string `json:"value"`
}

// authContext extracts (teamID, userID, ip) from the fiber context. Returns the
// 401 response and ok=false when the team JWT is missing/malformed. Routes that
// reach this handler are already guarded by RequireAuth, so this is a sanity net.
func (h *VaultHandler) authContext(c *fiber.Ctx) (uuid.UUID, uuid.NullUUID, string, error) {
	teamIDStr := middleware.GetTeamID(c)
	teamID, err := uuid.Parse(teamIDStr)
	if err != nil {
		return uuid.Nil, uuid.NullUUID{}, "", errors.New("invalid team id in token")
	}
	var userID uuid.NullUUID
	if uidStr := middleware.GetUserID(c); uidStr != "" {
		if uid, err := uuid.Parse(uidStr); err == nil {
			userID = uuid.NullUUID{UUID: uid, Valid: true}
		}
	}
	return teamID, userID, c.IP(), nil
}

// validateEnv enforces that env is non-empty and contains only safe path-friendly chars.
// Default to "production" when callers send an empty string (matches the migration default).
func validateEnv(env string) (string, bool) {
	env = strings.TrimSpace(env)
	if env == "" {
		env = vaultDefaultEnv
	}
	if len(env) > 64 {
		return "", false
	}
	for _, r := range env {
		switch {
		case r >= 'a' && r <= 'z':
		case r >= 'A' && r <= 'Z':
		case r >= '0' && r <= '9':
		case r == '-' || r == '_':
		default:
			return "", false
		}
	}
	return env, true
}

// validateKey enforces that key is non-empty, within length, and contains only
// characters legal in env-var names plus '.' and '-' for namespacing.
func validateKey(key string) (string, bool) {
	key = strings.TrimSpace(key)
	if key == "" || len(key) > vaultMaxKeyLen {
		return "", false
	}
	for _, r := range key {
		switch {
		case r >= 'a' && r <= 'z':
		case r >= 'A' && r <= 'Z':
		case r >= '0' && r <= '9':
		case r == '_' || r == '-' || r == '.':
		default:
			return "", false
		}
	}
	return key, true
}

// encryptPlaintext returns the raw GCM ciphertext bytes (nonce||ciphertext||tag).
// The shared crypto.Encrypt helper returns a base64url string; we decode it once
// here so the at-rest representation is opaque BYTEA, not text.
func (h *VaultHandler) encryptPlaintext(plain string) ([]byte, error) {
	key, err := crypto.ParseAESKey(h.cfg.AESKey)
	if err != nil {
		return nil, err
	}
	encoded, err := crypto.Encrypt(key, plain)
	if err != nil {
		return nil, err
	}
	raw, err := base64.URLEncoding.DecodeString(encoded)
	if err != nil {
		return nil, err
	}
	return raw, nil
}

// decryptCiphertext reverses encryptPlaintext. Tamper failures (corrupted bytes,
// wrong key) surface as *crypto.ErrDecrypt — handlers map that to 500, never 200.
func (h *VaultHandler) decryptCiphertext(raw []byte) (string, error) {
	key, err := crypto.ParseAESKey(h.cfg.AESKey)
	if err != nil {
		return "", err
	}
	encoded := base64.URLEncoding.EncodeToString(raw)
	return crypto.Decrypt(key, encoded)
}

// audit appends a vault_audit_log row best-effort. Failures are logged but never
// surface to the caller — auditing must not block the request.
func (h *VaultHandler) audit(c *fiber.Ctx, teamID uuid.UUID, userID uuid.NullUUID, action, env, key, ip string) {
	if err := models.AppendVaultAudit(c.UserContext(), h.db, teamID, userID, action, env, key, ip); err != nil {
		slog.Error("vault.audit_failed",
			"error", err,
			"team_id", teamID,
			"action", action,
			"env", env,
			"key", key,
			"request_id", middleware.GetRequestID(c),
		)
	}
}

// PutSecret handles PUT /api/v1/vault/:env/:key.
// Always creates a new version. Returns 201 with {key,version}.
func (h *VaultHandler) PutSecret(c *fiber.Ctx) error {
	return h.upsertSecret(c, "set")
}

// RotateSecret handles POST /api/v1/vault/:env/:key/rotate.
// Semantics are identical to PUT — exposed under a different action name so the
// audit log distinguishes intentional rotation from a regular write.
func (h *VaultHandler) RotateSecret(c *fiber.Ctx) error {
	return h.upsertSecret(c, "rotate")
}

func (h *VaultHandler) upsertSecret(c *fiber.Ctx, action string) error {
	teamID, userID, ip, err := h.authContext(c)
	if err != nil {
		return respondError(c, fiber.StatusUnauthorized, vaultErrUnauthorized, "Valid session token required")
	}

	env, ok := validateEnv(c.Params("env"))
	if !ok {
		return respondError(c, fiber.StatusBadRequest, vaultErrInvalidEnv, "env must be 1-64 chars [A-Za-z0-9_-]")
	}
	key, ok := validateKey(c.Params("key"))
	if !ok {
		return respondError(c, fiber.StatusBadRequest, vaultErrInvalidKey, "key must be 1-256 chars [A-Za-z0-9_.-]")
	}

	var body vaultBody
	if err := c.BodyParser(&body); err != nil {
		return respondError(c, fiber.StatusBadRequest, vaultErrInvalidBody, "Request body must be valid JSON")
	}
	if len(body.Value) > vaultMaxValueBytes {
		return respondError(c, fiber.StatusRequestEntityTooLarge, vaultErrInvalidValue, "value exceeds 1 MiB cap")
	}

	// Per-tier quota + env restriction. Fetch team to read its plan tier.
	// If h.plans is nil (older test paths that haven't been updated), we fall
	// open and skip tier checks — never block on plumbing.
	if h.plans != nil {
		team, terr := models.GetTeamByID(c.Context(), h.db, teamID)
		if terr != nil {
			slog.Warn("vault.tier.team_lookup_failed",
				"error", terr, "team_id", teamID,
				"request_id", middleware.GetRequestID(c))
		} else if team != nil {
			// Tier checks run in this order (most-restrictive first) so the
			// reported error tells the caller what to upgrade:
			//   1. env allowlist (403 vault_env_not_allowed)
			//   2. quota cap     (402 vault_quota_exceeded)
			//   3. availability  (403 vault_not_available) — handled inside quota
			//
			// Pre-fix the env check ran second; a hobby-tier caller at quota
			// who PUT to staging got 402 quota_exceeded instead of 403
			// env_not_allowed — misleading, since adding seats wouldn't help.

			// Tier check 1: env restriction (applies to both PUT and rotate).
			allowed := h.plans.VaultEnvsAllowed(team.PlanTier)
			if len(allowed) > 0 {
				envOK := false
				for _, a := range allowed {
					if a == env {
						envOK = true
						break
					}
				}
				if !envOK {
					return respondError(c, fiber.StatusForbidden, vaultErrEnvNotAllowed,
						fmt.Sprintf("Plan %q only allows vault env %v; got %q. Upgrade to Pro for multi-env vault.",
							team.PlanTier, allowed, env))
				}
			}

			// Tier check 2: vault availability + quota (skip on rotate — count
			// can only stay flat or shrink).
			if action != "rotate" {
				maxEntries := h.plans.VaultMaxEntries(team.PlanTier)
				if maxEntries == 0 {
					return respondError(c, fiber.StatusForbidden, vaultErrNotAvailable,
						"Vault is not available on the "+team.PlanTier+" tier. Upgrade to Hobby or higher.")
				}
				if maxEntries > 0 {
					n, cerr := models.CountVaultKeysByTeam(c.Context(), h.db, teamID)
					if cerr != nil {
						slog.Warn("vault.put.count_failed", "error", cerr, "team_id", teamID)
					} else {
						// Allow updating an existing key (won't grow the count).
						// TODO(race): the count + insert is not transactional, so two
						// concurrent PUTs at quota-1 may both succeed and exceed the cap.
						// Accept this for now; revisit with SELECT FOR UPDATE if abuse appears.
						existing, _ := models.GetVaultSecretLatest(c.Context(), h.db, teamID, env, key)
						if existing == nil && n >= maxEntries {
							return respondError(c, fiber.StatusPaymentRequired, vaultErrQuotaExceeded,
								fmt.Sprintf("Plan %q allows %d vault entries; you have %d. Upgrade to add more.",
									team.PlanTier, maxEntries, n))
						}
					}
				}
			}
		}
	}

	ciphertext, err := h.encryptPlaintext(body.Value)
	if err != nil {
		slog.Error("vault.encrypt_failed",
			"error", err, "team_id", teamID, "env", env, "key", key,
			"request_id", middleware.GetRequestID(c))
		return respondError(c, fiber.StatusInternalServerError, vaultErrInternal, "Encryption failed")
	}

	secret, err := models.CreateVaultSecret(c.UserContext(), h.db, teamID, env, key, ciphertext, userID)
	if err != nil {
		slog.Error("vault.persist_failed",
			"error", err, "team_id", teamID, "env", env, "key", key,
			"request_id", middleware.GetRequestID(c))
		return respondError(c, fiber.StatusServiceUnavailable, vaultErrPersist, "Failed to persist secret")
	}

	h.audit(c, teamID, userID, action, env, key, ip)

	return c.Status(fiber.StatusCreated).JSON(fiber.Map{
		"ok":      true,
		"key":     secret.Key,
		"env":     secret.Env,
		"version": secret.Version,
	})
}

// GetSecret handles GET /api/v1/vault/:env/:key[?version=N].
// Cross-team or missing → 404 (never 403).
func (h *VaultHandler) GetSecret(c *fiber.Ctx) error {
	teamID, userID, ip, err := h.authContext(c)
	if err != nil {
		return respondError(c, fiber.StatusUnauthorized, vaultErrUnauthorized, "Valid session token required")
	}

	env, ok := validateEnv(c.Params("env"))
	if !ok {
		return respondError(c, fiber.StatusBadRequest, vaultErrInvalidEnv, "env must be 1-64 chars [A-Za-z0-9_-]")
	}
	key, ok := validateKey(c.Params("key"))
	if !ok {
		return respondError(c, fiber.StatusBadRequest, vaultErrInvalidKey, "key must be 1-256 chars [A-Za-z0-9_.-]")
	}

	var (
		secret *models.VaultSecret
		fetchErr error
	)
	if v := strings.TrimSpace(c.Query("version")); v != "" {
		n, perr := strconv.Atoi(v)
		if perr != nil || n <= 0 {
			return respondError(c, fiber.StatusBadRequest, vaultErrInvalidBody, "version must be a positive integer")
		}
		secret, fetchErr = models.GetVaultSecretVersion(c.UserContext(), h.db, teamID, env, key, n)
	} else {
		secret, fetchErr = models.GetVaultSecretLatest(c.UserContext(), h.db, teamID, env, key)
	}

	if errors.Is(fetchErr, models.ErrVaultSecretNotFound) {
		return respondError(c, fiber.StatusNotFound, vaultErrNotFound, "secret not found")
	}
	if fetchErr != nil {
		slog.Error("vault.fetch_failed",
			"error", fetchErr, "team_id", teamID, "env", env, "key", key,
			"request_id", middleware.GetRequestID(c))
		return respondError(c, fiber.StatusInternalServerError, vaultErrInternal, "Failed to fetch secret")
	}

	plain, err := h.decryptCiphertext(secret.EncryptedValue)
	if err != nil {
		slog.Error("vault.decrypt_failed",
			"error", err, "team_id", teamID, "env", env, "key", key,
			"request_id", middleware.GetRequestID(c))
		return respondError(c, fiber.StatusInternalServerError, vaultErrInternal, "Failed to decrypt secret")
	}

	h.audit(c, teamID, userID, "get", env, key, ip)

	return c.JSON(fiber.Map{
		"ok":      true,
		"key":     secret.Key,
		"env":     secret.Env,
		"value":   plain,
		"version": secret.Version,
	})
}

// ListKeys handles GET /api/v1/vault/:env. Returns key names only — never values.
func (h *VaultHandler) ListKeys(c *fiber.Ctx) error {
	teamID, userID, ip, err := h.authContext(c)
	if err != nil {
		return respondError(c, fiber.StatusUnauthorized, vaultErrUnauthorized, "Valid session token required")
	}

	env, ok := validateEnv(c.Params("env"))
	if !ok {
		return respondError(c, fiber.StatusBadRequest, vaultErrInvalidEnv, "env must be 1-64 chars [A-Za-z0-9_-]")
	}

	keys, err := models.ListVaultKeys(c.UserContext(), h.db, teamID, env)
	if err != nil {
		slog.Error("vault.list_failed",
			"error", err, "team_id", teamID, "env", env,
			"request_id", middleware.GetRequestID(c))
		return respondError(c, fiber.StatusInternalServerError, vaultErrInternal, "Failed to list secrets")
	}

	// Audit list ops with a synthetic key so every read leaves a trail without
	// needing to enumerate fan-out per-key.
	h.audit(c, teamID, userID, "list", env, "*", ip)

	return c.JSON(fiber.Map{
		"ok":   true,
		"env":  env,
		"keys": keys,
	})
}

// DeleteSecret handles DELETE /api/v1/vault/:env/:key.
// Hard delete of all versions for (team,env,key). 204 on success, 404 when
// the secret does not exist for this team (idempotent + non-leaking).
func (h *VaultHandler) DeleteSecret(c *fiber.Ctx) error {
	teamID, userID, ip, err := h.authContext(c)
	if err != nil {
		return respondError(c, fiber.StatusUnauthorized, vaultErrUnauthorized, "Valid session token required")
	}

	env, ok := validateEnv(c.Params("env"))
	if !ok {
		return respondError(c, fiber.StatusBadRequest, vaultErrInvalidEnv, "env must be 1-64 chars [A-Za-z0-9_-]")
	}
	key, ok := validateKey(c.Params("key"))
	if !ok {
		return respondError(c, fiber.StatusBadRequest, vaultErrInvalidKey, "key must be 1-256 chars [A-Za-z0-9_.-]")
	}

	n, err := models.DeleteVaultSecret(c.UserContext(), h.db, teamID, env, key)
	if err != nil {
		slog.Error("vault.delete_failed",
			"error", err, "team_id", teamID, "env", env, "key", key,
			"request_id", middleware.GetRequestID(c))
		return respondError(c, fiber.StatusInternalServerError, vaultErrInternal, "Failed to delete secret")
	}
	if n == 0 {
		return respondError(c, fiber.StatusNotFound, vaultErrNotFound, "secret not found")
	}

	h.audit(c, teamID, userID, "delete", env, key, ip)
	return c.SendStatus(fiber.StatusNoContent)
}
