package handlers

import (
	"context"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"strings"

	"github.com/google/uuid"
	"instant.dev/internal/crypto"
	"instant.dev/internal/models"
)

// vaultRefPrefix is the syntax used in deployment env_vars to reference a
// vault secret. Values starting with this prefix are resolved at deploy time
// against vault_secrets for the team's current environment.
//
//	{ "RAZORPAY_KEY_SECRET": "vault://RAZORPAY_KEY_SECRET" }
//
// At deploy time, the value is replaced with the latest version of the named
// secret. Plaintext is never written to deployments.env_vars or any log.
const vaultRefPrefix = "vault://"

// ErrVaultRefMissing is returned when a deployment references a vault key
// that does not exist for the team in the requested environment.
var ErrVaultRefMissing = errors.New("vault reference not found")

// ResolveVaultRefs replaces every "vault://KEY" value in vars with the
// decrypted plaintext from the team's vault for the given environment.
// Non-prefixed values are passed through unchanged.
//
// The returned map is a fresh allocation; the input map is not mutated.
//
// Each resolved key is appended to vault_audit_log with action
// "read_for_deploy" — best-effort, audit failure does not block the deploy.
//
// If any reference cannot be resolved (key missing, ciphertext tampered),
// returns ErrVaultRefMissing wrapping the underlying cause. The caller
// fails the deploy with a clear error so the user knows which secret to add.
func ResolveVaultRefs(
	ctx context.Context,
	db *sql.DB,
	aesKeyHex string,
	teamID uuid.UUID,
	env string,
	vars map[string]string,
) (map[string]string, error) {
	out := make(map[string]string, len(vars))
	var aesKey []byte
	var aesKeyErr error

	for k, v := range vars {
		if !strings.HasPrefix(v, vaultRefPrefix) {
			out[k] = v
			continue
		}
		secretKey := strings.TrimPrefix(v, vaultRefPrefix)
		if secretKey == "" {
			return nil, fmt.Errorf("%w: empty key in vault://", ErrVaultRefMissing)
		}

		// Lazy-parse the AES key once per call (only when we actually have refs).
		if aesKey == nil && aesKeyErr == nil {
			aesKey, aesKeyErr = crypto.ParseAESKey(aesKeyHex)
		}
		if aesKeyErr != nil {
			return nil, fmt.Errorf("vault resolve: %w", aesKeyErr)
		}

		row, err := models.GetVaultSecretLatest(ctx, db, teamID, env, secretKey)
		if err != nil {
			if errors.Is(err, models.ErrVaultSecretNotFound) {
				return nil, fmt.Errorf("%w: %s/%s", ErrVaultRefMissing, env, secretKey)
			}
			return nil, fmt.Errorf("vault resolve %s: %w", secretKey, err)
		}

		encoded := base64.URLEncoding.EncodeToString(row.EncryptedValue)
		plain, err := crypto.Decrypt(aesKey, encoded)
		if err != nil {
			return nil, fmt.Errorf("vault decrypt %s: %w", secretKey, err)
		}
		out[k] = plain

		// Best-effort audit. Failures logged but never block.
		if auditErr := models.AppendVaultAudit(ctx, db, teamID, uuid.NullUUID{}, "read_for_deploy", env, secretKey, ""); auditErr != nil {
			slog.Warn("vault.audit_failed",
				"action", "read_for_deploy",
				"team_id", teamID, "env", env, "key", secretKey,
				"error", auditErr)
		}
	}

	return out, nil
}
