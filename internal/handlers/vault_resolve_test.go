package handlers_test

// vault_resolve_test.go — covers handlers.ResolveVaultRefs, the helper that
// substitutes "vault://KEY" entries in deployment env_vars with decrypted
// plaintext from the team's vault.
//
// Three groups of tests:
//   - TestResolveVaultRefs_NoRefs_PassesThrough   : pure-unit, no DB
//   - TestResolveVaultRefs_EmptyKey_Errors         : pure-unit, no DB
//   - TestResolveVaultRefs_DecryptsKnownSecret     : integration, needs DB
//   - TestResolveVaultRefs_MissingKey_ReturnsError : integration, needs DB

import (
	"context"
	"encoding/base64"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/google/uuid"
	"instant.dev/internal/crypto"
	"instant.dev/internal/handlers"
	"instant.dev/internal/models"
	"instant.dev/internal/testhelpers"
)

// TestResolveVaultRefs_NoRefs_PassesThrough verifies non-prefixed values
// flow through untouched without DB access.
func TestResolveVaultRefs_NoRefs_PassesThrough(t *testing.T) {
	in := map[string]string{
		"DATABASE_URL": "postgres://u:p@host/db",
		"PORT":         "8080",
		"FEATURE_FLAG": "true",
	}
	out, err := handlers.ResolveVaultRefs(
		context.Background(),
		nil,    // db unused — no vault refs
		"",     // aes key unused — no vault refs
		uuid.New(),
		"production",
		in,
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(out) != len(in) {
		t.Fatalf("len mismatch: in=%d out=%d", len(in), len(out))
	}
	for k, v := range in {
		if out[k] != v {
			t.Errorf("key %q: want %q, got %q", k, v, out[k])
		}
	}
}

// TestResolveVaultRefs_EmptyKey_Errors verifies that "vault://" with no key
// is rejected (not silently treated as empty key).
func TestResolveVaultRefs_EmptyKey_Errors(t *testing.T) {
	in := map[string]string{"BAD": "vault://"}
	_, err := handlers.ResolveVaultRefs(
		context.Background(), nil, "",
		uuid.New(), "production", in,
	)
	if err == nil {
		t.Fatal("want error for empty vault:// key, got nil")
	}
	if !errors.Is(err, handlers.ErrVaultRefMissing) {
		t.Errorf("want ErrVaultRefMissing, got %v", err)
	}
}

// TestResolveVaultRefs_DecryptsKnownSecret seeds a vault row, calls the
// resolver, and verifies the value is replaced with the decrypted plaintext.
// Skips when TEST_DATABASE_URL is unset.
func TestResolveVaultRefs_DecryptsKnownSecret(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set — skipping integration test")
	}
	db, cleanup := testhelpers.SetupTestDB(t)
	defer cleanup()

	teamID := uuid.New()
	if _, err := db.Exec(
		`INSERT INTO teams (id, name, plan_tier) VALUES ($1, $2, 'pro')`,
		teamID, "vault-resolve-test-"+teamID.String()[:8],
	); err != nil {
		t.Fatalf("seed team: %v", err)
	}

	// Generate an AES key + encrypt a known plaintext.
	aesKeyHex := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef" // 32 bytes hex
	aesKey, err := crypto.ParseAESKey(aesKeyHex)
	if err != nil {
		t.Fatalf("ParseAESKey: %v", err)
	}
	plaintext := "sk_live_super_secret_value_xyz"
	encoded, err := crypto.Encrypt(aesKey, plaintext)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	// vault stores raw bytes — decode the base64 wrapper.
	rawBytes, err := base64.URLEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatalf("decode wrapper: %v", err)
	}

	if _, err := models.CreateVaultSecret(
		context.Background(), db, teamID,
		"production", "RAZORPAY_KEY_SECRET", rawBytes, uuid.NullUUID{},
	); err != nil {
		t.Fatalf("CreateVaultSecret: %v", err)
	}

	in := map[string]string{
		"PUBLIC_VAR":  "not-a-secret",
		"RAZORPAY_KEY":  "vault://RAZORPAY_KEY_SECRET",
	}
	out, err := handlers.ResolveVaultRefs(
		context.Background(), db, aesKeyHex, teamID, "production", in,
	)
	if err != nil {
		t.Fatalf("ResolveVaultRefs: %v", err)
	}
	if out["PUBLIC_VAR"] != "not-a-secret" {
		t.Errorf("non-vault value mutated: got %q", out["PUBLIC_VAR"])
	}
	if out["RAZORPAY_KEY"] != plaintext {
		t.Errorf("vault value not decrypted: got %q want %q", out["RAZORPAY_KEY"], plaintext)
	}

	// Audit log should record one read_for_deploy entry.
	count, err := models.CountVaultAudit(
		context.Background(), db, teamID,
		"read_for_deploy", "production", "RAZORPAY_KEY_SECRET",
	)
	if err != nil {
		t.Fatalf("CountVaultAudit: %v", err)
	}
	if count != 1 {
		t.Errorf("audit count: want 1, got %d", count)
	}
}

// TestResolveVaultRefs_MissingKey_ReturnsError verifies that referencing a
// key the team has not stored returns ErrVaultRefMissing.
func TestResolveVaultRefs_MissingKey_ReturnsError(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set — skipping integration test")
	}
	db, cleanup := testhelpers.SetupTestDB(t)
	defer cleanup()

	teamID := uuid.New()
	if _, err := db.Exec(
		`INSERT INTO teams (id, name, plan_tier) VALUES ($1, $2, 'pro')`,
		teamID, "vault-miss-test-"+teamID.String()[:8],
	); err != nil {
		t.Fatalf("seed team: %v", err)
	}

	in := map[string]string{"X": "vault://NOT_THERE"}
	_, err := handlers.ResolveVaultRefs(
		context.Background(), db,
		"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		teamID, "production", in,
	)
	if err == nil {
		t.Fatal("want error, got nil")
	}
	if !errors.Is(err, handlers.ErrVaultRefMissing) {
		t.Errorf("want ErrVaultRefMissing, got %v", err)
	}
	if !strings.Contains(err.Error(), "NOT_THERE") {
		t.Errorf("error should mention the missing key, got %v", err)
	}
}


