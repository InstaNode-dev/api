package handlers_test

// stack_promote_vault_test.go — Slice 5 of env-aware deployments.
//
// Covers the auto-copy of vault refs on POST /api/v1/stacks/:slug/promote:
//   - default (copy_vault omitted) copies every source-only key into the target
//   - copy_vault=false leaves the target vault untouched
//   - keys that already exist in the target are skipped (non-destructive)
//   - no source keys → no-op, no audit rows
//
// All four cases assert on both the vault_secrets table and audit_log so a
// regression in either the copy or the attribution shows up.

import (
	"context"
	"net/http"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"instant.dev/internal/models"
	"instant.dev/internal/testhelpers"
)

const (
	promoteVaultEnvSource = "staging"
	// Target is the dev env so the migration-026 email-link approval gate
	// is bypassed (dev-env promotes execute immediately). Auto-copy vault
	// behaviour is the contract under test here — non-dev approval flow
	// has its own coverage in promote_approval_test.go.
	promoteVaultEnvTarget = "development"
)

func TestStackPromote_AutoCopiesVaultRefs_Default(t *testing.T) {
	requireTestDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	ensureStackTables(t, db)

	teamID := testhelpers.MustCreateTeamDB(t, db, "pro")
	teamUUID := uuid.MustParse(teamID)
	sessionJWT := testhelpers.MustSignSessionJWT(t, "u-promote-vault-1", teamID, "v1@example.com")

	// Seed three keys in staging, zero in production.
	for _, k := range []string{"DB_PASSWORD", "STRIPE_KEY", "OPENAI_KEY"} {
		_, err := models.CreateVaultSecret(
			context.Background(), db, teamUUID,
			promoteVaultEnvSource, k, []byte("ciphertext-for-"+k), uuid.NullUUID{},
		)
		require.NoError(t, err, "seed source key %s", k)
	}

	srcSlug, _ := seedPromoteSourceStack(t, db, teamID, promoteVaultEnvSource, "demo-vault-default")
	app := newStackTestApp(t, db)

	// copy_vault omitted → default (true).
	resp := postPromote(t, app, sessionJWT, srcSlug, map[string]any{
		"from": promoteVaultEnvSource, "to": promoteVaultEnvTarget,
	})
	defer resp.Body.Close()
	require.Equal(t, http.StatusAccepted, resp.StatusCode)

	// All three keys must now exist in production.
	var n int
	require.NoError(t, db.QueryRowContext(context.Background(),
		`SELECT count(DISTINCT key) FROM vault_secrets WHERE team_id = $1 AND env = $2`,
		teamID, promoteVaultEnvTarget,
	).Scan(&n))
	assert.Equal(t, 3, n, "all three source keys must be copied to target env on default promote")

	// audit_log should carry three vault.promoted rows.
	var audited int
	require.NoError(t, db.QueryRowContext(context.Background(),
		`SELECT count(*) FROM audit_log WHERE team_id = $1 AND kind = 'vault.promoted'`,
		teamID,
	).Scan(&audited))
	assert.Equal(t, 3, audited, "one audit_log row per copied key")
}

func TestStackPromote_CopyVaultFalse_LeavesTargetUntouched(t *testing.T) {
	requireTestDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	ensureStackTables(t, db)

	teamID := testhelpers.MustCreateTeamDB(t, db, "pro")
	teamUUID := uuid.MustParse(teamID)
	sessionJWT := testhelpers.MustSignSessionJWT(t, "u-promote-vault-2", teamID, "v2@example.com")

	for _, k := range []string{"DB_PASSWORD", "STRIPE_KEY"} {
		_, err := models.CreateVaultSecret(
			context.Background(), db, teamUUID,
			promoteVaultEnvSource, k, []byte("ct"), uuid.NullUUID{},
		)
		require.NoError(t, err)
	}

	srcSlug, _ := seedPromoteSourceStack(t, db, teamID, promoteVaultEnvSource, "demo-vault-optout")
	app := newStackTestApp(t, db)

	resp := postPromote(t, app, sessionJWT, srcSlug, map[string]any{
		"from": promoteVaultEnvSource, "to": promoteVaultEnvTarget,
		"copy_vault": false,
	})
	defer resp.Body.Close()
	require.Equal(t, http.StatusAccepted, resp.StatusCode)

	var n int
	require.NoError(t, db.QueryRowContext(context.Background(),
		`SELECT count(*) FROM vault_secrets WHERE team_id = $1 AND env = $2`,
		teamID, promoteVaultEnvTarget,
	).Scan(&n))
	assert.Equal(t, 0, n, "copy_vault=false must not copy anything")

	var audited int
	require.NoError(t, db.QueryRowContext(context.Background(),
		`SELECT count(*) FROM audit_log WHERE team_id = $1 AND kind = 'vault.promoted'`,
		teamID,
	).Scan(&audited))
	assert.Equal(t, 0, audited, "no audit rows when copy_vault=false")
}

func TestStackPromote_AutoCopyIsNonDestructive(t *testing.T) {
	requireTestDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	ensureStackTables(t, db)

	teamID := testhelpers.MustCreateTeamDB(t, db, "pro")
	teamUUID := uuid.MustParse(teamID)
	sessionJWT := testhelpers.MustSignSessionJWT(t, "u-promote-vault-3", teamID, "v3@example.com")

	// Two keys in source; the second key already exists in target with a
	// different value — production must win.
	for _, k := range []string{"SHARED_KEY", "STAGING_ONLY"} {
		_, err := models.CreateVaultSecret(
			context.Background(), db, teamUUID,
			promoteVaultEnvSource, k, []byte("staging-value-"+k), uuid.NullUUID{},
		)
		require.NoError(t, err)
	}
	_, err := models.CreateVaultSecret(
		context.Background(), db, teamUUID,
		promoteVaultEnvTarget, "SHARED_KEY", []byte("prod-value-keep-me"), uuid.NullUUID{},
	)
	require.NoError(t, err)

	srcSlug, _ := seedPromoteSourceStack(t, db, teamID, promoteVaultEnvSource, "demo-vault-non-destructive")
	app := newStackTestApp(t, db)

	resp := postPromote(t, app, sessionJWT, srcSlug, map[string]any{
		"from": promoteVaultEnvSource, "to": promoteVaultEnvTarget,
	})
	defer resp.Body.Close()
	require.Equal(t, http.StatusAccepted, resp.StatusCode)

	// Target now has both keys.
	var distinctKeys int
	require.NoError(t, db.QueryRowContext(context.Background(),
		`SELECT count(DISTINCT key) FROM vault_secrets WHERE team_id = $1 AND env = $2`,
		teamID, promoteVaultEnvTarget,
	).Scan(&distinctKeys))
	assert.Equal(t, 2, distinctKeys, "STAGING_ONLY copied + SHARED_KEY already present")

	// SHARED_KEY's latest target value must still be the prod-pinned one.
	var encVal []byte
	require.NoError(t, db.QueryRowContext(context.Background(),
		`SELECT encrypted_value FROM vault_secrets
		 WHERE team_id = $1 AND env = $2 AND key = 'SHARED_KEY'
		 ORDER BY version DESC LIMIT 1`,
		teamID, promoteVaultEnvTarget,
	).Scan(&encVal))
	assert.Equal(t, []byte("prod-value-keep-me"), encVal,
		"existing target value must win — copy is non-destructive")

	// Only one audit row: STAGING_ONLY was the only key actually copied.
	var audited int
	require.NoError(t, db.QueryRowContext(context.Background(),
		`SELECT count(*) FROM audit_log WHERE team_id = $1 AND kind = 'vault.promoted'`,
		teamID,
	).Scan(&audited))
	assert.Equal(t, 1, audited, "exactly one audit row — only STAGING_ONLY was copied")
}

func TestStackPromote_AutoCopy_NoSourceKeys_IsNoOp(t *testing.T) {
	requireTestDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	ensureStackTables(t, db)

	teamID := testhelpers.MustCreateTeamDB(t, db, "pro")
	sessionJWT := testhelpers.MustSignSessionJWT(t, "u-promote-vault-4", teamID, "v4@example.com")

	// No vault rows seeded — the source env has nothing to copy.
	srcSlug, _ := seedPromoteSourceStack(t, db, teamID, promoteVaultEnvSource, "demo-vault-noop")
	app := newStackTestApp(t, db)

	resp := postPromote(t, app, sessionJWT, srcSlug, map[string]any{
		"from": promoteVaultEnvSource, "to": promoteVaultEnvTarget,
	})
	defer resp.Body.Close()
	require.Equal(t, http.StatusAccepted, resp.StatusCode,
		"empty source vault must not break promote")

	var audited int
	require.NoError(t, db.QueryRowContext(context.Background(),
		`SELECT count(*) FROM audit_log WHERE team_id = $1 AND kind = 'vault.promoted'`,
		teamID,
	).Scan(&audited))
	assert.Equal(t, 0, audited, "no audit rows when source vault is empty")
}
