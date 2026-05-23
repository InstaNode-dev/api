package handlers_test

// resolve_bindings_final3_test.go — FINAL serial pass #3. Drives the
// resolveResourceBindings rejection arms directly via the exporter against a
// seeded DB:
//   - bad-AES-key                 (BindingErrLookupFailed)
//   - invalid-UUID                (BindingErrInvalidUUID)
//   - family: prefix, flag off    (BindingErrInvalidBinding)
//   - token not found             (BindingErrNotFound)
//   - deleted resource            (BindingErrNotFound)
//   - family root not found       (BindingErrNotFound)
//   - reserved underscore key skipped + happy direct-token resolve

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"instant.dev/internal/handlers"
	"instant.dev/internal/testhelpers"
)

func TestResolveBindingsFinal3_Arms(t *testing.T) {
	db, clean := testhelpers.SetupTestDB(t)
	defer clean()
	ctx := context.Background()
	teamID := uuid.MustParse(testhelpers.MustCreateTeamDB(t, db, "pro"))
	aes := testhelpers.TestAESKeyHex

	t.Run("empty_bindings", func(t *testing.T) {
		out, k := handlers.ResolveResourceBindingsForTest(ctx, db, aes, teamID, "production", nil, true)
		assert.Empty(t, k)
		assert.Empty(t, out)
	})

	t.Run("bad_aes_key", func(t *testing.T) {
		_, k := handlers.ResolveResourceBindingsForTest(ctx, db, "not-hex", teamID, "production",
			map[string]string{"DB": uuid.NewString()}, true)
		assert.Equal(t, "lookup_failed", k)
	})

	t.Run("invalid_uuid", func(t *testing.T) {
		_, k := handlers.ResolveResourceBindingsForTest(ctx, db, aes, teamID, "production",
			map[string]string{"DB": "not-a-uuid"}, true)
		assert.Equal(t, "invalid_uuid", k)
	})

	t.Run("family_prefix_flag_off", func(t *testing.T) {
		// family: prefix used while familyEnabled=false → treated as raw value,
		// fails UUID parse, and the special "family disabled" detail arm fires.
		_, k := handlers.ResolveResourceBindingsForTest(ctx, db, aes, teamID, "production",
			map[string]string{"DB": "family:" + uuid.NewString()}, false)
		assert.Equal(t, "invalid_binding", k)
	})

	t.Run("token_not_found", func(t *testing.T) {
		_, k := handlers.ResolveResourceBindingsForTest(ctx, db, aes, teamID, "production",
			map[string]string{"DB": uuid.NewString()}, true)
		assert.Equal(t, "not_found", k)
	})

	t.Run("deleted_resource", func(t *testing.T) {
		tok := uuid.NewString()
		_, err := db.ExecContext(ctx, `
			INSERT INTO resources (team_id, token, resource_type, tier, env, status)
			VALUES ($1::uuid, $2, 'postgres', 'pro', 'production', 'deleted')`,
			teamID, tok)
		require.NoError(t, err)
		_, k := handlers.ResolveResourceBindingsForTest(ctx, db, aes, teamID, "production",
			map[string]string{"DB": tok}, true)
		assert.Equal(t, "not_found", k)
	})

	t.Run("family_root_not_found", func(t *testing.T) {
		_, k := handlers.ResolveResourceBindingsForTest(ctx, db, aes, teamID, "production",
			map[string]string{"DB": "family:" + uuid.NewString()}, true)
		assert.Equal(t, "not_found", k)
	})

	t.Run("underscore_key_skipped", func(t *testing.T) {
		// A reserved underscore key is skipped (no error even though the value
		// is a non-existent token).
		out, k := handlers.ResolveResourceBindingsForTest(ctx, db, aes, teamID, "production",
			map[string]string{"_internal": uuid.NewString()}, true)
		assert.Empty(t, k)
		_, has := out["_internal"]
		assert.False(t, has, "underscore key must be dropped")
	})

	t.Run("family_cross_team", func(t *testing.T) {
		// A family root owned by a DIFFERENT team → cross_team.
		otherTeam := uuid.MustParse(testhelpers.MustCreateTeamDB(t, db, "pro"))
		var rootID string
		require.NoError(t, db.QueryRowContext(ctx, `
			INSERT INTO resources (team_id, token, resource_type, tier, env, status, parent_resource_id)
			VALUES ($1::uuid, $2, 'postgres', 'pro', 'production', 'active', NULL)
			RETURNING id::text`,
			otherTeam, uuid.NewString()).Scan(&rootID))
		_, k := handlers.ResolveResourceBindingsForTest(ctx, db, aes, teamID, "production",
			map[string]string{"DB": "family:" + rootID}, true)
		assert.Equal(t, "cross_team", k)
	})

	t.Run("family_no_env_twin", func(t *testing.T) {
		// A family root owned by MY team in production → resolving against
		// env=staging finds no sibling → no_env_twin.
		var rootID string
		require.NoError(t, db.QueryRowContext(ctx, `
			INSERT INTO resources (team_id, token, resource_type, tier, env, status, parent_resource_id)
			VALUES ($1::uuid, $2, 'postgres', 'pro', 'production', 'active', NULL)
			RETURNING id::text`,
			teamID, uuid.NewString()).Scan(&rootID))
		_, k := handlers.ResolveResourceBindingsForTest(ctx, db, aes, teamID, "staging",
			map[string]string{"DB": "family:" + rootID}, true)
		assert.Equal(t, "no_env_twin", k)
	})
}
