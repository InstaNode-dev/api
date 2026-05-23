package handlers_test

// helper_branches_provarms_test.go — pins the remaining error / edge branches
// of the shared provisioning helpers + bulk-twin internals that the HTTP-level
// suites don't reach:
//   - requireName: empty / too-long / bad-format / control-char-normalisation
//   - checkProvisionLimit + markRecycleSeen + recycleSeen: Redis-error + empty-fp
//   - findParents: paused-skip / wrong-type-skip / already-a-twin-skip
//   - resolveHeadroom: nil-hook default + negative clamp
//   - NewBulkTwinHandler: nil sub-handler panic guard

import (
	"context"
	"database/sql"
	"strings"
	"testing"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/valyala/fasthttp"

	"instant.dev/internal/config"
	"instant.dev/internal/handlers"
	"instant.dev/internal/models"
	"instant.dev/internal/plans"
	"instant.dev/internal/testhelpers"
)

func freshCtx(t *testing.T) (*fiber.Ctx, func()) {
	t.Helper()
	app := fiber.New()
	c := app.AcquireCtx(&fasthttp.RequestCtx{})
	return c, func() { app.ReleaseCtx(c) }
}

func TestRequireName_Branches(t *testing.T) {
	// empty → name_required
	c, rel := freshCtx(t)
	_, err := handlers.RequireNameForTest(c, "")
	assert.Error(t, err)
	assert.Equal(t, fiber.StatusBadRequest, c.Response().StatusCode())
	rel()

	// too long (>64 runes) → invalid_name
	c, rel = freshCtx(t)
	_, err = handlers.RequireNameForTest(c, strings.Repeat("a", 65))
	assert.Error(t, err)
	assert.Equal(t, fiber.StatusBadRequest, c.Response().StatusCode())
	rel()

	// bad format (starts with a dash / illegal chars) → invalid_name
	c, rel = freshCtx(t)
	_, err = handlers.RequireNameForTest(c, "-bad@name")
	assert.Error(t, err)
	assert.Equal(t, fiber.StatusBadRequest, c.Response().StatusCode())
	rel()

	// control-char normalisation: stripped → valid name + X-Instant-Notice header
	c, rel = freshCtx(t)
	got, err := handlers.RequireNameForTest(c, "good\rname")
	require.NoError(t, err)
	assert.Equal(t, "goodname", got)
	assert.NotEmpty(t, string(c.Response().Header.Peek("X-Instant-Notice")),
		"normalisation must surface a notice header")
	rel()

	// clean name → returned trimmed
	c, rel = freshCtx(t)
	got, err = handlers.RequireNameForTest(c, "  My DB  ")
	require.NoError(t, err)
	assert.Equal(t, "My DB", got)
	rel()
}

// closedRedis returns a redis client whose connection is closed so every
// command errors — drives the fail-open Redis-error branches.
func closedRedis(t *testing.T) *redis.Client {
	t.Helper()
	rdb := redis.NewClient(&redis.Options{Addr: "127.0.0.1:6379"})
	require.NoError(t, rdb.Close())
	return rdb
}

func TestCheckProvisionLimit_RedisError_FailsOpen(t *testing.T) {
	cfg := &config.Config{AESKey: testhelpers.TestAESKeyHex, EnabledServices: "postgres"}
	h := handlers.NewDBHandler(nil, closedRedis(t), cfg, nil, plans.Default())
	exceeded, err := h.CheckProvisionLimitForTest(context.Background(), "fp-x")
	require.Error(t, err, "closed redis must surface an error")
	assert.False(t, exceeded, "fail-open: never report over-cap on a redis error")
}

func TestMarkRecycleSeen_EmptyFP_NoOp(t *testing.T) {
	cfg := &config.Config{AESKey: testhelpers.TestAESKeyHex, EnabledServices: "postgres"}
	h := handlers.NewDBHandler(nil, closedRedis(t), cfg, nil, plans.Default())
	// empty fp → early return nil (never touches redis).
	assert.NoError(t, h.MarkRecycleSeenForTest(context.Background(), ""))
	// non-empty fp on a closed redis → error surfaced.
	assert.Error(t, h.MarkRecycleSeenForTest(context.Background(), "fp-x"))
}

func TestRecycleSeen_EmptyAndError(t *testing.T) {
	cfg := &config.Config{AESKey: testhelpers.TestAESKeyHex, EnabledServices: "postgres"}
	h := handlers.NewDBHandler(nil, closedRedis(t), cfg, nil, plans.Default())
	seen, err := h.RecycleSeenForTest(context.Background(), "")
	assert.NoError(t, err)
	assert.False(t, seen)
	_, err = h.RecycleSeenForTest(context.Background(), "fp-x")
	assert.Error(t, err)
}

func TestNewBulkTwinHandler_NilHandlers_Panics(t *testing.T) {
	assert.Panics(t, func() {
		handlers.NewBulkTwinHandlerPanicsForTest(nil, plans.Default())
	})
}

func TestResolveHeadroom_DefaultAndClamp(t *testing.T) {
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()
	cfg := &config.Config{AESKey: testhelpers.TestAESKeyHex, EnabledServices: "postgres,redis,mongodb"}
	reg := plans.Default()
	dbH := handlers.NewDBHandler(db, rdb, cfg, nil, reg)
	cacheH := handlers.NewCacheHandler(db, rdb, cfg, nil, reg)
	nosqlH := handlers.NewNoSQLHandler(db, rdb, cfg, nil, reg)
	bt := handlers.NewBulkTwinHandler(db, dbH, cacheH, nosqlH, reg)

	tid := uuid.New()
	// nil hook → default large headroom.
	assert.Positive(t, bt.ResolveHeadroomForTest(context.Background(), tid, "postgres"))

	// negative hook → clamped to 0.
	bt.QuotaHeadroom = func(_ context.Context, _ uuid.UUID, _ string) int { return -5 }
	assert.Equal(t, 0, bt.ResolveHeadroomForTest(context.Background(), tid, "postgres"))

	// positive hook → returned as-is.
	bt.QuotaHeadroom = func(_ context.Context, _ uuid.UUID, _ string) int { return 3 }
	assert.Equal(t, 3, bt.ResolveHeadroomForTest(context.Background(), tid, "postgres"))
}

func TestFindParents_SkipFilters(t *testing.T) {
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()
	cfg := &config.Config{AESKey: testhelpers.TestAESKeyHex, EnabledServices: "postgres,redis,mongodb"}
	reg := plans.Default()
	dbH := handlers.NewDBHandler(db, rdb, cfg, nil, reg)
	cacheH := handlers.NewCacheHandler(db, rdb, cfg, nil, reg)
	nosqlH := handlers.NewNoSQLHandler(db, rdb, cfg, nil, reg)
	bt := handlers.NewBulkTwinHandler(db, dbH, cacheH, nosqlH, reg)

	teamID := testhelpers.MustCreateTeamDB(t, db, "pro")
	tUUID := uuid.MustParse(teamID)

	// (a) a healthy postgres root in production → eligible
	rootID := insertRes(t, db, teamID, "postgres", "production", "active", nil)
	// (b) a paused postgres root → skipped by IsActive filter
	insertRes(t, db, teamID, "postgres", "production", "paused", nil)
	// (c) a redis root → skipped when filter is postgres-only
	insertRes(t, db, teamID, "redis", "production", "active", nil)
	// (d) an already-a-twin postgres child (parent set) → skipped (not a root)
	insertRes(t, db, teamID, "postgres", "production", "active", &rootID)

	filter := map[string]struct{}{"postgres": {}}
	parents, err := bt.FindParentsForTest(context.Background(), tUUID, "production", filter)
	require.NoError(t, err)
	// Only the single healthy postgres ROOT (a) is eligible.
	require.Len(t, parents, 1)
	assert.Equal(t, "postgres", parents[0].ResourceType)
	_ = models.ResourceTypePostgres
}

// insertRes inserts a resource and returns its id (string).
func insertRes(t *testing.T, db *sql.DB, teamID, rtype, env, status string, parentRootID *string) string {
	t.Helper()
	var id string
	if parentRootID == nil {
		require.NoError(t, db.QueryRowContext(context.Background(), `
			INSERT INTO resources (team_id, resource_type, tier, env, status)
			VALUES ($1::uuid, $2, 'pro', $3, $4) RETURNING id::text
		`, teamID, rtype, env, status).Scan(&id))
	} else {
		require.NoError(t, db.QueryRowContext(context.Background(), `
			INSERT INTO resources (team_id, resource_type, tier, env, status, parent_resource_id)
			VALUES ($1::uuid, $2, 'pro', $3, $4, $5::uuid) RETURNING id::text
		`, teamID, rtype, env, status, *parentRootID).Scan(&id))
	}
	return id
}