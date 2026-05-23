package handlers_test

// team_members_arms_final3_test.go — FINAL serial pass #3. Drives the
// best-effort helper arms of TeamMembersHandler:
//   - cacheInviteResponse: nil-rdb early return + dead-rdb Set-error
//   - emitInviteAudit: audit-insert error (fault DB)

import (
	"context"
	"testing"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"

	"instant.dev/internal/config"
	"instant.dev/internal/email"
	"instant.dev/internal/handlers"
	"instant.dev/internal/plans"
	"instant.dev/internal/testhelpers"
)

func TestTeamMembersFinal3_CacheInviteResponse_Arms(t *testing.T) {
	cfg := &config.Config{JWTSecret: testhelpers.TestJWTSecret}
	teamID := uuid.New()
	body := fiber.Map{"ok": true}

	// nil rdb → early return (team_members.go:395-396).
	hNil := handlers.NewTeamMembersHandler(nil, cfg, plans.Default(), email.NewNoop(), nil)
	hNil.CacheInviteResponseForTest(context.Background(), teamID, "idem-key", 200, body)

	// empty key → early return.
	hNil.CacheInviteResponseForTest(context.Background(), teamID, "", 200, body)

	// dead rdb → Set errors (team_members.go:410 store-error arm).
	deadRdb := redis.NewClient(&redis.Options{Addr: "127.0.0.1:1", DialTimeout: 200 * time.Millisecond})
	t.Cleanup(func() { deadRdb.Close() })
	hDead := handlers.NewTeamMembersHandler(nil, cfg, plans.Default(), email.NewNoop(), deadRdb)
	hDead.CacheInviteResponseForTest(context.Background(), teamID, "idem-key", 200, body)
}

func TestTeamMembersFinal3_EmitInviteAudit_InsertError(t *testing.T) {
	cfg := &config.Config{JWTSecret: testhelpers.TestJWTSecret}
	// Fault DB: the audit INSERT errors → the best-effort warn arm
	// (team_members.go:429) runs without surfacing to the caller.
	faultDB := openFaultDB(t, 0)
	h := handlers.NewTeamMembersHandler(faultDB, cfg, plans.Default(), email.NewNoop(), nil)
	h.EmitInviteAuditForTest(context.Background(), uuid.New(), uuid.New(), uuid.New(),
		"invitee@example.com", "member")
}
