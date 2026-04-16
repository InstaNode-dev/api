//go:build e2e

// Persona H — The Sample Application Developer
//
// Simulates complete mini-applications that integrate with instant.dev services,
// verifying the full "vibe-code → working app" experience:
//
//   H1: Todo app — creates table, inserts, queries, deletes via Postgres
//   H2: Rate limiter — SET/GET/INCR/EXPIRE pattern via Redis
//   H3: Event log — insert/find/delete via MongoDB
//   H4: Full-stack startup sequence — DB + cache + nosql claimed as one team
//
// Requires real driver connections for H1-H3; skips if the service returns 503.
// No optional env vars required for H1-H4. H5 requires E2E_JWT_SECRET.
package e2e

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	goredis "github.com/redis/go-redis/v9"
	"go.mongodb.org/mongo-driver/bson"
	gomongo "go.mongodb.org/mongo-driver/mongo"
	mongoopts "go.mongodb.org/mongo-driver/mongo/options"
)

// ── H1: Todo app — full Postgres CRUD via provisioned URL ────────────────────

func TestE2E_SampleApp_TodoApp_PostgresCRUD(t *testing.T) {
	if os.Getenv("E2E_PG_HOST") == "" {
		t.Skip("E2E_PG_HOST not set — needs kubectl port-forward -n instant-data svc/postgres-customers 5435:5432")
	}
	ip := uniqueIP(t)
	db := provisionDB(t, ip)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	conn, err := pgx.Connect(ctx, localURL(db.ConnectionURL))
	if err != nil {
		t.Fatalf("pgx.Connect: %v", err)
	}
	defer conn.Close(ctx)

	table := "todos_" + strings.ReplaceAll(uuid.NewString()[:8], "-", "_")

	// Create table.
	_, err = conn.Exec(ctx, fmt.Sprintf(`
		CREATE TABLE %s (
			id   SERIAL PRIMARY KEY,
			task TEXT NOT NULL,
			done BOOLEAN DEFAULT FALSE
		)`, table))
	if err != nil {
		t.Fatalf("CREATE TABLE: %v", err)
	}

	// Insert 3 todos.
	tasks := []string{"provision infra", "write app", "ship it"}
	for _, task := range tasks {
		if _, err := conn.Exec(ctx,
			fmt.Sprintf("INSERT INTO %s (task) VALUES ($1)", table), task,
		); err != nil {
			t.Fatalf("INSERT %q: %v", task, err)
		}
	}

	// Count them.
	var count int
	if err := conn.QueryRow(ctx,
		fmt.Sprintf("SELECT count(*) FROM %s", table),
	).Scan(&count); err != nil {
		t.Fatalf("SELECT count: %v", err)
	}
	if count != 3 {
		t.Errorf("expected 3 todos, got %d", count)
	}

	// Mark one done.
	if _, err := conn.Exec(ctx,
		fmt.Sprintf("UPDATE %s SET done=true WHERE task=$1", table), "ship it",
	); err != nil {
		t.Fatalf("UPDATE: %v", err)
	}

	// Query done.
	var doneTask string
	if err := conn.QueryRow(ctx,
		fmt.Sprintf("SELECT task FROM %s WHERE done=true LIMIT 1", table),
	).Scan(&doneTask); err != nil {
		t.Fatalf("SELECT done: %v", err)
	}
	if doneTask != "ship it" {
		t.Errorf("expected done task 'ship it', got %q", doneTask)
	}

	// Delete and verify empty.
	if _, err := conn.Exec(ctx, fmt.Sprintf("DELETE FROM %s", table)); err != nil {
		t.Fatalf("DELETE: %v", err)
	}
	if err := conn.QueryRow(ctx,
		fmt.Sprintf("SELECT count(*) FROM %s", table),
	).Scan(&count); err != nil {
		t.Fatalf("SELECT after DELETE: %v", err)
	}
	if count != 0 {
		t.Errorf("expected 0 todos after DELETE, got %d", count)
	}

	conn.Exec(ctx, fmt.Sprintf("DROP TABLE %s", table))
}

// ── H2: Rate limiter — Redis INCR/EXPIRE pattern ─────────────────────────────

func TestE2E_SampleApp_RateLimiter_RedisIncrExpire(t *testing.T) {
	if os.Getenv("E2E_REDIS_HOST") == "" {
		t.Skip("E2E_REDIS_HOST not set — needs kubectl port-forward -n instant-data svc/redis-provision 6380:6379")
	}
	ip := uniqueIP(t)
	cache := provisionCache(t, ip)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	opts, err := goredis.ParseURL(localURL(cache.ConnectionURL))
	if err != nil {
		t.Fatalf("parse redis URL: %v", err)
	}
	rdb := goredis.NewClient(opts)
	defer rdb.Close()

	// Redis ACL restricts this user to the provisioned key prefix namespace.
	// Simulate a rate limiter: key = "<prefix>rl:<user>:<date>", limit = 5 requests.
	key := cache.redisKeyPrefix() + "rl:user-" + uuid.NewString()[:8] + ":2026-04-09"

	for i := 1; i <= 5; i++ {
		count, err := rdb.Incr(ctx, key).Result()
		if err != nil {
			t.Fatalf("INCR (request %d): %v", i, err)
		}
		if i == 1 {
			// Set TTL on first increment.
			if err := rdb.Expire(ctx, key, 25*time.Hour).Err(); err != nil {
				t.Fatalf("EXPIRE: %v", err)
			}
		}
		if count != int64(i) {
			t.Errorf("INCR %d: expected count=%d, got %d", i, i, count)
		}
	}

	// 6th request should be "rate limited" (count > 5).
	count, err := rdb.Incr(ctx, key).Result()
	if err != nil {
		t.Fatalf("INCR (request 6): %v", err)
	}
	if count <= 5 {
		t.Errorf("expected count > 5 after 6 increments, got %d", count)
	}

	// Verify TTL is set (non-negative).
	ttl, err := rdb.TTL(ctx, key).Result()
	if err != nil {
		t.Fatalf("TTL: %v", err)
	}
	if ttl <= 0 {
		t.Errorf("expected positive TTL, got %v", ttl)
	}

	rdb.Del(ctx, key)
}

// ── H3: Event log — MongoDB insert/query/delete ───────────────────────────────

func TestE2E_SampleApp_EventLog_MongoCRUD(t *testing.T) {
	if os.Getenv("E2E_MONGO_HOST") == "" {
		t.Skip("E2E_MONGO_HOST not set — needs kubectl port-forward -n instant-data svc/mongodb 27018:27017")
	}
	ip := uniqueIP(t)
	nosql := provisionNoSQL(t, ip)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	clientOpts := mongoopts.Client().ApplyURI(localURL(nosql.ConnectionURL)).
		SetConnectTimeout(10 * time.Second).
		SetServerSelectionTimeout(10 * time.Second)

	mc, err := gomongo.Connect(ctx, clientOpts)
	if err != nil {
		t.Fatalf("mongo.Connect: %v", err)
	}
	defer mc.Disconnect(ctx)

	if err := mc.Ping(ctx, nil); err != nil {
		t.Fatalf("mongo.Ping: %v", err)
	}

	col := mc.Database(mongoDBName(nosql.ConnectionURL)).Collection("events")

	// Insert 3 events.
	events := []bson.M{
		{"_id": uuid.NewString(), "type": "user.signup", "user": "alice", "ts": time.Now()},
		{"_id": uuid.NewString(), "type": "item.purchase", "user": "alice", "ts": time.Now()},
		{"_id": uuid.NewString(), "type": "user.logout", "user": "alice", "ts": time.Now()},
	}
	for _, ev := range events {
		if _, err := col.InsertOne(ctx, ev); err != nil {
			t.Fatalf("InsertOne %v: %v", ev["type"], err)
		}
	}

	// Query events for alice.
	cursor, err := col.Find(ctx, bson.M{"user": "alice"})
	if err != nil {
		t.Fatalf("Find: %v", err)
	}
	var results []bson.M
	if err := cursor.All(ctx, &results); err != nil {
		t.Fatalf("cursor.All: %v", err)
	}
	if len(results) != 3 {
		t.Errorf("expected 3 events, got %d", len(results))
	}

	// Delete all.
	delResult, err := col.DeleteMany(ctx, bson.M{"user": "alice"})
	if err != nil {
		t.Fatalf("DeleteMany: %v", err)
	}
	if delResult.DeletedCount != 3 {
		t.Errorf("expected 3 deleted, got %d", delResult.DeletedCount)
	}
}

// ── H4: Full-stack startup — DB + cache + nosql claimed as one team ──────────

func TestE2E_SampleApp_FullStackStartup_ClaimAllServices(t *testing.T) {
	ip := uniqueIP(t)

	// Provision all three data services.
	db := provisionDB(t, ip)
	cache := provisionCache(t, ip)
	nosql := provisionNoSQL(t, ip)

	// Use the cache's JWT — it bundles all resources from this fingerprint.
	jwt := extractJWTFromNote(t, cache.Note)
	email := uniqueEmail()
	teamName := "e2e-startup-" + uuid.NewString()[:6]

	claimResp := post(t, "/claim", map[string]any{
		"jwt":       jwt,
		"email":     email,
		"team_name": teamName,
	})
	if claimResp.StatusCode != 201 {
		t.Fatalf("POST /claim: want 201, got %d\n%s", claimResp.StatusCode, readBody(t, claimResp))
	}
	var claim claimResponse
	decodeJSON(t, claimResp, &claim)

	sessionJWT := makeSessionJWTWithUser(t, claim.UserID, claim.TeamID, email)

	// Resource list must contain all 3 service tokens.
	listResp := get(t, "/api/v1/resources", "Authorization", "Bearer "+sessionJWT)
	if listResp.StatusCode != 200 {
		t.Fatalf("GET /api/v1/resources: want 200, got %d\n%s", listResp.StatusCode, readBody(t, listResp))
	}
	var listBody struct {
		Items []map[string]any `json:"items"`
	}
	decodeJSON(t, listResp, &listBody)

	present := make(map[string]bool)
	for _, item := range listBody.Items {
		if tok, ok := item["token"].(string); ok {
			present[tok] = true
		}
	}

	for _, tok := range []string{db.Token, cache.Token, nosql.Token} {
		if tok != "" && !present[tok] {
			t.Errorf("resource list after claim missing token %q", tok)
		}
	}

	// Auth/me must show hobby tier.
	meResp := get(t, "/auth/me", "Authorization", "Bearer "+sessionJWT)
	if meResp.StatusCode != 200 {
		t.Fatalf("GET /auth/me: want 200, got %d\n%s", meResp.StatusCode, readBody(t, meResp))
	}
	var me map[string]any
	decodeJSON(t, meResp, &me)
	if me["tier"] != "hobby" {
		t.Errorf("GET /auth/me: want tier=hobby, got %q", me["tier"])
	}
}
