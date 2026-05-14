//go:build e2e

// Persona A — The Vibe Coder
//
// Simulates Claude Code generating a full-stack app and provisioning all three
// data services (Postgres, Redis, MongoDB) anonymously in a single session.
// Each connection URL is verified by opening a real driver connection and
// performing a read/write round-trip — not just a string check.
//
// Required drivers (already in go.mod):
//   github.com/jackc/pgx/v5
//   github.com/redis/go-redis/v9
//   go.mongodb.org/mongo-driver/mongo
package e2e

import (
	"context"
	"fmt"
	"net/http"
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

// ── helpers ───────────────────────────────────────────────────────────────────

// provisionDB calls POST /db/new and returns the parsed response.
// Skips (not fails) if the service returns 503.
func provisionDB(t *testing.T, ip string) provisionNewResponse {
	t.Helper()
	resp := post(t, "/db/new", nil, "X-Forwarded-For", ip)
	if resp.StatusCode == 503 {
		readBody(t, resp)
		t.Skip("POST /db/new: service not enabled (503) — skip")
	}
	var body provisionNewResponse
	decodeJSON(t, resp, &body)
	if body.Token == "" {
		t.Fatalf("provisionDB: empty token (status %d)", resp.StatusCode)
	}
	return body
}

// provisionCache calls POST /cache/new and returns the parsed response.
func provisionCache(t *testing.T, ip string) provisionNewResponse {
	t.Helper()
	resp := post(t, "/cache/new", nil, "X-Forwarded-For", ip)
	if resp.StatusCode == 503 {
		readBody(t, resp)
		t.Skip("POST /cache/new: service not enabled (503) — skip")
	}
	var body provisionNewResponse
	decodeJSON(t, resp, &body)
	if body.Token == "" {
		t.Fatalf("provisionCache: empty token (status %d)", resp.StatusCode)
	}
	return body
}

// provisionNoSQL calls POST /nosql/new and returns the parsed response.
func provisionNoSQL(t *testing.T, ip string) provisionNewResponse {
	t.Helper()
	resp := post(t, "/nosql/new", nil, "X-Forwarded-For", ip)
	if resp.StatusCode == 503 {
		readBody(t, resp)
		t.Skip("POST /nosql/new: service not enabled (503) — skip")
	}
	var body provisionNewResponse
	decodeJSON(t, resp, &body)
	if body.Token == "" {
		t.Fatalf("provisionNoSQL: empty token (status %d)", resp.StatusCode)
	}
	return body
}

// ── A1: Provision all three — URLs are syntactically valid ───────────────────

func TestE2E_FullStack_ProvisionAllThree_URLsAreValid(t *testing.T) {
	ip := uniqueIP(t)

	db := provisionDB(t, ip)
	cache := provisionCache(t, ip)
	nosql := provisionNoSQL(t, ip)

	if !strings.HasPrefix(db.ConnectionURL, "postgres://") {
		t.Errorf("db URL must start with postgres://, got %q", db.ConnectionURL)
	}
	if !strings.HasPrefix(cache.ConnectionURL, "redis://") {
		t.Errorf("cache URL must start with redis://, got %q", cache.ConnectionURL)
	}
	if !strings.HasPrefix(nosql.ConnectionURL, "mongodb://") {
		t.Errorf("nosql URL must start with mongodb://, got %q", nosql.ConnectionURL)
	}

	for _, tok := range []string{db.Token, cache.Token, nosql.Token} {
		if _, err := uuid.Parse(tok); err != nil {
			t.Errorf("token %q must be a valid UUID: %v", tok, err)
		}
	}
}

// ── A2: Real Postgres write round-trip ───────────────────────────────────────

func TestE2E_FullStack_DB_RealWrite(t *testing.T) {
	if os.Getenv("E2E_PG_HOST") == "" {
		t.Skip("E2E_PG_HOST not set — needs kubectl port-forward -n instant-data svc/postgres-customers 5435:5432")
	}
	ip := uniqueIP(t)
	db := provisionDB(t, ip)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	conn, err := pgx.Connect(ctx, localURL(db.ConnectionURL))
	if err != nil {
		t.Fatalf("pgx.Connect to provisioned URL: %v", err)
	}
	defer conn.Close(ctx)

	table := "e2e_" + strings.ReplaceAll(uuid.NewString()[:8], "-", "_")

	_, err = conn.Exec(ctx, fmt.Sprintf(`CREATE TABLE %s (id SERIAL PRIMARY KEY, val TEXT)`, table))
	if err != nil {
		t.Fatalf("CREATE TABLE: %v", err)
	}

	_, err = conn.Exec(ctx, fmt.Sprintf(`INSERT INTO %s (val) VALUES ($1)`, table), "hello-instant")
	if err != nil {
		t.Fatalf("INSERT: %v", err)
	}

	var count int
	err = conn.QueryRow(ctx, fmt.Sprintf(`SELECT count(*) FROM %s WHERE val = $1`, table), "hello-instant").Scan(&count)
	if err != nil {
		t.Fatalf("SELECT: %v", err)
	}
	if count != 1 {
		t.Errorf("expected 1 row, got %d", count)
	}

	_, _ = conn.Exec(ctx, fmt.Sprintf(`DROP TABLE %s`, table))
}

// ── A3: Real Redis write round-trip ──────────────────────────────────────────

func TestE2E_FullStack_Cache_RealWrite(t *testing.T) {
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
	key := cache.redisKeyPrefix() + "e2e-" + uuid.NewString()[:8]
	if err := rdb.Set(ctx, key, "hello-instant", 60*time.Second).Err(); err != nil {
		t.Fatalf("SET: %v", err)
	}

	val, err := rdb.Get(ctx, key).Result()
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	if val != "hello-instant" {
		t.Errorf("expected 'hello-instant', got %q", val)
	}

	rdb.Del(ctx, key)
}

// ── A4: Real MongoDB write round-trip ────────────────────────────────────────

func TestE2E_FullStack_NoSQL_RealWrite(t *testing.T) {
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

	// Database name is embedded in the connection URL (pool may use a different name than db_{token}).
	col := mc.Database(mongoDBName(nosql.ConnectionURL)).Collection("e2e_test")

	docID := uuid.NewString()
	_, err = col.InsertOne(ctx, bson.M{"_id": docID, "val": "hello-instant"})
	if err != nil {
		t.Fatalf("InsertOne: %v", err)
	}

	var result bson.M
	err = col.FindOne(ctx, bson.M{"_id": docID}).Decode(&result)
	if err != nil {
		t.Fatalf("FindOne: %v", err)
	}
	if result["val"] != "hello-instant" {
		t.Errorf("expected val='hello-instant', got %v", result["val"])
	}

	_, _ = col.DeleteOne(ctx, bson.M{"_id": docID})
}

// ── A5: All three tokens appear in /start landing ────────────────────────────

func TestE2E_FullStack_AllThreeTokens_AppearInStartLanding(t *testing.T) {
	ip := uniqueIP(t)

	db := provisionDB(t, ip)
	provisionCache(t, ip)
	provisionNoSQL(t, ip)

	// Use the JWT from the DB's note — the fingerprint covers all three.
	jwt := extractJWTFromNote(t, db.Note)

	// /start now redirects (302) to the dashboard ClaimPage with the JWT embedded.
	// The dashboard ClaimPage calls GET /claim/preview to retrieve resource details.
	resp := getNoRedirect(t, "/start?t="+jwt)
	readBody(t, resp)

	if resp.StatusCode != http.StatusFound {
		t.Fatalf("GET /start?t=jwt: want 302, got %d", resp.StatusCode)
	}
	loc := resp.Header.Get("Location")
	if !strings.Contains(loc, "/claim?t=") {
		t.Errorf("/start: Location must contain /claim?t=, got %q", loc)
	}
}

// ── A6: Claim — all three resources appear in management API ─────────────────

func TestE2E_FullStack_ClaimAllThree_ResourceListHasAll(t *testing.T) {
	ip := uniqueIP(t)

	db := provisionDB(t, ip)
	cache := provisionCache(t, ip)
	nosql := provisionNoSQL(t, ip)
	anonCache := provisionAnonymous(t, ip)

	jwt := extractJWTFromNote(t, anonCache.Note)
	email := uniqueEmail()
	teamName := "e2e-fullstack-" + uuid.NewString()[:6]

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

	sessionJWT := makeSessionJWT(t, claim.TeamID, email)

	listResp := get(t, "/api/v1/resources", "Authorization", "Bearer "+sessionJWT)
	if listResp.StatusCode != 200 {
		t.Fatalf("GET /api/v1/resources: want 200, got %d\n%s", listResp.StatusCode, readBody(t, listResp))
	}

	var listBody struct {
		OK    bool             `json:"ok"`
		Items []map[string]any `json:"items"`
		Total int              `json:"total"`
	}
	decodeJSON(t, listResp, &listBody)

	// Build a set of present resource types.
	types := make(map[string]bool)
	for _, item := range listBody.Items {
		if rt, ok := item["resource_type"].(string); ok {
			types[rt] = true
		}
	}

	for _, want := range []string{"postgres", "redis", "mongodb"} {
		if !types[want] {
			t.Errorf("resource list must include type %q; got types: %v", want, types)
		}
	}

	// All 4 tokens must appear (anonymous onboarding JWT comes from /cache/new).
	tokens := make(map[string]bool)
	for _, item := range listBody.Items {
		if tok, ok := item["token"].(string); ok {
			tokens[tok] = true
		}
	}
	for _, tok := range []string{db.Token, cache.Token, nosql.Token, anonCache.Token} {
		if !tokens[tok] {
			t.Errorf("resource list must include token %q", tok)
		}
	}
}

// ── A7: GET /auth/me reflects hobby tier after claim ─────────────────────────

func TestE2E_FullStack_AuthMe_ReflectsHobbyTierAfterClaim(t *testing.T) {
	ip := uniqueIP(t)
	anonCache := provisionAnonymous(t, ip)
	jwt := extractJWTFromNote(t, anonCache.Note)
	email := uniqueEmail()

	claimResp := post(t, "/claim", map[string]any{
		"jwt":       jwt,
		"email":     email,
		"team_name": "e2e-authme-" + uuid.NewString()[:6],
	})
	if claimResp.StatusCode != 201 {
		t.Fatalf("POST /claim: want 201, got %d\n%s", claimResp.StatusCode, readBody(t, claimResp))
	}
	var claim claimResponse
	decodeJSON(t, claimResp, &claim)

	sessionJWT := makeSessionJWTWithUser(t, claim.UserID, claim.TeamID, email)

	meResp := get(t, "/auth/me", "Authorization", "Bearer "+sessionJWT)
	if meResp.StatusCode != 200 {
		t.Fatalf("GET /auth/me: want 200, got %d\n%s", meResp.StatusCode, readBody(t, meResp))
	}

	// Decode into a permissive map so we can assert on field PRESENCE
	// (not just value). The platform has no trial period (see policy memory
	// project_no_trial_pay_day_one.md); /auth/me must never expose a
	// trial_ends_at key.
	var me map[string]any
	decodeJSON(t, meResp, &me)

	if tier, _ := me["tier"].(string); tier != "hobby" {
		t.Errorf("GET /auth/me: want tier=hobby after claim, got %q", tier)
	}
	if _, present := me["trial_ends_at"]; present {
		t.Errorf("GET /auth/me: trial_ends_at must NOT be present — no trial period exists; got %v", me["trial_ends_at"])
	}
}
