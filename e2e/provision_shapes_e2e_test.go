//go:build e2e

// Provision Shapes — S2 & S3 from the full-system test plan.
//
// Verifies every provisioning endpoint returns the correct response shape,
// embeds a valid upgrade JWT in its note, sets expires_at for anonymous
// resources, and that the JWT payload carries the expected claims.
//
// S2: Response shapes for all four service types.
// S3: JWT claim decoding, multi-service bundling, tamper resistance.
package e2e

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

)

// decodeJWTClaims decodes the payload of a JWT without verifying the signature.
// Sufficient for black-box claim inspection where we trust the note came from our server.
func decodeJWTClaims(t *testing.T, rawJWT string) map[string]any {
	t.Helper()
	parts := strings.Split(rawJWT, ".")
	if len(parts) != 3 {
		t.Fatalf("decodeJWTClaims: expected 3 JWT parts, got %d (raw: %q)", len(parts), rawJWT)
	}
	// Add padding if needed.
	payload := parts[1]
	switch len(payload) % 4 {
	case 2:
		payload += "=="
	case 3:
		payload += "="
	}
	decoded, err := base64.URLEncoding.DecodeString(payload)
	if err != nil {
		t.Fatalf("decodeJWTClaims: base64 decode: %v", err)
	}
	var claims map[string]any
	if err := json.Unmarshal(decoded, &claims); err != nil {
		t.Fatalf("decodeJWTClaims: json unmarshal: %v", err)
	}
	return claims
}

// ── S2: Response shapes — provisioning services ───────────────────────────────

func TestE2E_ProvisionShapes_DB_HasAllRequiredFields(t *testing.T) {
	ip := uniqueIP(t)
	resp := post(t, "/db/new", nil, "X-Forwarded-For", ip)
	if resp.StatusCode == 503 {
		readBody(t, resp)
		t.Skip("POST /db/new: service not enabled (503)")
	}
	if resp.StatusCode != 201 {
		t.Fatalf("POST /db/new: want 201, got %d\n%s", resp.StatusCode, readBody(t, resp))
	}
	var body provisionNewResponse
	decodeJSON(t, resp, &body)

	if body.Token == "" {
		t.Error("token must not be empty")
	}
	if body.ConnectionURL == "" {
		t.Error("connection_url must not be empty")
	}
	if !strings.HasPrefix(body.ConnectionURL, "postgres://") {
		t.Errorf("connection_url must start with postgres://, got %q", body.ConnectionURL)
	}
	if body.Tier != "anonymous" {
		t.Errorf("tier must be anonymous, got %q", body.Tier)
	}
	if _, ok := body.Limits["storage_mb"]; !ok {
		t.Error("limits.storage_mb must be present")
	}
	if !strings.Contains(body.Note, "/start?t=") {
		t.Errorf("note must contain upgrade URL, got %q", body.Note)
	}
}

func TestE2E_ProvisionShapes_Cache_HasAllRequiredFields(t *testing.T) {
	ip := uniqueIP(t)
	resp := post(t, "/cache/new", nil, "X-Forwarded-For", ip)
	if resp.StatusCode == 503 {
		readBody(t, resp)
		t.Skip("POST /cache/new: service not enabled (503)")
	}
	if resp.StatusCode != 201 {
		t.Fatalf("POST /cache/new: want 201, got %d\n%s", resp.StatusCode, readBody(t, resp))
	}
	var body provisionNewResponse
	decodeJSON(t, resp, &body)

	if body.Token == "" {
		t.Error("token must not be empty")
	}
	if body.ConnectionURL == "" {
		t.Error("connection_url must not be empty")
	}
	if !strings.HasPrefix(body.ConnectionURL, "redis://") {
		t.Errorf("connection_url must start with redis://, got %q", body.ConnectionURL)
	}
	if body.Tier != "anonymous" {
		t.Errorf("tier must be anonymous, got %q", body.Tier)
	}
	if _, ok := body.Limits["memory_mb"]; !ok {
		t.Error("limits.memory_mb must be present")
	}
	if !strings.Contains(body.Note, "/start?t=") {
		t.Errorf("note must contain upgrade URL, got %q", body.Note)
	}
}

func TestE2E_ProvisionShapes_NoSQL_HasAllRequiredFields(t *testing.T) {
	ip := uniqueIP(t)
	resp := post(t, "/nosql/new", nil, "X-Forwarded-For", ip)
	if resp.StatusCode == 503 {
		readBody(t, resp)
		t.Skip("POST /nosql/new: service not enabled (503)")
	}
	if resp.StatusCode != 201 {
		t.Fatalf("POST /nosql/new: want 201, got %d\n%s", resp.StatusCode, readBody(t, resp))
	}
	var body provisionNewResponse
	decodeJSON(t, resp, &body)

	if body.Token == "" {
		t.Error("token must not be empty")
	}
	if body.ConnectionURL == "" {
		t.Error("connection_url must not be empty")
	}
	if !strings.HasPrefix(body.ConnectionURL, "mongodb://") {
		t.Errorf("connection_url must start with mongodb://, got %q", body.ConnectionURL)
	}
	if body.Tier != "anonymous" {
		t.Errorf("tier must be anonymous, got %q", body.Tier)
	}
	if !strings.Contains(body.Note, "/start?t=") {
		t.Errorf("note must contain upgrade URL, got %q", body.Note)
	}
}

// ── S2.5: expires_at is set for anonymous resources ──────────────────────────

func TestE2E_ProvisionShapes_Anonymous_ExpiresAtIsSet(t *testing.T) {
	ip := uniqueIP(t)
	prov := provisionAnonymous(t, ip)

	jwtStr := extractJWTFromNote(t, prov.Note)
	claims := decodeJWTClaims(t, jwtStr)

	expRaw, ok := claims["exp"]
	if !ok {
		t.Fatal("JWT claims must contain 'exp'")
	}
	exp := int64(expRaw.(float64))
	now := time.Now().Unix()

	// exp must be 1-10 days from now (JWT is 7 days per plan).
	if exp <= now {
		t.Errorf("exp must be in the future: exp=%d, now=%d", exp, now)
	}
	daysFromNow := float64(exp-now) / 86400.0
	if daysFromNow > 10 {
		t.Errorf("exp must be within 10 days, got %.1f days from now", daysFromNow)
	}
}

// ── S2.6: Note field contains a valid 3-part JWT ─────────────────────────────

func TestE2E_ProvisionShapes_NoteJWTHasThreeParts(t *testing.T) {
	ip := uniqueIP(t)
	prov := provisionAnonymous(t, ip)

	jwtStr := extractJWTFromNote(t, prov.Note)
	parts := strings.Split(jwtStr, ".")
	if len(parts) != 3 {
		t.Errorf("JWT in note must have 3 parts (header.payload.sig), got %d: %q", len(parts), jwtStr)
	}
	for i, part := range parts {
		if part == "" {
			t.Errorf("JWT part %d is empty", i)
		}
	}
}

// ── S3: JWT claim decoding ────────────────────────────────────────────────────

func TestE2E_UpgradeJWT_ClaimsAreCorrect(t *testing.T) {
	ip := uniqueIP(t)
	prov := provisionAnonymous(t, ip)

	jwtStr := extractJWTFromNote(t, prov.Note)
	claims := decodeJWTClaims(t, jwtStr)

	// fp: 32-char hex fingerprint.
	fp, ok := claims["fp"].(string)
	if !ok || fp == "" {
		t.Error("JWT claim 'fp' (fingerprint) must be a non-empty string")
	}
	if len(fp) != 32 {
		t.Errorf("fingerprint must be 32 hex chars, got %d: %q", len(fp), fp)
	}

	// tok: array containing the provisioned token.
	tokRaw, ok := claims["tok"]
	if !ok {
		t.Fatal("JWT claim 'tok' must be present")
	}
	toks, ok := tokRaw.([]any)
	if !ok || len(toks) == 0 {
		t.Fatalf("JWT claim 'tok' must be a non-empty array, got: %v", tokRaw)
	}
	found := false
	for _, tok := range toks {
		if tok.(string) == prov.Token {
			found = true
		}
	}
	if !found {
		t.Errorf("JWT tok array must contain token %q, got %v", prov.Token, toks)
	}

	// rt: resource types array — must be present and non-empty.
	rtRaw, ok := claims["rt"]
	if !ok {
		t.Fatal("JWT claim 'rt' (resource types) must be present")
	}
	rts, ok := rtRaw.([]any)
	if !ok || len(rts) == 0 {
		t.Fatalf("JWT claim 'rt' must be a non-empty array, got: %v", rtRaw)
	}

	// jti: unique per JWT.
	jti, ok := claims["jti"].(string)
	if !ok || jti == "" {
		t.Error("JWT claim 'jti' must be a non-empty string")
	}

	// exp: 7 days from now ±1 day tolerance.
	expRaw, ok := claims["exp"]
	if !ok {
		t.Fatal("JWT claim 'exp' must be present")
	}
	exp := int64(expRaw.(float64))
	sevenDays := int64(7 * 24 * 3600)
	delta := exp - time.Now().Unix()
	if delta < sevenDays-86400 || delta > sevenDays+86400 {
		t.Errorf("JWT exp should be ~7 days from now, got %d seconds (~%.1f days)", delta, float64(delta)/86400)
	}
}

// ── S3.3: Multi-service JWT bundles all tokens ────────────────────────────────

func TestE2E_UpgradeJWT_MultiService_BundlesAllTokens(t *testing.T) {
	ip := uniqueIP(t)

	// Provision cache + DB with same fingerprint (same IP).
	cache := provisionAnonymous(t, ip)

	dbResp := post(t, "/db/new", nil, "X-Forwarded-For", ip)
	if dbResp.StatusCode == 503 {
		readBody(t, dbResp)
		t.Skip("POST /db/new not enabled — skip multi-service JWT test")
	}
	var db provisionNewResponse
	decodeJSON(t, dbResp, &db)

	// Use the DB's JWT — it was provisioned second, so its JWT reflects the
	// full fingerprint state (cache + DB).
	jwtStr := extractJWTFromNote(t, db.Note)
	claims := decodeJWTClaims(t, jwtStr)

	tokRaw, _ := claims["tok"]
	toks, _ := tokRaw.([]any)

	tokenSet := make(map[string]bool)
	for _, tok := range toks {
		if s, ok := tok.(string); ok {
			tokenSet[s] = true
		}
	}

	if !tokenSet[cache.Token] {
		t.Errorf("JWT tok must contain cache token %q, got %v", cache.Token, toks)
	}
	if !tokenSet[db.Token] {
		t.Errorf("JWT tok must contain DB token %q, got %v", db.Token, toks)
	}

	// rt must contain both types.
	rtRaw, _ := claims["rt"]
	rts, _ := rtRaw.([]any)
	rtSet := make(map[string]bool)
	for _, rt := range rts {
		if s, ok := rt.(string); ok {
			rtSet[s] = true
		}
	}
	if !rtSet["redis"] {
		t.Errorf("JWT rt must contain 'redis', got %v", rts)
	}
	if !rtSet["postgres"] {
		t.Errorf("JWT rt must contain 'postgres', got %v", rts)
	}
}

// ── S3.4: Tampered JWT → /start returns error state, not 500 ─────────────────

func TestE2E_UpgradeJWT_TamperedSignature_StartPageShowsError(t *testing.T) {
	ip := uniqueIP(t)
	prov := provisionAnonymous(t, ip)

	jwtStr := extractJWTFromNote(t, prov.Note)
	parts := strings.Split(jwtStr, ".")
	// Corrupt the signature.
	tampered := parts[0] + "." + parts[1] + ".invalidsignature"

	resp := get(t, "/start?t="+tampered)
	body := readBody(t, resp)

	// Must not be a 500.
	if resp.StatusCode == 500 {
		t.Fatalf("tampered JWT should not cause 500; got 500 with body: %.200s", body)
	}
	// Either 200 (error rendered inline) or 400.
	if resp.StatusCode != 200 && resp.StatusCode != 400 {
		t.Errorf("tampered JWT: want 200 or 400, got %d", resp.StatusCode)
	}
}

// ── S3.8: /start with no ?t param renders gracefully ─────────────────────────

func TestE2E_UpgradeJWT_NoToken_StartPageRendersGracefully(t *testing.T) {
	resp := get(t, "/start")
	body := readBody(t, resp)

	if resp.StatusCode == 500 {
		t.Fatalf("GET /start with no token must not 500; got: %.200s", body)
	}
}

// ── S2.7: Same fingerprint 6 times — never 500 ───────────────────────────────

func TestE2E_ProvisionShapes_RateLimit_NeverReturns500(t *testing.T) {
	// Use a unique IP per test run so this fingerprint won't collide with other tests.
	ip := uniqueIP(t)

	for i := 0; i < 6; i++ {
		resp := post(t, "/cache/new", nil, "X-Forwarded-For", ip)
		body := readBody(t, resp)
		if resp.StatusCode == 500 {
			t.Errorf("call %d: POST /cache/new returned 500: %.200s", i+1, body)
		}
		// Accept 200 (upgrade CTA) or 201 (new token) — both are valid.
		if resp.StatusCode != 200 && resp.StatusCode != 201 {
			t.Errorf("call %d: POST /cache/new: want 200 or 201, got %d: %.200s", i+1, resp.StatusCode, body)
		}
	}
}
