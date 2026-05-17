package middleware

// dpop.go — RFC 9449 (Demonstrating Proof of Possession) middleware.
//
// When a bearer token carries `cnf.jkt` (set by the auth middleware into
// LocalKeyDPoPKeyThumbprint) the request MUST also include a `DPoP` header
// whose proof JWT:
//
//   - Has typ="dpop+jwt" in its header.
//   - Carries the public key as a JWK in the header (`jwk` parameter) whose
//     RFC 7638 thumbprint matches the bound jkt.
//   - Has htm == request method (uppercase).
//   - Has htu == request URL (no query string, no fragment).
//   - Has iat within the freshness window (default 5 minutes).
//   - Has a unique jti — replays are rejected via Redis-backed dedup.
//
// The middleware is OPT-IN: requests whose token does not carry cnf.jkt pass
// through unchanged. This preserves back-compat with existing dashboard JWTs
// while letting agent-issued tokens upgrade to sender-bound credentials.

import (
	"context"
	"crypto"
	_ "crypto/sha256" // register sha256.New for crypto.SHA256
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/redis/go-redis/v9"
	"instant.dev/internal/circuit"
)

const (
	// dpopHeaderName is the request header that carries the proof JWT.
	dpopHeaderName = "DPoP"

	// dpopFreshnessWindow caps how old the iat claim of a DPoP proof may be.
	// RFC 9449 §4.3 leaves the window implementation-defined; 5 minutes
	// matches the worked example in the spec.
	dpopFreshnessWindow = 5 * time.Minute

	// dpopReplayKeyPrefix namespaces the Redis keys used for jti dedup.
	dpopReplayKeyPrefix = "dpop:jti:"

	// dpopJWTType is the required value of the DPoP proof's typ header.
	dpopJWTType = "dpop+jwt"

	// dpopErrorInvalid is the WWW-Authenticate error keyword for malformed,
	// expired, or replayed proofs (RFC 9449 §7.1).
	dpopErrorInvalid = "invalid_dpop_proof"

	// dpopRedisCircuitName / Threshold / Cooldown — circuit-breaker tuning
	// for the Redis-backed DPoP replay-detection store. Converts the
	// fail-CLOSED pathology ("Redis is down → every DPoP token locked out")
	// into a bounded 30s blast radius.
	//
	// Threshold 3 — Redis is fast; consecutive failures imply real outage,
	// not flap. Cooldown 30s — matches retry_after_seconds=30 for 503.
	dpopRedisCircuitName      = "dpop_redis"
	dpopRedisCircuitThreshold = 3
	dpopRedisCircuitCooldown  = 30 * time.Second
)

// dpopRedisBreaker is the package-level breaker for the DPoP replay
// Redis client. Lazy-init so test code that doesn't exercise the
// middleware doesn't register Prometheus metrics.
var (
	dpopRedisBreakerOnce sync.Once
	dpopRedisBreakerInst *circuit.Breaker
)

func dpopRedisBreaker() *circuit.Breaker {
	dpopRedisBreakerOnce.Do(func() {
		dpopRedisBreakerInst = circuit.NewBreaker(
			dpopRedisCircuitName,
			dpopRedisCircuitThreshold,
			dpopRedisCircuitCooldown,
		).WithOnOpen(func() {
			slog.Error("dpop.redis.circuit.opened",
				"name", dpopRedisCircuitName,
				"threshold", dpopRedisCircuitThreshold,
				"cooldown_seconds", int(dpopRedisCircuitCooldown.Seconds()),
				"impact", "DPoP-tagged tokens see 503 dpop_replay_check_unavailable until Redis recovers",
				"runbook", "https://instanode.dev/status",
			)
		})
	})
	return dpopRedisBreakerInst
}

// DPoPRedisBreaker exposes the singleton breaker for tests and /healthz.
// Read-only — do NOT mutate.
func DPoPRedisBreaker() *circuit.Breaker { return dpopRedisBreaker() }

// ResetDPoPRedisBreakerForTest replaces the package-singleton with a
// freshly-constructed breaker. Test-only — production MUST NOT call.
// Used by tests that exercise circuit transitions; without this hook,
// test ordering leaks open-state across runs.
func ResetDPoPRedisBreakerForTest() {
	dpopRedisBreakerInst = circuit.NewBreaker(
		dpopRedisCircuitName,
		dpopRedisCircuitThreshold,
		dpopRedisCircuitCooldown,
	)
	dpopRedisBreakerOnce.Do(func() {})
}

// errDPoPReplayStoreDown is the internal sentinel signalling "couldn't
// verify the jti was unique because Redis is broken". Converted to the
// canonical 503 envelope by RequireDPoP. Using a sentinel (not the raw
// Redis error) prevents the JSON body from leaking server addresses.
var errDPoPReplayStoreDown = errors.New("dpop replay store unavailable")

// base64URLNoPad encodes b as base64url with no padding (RFC 4648 §5).
func base64URLNoPad(b []byte) string {
	return base64.RawURLEncoding.EncodeToString(b)
}

// RequireDPoP returns a Fiber handler that enforces RFC 9449 sender-binding
// for any request whose JWT carries `cnf.jkt`. Requests without that claim
// pass through. The middleware MUST be installed AFTER RequireAuth so that
// LocalKeyDPoPKeyThumbprint is populated.
//
// rdb may be nil; replay detection is then disabled (proofs are still
// signature/htm/htu/iat-validated). A warning is logged on every request in
// that case so operators notice the degraded posture.
func RequireDPoP(rdb *redis.Client) fiber.Handler {
	return func(c *fiber.Ctx) error {
		jkt := GetDPoPKeyThumbprint(c)
		if jkt == "" {
			// Token is not key-bound; DPoP is not required for this request.
			return c.Next()
		}

		proof := c.Get(dpopHeaderName)
		if proof == "" {
			return rejectDPoP(c, "missing DPoP header")
		}

		if err := verifyDPoPProof(c, proof, jkt, rdb); err != nil {
			// Replay-store-down is operationally distinct from "the
			// agent's proof is bad" — return 503 so the agent retries
			// the SAME token, not re-mints one that'd also fail.
			if errors.Is(err, errDPoPReplayStoreDown) {
				slog.Error("middleware.dpop.replay_store_unavailable",
					"jkt", jkt, "path", c.Path())
				return c.Status(fiber.StatusServiceUnavailable).JSON(fiber.Map{
					"ok":                  false,
					"error":               "dpop_replay_check_unavailable",
					"message":             "DPoP replay-protection store is temporarily degraded. Retry in 30 seconds — your token is still valid.",
					"request_id":          GetRequestID(c),
					"retry_after_seconds": 30,
					"agent_action":        "Tell the user the replay-protection store is temporarily degraded. Retry in 30 seconds — token is valid; see https://instanode.dev/status for live recovery info.",
					"upgrade_url":         "https://instanode.dev/status",
				})
			}
			slog.Info("middleware.dpop.rejected",
				"error", err,
				"jkt", jkt,
				"path", c.Path(),
			)
			return rejectDPoP(c, err.Error())
		}

		return c.Next()
	}
}

// verifyDPoPProof performs the full RFC 9449 verification chain.
// Returns nil on success or a descriptive error on failure.
func verifyDPoPProof(c *fiber.Ctx, proof, expectedJKT string, rdb *redis.Client) error {
	// Parse the JWS without verification first so we can pull the embedded JWK
	// out of the protected header.
	parsed, err := jws.Parse([]byte(proof))
	if err != nil {
		return fmt.Errorf("parse DPoP JWS: %w", err)
	}
	sigs := parsed.Signatures()
	if len(sigs) != 1 {
		return errors.New("DPoP proof must have exactly one signature")
	}
	hdr := sigs[0].ProtectedHeaders()
	if hdr.Type() != dpopJWTType {
		return fmt.Errorf("DPoP typ must be %q, got %q", dpopJWTType, hdr.Type())
	}
	jwkKey := hdr.JWK()
	if jwkKey == nil {
		return errors.New("DPoP proof header missing jwk")
	}

	// Validate jkt: the RFC 7638 thumbprint of the embedded JWK MUST equal
	// the cnf.jkt the bearer token was issued for.
	tp, err := jwkThumbprintBase64URL(jwkKey)
	if err != nil {
		return fmt.Errorf("compute thumbprint: %w", err)
	}
	if tp != expectedJKT {
		return errors.New("DPoP key thumbprint does not match cnf.jkt")
	}

	// Verify the signature using the embedded JWK.
	if _, err := jws.Verify([]byte(proof), jws.WithKey(hdr.Algorithm(), jwkKey)); err != nil {
		return fmt.Errorf("verify DPoP signature: %w", err)
	}

	// Parse claims and check htm, htu, iat, jti.
	tok, err := jwt.Parse([]byte(proof), jwt.WithVerify(false), jwt.WithValidate(false))
	if err != nil {
		return fmt.Errorf("parse DPoP claims: %w", err)
	}

	htm, ok := getStringClaim(tok, "htm")
	if !ok {
		return errors.New("DPoP missing htm claim")
	}
	if !strings.EqualFold(htm, c.Method()) {
		return fmt.Errorf("DPoP htm %q does not match request method %q", htm, c.Method())
	}

	htu, ok := getStringClaim(tok, "htu")
	if !ok {
		return errors.New("DPoP missing htu claim")
	}
	if !urlMatches(htu, requestCanonicalURL(c)) {
		return fmt.Errorf("DPoP htu %q does not match request URL %q", htu, requestCanonicalURL(c))
	}

	iat := tok.IssuedAt()
	if iat.IsZero() {
		return errors.New("DPoP missing iat claim")
	}
	now := time.Now()
	skew := now.Sub(iat)
	if skew < -dpopFreshnessWindow || skew > dpopFreshnessWindow {
		return fmt.Errorf("DPoP iat outside freshness window (skew=%s)", skew)
	}

	jti := tok.JwtID()
	if jti == "" {
		return errors.New("DPoP missing jti claim")
	}

	// Replay protection — track jti in Redis with TTL = freshness window.
	//
	// W12 / B43 S12 — DPoP previously failed OPEN on Redis errors and
	// when rdb==nil. That silently restored token replayability for
	// every key-bound session during a Redis outage. Fixed here:
	//
	//   - rdb == nil:      respond 503 dpop_replay_check_unavailable.
	//                      Silent fail-open is no longer a posture.
	//   - rdb errors:      record against the dpop_redis breaker.
	//                      After 3 consecutive failures the breaker
	//                      opens and subsequent requests 503 in <1ms
	//                      (no 250ms Redis timeout per request). An
	//                      outage costs 30s of 503s, not permanent
	//                      replayability. A successful half-open trial
	//                      auto-closes the breaker on recovery.
	//   - SetNX returns false (jti seen): replay — reject as before.
	if rdb == nil {
		return errDPoPReplayStoreDown
	}
	b := dpopRedisBreaker()
	if !b.Allow() {
		return errDPoPReplayStoreDown
	}
	ctx, cancel := context.WithTimeout(c.Context(), 250*time.Millisecond)
	defer cancel()
	key := dpopReplayKeyPrefix + jti
	setOK, err := rdb.SetNX(ctx, key, "1", dpopFreshnessWindow).Result()
	b.Record(err)
	if err != nil {
		slog.Warn("middleware.dpop.replay_check_failed",
			"error", err, "jti", jti)
		return errDPoPReplayStoreDown
	}
	if !setOK {
		return errors.New("DPoP jti has been seen before (replay)")
	}

	return nil
}

// rejectDPoP writes an RFC 9449 §7.1 401 with WWW-Authenticate: DPoP and a
// matching error keyword agents can branch on.
//
// W12: the body shape matches respondUnauthorized's canonical envelope —
// message, request_id, retry_after_seconds, agent_action, upgrade_url are
// all populated so an agent inspecting the response sees the same field
// set as any other 401 from this API. error_description is retained
// alongside `message` because RFC 9449 §7.1 names that field explicitly in
// the WWW-Authenticate header companion.
func rejectDPoP(c *fiber.Ctx, description string) error {
	c.Set("WWW-Authenticate",
		fmt.Sprintf(`DPoP error="%s", error_description="%s"`, dpopErrorInvalid, description))
	return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
		"ok":                  false,
		"error":               dpopErrorInvalid,
		"error_description":   description,
		"message":             "DPoP proof rejected: " + description + ". The agent must re-mint a fresh DPoP proof bound to the request method + URL.",
		"request_id":          GetRequestID(c),
		"retry_after_seconds": nil,
		"agent_action":        unauthorizedAgentAction,
		"upgrade_url":         AuthLoginURL,
	})
}

// jwkThumbprintBase64URL computes the RFC 7638 thumbprint of a JWK and
// returns it base64url-encoded (no padding) — the canonical representation
// used by RFC 9449 cnf.jkt.
func jwkThumbprintBase64URL(key jwk.Key) (string, error) {
	tp, err := key.Thumbprint(crypto.SHA256)
	if err != nil {
		return "", err
	}
	return base64URLNoPad(tp), nil
}

// requestCanonicalURL builds the htu canonical form (RFC 9449 §4.2):
// scheme://host{:port}/path with no query string and no fragment.
//
// P2 (2026-05-17): the scheme+host are taken from the canonical resource URL
// (API_PUBLIC_URL / compiled default), NOT from client-settable headers
// (X-Forwarded-Host / X-Forwarded-Proto). htu is a security check — an
// attacker who can spoof the forwarded host could otherwise forge a proof
// whose htu matches a request to a different host. Only the path comes from
// the live request.
func requestCanonicalURL(c *fiber.Ctx) string {
	base, err := url.Parse(CanonicalResourceURLFor(c))
	if err != nil || base.Host == "" {
		// Defensive fallback — CanonicalResourceURLFor never returns an
		// unparseable value in practice, but never panic on the auth path.
		base = &url.URL{Scheme: "https", Host: c.Hostname()}
	}
	u := url.URL{Scheme: base.Scheme, Host: base.Host, Path: c.Path()}
	return u.String()
}

// urlMatches compares two URLs ignoring case in scheme/host and ignoring
// trailing slashes. Path comparison is exact.
func urlMatches(a, b string) bool {
	pa, err := url.Parse(a)
	if err != nil {
		return false
	}
	pb, err := url.Parse(b)
	if err != nil {
		return false
	}
	if !strings.EqualFold(pa.Scheme, pb.Scheme) {
		return false
	}
	if !strings.EqualFold(pa.Host, pb.Host) {
		return false
	}
	pathA := strings.TrimRight(pa.Path, "/")
	pathB := strings.TrimRight(pb.Path, "/")
	if pathA == "" {
		pathA = "/"
	}
	if pathB == "" {
		pathB = "/"
	}
	return pathA == pathB
}

// getStringClaim pulls an arbitrary string-valued claim out of a parsed JWT.
// jwx exposes htm/htu only via the generic claim accessor.
func getStringClaim(tok jwt.Token, name string) (string, bool) {
	v, ok := tok.Get(name)
	if !ok {
		return "", false
	}
	s, ok := v.(string)
	return s, ok
}
