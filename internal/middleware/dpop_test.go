package middleware_test

// dpop_test.go — RFC 9449 verification tests.
//
// Each test builds a DPoP-bound bearer JWT (cnf.jkt set) plus a fresh DPoP
// proof signed with the corresponding private key. The proof's claims (htm,
// htu, iat, jti) are tweaked per-test to drive each failure mode.

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	_ "crypto/sha256"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt/v4"
	"github.com/google/uuid"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jws"
	jwxjwt "github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"instant.dev/internal/config"
	"instant.dev/internal/middleware"
)

// dpopTestJWTSecret is a 44-byte HMAC secret used by these tests. Inlined
// here rather than imported from internal/testhelpers because that package
// transitively imports internal/handlers, which currently has unrelated
// in-flight changes that would prevent middleware tests from compiling.
const dpopTestJWTSecret = "test-secret-that-is-at-least-32-bytes-long!!"

// dpopFixture holds everything needed to drive a single DPoP test:
// the bearer JWT, the matching private key, and convenience helpers.
type dpopFixture struct {
	t          *testing.T
	bearer     string
	privateKey jwk.Key
	publicKey  jwk.Key
	thumbprint string
}

// newDPoPFixture mints an ES256 keypair, computes its RFC 7638 thumbprint,
// and signs a session JWT whose cnf.jkt binds to that thumbprint.
func newDPoPFixture(t *testing.T) *dpopFixture {
	t.Helper()

	raw, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	priv, err := jwk.FromRaw(raw)
	require.NoError(t, err)
	require.NoError(t, priv.Set(jwk.AlgorithmKey, jwa.ES256))

	pub, err := priv.PublicKey()
	require.NoError(t, err)
	require.NoError(t, pub.Set(jwk.AlgorithmKey, jwa.ES256))

	tp, err := pub.Thumbprint(crypto.SHA256)
	require.NoError(t, err)
	thumbprint := base64.RawURLEncoding.EncodeToString(tp)

	type cnfClaim struct {
		JKT string `json:"jkt"`
	}
	type sessionClaims struct {
		UserID string   `json:"uid"`
		TeamID string   `json:"tid"`
		Email  string   `json:"email"`
		Cnf    cnfClaim `json:"cnf"`
		jwt.RegisteredClaims
	}
	claims := sessionClaims{
		UserID: uuid.NewString(),
		TeamID: uuid.NewString(),
		Email:  "agent@instanode.dev",
		Cnf:    cnfClaim{JKT: thumbprint},
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
			ID:        uuid.NewString(),
		},
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := tok.SignedString([]byte(dpopTestJWTSecret))
	require.NoError(t, err)

	return &dpopFixture{
		t:          t,
		bearer:     signed,
		privateKey: priv,
		publicKey:  pub,
		thumbprint: thumbprint,
	}
}

// signProof builds a DPoP proof JWT with htm/htu/iat/jti and signs it with
// the fixture's private key, embedding the public key in the protected
// header (RFC 9449 §4.2: typ=dpop+jwt, alg=ES256, jwk=public-key).
func (f *dpopFixture) signProof(htm, htu string, iat time.Time, jti string) string {
	f.t.Helper()

	tok := jwxjwt.New()
	require.NoError(f.t, tok.Set("htm", htm))
	require.NoError(f.t, tok.Set("htu", htu))
	require.NoError(f.t, tok.Set(jwxjwt.IssuedAtKey, iat))
	require.NoError(f.t, tok.Set(jwxjwt.JwtIDKey, jti))

	hdrs := jws.NewHeaders()
	require.NoError(f.t, hdrs.Set(jws.TypeKey, "dpop+jwt"))
	require.NoError(f.t, hdrs.Set(jws.JWKKey, f.publicKey))

	signed, err := jwxjwt.Sign(tok,
		jwxjwt.WithKey(jwa.ES256, f.privateKey, jws.WithProtectedHeaders(hdrs)),
	)
	require.NoError(f.t, err)
	return string(signed)
}

// newDPoPApp wires RequireAuth → RequireDPoP → echo handler. Pass rdb=nil to
// disable replay detection.
func newDPoPApp(rdb *redis.Client) *fiber.App {
	cfg := &config.Config{JWTSecret: dpopTestJWTSecret}
	app := fiber.New()
	app.Post("/db/new",
		middleware.RequireAuth(cfg),
		middleware.RequireDPoP(rdb),
		func(c *fiber.Ctx) error {
			return c.JSON(fiber.Map{"ok": true})
		},
	)
	return app
}

// runRequest executes a single Fiber test request with optional bearer +
// DPoP headers. Returns the *http.Response for inspection.
func runRequest(t *testing.T, app *fiber.App, method, target, bearer, dpop string) *http.Response {
	t.Helper()
	req := httptest.NewRequest(method, target, nil)
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	if dpop != "" {
		req.Header.Set("DPoP", dpop)
	}
	req.Host = "api.instanode.dev"
	req.Header.Set("X-Forwarded-Proto", "https")
	resp, err := app.Test(req, 1500)
	require.NoError(t, err)
	return resp
}

// TestDPoP_Valid verifies a well-formed proof passes through.
func TestDPoP_Valid(t *testing.T) {
	t.Setenv("API_PUBLIC_URL", "https://api.instanode.dev")

	mr, err := miniredis.Run()
	require.NoError(t, err)
	defer mr.Close()
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	defer rdb.Close()

	f := newDPoPFixture(t)
	proof := f.signProof("POST", "https://api.instanode.dev/db/new", time.Now(), uuid.NewString())

	app := newDPoPApp(rdb)
	resp := runRequest(t, app, http.MethodPost, "https://api.instanode.dev/db/new", f.bearer, proof)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)
}

// TestDPoP_BadSig verifies a tampered proof returns 401.
func TestDPoP_BadSig(t *testing.T) {
	t.Setenv("API_PUBLIC_URL", "https://api.instanode.dev")

	f := newDPoPFixture(t)
	proof := f.signProof("POST", "https://api.instanode.dev/db/new", time.Now(), uuid.NewString())

	// Flip a byte after the second '.' (signature segment).
	mangled := []byte(proof)
	dotCount := 0
	for i := range mangled {
		if mangled[i] == '.' {
			dotCount++
			if dotCount == 2 && i+1 < len(mangled) {
				if mangled[i+1] == 'A' {
					mangled[i+1] = 'B'
				} else {
					mangled[i+1] = 'A'
				}
				break
			}
		}
	}

	app := newDPoPApp(nil)
	resp := runRequest(t, app, http.MethodPost, "https://api.instanode.dev/db/new", f.bearer, string(mangled))
	defer resp.Body.Close()

	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	assert.Contains(t, resp.Header.Get("WWW-Authenticate"), "DPoP")
}

// TestDPoP_Replay verifies that the same jti reused returns 401.
func TestDPoP_Replay(t *testing.T) {
	t.Setenv("API_PUBLIC_URL", "https://api.instanode.dev")

	mr, err := miniredis.Run()
	require.NoError(t, err)
	defer mr.Close()
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	defer rdb.Close()

	f := newDPoPFixture(t)
	app := newDPoPApp(rdb)

	jti := uuid.NewString()
	proof := f.signProof("POST", "https://api.instanode.dev/db/new", time.Now(), jti)

	resp1 := runRequest(t, app, http.MethodPost, "https://api.instanode.dev/db/new", f.bearer, proof)
	defer resp1.Body.Close()
	require.Equal(t, http.StatusOK, resp1.StatusCode)

	resp2 := runRequest(t, app, http.MethodPost, "https://api.instanode.dev/db/new", f.bearer, proof)
	defer resp2.Body.Close()
	assert.Equal(t, http.StatusUnauthorized, resp2.StatusCode,
		"second call with same jti must be rejected (replay)")
}

// TestDPoP_OptIn verifies that a token without cnf.jkt does NOT require DPoP.
func TestDPoP_OptIn(t *testing.T) {
	t.Setenv("API_PUBLIC_URL", "https://api.instanode.dev")

	cfg := &config.Config{JWTSecret: dpopTestJWTSecret}
	app := fiber.New()
	app.Post("/db/new",
		middleware.RequireAuth(cfg),
		middleware.RequireDPoP(nil),
		func(c *fiber.Ctx) error {
			return c.JSON(fiber.Map{"ok": true})
		},
	)

	type plainSession struct {
		UserID string `json:"uid"`
		TeamID string `json:"tid"`
		Email  string `json:"email"`
		jwt.RegisteredClaims
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, plainSession{
		UserID: uuid.NewString(),
		TeamID: uuid.NewString(),
		Email:  "user@instanode.dev",
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
			ID:        uuid.NewString(),
		},
	})
	signed, err := tok.SignedString([]byte(dpopTestJWTSecret))
	require.NoError(t, err)

	resp := runRequest(t, app, http.MethodPost, "https://api.instanode.dev/db/new", signed, "")
	defer resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode,
		"a plain session JWT (no cnf.jkt) must not require a DPoP header")
}

// TestDPoP_StaleProof verifies that a proof outside the freshness window
// is rejected.
func TestDPoP_StaleProof(t *testing.T) {
	t.Setenv("API_PUBLIC_URL", "https://api.instanode.dev")

	f := newDPoPFixture(t)
	proof := f.signProof("POST", "https://api.instanode.dev/db/new",
		time.Now().Add(-30*time.Minute), uuid.NewString())

	app := newDPoPApp(nil)
	resp := runRequest(t, app, http.MethodPost, "https://api.instanode.dev/db/new", f.bearer, proof)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

// TestDPoP_WrongMethod verifies that a proof with htm != request method
// is rejected.
func TestDPoP_WrongMethod(t *testing.T) {
	t.Setenv("API_PUBLIC_URL", "https://api.instanode.dev")

	f := newDPoPFixture(t)
	proof := f.signProof("GET", "https://api.instanode.dev/db/new", time.Now(), uuid.NewString())

	app := newDPoPApp(nil)
	resp := runRequest(t, app, http.MethodPost, "https://api.instanode.dev/db/new", f.bearer, proof)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

// TestDPoP_MissingHeader verifies that when the bearer carries cnf.jkt but
// the request omits the DPoP header, the request is rejected.
func TestDPoP_MissingHeader(t *testing.T) {
	t.Setenv("API_PUBLIC_URL", "https://api.instanode.dev")

	f := newDPoPFixture(t)
	app := newDPoPApp(nil)
	resp := runRequest(t, app, http.MethodPost, "https://api.instanode.dev/db/new", f.bearer, "")
	defer resp.Body.Close()

	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	assert.Contains(t, resp.Header.Get("WWW-Authenticate"), "DPoP")
}
