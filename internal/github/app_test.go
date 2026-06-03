package github

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/golang-jwt/jwt/v4"
	"github.com/redis/go-redis/v9"
)

// testKeyPEM generates a throwaway RSA private key in PKCS#1 PEM (the format
// GitHub issues App keys in).
func testKeyPEM(t *testing.T) (string, *rsa.PrivateKey) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("gen key: %v", err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	})
	return string(pemBytes), key
}

// roundTripFunc adapts a func to an http transport-ish injectable.
func doFunc(fn func(*http.Request) (*http.Response, error)) func(*http.Request) (*http.Response, error) {
	return fn
}

func jsonResp(status int, body string) *http.Response {
	return &http.Response{
		StatusCode: status,
		Body:       io.NopCloser(strings.NewReader(body)),
		Header:     make(http.Header),
	}
}

func TestNewApp_Validation(t *testing.T) {
	pemStr, _ := testKeyPEM(t)
	if _, err := NewApp("", pemStr, nil); err == nil {
		t.Error("empty appID must error")
	}
	if _, err := NewApp("123", "not a pem", nil); err == nil {
		t.Error("malformed private key must error")
	}
	if _, err := NewApp("123", pemStr, nil); err != nil {
		t.Errorf("valid config must construct: %v", err)
	}
}

func TestAppJWT_SignsAndVerifies(t *testing.T) {
	pemStr, key := testKeyPEM(t)
	a, err := NewApp("999", pemStr, nil)
	if err != nil {
		t.Fatal(err)
	}
	fixed := time.Unix(1_700_000_000, 0)
	a.now = func() time.Time { return fixed }

	tokStr, err := a.appJWT()
	if err != nil {
		t.Fatalf("appJWT: %v", err)
	}
	claims := jwt.RegisteredClaims{}
	// Skip time-based claim validation: we sign with a fixed past `now`, so an
	// exp check against the real clock would (correctly) say "expired". We only
	// assert the signature verifies and the claim values are right.
	parser := jwt.NewParser(jwt.WithoutClaimsValidation())
	_, err = parser.ParseWithClaims(tokStr, &claims, func(*jwt.Token) (interface{}, error) {
		return &key.PublicKey, nil
	})
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if claims.Issuer != "999" {
		t.Errorf("iss = %q want 999", claims.Issuer)
	}
	// exp must be within GitHub's 10-min cap and iat backdated for skew.
	if claims.ExpiresAt.Sub(fixed) > 10*time.Minute {
		t.Error("exp exceeds GitHub's 10-min cap")
	}
	if !claims.IssuedAt.Before(fixed) {
		t.Error("iat must be backdated for clock skew")
	}
}

func TestInstallationToken_MintAndRequestShape(t *testing.T) {
	pemStr, _ := testKeyPEM(t)
	a, _ := NewApp("999", pemStr, nil) // nil rdb → no cache, always mints
	var gotURL, gotAuth, gotBody string
	a.httpDo = doFunc(func(r *http.Request) (*http.Response, error) {
		gotURL = r.URL.String()
		gotAuth = r.Header.Get("Authorization")
		b, _ := io.ReadAll(r.Body)
		gotBody = string(b)
		return jsonResp(http.StatusCreated, `{"token":"ghs_minted","expires_at":"2026-01-01T00:00:00Z"}`), nil
	})

	tok, err := a.InstallationToken(context.Background(), 42)
	if err != nil {
		t.Fatalf("InstallationToken: %v", err)
	}
	if tok != "ghs_minted" {
		t.Errorf("token = %q", tok)
	}
	if !strings.HasSuffix(gotURL, "/app/installations/42/access_tokens") {
		t.Errorf("url = %q", gotURL)
	}
	if !strings.HasPrefix(gotAuth, "Bearer ") {
		t.Errorf("auth header must be a Bearer App JWT, got %q", gotAuth)
	}
	if !strings.Contains(gotBody, `"contents":"read"`) {
		t.Errorf("must request least-privilege contents:read, got %q", gotBody)
	}
}

func TestInstallationToken_Non201_Errors(t *testing.T) {
	pemStr, _ := testKeyPEM(t)
	a, _ := NewApp("999", pemStr, nil)
	a.httpDo = doFunc(func(*http.Request) (*http.Response, error) {
		return jsonResp(http.StatusForbidden, `{"message":"Bad credentials"}`), nil
	})
	if _, err := a.InstallationToken(context.Background(), 7); err == nil ||
		!strings.Contains(err.Error(), "status 403") {
		t.Fatalf("403 must error, got: %v", err)
	}
}

func TestInstallationToken_EmptyToken_Errors(t *testing.T) {
	pemStr, _ := testKeyPEM(t)
	a, _ := NewApp("999", pemStr, nil)
	a.httpDo = doFunc(func(*http.Request) (*http.Response, error) {
		return jsonResp(http.StatusCreated, `{"token":"","expires_at":"2026-01-01T00:00:00Z"}`), nil
	})
	if _, err := a.InstallationToken(context.Background(), 7); err == nil ||
		!strings.Contains(err.Error(), "empty token") {
		t.Fatalf("empty token must error, got: %v", err)
	}
}

func TestInstallationToken_BadJSON_Errors(t *testing.T) {
	pemStr, _ := testKeyPEM(t)
	a, _ := NewApp("999", pemStr, nil)
	a.httpDo = doFunc(func(*http.Request) (*http.Response, error) {
		return jsonResp(http.StatusCreated, `not json`), nil
	})
	if _, err := a.InstallationToken(context.Background(), 7); err == nil ||
		!strings.Contains(err.Error(), "decode") {
		t.Fatalf("bad json must error, got: %v", err)
	}
}

func TestInstallationToken_TransportError(t *testing.T) {
	pemStr, _ := testKeyPEM(t)
	a, _ := NewApp("999", pemStr, nil)
	a.httpDo = doFunc(func(*http.Request) (*http.Response, error) {
		return nil, io.ErrUnexpectedEOF
	})
	if _, err := a.InstallationToken(context.Background(), 7); err == nil ||
		!strings.Contains(err.Error(), "access_tokens request") {
		t.Fatalf("transport error must propagate, got: %v", err)
	}
}

func TestInstallationToken_RedisCache(t *testing.T) {
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatal(err)
	}
	defer mr.Close()
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	defer func() { _ = rdb.Close() }()

	pemStr, _ := testKeyPEM(t)
	a, _ := NewApp("999", pemStr, rdb)
	var mints int
	a.httpDo = doFunc(func(*http.Request) (*http.Response, error) {
		mints++
		return jsonResp(http.StatusCreated, `{"token":"ghs_cached","expires_at":"2026-01-01T00:00:00Z"}`), nil
	})

	// First call mints + caches.
	if tok, err := a.InstallationToken(context.Background(), 55); err != nil || tok != "ghs_cached" {
		t.Fatalf("mint: tok=%q err=%v", tok, err)
	}
	// Second call is served from cache — no second mint.
	if tok, err := a.InstallationToken(context.Background(), 55); err != nil || tok != "ghs_cached" {
		t.Fatalf("cache hit: tok=%q err=%v", tok, err)
	}
	if mints != 1 {
		t.Errorf("expected exactly 1 mint (then cache), got %d", mints)
	}
	// The cache key carries the installation id.
	if v, _ := mr.Get("ghapp:insttok:55"); v != "ghs_cached" {
		t.Errorf("cache key not set: %q", v)
	}
}

// A non-RSA key makes jwt's RS256 SignedString return ErrInvalidKeyType — the
// only way appJWT's (otherwise unreachable) sign-error branch fires.
func TestAppJWT_SignError(t *testing.T) {
	pemStr, _ := testKeyPEM(t)
	a, _ := NewApp("999", pemStr, nil)
	a.privateKey = "not an rsa key"
	if _, err := a.appJWT(); err == nil || !strings.Contains(err.Error(), "sign jwt") {
		t.Fatalf("bad signing key must error, got: %v", err)
	}
}

// Same broken key surfaces through InstallationToken's appJWT() propagation.
func TestInstallationToken_JWTError(t *testing.T) {
	pemStr, _ := testKeyPEM(t)
	a, _ := NewApp("999", pemStr, nil)
	a.privateKey = "not an rsa key"
	if _, err := a.InstallationToken(context.Background(), 9); err == nil ||
		!strings.Contains(err.Error(), "sign jwt") {
		t.Fatalf("jwt error must propagate, got: %v", err)
	}
}

// An invalid API base makes http.NewRequestWithContext fail (the build-request
// defensive branch).
func TestInstallationToken_BadRequestURL(t *testing.T) {
	orig := githubAPIBase
	githubAPIBase = "://not a url"
	defer func() { githubAPIBase = orig }()

	pemStr, _ := testKeyPEM(t)
	a, _ := NewApp("999", pemStr, nil)
	a.httpDo = doFunc(func(*http.Request) (*http.Response, error) {
		t.Fatal("httpDo must not be reached when request build fails")
		return nil, nil
	})
	if _, err := a.InstallationToken(context.Background(), 9); err == nil ||
		!strings.Contains(err.Error(), "build request") {
		t.Fatalf("bad URL must error at request build, got: %v", err)
	}
}

func TestSnippet_Truncates(t *testing.T) {
	if got := snippet([]byte("  short  ")); got != "short" {
		t.Errorf("snippet trim: %q", got)
	}
	long := strings.Repeat("x", 500)
	if got := snippet([]byte(long)); len(got) <= len(long) && !strings.HasSuffix(got, "…") {
		t.Errorf("snippet must truncate long bodies, got len %d", len(got))
	}
}
