// Package github implements the InstaNode GitHub App (P4) token layer: it signs
// an App JWT with the App's RSA private key and exchanges it for short-lived,
// least-privilege installation access tokens used to clone private repos during
// a source=git build. Tokens are minted on demand and cached in Redis (~55 min);
// the only secret stored at rest is the App private key (an operator k8s secret).
package github

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/redis/go-redis/v9"
)

// githubAPIBase is the GitHub REST base. A package var so tests can point it at
// a local httptest server (the injected httpDo also intercepts, but keeping the
// base overridable keeps request-shape assertions honest).
var githubAPIBase = "https://api.github.com"

// installationTokenTTL caches a minted token below GitHub's 1h expiry so a build
// never races the boundary.
const installationTokenTTL = 55 * time.Minute

// App mints installation access tokens for the InstaNode GitHub App.
type App struct {
	appID      string
	privateKey interface{} // *rsa.PrivateKey (parsed from PEM)
	rdb        *redis.Client
	// httpDo / now are injectable for deterministic tests.
	httpDo func(*http.Request) (*http.Response, error)
	now    func() time.Time
}

// NewApp parses the App private-key PEM and returns a minter. rdb may be nil
// (no caching — every call mints). Returns an error on a malformed key or empty
// appID so a misconfigured deployment fails loudly at construction, not mid-build.
func NewApp(appID, privateKeyPEM string, rdb *redis.Client) (*App, error) {
	if strings.TrimSpace(appID) == "" {
		return nil, fmt.Errorf("github app: GITHUB_APP_ID is empty")
	}
	key, err := jwt.ParseRSAPrivateKeyFromPEM([]byte(privateKeyPEM))
	if err != nil {
		return nil, fmt.Errorf("github app: parse private key: %w", err)
	}
	return &App{
		appID:      appID,
		privateKey: key,
		rdb:        rdb,
		httpDo:     http.DefaultClient.Do,
		now:        time.Now,
	}, nil
}

// appJWT mints a short-lived RS256 JWT identifying the App (GitHub requires
// exp ≤ 10 min; we use 9 min and backdate iat 30s for clock-skew tolerance).
func (a *App) appJWT() (string, error) {
	now := a.now()
	claims := jwt.RegisteredClaims{
		Issuer:    a.appID,
		IssuedAt:  jwt.NewNumericDate(now.Add(-30 * time.Second)),
		ExpiresAt: jwt.NewNumericDate(now.Add(9 * time.Minute)),
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	signed, err := tok.SignedString(a.privateKey)
	if err != nil {
		return "", fmt.Errorf("github app: sign jwt: %w", err)
	}
	return signed, nil
}

// InstallationToken returns a `contents:read`-scoped installation access token,
// served from the Redis cache when warm or freshly minted from GitHub otherwise.
func (a *App) InstallationToken(ctx context.Context, installationID int64) (string, error) {
	cacheKey := fmt.Sprintf("ghapp:insttok:%d", installationID)
	if a.rdb != nil {
		if v, err := a.rdb.Get(ctx, cacheKey).Result(); err == nil && v != "" {
			return v, nil
		}
	}

	appJWT, err := a.appJWT()
	if err != nil {
		return "", err
	}
	url := fmt.Sprintf("%s/app/installations/%d/access_tokens", githubAPIBase, installationID)
	// Least privilege: only the permissions a clone build needs.
	body := strings.NewReader(`{"permissions":{"contents":"read","metadata":"read"}}`)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, body)
	if err != nil {
		return "", fmt.Errorf("github app: build request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+appJWT)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	req.Header.Set("Content-Type", "application/json")

	resp, err := a.httpDo(req)
	if err != nil {
		return "", fmt.Errorf("github app: access_tokens request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusCreated {
		return "", fmt.Errorf("github app: access_tokens status %d: %s", resp.StatusCode, snippet(raw))
	}
	var out struct {
		Token     string    `json:"token"`
		ExpiresAt time.Time `json:"expires_at"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return "", fmt.Errorf("github app: decode access_tokens: %w", err)
	}
	if out.Token == "" {
		return "", fmt.Errorf("github app: access_tokens returned an empty token")
	}
	if a.rdb != nil {
		// Best-effort cache; a failure here just means the next clone re-mints.
		_ = a.rdb.Set(ctx, cacheKey, out.Token, installationTokenTTL).Err()
	}
	return out.Token, nil
}

// snippet truncates an error body for safe logging (never echo a full GitHub
// response into our error chain / logs).
func snippet(b []byte) string {
	const max = 200
	s := strings.TrimSpace(string(b))
	if len(s) > max {
		return s[:max] + "…"
	}
	return s
}
