package handlers_test

// queue_resolver_wiring_test.go — covers the NATS resolver-pusher wiring
// added to queue_provider.go / queue.go.
//
// The bug being locked down: common/queueprovider/nats minted a per-tenant
// account JWT and pushed it to a NO-OP ResolverPusher, so nats-server never
// learned the account existed and every /queue/new credential failed at
// CONNECT with "Authorization Violation". These tests assert that
//
//  1. a nats backend with an operator seed gets a REAL pusher, and the minted
//     account claim actually reaches it;
//  2. a pusher that cannot be built is a hard error, never a quiet downgrade
//     to legacy_open (that downgrade is what shipped dead credentials);
//  3. a push rejection fails the provision with 503 instead of returning an
//     unusable connection URL;
//  4. a non-nats backend never panics on the SetResolverPusher type assertion.
//
// No NATS server is involved: the pusher-construction seam is swapped.

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/nats-io/nkeys"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	commonqp "instant.dev/common/queueprovider"
	natsqp "instant.dev/common/queueprovider/nats"
	"instant.dev/internal/config"
	"instant.dev/internal/handlers"
	"instant.dev/internal/middleware"
	"instant.dev/internal/models"
	"instant.dev/internal/natsresolver"
	"instant.dev/internal/plans"
	"instant.dev/internal/testhelpers"
)

// ── fixtures ─────────────────────────────────────────────────────────────────

// recordingPusher captures every account claim handed to the resolver and can
// be programmed to reject, exactly as a real nats-server non-ack does.
type recordingPusher struct {
	mu      sync.Mutex
	pushed  []pushedClaim
	pushErr error
}

type pushedClaim struct{ accountPub, accountJWT string }

func (r *recordingPusher) PushAccountClaim(_ context.Context, accountPub, accountJWT string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.pushed = append(r.pushed, pushedClaim{accountPub, accountJWT})
	return r.pushErr
}

func (r *recordingPusher) claims() []pushedClaim {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]pushedClaim(nil), r.pushed...)
}

// mustOperatorSeed returns a real operator NKey seed so the nats provider
// reaches its isolated-credential path (a fake seed fails at builder time).
func mustOperatorSeed(t *testing.T) string {
	t.Helper()
	kp, err := nkeys.CreateOperator()
	require.NoError(t, err)
	seed, err := kp.Seed()
	require.NoError(t, err)
	return string(seed)
}

func sysCredCfg(t *testing.T, backend string) *config.Config {
	t.Helper()
	return &config.Config{
		QueueBackend:       backend,
		NATSOperatorSeed:   mustOperatorSeed(t),
		NATSHost:           "nats.instant-data.svc.cluster.local",
		NATSPublicHost:     "nats.instanode.dev",
		NATSSystemUserJWT:  "eyJ0eXAiOiJKV1QifQ.system.user",
		NATSSystemUserSeed: "SUAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
	}
}

// ── attachResolverPusher ─────────────────────────────────────────────────────

// TestAttachResolverPusher_Arms is the wiring table: which configurations get
// a pusher, which skip it, and which fail loudly.
func TestAttachResolverPusher_Arms(t *testing.T) {
	tests := []struct {
		name string
		// cfgFn builds the config under test.
		cfgFn func(t *testing.T) *config.Config
		// factoryErr, when set, makes the pusher constructor fail.
		factoryErr error
		wantErr    bool
		wantErrHas string
		// wantFactoryCalls is how often the pusher constructor should run.
		wantFactoryCalls int
		wantBackend      string
	}{
		{
			name:             "nats backend with operator seed attaches a real pusher",
			cfgFn:            func(t *testing.T) *config.Config { return sysCredCfg(t, "nats") },
			wantFactoryCalls: 1,
			wantBackend:      "nats",
		},
		{
			name: "nats backend without an operator seed skips the pusher",
			cfgFn: func(*testing.T) *config.Config {
				return &config.Config{
					QueueBackend:   "nats",
					NATSHost:       "nats.test",
					NATSPublicHost: "nats.instanode.dev",
				}
			},
			wantFactoryCalls: 0,
			wantBackend:      "nats",
		},
		{
			name: "non-nats backend has no SetResolverPusher — type assertion misses, no panic",
			cfgFn: func(t *testing.T) *config.Config {
				// Operator seed present but the backend is legacy_open: the
				// returned provider does not implement the setter at all.
				return sysCredCfg(t, "legacy_open")
			},
			wantFactoryCalls: 0,
			wantBackend:      "legacy_open",
		},
		{
			name:             "pusher construction failure is a hard error, never a legacy_open downgrade",
			cfgFn:            func(t *testing.T) *config.Config { return sysCredCfg(t, "nats") },
			factoryErr:       fmt.Errorf("%w: connect refused", natsresolver.ErrPushFailed),
			wantErr:          true,
			wantErrHas:       natsresolver.ClaimsUpdateSubject,
			wantFactoryCalls: 1,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var calls int
			var gotCfg natsresolver.Config
			restore := handlers.SwapResolverPusherFactoryForTest(
				func(c natsresolver.Config) (natsqp.ResolverPusher, error) {
					calls++
					gotCfg = c
					if tc.factoryErr != nil {
						return nil, tc.factoryErr
					}
					return &recordingPusher{}, nil
				})
			defer restore()

			cfg := tc.cfgFn(t)
			qp, err := handlers.BuildQueueProviderForTest(cfg)

			assert.Equal(t, tc.wantFactoryCalls, calls, "resolver-pusher constructor call count")
			if tc.wantErr {
				require.Error(t, err)
				assert.Nil(t, qp, "a provider that cannot push claims must not be returned")
				assert.Contains(t, err.Error(), tc.wantErrHas)
				assert.ErrorIs(t, err, natsresolver.ErrPushFailed)
				return
			}
			require.NoError(t, err)
			require.NotNil(t, qp)
			assert.Equal(t, tc.wantBackend, qp.Name())
			if tc.wantFactoryCalls > 0 {
				assert.Equal(t, "nats://nats.instant-data.svc.cluster.local:4222", gotCfg.URL)
				assert.Equal(t, cfg.NATSSystemUserJWT, gotCfg.UserJWT)
				assert.Equal(t, cfg.NATSSystemUserSeed, gotCfg.UserSeed)
			}
		})
	}
}

// TestAttachResolverPusher_ClaimReachesTheResolver is the end-to-end assertion
// the original bug failed: minting a tenant account must PUBLISH that account's
// claim, otherwise the credential is dead on arrival.
func TestAttachResolverPusher_ClaimReachesTheResolver(t *testing.T) {
	rec := &recordingPusher{}
	restore := handlers.SwapResolverPusherFactoryForTest(
		func(natsresolver.Config) (natsqp.ResolverPusher, error) { return rec, nil })
	defer restore()

	qp, err := handlers.BuildQueueProviderForTest(sysCredCfg(t, "nats"))
	require.NoError(t, err)

	token := uuid.NewString()
	creds, err := qp.IssueTenantCredentials(context.Background(), commonqp.IssueRequest{ResourceToken: token})
	require.NoError(t, err)
	require.NotNil(t, creds)
	assert.Equal(t, commonqp.AuthModeIsolated, creds.AuthMode)

	claims := rec.claims()
	require.Len(t, claims, 1, "exactly one account claim must be pushed per issued credential")
	assert.Equal(t, creds.KeyID, claims[0].accountPub,
		"the pushed account must be the one the returned user JWT belongs to")
	assert.NotEmpty(t, claims[0].accountJWT)
}

// TestAttachResolverPusher_RejectedClaimFailsIssuance — a resolver that does
// not ack must abort issuance, and the error must be recognisable as an
// isolation failure so the handler can 503.
func TestAttachResolverPusher_RejectedClaimFailsIssuance(t *testing.T) {
	rec := &recordingPusher{pushErr: fmt.Errorf("%w: resolver did not ack", natsresolver.ErrPushFailed)}
	restore := handlers.SwapResolverPusherFactoryForTest(
		func(natsresolver.Config) (natsqp.ResolverPusher, error) { return rec, nil })
	defer restore()

	qp, err := handlers.BuildQueueProviderForTest(sysCredCfg(t, "nats"))
	require.NoError(t, err)

	creds, err := qp.IssueTenantCredentials(context.Background(),
		commonqp.IssueRequest{ResourceToken: uuid.NewString()})
	require.Error(t, err)
	assert.Nil(t, creds, "no credential may be returned when the claim was not installed")
	assert.True(t, handlers.IsolationUnavailableForTest(err),
		"a push rejection must be classified as isolation-unavailable so /queue/new 503s")
}

// ── natsSystemURL ────────────────────────────────────────────────────────────

func TestNATSSystemURL(t *testing.T) {
	tests := []struct {
		name string
		cfg  *config.Config
		want string
	}{
		{
			name: "derived from NATS_HOST",
			cfg:  &config.Config{NATSHost: "nats.instant-data.svc.cluster.local"},
			want: "nats://nats.instant-data.svc.cluster.local:4222",
		},
		{
			name: "explicit NATS_SYSTEM_URL wins",
			cfg:  &config.Config{NATSHost: "ignored", NATSSystemURL: "tls://nats.example:4443"},
			want: "tls://nats.example:4443",
		},
		{
			name: "whitespace-only override falls back to the derived URL",
			cfg:  &config.Config{NATSHost: "nats.test", NATSSystemURL: "   "},
			want: "nats://nats.test:4222",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, handlers.NATSSystemURLForTest(tc.cfg))
		})
	}
}

// ── isolationUnavailable / unavailableCredProvider ───────────────────────────

func TestIsolationUnavailable(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{name: "nil error", err: nil, want: false},
		{name: "unrelated error", err: errors.New("operator seed unavailable"), want: false},
		{name: "sentinel", err: natsresolver.ErrPushFailed, want: true},
		{
			name: "wrapped sentinel (the shape the nats provider returns)",
			err: fmt.Errorf("queueprovider.nats: push account claim to resolver: %w",
				fmt.Errorf("%w: timeout", natsresolver.ErrPushFailed)),
			want: true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, handlers.IsolationUnavailableForTest(tc.err))
		})
	}
}

func TestUnavailableCredProvider(t *testing.T) {
	cause := errors.New("resolver pusher could not connect")
	p := handlers.NewUnavailableCredProviderForTest(cause)

	assert.Equal(t, "nats-unavailable", p.Name())
	caps := p.Capabilities()
	assert.True(t, caps.PerTenantAccounts, "isolation is configured — the capability is still advertised")
	assert.True(t, caps.SubjectScopedAuth)
	assert.True(t, caps.StreamIsolation)
	assert.NoError(t, p.RevokeTenantCredentials(context.Background(), "AKEY"))

	creds, err := p.IssueTenantCredentials(context.Background(),
		commonqp.IssueRequest{ResourceToken: uuid.NewString()})
	require.Error(t, err)
	assert.Nil(t, creds)
	assert.True(t, handlers.IsolationUnavailableForTest(err))
	assert.Contains(t, err.Error(), cause.Error())
}

// ── handler behaviour: 503 instead of a dead connection URL ──────────────────

// queueResolverApp builds a /queue/new app whose QueueHandler is constructed
// from cfg — i.e. the real NewQueueHandler branch selection runs, including
// the "isolation configured but broken" arm.
func queueResolverApp(t *testing.T, db *sql.DB, rdb *redis.Client, cfg *config.Config) *fiber.App {
	t.Helper()
	cfg.JWTSecret = testhelpers.TestJWTSecret
	cfg.AESKey = testhelpers.TestAESKeyHex
	cfg.EnabledServices = "queue"
	cfg.Environment = "test"
	// The local queue provider health-checks http://<NATSHost>:8222/healthz
	// before returning a URL; an empty host resolves to localhost, where both
	// CI (ci.yml / deploy.yml run nats-server with -m 8222) and the local gate
	// have a NATS. Without this the provision 503s before the credential step
	// under test is ever reached.
	cfg.NATSHost = ""
	app := fiber.New(fiber.Config{
		ErrorHandler: func(c *fiber.Ctx, err error) error {
			if errors.Is(err, handlers.ErrResponseWritten) {
				return nil
			}
			return c.Status(fiber.StatusInternalServerError).
				JSON(fiber.Map{"ok": false, "error": "internal_error", "message": err.Error()})
		},
	})
	app.Use(middleware.RequestID(), middleware.Fingerprint())
	h := handlers.NewQueueHandler(db, rdb, cfg, nil, plans.Default())
	app.Post("/queue/new", middleware.OptionalAuth(cfg), h.NewQueue)
	return app
}

type queueErrBody struct {
	OK      bool   `json:"ok"`
	Error   string `json:"error"`
	Message string `json:"message"`
}

func postQueueNew(t *testing.T, app *fiber.App, ip, bearer string) (int, queueErrBody) {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/queue/new", strings.NewReader(`{"name":"events"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Forwarded-For", ip)
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	resp, err := app.Test(req, 10000)
	require.NoError(t, err)
	defer resp.Body.Close()
	var body queueErrBody
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	return resp.StatusCode, body
}

// TestQueueNew_IsolationBroken_Returns503_Anonymous — with the operator seed
// configured and the resolver pusher unbuildable, the anonymous path must NOT
// answer 201 with a legacy_open URL (which no client could connect to against
// an auth_required server). It must fail the provision.
func TestQueueNew_IsolationBroken_Returns503_Anonymous(t *testing.T) {
	requireTestDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanR := testhelpers.SetupTestRedis(t)
	defer cleanR()

	restore := handlers.SwapResolverPusherFactoryForTest(
		func(natsresolver.Config) (natsqp.ResolverPusher, error) {
			return nil, fmt.Errorf("%w: dial tcp: connection refused", natsresolver.ErrPushFailed)
		})
	defer restore()

	app := queueResolverApp(t, db, rdb, sysCredCfg(t, "nats"))
	status, body := postQueueNew(t, app, "10.71.0.1", "")

	require.Equal(t, http.StatusServiceUnavailable, status)
	assert.False(t, body.OK)
	assert.Equal(t, "provision_failed", body.Error)
	assert.Contains(t, body.Message, "isolated NATS credentials",
		"the 503 must name the credential-issuance failure, not a generic provision failure")
}

// TestQueueNew_IsolationBroken_Returns503_Authenticated — same guarantee on
// the authenticated path (the second issueTenantCreds call site).
func TestQueueNew_IsolationBroken_Returns503_Authenticated(t *testing.T) {
	requireTestDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanR := testhelpers.SetupTestRedis(t)
	defer cleanR()

	restore := handlers.SwapResolverPusherFactoryForTest(
		func(natsresolver.Config) (natsqp.ResolverPusher, error) {
			return nil, fmt.Errorf("%w: dial tcp: connection refused", natsresolver.ErrPushFailed)
		})
	defer restore()

	teamID := testhelpers.MustCreateTeamDB(t, db, "hobby")
	sessionJWT := testhelpers.MustSignSessionJWT(t, "user-queue-iso", teamID, "queue-iso@example.com")

	app := queueResolverApp(t, db, rdb, sysCredCfg(t, "nats"))
	status, body := postQueueNew(t, app, "10.71.0.2", sessionJWT)

	require.Equal(t, http.StatusServiceUnavailable, status)
	assert.Equal(t, "provision_failed", body.Error)
	assert.Contains(t, body.Message, "isolated NATS credentials")
}

// TestFailQueueCredIssue_MarkFailedError_IsLogged drives the mark-failed
// error branch of the shared teardown helper with a closed DB.
func TestFailQueueCredIssue_MarkFailedError_IsLogged(t *testing.T) {
	cfg := &config.Config{AESKey: testhelpers.TestAESKeyHex, EnabledServices: "queue"}
	h := handlers.NewQueueHandler(closedPlatformDB(t), nil, cfg, nil, plans.Default())

	app := fiber.New(fiber.Config{
		ErrorHandler: func(c *fiber.Ctx, err error) error {
			if errors.Is(err, handlers.ErrResponseWritten) {
				return nil
			}
			return c.SendStatus(fiber.StatusTeapot)
		},
	})
	res := &models.Resource{ID: uuid.New()}
	app.Post("/fail", func(c *fiber.Ctx) error {
		return h.FailQueueCredIssueForTest(c, res, "prid-1", "tok-1", "queue.test",
			fmt.Errorf("%w: rejected", natsresolver.ErrPushFailed))
	})

	resp, err := app.Test(httptest.NewRequest(http.MethodPost, "/fail", nil), 5000)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode,
		"a broken isolation path is a 503, never a partially-issued 201")
}
