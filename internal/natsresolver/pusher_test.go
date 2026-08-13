package natsresolver

// pusher_test.go — in-package tests for the SYS-account resolver pusher.
//
// In-package (not natsresolver_test) so the connectFn dial seam can be
// substituted: every test here runs without a NATS server, which is the point
// — the ack / non-ack / timeout arms are exactly the ones a live-server test
// cannot force on demand.

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	testAccountPub = "ACCOUNTPUBLICKEY123456789"
	testAccountJWT = "eyJ0eXAiOiJKV1QifQ.account.claim"
	testSysJWT     = "eyJ0eXAiOiJKV1QifQ.system.user"
	testSysSeed    = "SUAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
)

// fakeRequester is a programmable stand-in for *nats.Conn.
type fakeRequester struct {
	mu      sync.Mutex
	reply   *nats.Msg
	err     error
	block   bool // block until the context deadline fires
	gotSubj string
	gotData []byte
	calls   int
	closed  bool
}

func (f *fakeRequester) RequestWithContext(ctx context.Context, subj string, data []byte) (*nats.Msg, error) {
	f.mu.Lock()
	f.calls++
	f.gotSubj = subj
	f.gotData = data
	block, reply, err := f.block, f.reply, f.err
	f.mu.Unlock()

	if block {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	return reply, err
}

func (f *fakeRequester) Close() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.closed = true
}

func (f *fakeRequester) snapshot() (subj string, data []byte, calls int, closed bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.gotSubj, f.gotData, f.calls, f.closed
}

// withConnect swaps the dial seam for the duration of a test.
func withConnect(t *testing.T, fn func(url string, opts ...nats.Option) (Requester, error)) {
	t.Helper()
	prev := connectFn
	connectFn = fn
	t.Cleanup(func() { connectFn = prev })
}

func msgOf(payload string) *nats.Msg {
	return &nats.Msg{Data: []byte(payload)}
}

func validConfig() Config {
	return Config{URL: "nats://nats.test:4222", UserJWT: testSysJWT, UserSeed: testSysSeed}
}

// ── New ──────────────────────────────────────────────────────────────────────

// TestNew_ValidationAndDial covers every constructor arm: each missing
// credential, an unreachable server, and the two success shapes (default and
// explicit push timeout). The "pusher constructed / not constructed" split
// lives here.
func TestNew_ValidationAndDial(t *testing.T) {
	dialErr := errors.New("nats: no servers available for connection, seed " + testSysSeed)

	tests := []struct {
		name        string
		cfg         Config
		dial        func(url string, opts ...nats.Option) (Requester, error)
		wantErr     bool
		wantErrHas  string
		wantTimeout time.Duration
	}{
		{
			name:       "missing url",
			cfg:        Config{UserJWT: testSysJWT, UserSeed: testSysSeed},
			wantErr:    true,
			wantErrHas: "no NATS URL configured",
		},
		{
			name:       "missing user jwt",
			cfg:        Config{URL: "nats://nats.test:4222", UserSeed: testSysSeed},
			wantErr:    true,
			wantErrHas: "no system-account user JWT configured",
		},
		{
			name:       "blank user seed",
			cfg:        Config{URL: "nats://nats.test:4222", UserJWT: testSysJWT, UserSeed: "   "},
			wantErr:    true,
			wantErrHas: "no system-account user NKey seed configured",
		},
		{
			name: "dial failure surfaces as an error, never a no-op pusher",
			cfg:  validConfig(),
			dial: func(string, ...nats.Option) (Requester, error) {
				return nil, dialErr
			},
			wantErr:    true,
			wantErrHas: "connect to nats://nats.test:4222 as system user",
		},
		{
			name:        "constructed with default timeout",
			cfg:         validConfig(),
			wantTimeout: DefaultPushTimeout,
		},
		{
			name: "constructed with explicit timeout",
			cfg: Config{
				URL: "nats://nats.test:4222", UserJWT: testSysJWT,
				UserSeed: testSysSeed, Timeout: 250 * time.Millisecond,
			},
			wantTimeout: 250 * time.Millisecond,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var gotURL string
			var gotOpts int
			dial := tc.dial
			if dial == nil {
				dial = func(url string, opts ...nats.Option) (Requester, error) {
					gotURL, gotOpts = url, len(opts)
					return &fakeRequester{}, nil
				}
			}
			withConnect(t, dial)

			p, err := New(tc.cfg)
			if tc.wantErr {
				require.Error(t, err)
				assert.Nil(t, p, "a failed New must not return a usable pusher")
				assert.ErrorIs(t, err, ErrPushFailed, "every failure wraps the sentinel")
				assert.Contains(t, err.Error(), tc.wantErrHas)
				assert.NotContains(t, err.Error(), testSysSeed, "the NKey seed must never reach an error string")
				return
			}
			require.NoError(t, err)
			require.NotNil(t, p)
			assert.Equal(t, tc.wantTimeout, p.timeout)
			assert.Equal(t, tc.cfg.URL, gotURL)
			assert.Positive(t, gotOpts, "connection options (creds, reconnect, handlers) must be passed")
			assert.Equal(t, []string{testSysJWT, testSysSeed}, p.secrets)
		})
	}
}

// TestNatsOptions_CarriesIdentityAndReconnect asserts the option set is the
// production one — a real nats.Options is materialised from it so a renamed
// or dropped option fails here rather than at 3am in the cluster.
func TestNatsOptions_CarriesIdentityAndReconnect(t *testing.T) {
	var opts nats.Options
	for _, apply := range natsOptions(validConfig()) {
		require.NoError(t, apply(&opts))
	}
	assert.Equal(t, ConnectionName, opts.Name)
	assert.Equal(t, DefaultDialTimeout, opts.Timeout)
	assert.Equal(t, reconnectForever, opts.MaxReconnect)
	assert.Equal(t, reconnectWait, opts.ReconnectWait)
	assert.NotNil(t, opts.DisconnectedErrCB)
	assert.NotNil(t, opts.ReconnectedCB)
	assert.NotEmpty(t, opts.UserJWT, "SYS user JWT callback must be installed")
}

// TestLifecycleHandlers_DoNotPanic — the reconnect callbacks run on a
// nats.go goroutine; they must never touch the connection.
func TestLifecycleHandlers_DoNotPanic(t *testing.T) {
	assert.NotPanics(t, func() { onDisconnect(nil, errors.New("connection reset")) })
	assert.NotPanics(t, func() { onDisconnect(nil, nil) })
	assert.NotPanics(t, func() { onReconnect(nil) })
}

// ── PushAccountClaim ─────────────────────────────────────────────────────────

// TestPushAccountClaim_ReplyHandling is the core table: an ack is the ONLY
// outcome that returns nil. Every other reply shape must error, because a
// claim that may not be installed must never be reported as installed.
func TestPushAccountClaim_ReplyHandling(t *testing.T) {
	tests := []struct {
		name       string
		reply      *nats.Msg
		reqErr     error
		wantErr    bool
		wantErrHas string
	}{
		{
			name:  "ack — code 200 with matching account",
			reply: msgOf(`{"server":{"name":"n1"},"data":{"account":"` + testAccountPub + `","code":200,"message":"jwt updated"}}`),
		},
		{
			name:  "ack — 2xx with no account echoed back",
			reply: msgOf(`{"data":{"code":204,"message":"jwt updated"}}`),
		},
		{
			name:       "non-ack — server-side 500 in the data envelope",
			reply:      msgOf(`{"data":{"account":"` + testAccountPub + `","code":500,"description":"jwt update skipped - memory resolver"}}`),
			wantErr:    true,
			wantErrHas: "resolver did not ack",
		},
		{
			name:       "non-ack — 4xx with only a message field",
			reply:      msgOf(`{"data":{"code":400,"message":"bad claim"}}`),
			wantErr:    true,
			wantErrHas: "bad claim",
		},
		{
			name:       "non-ack — top-level error envelope",
			reply:      msgOf(`{"error":{"code":401,"description":"permissions violation"}}`),
			wantErr:    true,
			wantErrHas: "resolver returned an error",
		},
		{
			name:       "non-ack — no data envelope at all",
			reply:      msgOf(`{"server":{"name":"n1"}}`),
			wantErr:    true,
			wantErrHas: "carried no data envelope",
		},
		{
			name:       "non-ack — reply names a different account",
			reply:      msgOf(`{"data":{"account":"AOTHERACCOUNT","code":200,"message":"jwt updated"}}`),
			wantErr:    true,
			wantErrHas: "acked a different account",
		},
		{
			name:       "non-ack — unparseable reply",
			reply:      msgOf(`not-json`),
			wantErr:    true,
			wantErrHas: "unparseable resolver reply",
		},
		{
			name:       "non-ack — empty reply body",
			reply:      msgOf(``),
			wantErr:    true,
			wantErrHas: "empty reply from resolver",
		},
		{
			name:       "non-ack — nil message",
			reply:      nil,
			wantErr:    true,
			wantErrHas: "empty reply from resolver",
		},
		{
			name:       "transport error is redacted",
			reqErr:     errors.New("write failed for user " + testSysJWT),
			wantErr:    true,
			wantErrHas: ClaimsUpdateSubject,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			fake := &fakeRequester{reply: tc.reply, err: tc.reqErr}
			p := &Pusher{conn: fake, timeout: time.Second, secrets: []string{testSysJWT, testSysSeed}}

			err := p.PushAccountClaim(context.Background(), testAccountPub, testAccountJWT)

			subj, data, calls, _ := fake.snapshot()
			assert.Equal(t, ClaimsUpdateSubject, subj)
			assert.Equal(t, testAccountJWT, string(data), "the raw account JWT is the request payload")
			assert.Equal(t, 1, calls)

			if !tc.wantErr {
				require.NoError(t, err)
				return
			}
			require.Error(t, err)
			assert.ErrorIs(t, err, ErrPushFailed)
			assert.Contains(t, err.Error(), tc.wantErrHas)
			assert.NotContains(t, err.Error(), testSysJWT, "credentials must be redacted from error strings")
		})
	}
}

// TestPushAccountClaim_Timeout — a NATS server that never replies must fail
// inside the push budget, so /queue/new can return 503 instead of hanging.
func TestPushAccountClaim_Timeout(t *testing.T) {
	fake := &fakeRequester{block: true}
	p := &Pusher{conn: fake, timeout: 30 * time.Millisecond}

	start := time.Now()
	err := p.PushAccountClaim(context.Background(), testAccountPub, testAccountJWT)
	elapsed := time.Since(start)

	require.Error(t, err)
	assert.ErrorIs(t, err, ErrPushFailed)
	assert.Contains(t, err.Error(), context.DeadlineExceeded.Error())
	assert.Less(t, elapsed, 2*time.Second, "the push must be bounded by Pusher.timeout")
}

// TestPushAccountClaim_Guards covers the arms that never reach the wire.
func TestPushAccountClaim_Guards(t *testing.T) {
	t.Run("nil pusher", func(t *testing.T) {
		var p *Pusher
		err := p.PushAccountClaim(context.Background(), testAccountPub, testAccountJWT)
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrPushFailed)
		assert.Contains(t, err.Error(), "not initialised")
	})

	t.Run("pusher with no connection", func(t *testing.T) {
		err := (&Pusher{}).PushAccountClaim(context.Background(), testAccountPub, testAccountJWT)
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrPushFailed)
	})

	t.Run("empty account jwt", func(t *testing.T) {
		fake := &fakeRequester{}
		p := &Pusher{conn: fake, timeout: time.Second}
		err := p.PushAccountClaim(context.Background(), testAccountPub, "")
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrPushFailed)
		_, _, calls, _ := fake.snapshot()
		assert.Zero(t, calls, "an empty claim must not be published")
	})

	t.Run("nil context is tolerated", func(t *testing.T) {
		// A nil ctx would panic inside context.WithTimeout; the guard turns
		// it into a background context. Assigned to a variable so staticcheck
		// does not flag the literal-nil call.
		var nilCtx context.Context
		fake := &fakeRequester{reply: msgOf(`{"data":{"code":200,"message":"jwt updated"}}`)}
		p := &Pusher{conn: fake, timeout: time.Second}
		require.NoError(t, p.PushAccountClaim(nilCtx, testAccountPub, testAccountJWT))
	})

	t.Run("caller cancellation propagates", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		p := &Pusher{conn: &fakeRequester{block: true}, timeout: time.Minute}
		err := p.PushAccountClaim(ctx, testAccountPub, testAccountJWT)
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrPushFailed)
	})
}

// ── Close / helpers ──────────────────────────────────────────────────────────

func TestClose(t *testing.T) {
	t.Run("nil pusher is a no-op", func(t *testing.T) {
		var p *Pusher
		assert.NotPanics(t, p.Close)
	})
	t.Run("pusher with no connection is a no-op", func(t *testing.T) {
		assert.NotPanics(t, (&Pusher{}).Close)
	})
	t.Run("closes the underlying connection", func(t *testing.T) {
		fake := &fakeRequester{}
		(&Pusher{conn: fake}).Close()
		_, _, _, closed := fake.snapshot()
		assert.True(t, closed)
	})
}

func TestRedact(t *testing.T) {
	tests := []struct {
		name    string
		in      string
		secrets []string
		want    string
	}{
		{
			name:    "replaces every occurrence",
			in:      "auth error for " + testSysSeed + " (" + testSysSeed + ")",
			secrets: []string{testSysSeed},
			want:    "auth error for " + redactedPlaceholder + " (" + redactedPlaceholder + ")",
		},
		{
			name:    "short secrets are skipped so common substrings survive",
			in:      "connection refused",
			secrets: []string{"con"},
			want:    "connection refused",
		},
		{
			name: "no secrets configured",
			in:   "plain error",
			want: "plain error",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, redact(tc.in, tc.secrets...))
		})
	}

	t.Run("method form uses the pusher's own secrets", func(t *testing.T) {
		p := &Pusher{secrets: []string{testSysJWT}}
		assert.Equal(t, "boom "+redactedPlaceholder, p.redact("boom "+testSysJWT))
	})
}

func TestAckDetail(t *testing.T) {
	assert.Equal(t, "why it failed", ackDetail(&claimsUpdateData{Description: "why it failed", Message: "m"}))
	assert.Equal(t, "jwt updated", ackDetail(&claimsUpdateData{Message: "jwt updated"}))
}

func TestErrString(t *testing.T) {
	assert.Empty(t, errString(nil))
	assert.Equal(t, "boom", errString(errors.New("boom")))
}

// TestConnectFn_DefaultDialsRealNATS exercises the production dial seam
// itself (the one every other test replaces) against an address with no
// listener: it must return an error and no Requester, never a half-built
// connection. Keeps the seam's own two lines honest.
func TestConnectFn_DefaultDialsRealNATS(t *testing.T) {
	conn, err := connectFn("nats://127.0.0.1:1", nats.Timeout(200*time.Millisecond), nats.MaxReconnects(0))
	require.Error(t, err)
	assert.Nil(t, conn)
	assert.True(t,
		strings.Contains(err.Error(), "connection refused") || strings.Contains(err.Error(), "no servers"),
		"unexpected dial error: %v", err)
}
