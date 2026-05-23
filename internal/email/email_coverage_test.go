package email

// email_coverage_test.go — straggler coverage for the low-level dispatch,
// provider, and helper paths that the behavioural tests don't reach:
//   - resolveProvider precedence (explicit strings + key-based inference)
//   - ProviderName nil-provider branch
//   - sendWithKey: nil provider, suppression fail-open + suppressed,
//     ledger probe fail-open + dedup, MarkSent fail-open
//   - brevoProvider.Send: empty recipient, non-2xx status, keyed headers
//   - resendProvider.Send: keyless + keyed happy paths and the error path
//   - maskEmail edge cases (no "@", leading "@", one-char local part)
//
// White-box (package email) so we can construct providers directly and
// reach unexported fields.

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	resend "github.com/resend/resend-go/v2"
)

// ---------------------------------------------------------------------------
// resolveProvider
// ---------------------------------------------------------------------------

func TestResolveProvider_Precedence(t *testing.T) {
	cases := []struct {
		name string
		cfg  Config
		want ProviderName
	}{
		{"explicit brevo", Config{Provider: "brevo"}, ProviderBrevo},
		{"explicit resend", Config{Provider: "Resend"}, ProviderResend},
		{"explicit noop", Config{Provider: "noop"}, ProviderNoop},
		{"brevo key infers brevo", Config{BrevoAPIKey: "xkeysib-x"}, ProviderBrevo},
		{"resend key infers resend", Config{ResendAPIKey: "re_live_x"}, ProviderResend},
		{"resend sentinel ignored", Config{ResendAPIKey: resendSentinelUnset}, ProviderNoop},
		{"empty config defaults noop", Config{}, ProviderNoop},
		{"brevo key wins over resend key", Config{BrevoAPIKey: "x", ResendAPIKey: "re_y"}, ProviderBrevo},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := resolveProvider(tc.cfg); got != tc.want {
				t.Errorf("resolveProvider = %v, want %v", got, tc.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// ProviderName nil-provider branch
// ---------------------------------------------------------------------------

func TestClient_ProviderName_NilProviderReturnsNoop(t *testing.T) {
	c := &Client{} // zero value, provider is nil
	if got := c.ProviderName(); got != ProviderNoop {
		t.Errorf("ProviderName on nil-provider client = %v, want ProviderNoop", got)
	}
}

// ---------------------------------------------------------------------------
// sendWithKey paths
// ---------------------------------------------------------------------------

func TestSendWithKey_NilProviderIsNoop(t *testing.T) {
	c := &Client{} // provider nil → defensive noop, returns nil
	if err := c.sendWithKey(context.Background(), "u@example.com", "s", "t", "h", "", ""); err != nil {
		t.Errorf("nil-provider sendWithKey: want nil, got %v", err)
	}
}

// covSuppression returns a fixed (suppressed, err) for IsSuppressed. Named to
// avoid colliding with the existing fakeSuppression in email_test.go.
type covSuppression struct {
	suppressed bool
	err        error
}

func (f covSuppression) IsSuppressed(_ context.Context, _ string) (bool, error) {
	return f.suppressed, f.err
}

func TestSendWithKey_SuppressionErrorFailsOpen(t *testing.T) {
	c := NewNoop().WithSuppressionChecker(covSuppression{err: errors.New("db down")})
	// Fail-open: a suppression-lookup error must still deliver (noop → nil).
	if err := c.sendWithKey(context.Background(), "u@example.com", "s", "t", "h", "", ""); err != nil {
		t.Errorf("suppression fail-open: want nil, got %v", err)
	}
}

func TestSendWithKey_SuppressedRecipientSkipped(t *testing.T) {
	c := NewNoop().WithSuppressionChecker(covSuppression{suppressed: true})
	if err := c.sendWithKey(context.Background(), "u@example.com", "s", "t", "h", "", ""); err != nil {
		t.Errorf("suppressed recipient: want nil (skipped), got %v", err)
	}
}

// covLedger drives the SendLedger probe + mark branches. Named to avoid
// colliding with the existing fakeLedger in breaker_test.go.
type covLedger struct {
	sent        bool
	sentErr     error
	markErr     error
	markedKeys  []string
	markedKinds []string
}

func (f *covLedger) Sent(_ context.Context, _ string) (bool, error) {
	return f.sent, f.sentErr
}

func (f *covLedger) MarkSent(_ context.Context, key, kind string) error {
	f.markedKeys = append(f.markedKeys, key)
	f.markedKinds = append(f.markedKinds, kind)
	return f.markErr
}

func TestSendWithKey_LedgerProbeErrorFailsOpen(t *testing.T) {
	led := &covLedger{sentErr: errors.New("probe boom")}
	c := NewNoop().WithSendLedger(led)
	// Probe error → fail open → send proceeds → MarkSent attempted.
	if err := c.sendWithKey(context.Background(), "u@example.com", "s", "t", "h", "key-1", "magic_link"); err != nil {
		t.Errorf("ledger probe fail-open: want nil, got %v", err)
	}
	if len(led.markedKeys) != 1 || led.markedKeys[0] != "key-1" {
		t.Errorf("expected MarkSent(key-1), got %v", led.markedKeys)
	}
}

func TestSendWithKey_LedgerDedupSkips(t *testing.T) {
	led := &covLedger{sent: true}
	c := NewNoop().WithSendLedger(led)
	if err := c.sendWithKey(context.Background(), "u@example.com", "s", "t", "h", "key-dup", "magic_link"); err != nil {
		t.Errorf("ledger dedup: want nil, got %v", err)
	}
	if len(led.markedKeys) != 0 {
		t.Errorf("deduped send must not MarkSent, got %v", led.markedKeys)
	}
}

func TestSendWithKey_MarkSentErrorIsSwallowed(t *testing.T) {
	led := &covLedger{markErr: errors.New("mark boom")}
	c := NewNoop().WithSendLedger(led)
	// MarkSent error is best-effort — must not surface to the caller.
	if err := c.sendWithKey(context.Background(), "u@example.com", "s", "t", "h", "key-2", "team_invite"); err != nil {
		t.Errorf("MarkSent error must be swallowed, got %v", err)
	}
}

// covRewriter is a RoundTripper that rewrites scheme+host to the test server.
// (email_test.go's urlRewriter lives in the external email_test package and is
// not visible here in package email.)
type covRewriter struct{ base string }

func (u *covRewriter) RoundTrip(req *http.Request) (*http.Response, error) {
	if idx := strings.Index(u.base, "://"); idx > 0 {
		req.URL.Scheme = u.base[:idx]
		req.URL.Host = u.base[idx+3:]
	}
	return http.DefaultTransport.RoundTrip(req)
}

// ---------------------------------------------------------------------------
// brevoProvider.Send error + keyed-header paths
// ---------------------------------------------------------------------------

func TestBrevoProvider_Send_EmptyRecipientErrors(t *testing.T) {
	p := &brevoProvider{apiKey: "k", http: http.DefaultClient, fromName: "I", fromAddr: "n@i.dev"}
	err := p.Send(context.Background(), "   ", "s", "t", "h", "")
	if err == nil || !strings.Contains(err.Error(), "empty recipient") {
		t.Fatalf("empty recipient: want error, got %v", err)
	}
}

func TestBrevoProvider_Send_Non2xxStatusErrors(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"message":"sender not verified"}`))
	}))
	defer srv.Close()

	p := &brevoProvider{
		apiKey:   "k",
		http:     &http.Client{Transport: &covRewriter{base: srv.URL}},
		fromName: "I", fromAddr: "n@i.dev",
	}
	err := p.Send(context.Background(), "u@example.com", "s", "t", "h", "")
	if err == nil || !strings.Contains(err.Error(), "unexpected status 400") {
		t.Fatalf("non-2xx: want status error, got %v", err)
	}
	if !strings.Contains(err.Error(), "sender not verified") {
		t.Errorf("error must surface body, got %v", err)
	}
}

func TestBrevoProvider_Send_KeyedSetsIdempotencyHeaders(t *testing.T) {
	var customHdr, idemHdr string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		customHdr = r.Header.Get("X-Mailin-Custom")
		idemHdr = r.Header.Get("Idempotency-Key")
		w.WriteHeader(http.StatusCreated)
	}))
	defer srv.Close()

	p := &brevoProvider{
		apiKey:   "k",
		http:     &http.Client{Transport: &covRewriter{base: srv.URL}},
		fromName: "I", fromAddr: "n@i.dev",
	}
	if err := p.Send(context.Background(), "u@example.com", "s", "t", "h", "idem-99"); err != nil {
		t.Fatalf("keyed send: %v", err)
	}
	if customHdr != "idem-99" {
		t.Errorf("X-Mailin-Custom = %q, want idem-99", customHdr)
	}
	if idemHdr != "idem-99" {
		t.Errorf("Idempotency-Key = %q, want idem-99", idemHdr)
	}
}

func TestBrevoProvider_Send_Accepted202IsSuccess(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusAccepted)
	}))
	defer srv.Close()
	p := &brevoProvider{
		apiKey:   "k",
		http:     &http.Client{Transport: &covRewriter{base: srv.URL}},
		fromName: "I", fromAddr: "n@i.dev",
	}
	if err := p.Send(context.Background(), "u@example.com", "s", "t", "h", ""); err != nil {
		t.Errorf("202 Accepted should be success, got %v", err)
	}
}

// ---------------------------------------------------------------------------
// resendProvider.Send keyless + keyed happy paths + error path
// ---------------------------------------------------------------------------

// newResendProviderTo builds a resendProvider whose SDK client targets srv.
func newResendProviderTo(t *testing.T, srvURL string) *resendProvider {
	t.Helper()
	cli := resend.NewCustomClient(http.DefaultClient, "re_test_key")
	u, err := url.Parse(srvURL + "/")
	if err != nil {
		t.Fatalf("parse url: %v", err)
	}
	cli.BaseURL = u
	return &resendProvider{client: cli, from: "InstaNode <noreply@instanode.dev>"}
}

func TestResendProvider_Send_KeylessSuccess(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"id":"re-123"}`))
	}))
	defer srv.Close()

	p := newResendProviderTo(t, srv.URL)
	if err := p.Send(context.Background(), "u@example.com", "s", "t", "<p>h</p>", ""); err != nil {
		t.Errorf("keyless resend send: %v", err)
	}
}

func TestResendProvider_Send_KeyedSuccess(t *testing.T) {
	var sawIdem string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sawIdem = r.Header.Get("Idempotency-Key")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"id":"re-456"}`))
	}))
	defer srv.Close()

	p := newResendProviderTo(t, srv.URL)
	if err := p.Send(context.Background(), "u@example.com", "s", "t", "<p>h</p>", "idem-key-7"); err != nil {
		t.Errorf("keyed resend send: %v", err)
	}
	if sawIdem != "idem-key-7" {
		t.Errorf("resend Idempotency-Key header = %q, want idem-key-7", sawIdem)
	}
}

func TestResendProvider_Send_ErrorPath(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnprocessableEntity)
		_, _ = w.Write([]byte(`{"message":"invalid from","name":"validation_error"}`))
	}))
	defer srv.Close()

	p := newResendProviderTo(t, srv.URL)
	err := p.Send(context.Background(), "u@example.com", "s", "t", "h", "")
	if err == nil || !strings.Contains(err.Error(), "email.send") {
		t.Fatalf("resend error path: want wrapped error, got %v", err)
	}
}

func TestResendProvider_Name(t *testing.T) {
	p := &resendProvider{}
	if p.Name() != ProviderResend {
		t.Errorf("resendProvider.Name() = %v, want ProviderResend", p.Name())
	}
}

// ---------------------------------------------------------------------------
// maskEmail edge cases
// ---------------------------------------------------------------------------

func TestMaskEmail_EdgeCases(t *testing.T) {
	cases := []struct{ in, want string }{
		{"alice@example.com", "a***@example.com"},
		{"a@example.com", "a@example.com"}, // one-char local part kept as-is
		{"no-at-sign", "no-at-sign"},       // no "@" → unchanged
		{"@example.com", "@example.com"},   // leading "@" (at == 0) → unchanged
		{"", ""},                           // empty → unchanged
	}
	for _, tc := range cases {
		if got := maskEmail(tc.in); got != tc.want {
			t.Errorf("maskEmail(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}
