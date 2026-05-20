package razorpaybilling

// timeout_test.go — P0-2 regression tests
// (CIRCUIT-RETRY-AUDIT-2026-05-20).
//
// The Razorpay SDK defaults to a 10s HTTP timeout (see
// requests.TIMEOUT == 10). That's below Razorpay's documented p99 for
// subscription create — a brownout where p99 climbs to 12-25s would
// 10s-fail every checkout *without ever flipping our circuit breaker*,
// because the breaker only opens after N consecutive errors and the
// 10s-truncated response never even becomes a recognizable upstream fault
// — it's just "connection deadline" to our caller. We bump the api-side
// timeout to 30s explicitly and pin it with this test so a future
// dependency upgrade or refactor cannot silently regress it.

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	razorpay "github.com/razorpay/razorpay-go"
)

// TestRazorpayHTTPTimeout_Is30Seconds anchors the audit decision so
// changing the constant requires updating this test, which forces a
// reviewer to acknowledge the contract.
func TestRazorpayHTTPTimeout_Is30Seconds(t *testing.T) {
	if RazorpayHTTPTimeoutSeconds != 30 {
		t.Errorf("RazorpayHTTPTimeoutSeconds = %d; audit P0-2 specifies 30", RazorpayHTTPTimeoutSeconds)
	}
}

// TestApplyHTTPTimeout_InstallsThirtySecondClient — confirm the helper
// actually mutates the underlying http.Client.Timeout to 30s, not the
// SDK's 10s default. This is the load-bearing assertion: the bug only
// reproduces under network conditions, so we have to inspect the
// installed *http.Client to know the patch took.
func TestApplyHTTPTimeout_InstallsThirtySecondClient(t *testing.T) {
	c := razorpay.NewClient("rzp_test_dummy_key", "secret_dummy")
	// Before patch — SDK default is 10s.
	if got := c.Request.HTTPClient.Timeout; got != 10*time.Second {
		t.Logf("SDK default changed: was 10s, now %s — update doc & this test", got)
	}
	c = ApplyHTTPTimeout(c)
	if got := c.Request.HTTPClient.Timeout; got != 30*time.Second {
		t.Errorf("after ApplyHTTPTimeout: want 30s, got %s", got)
	}
}

// TestNewTimeoutClient_ConvenienceConstructorInstalls30s — every api-side
// call site MUST go through NewTimeoutClient (see CreateSubscription /
// FetchCheckoutSubscription in handlers/billing.go and Portal.client in
// portal.go). This test guards the helper itself.
func TestNewTimeoutClient_ConvenienceConstructorInstalls30s(t *testing.T) {
	c := NewTimeoutClient("rzp_test_key", "secret")
	if c == nil {
		t.Fatal("NewTimeoutClient returned nil")
	}
	if got := c.Request.HTTPClient.Timeout; got != 30*time.Second {
		t.Errorf("NewTimeoutClient: want 30s timeout, got %s", got)
	}
}

// TestNewTimeoutClient_AbortsBeforeMinutesLongHang — behavioural proof of
// what the timeout actually does. We point the Razorpay client at a fake
// server that NEVER responds; with the 30s timeout the call must return
// with an error in well under a minute, instead of holding the goroutine
// open indefinitely. We use a tight test variant (sub-second timeout via
// SetTimeout(1)) so the CI run-time is bounded; the production 30s value
// is pinned by TestRazorpayHTTPTimeout_Is30Seconds.
func TestNewTimeoutClient_AbortsBeforeMinutesLongHang(t *testing.T) {
	hung := make(chan struct{})
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-hung // never write a response
	}))
	defer func() {
		close(hung)
		ts.Close()
	}()

	// Construct a real client, then point it at the hung server via the
	// SDK's Request.BaseURL field — that's how the SDK assembles outbound
	// URLs. Verify it parses.
	if _, err := url.Parse(ts.URL); err != nil {
		t.Fatalf("test server URL didn't parse: %v", err)
	}

	c := NewTimeoutClient("rzp_test", "secret")
	c.Request.BaseURL = ts.URL
	// For the test we tighten the timeout to 1s — the production value is
	// pinned by the constant test above. SetTimeout takes int16 seconds.
	c.Request.SetTimeout(1)

	start := time.Now()
	_, err := c.Subscription.Fetch("sub_nonexistent", nil, nil)
	elapsed := time.Since(start)
	if err == nil {
		t.Fatal("Subscription.Fetch against hung server: expected timeout error, got nil")
	}
	// A 1s timeout must abort in well under 5s, otherwise the timeout is
	// not installed and the SDK is falling back to net/http defaults
	// (which would block until the OS aborted the socket).
	if elapsed > 5*time.Second {
		t.Errorf("call took %s; the timeout did not actually fire — SDK default would be ~10s+", elapsed)
	}
}

// TestApplyHTTPTimeout_NilSafe — defensively prove the helper does not
// panic when handed a nil client. main.go has paths that early-return
// when Razorpay credentials are missing; we want the helper to behave
// equally well in those paths.
func TestApplyHTTPTimeout_NilSafe(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("ApplyHTTPTimeout panicked on nil: %v", r)
		}
	}()
	if got := ApplyHTTPTimeout(nil); got != nil {
		t.Errorf("ApplyHTTPTimeout(nil) = %v; want nil", got)
	}
}

// _ = context.Background — appease lint; context is imported in case a
// future test variant needs to thread a context into the SDK call.
var _ = context.Background
