package queue

// provision_test.go — branch coverage for Provider.Provision. These are
// white-box tests (package queue) so they can swap the monitorHealthURL seam to
// point at an httptest.Server, exercising the healthy / unhealthy-status /
// build-request-error branches without a real NATS pod.

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// withMonitorURL swaps the monitorHealthURL seam for the duration of a test and
// restores it afterward.
func withMonitorURL(t *testing.T, fn func(string) string) {
	t.Helper()
	orig := monitorHealthURL
	monitorHealthURL = fn
	t.Cleanup(func() { monitorHealthURL = orig })
}

// TestProvision_HappyPath exercises the full success path: NATS monitoring
// returns 200, so Provision must return a Credentials with the canonical
// full-token SubjectPrefix and the nats:// URL built from the host.
func TestProvision_HappyPath(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)

	host := strings.TrimPrefix(srv.URL, "http://") // "127.0.0.1:PORT"
	withMonitorURL(t, func(string) string { return srv.URL + "/healthz" })

	p := &Provider{natsHost: host, httpClient: &http.Client{Timeout: 5 * time.Second}}

	token := "abcd1234-ef56-7890-abcd-ef1234567890"
	creds, err := p.Provision(context.Background(), token, "pro")
	if err != nil {
		t.Fatalf("Provision happy path returned error: %v", err)
	}
	if creds == nil {
		t.Fatal("Provision returned nil Credentials with no error")
	}
	wantPrefix := canonicalSubjectPrefix(token)
	if creds.SubjectPrefix != wantPrefix {
		t.Fatalf("SubjectPrefix = %q, want canonical %q", creds.SubjectPrefix, wantPrefix)
	}
	wantURL := "nats://" + host + ":4222"
	if creds.URL != wantURL {
		t.Fatalf("URL = %q, want %q", creds.URL, wantURL)
	}
	if creds.ProviderResourceID != "" {
		t.Fatalf("ProviderResourceID = %q, want empty for shared NATS", creds.ProviderResourceID)
	}
}

// TestProvision_AnonymousTier exercises the happy path with the anonymous
// auth_mode arm (the legacy_open fallback) — the tier only affects the log
// line, but this confirms both arms return credentials.
func TestProvision_AnonymousTier(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)

	withMonitorURL(t, func(string) string { return srv.URL + "/healthz" })
	p := &Provider{natsHost: "anon.host", httpClient: &http.Client{Timeout: 5 * time.Second}}

	creds, err := p.Provision(context.Background(), "anontoken1234567", "anonymous")
	if err != nil {
		t.Fatalf("anonymous Provision returned error: %v", err)
	}
	if creds.URL != "nats://anon.host:4222" {
		t.Fatalf("URL = %q, want nats://anon.host:4222", creds.URL)
	}
}

// TestProvision_UnhealthyStatus covers the non-200 branch: NATS monitoring is
// reachable but returns a 5xx, so Provision must refuse to issue a URL.
func TestProvision_UnhealthyStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	t.Cleanup(srv.Close)

	withMonitorURL(t, func(string) string { return srv.URL + "/healthz" })
	p := &Provider{natsHost: "h", httpClient: &http.Client{Timeout: 5 * time.Second}}

	_, err := p.Provision(context.Background(), "tok1234567890abc", "free")
	if err == nil {
		t.Fatal("Provision must error when NATS returns non-200")
	}
	if !strings.Contains(err.Error(), "unhealthy") {
		t.Fatalf("error %q must mention 'unhealthy'", err.Error())
	}
}

// TestProvision_BuildRequestError covers the http.NewRequestWithContext error
// branch by feeding the seam a URL containing a control character that the URL
// parser rejects.
func TestProvision_BuildRequestError(t *testing.T) {
	withMonitorURL(t, func(string) string { return "http://example.com/\x7f\x00bad" })
	p := &Provider{natsHost: "h", httpClient: &http.Client{Timeout: time.Second}}

	_, err := p.Provision(context.Background(), "tok1234567890abc", "free")
	if err == nil {
		t.Fatal("Provision must error on a malformed monitor URL")
	}
	if !strings.Contains(err.Error(), "build health request") {
		t.Fatalf("error %q must mention 'build health request'", err.Error())
	}
}

// TestProvision_ConnFail covers the httpClient.Do error branch (connection
// refused) — the seam points at a closed port.
func TestProvision_ConnFail(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	url := srv.URL
	srv.Close() // close immediately so the port refuses connections

	withMonitorURL(t, func(string) string { return url + "/healthz" })
	p := &Provider{natsHost: "h", httpClient: &http.Client{Timeout: time.Second}}

	_, err := p.Provision(context.Background(), "tok1234567890abc", "free")
	if err == nil {
		t.Fatal("Provision must error when the NATS health endpoint is unreachable")
	}
	if !strings.Contains(err.Error(), "health check failed") {
		t.Fatalf("error %q must mention 'health check failed'", err.Error())
	}
}
