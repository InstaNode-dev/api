package db

// Neon backend tests. We never hit the real https://console.neon.tech
// surface; instead the test stands up an httptest.Server and redirects
// the backend at it by overriding the embedded *http.Client's Transport.
// This proves the per-method request shape (method, path, Bearer header,
// JSON body) and the response-parsing branches: happy-path, non-2xx,
// malformed JSON, missing project_id, missing connection_uri, empty
// providerResourceID guard, and the extensions-not-supported error.

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// rewriteTransport rewrites every outbound request's URL host so that
// requests targeted at neon.tech land on our local httptest server.
type rewriteTransport struct {
	target string // "http://127.0.0.1:NNNN"
	t      *testing.T
}

func (rt *rewriteTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	// Replace scheme+host of neonAPIBase with the httptest target.
	rewritten := strings.Replace(r.URL.String(), neonAPIBase, rt.target+"/api/v2", 1)
	req2, err := http.NewRequestWithContext(r.Context(), r.Method, rewritten, r.Body)
	if err != nil {
		return nil, err
	}
	req2.Header = r.Header.Clone()
	return http.DefaultTransport.RoundTrip(req2)
}

// newNeonBackendForTest wires a NeonBackend at a local httptest server.
func newNeonBackendForTest(t *testing.T, srv *httptest.Server, apiKey, regionID string) *NeonBackend {
	t.Helper()
	b := newNeonBackend(apiKey, regionID)
	b.client.Transport = &rewriteTransport{target: srv.URL, t: t}
	return b
}

// TestNewNeonBackend_DefaultRegion — empty regionID substitutes the
// package-level default.
func TestNewNeonBackend_DefaultRegion(t *testing.T) {
	b := newNeonBackend("k", "")
	if b.regionID != defaultNeonRegion {
		t.Fatalf("default region: got %q want %q", b.regionID, defaultNeonRegion)
	}
	b2 := newNeonBackend("k", "aws-eu-west-1")
	if b2.regionID != "aws-eu-west-1" {
		t.Fatalf("explicit region: got %q want aws-eu-west-1", b2.regionID)
	}
}

// TestNeon_Provision_HappyPath — Server returns a valid project payload;
// backend should fill Credentials.URL + ProviderResourceID.
func TestNeon_Provision_HappyPath(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Per-request invariants.
		if r.Method != http.MethodPost {
			t.Errorf("method: got %q want POST", r.Method)
		}
		if r.URL.Path != "/api/v2/projects" {
			t.Errorf("path: got %q want /api/v2/projects", r.URL.Path)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer test-key" {
			t.Errorf("auth: got %q", got)
		}
		if r.Header.Get("Content-Type") != "application/json" {
			t.Errorf("content-type: got %q", r.Header.Get("Content-Type"))
		}
		var body map[string]any
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Errorf("decode body: %v", err)
		}
		proj, ok := body["project"].(map[string]any)
		if !ok {
			t.Errorf("project envelope missing")
		}
		if name := proj["name"].(string); name != "instant-tok-9" {
			t.Errorf("name: got %q", name)
		}
		w.WriteHeader(http.StatusCreated)
		_, _ = io.WriteString(w, `{
			"project":{"id":"proj_abc123"},
			"connection_uris":[{"connection_uri":"postgres://user:pass@neon/db"}]
		}`)
	}))
	defer srv.Close()

	b := newNeonBackendForTest(t, srv, "test-key", "aws-us-east-1")
	creds, err := b.Provision(context.Background(), "tok-9", "pro")
	if err != nil {
		t.Fatalf("Provision: %v", err)
	}
	if creds.URL != "postgres://user:pass@neon/db" {
		t.Errorf("url: got %q", creds.URL)
	}
	if creds.ProviderResourceID != "proj_abc123" {
		t.Errorf("prid: got %q", creds.ProviderResourceID)
	}
	if creds.DatabaseName != "neondb" || creds.Username != "" {
		t.Errorf("db/username defaults: %+v", creds)
	}
}

// TestNeon_Provision_ErrorBranches — every error branch of Provision.
func TestNeon_Provision_ErrorBranches(t *testing.T) {
	type tc struct {
		name    string
		handler http.HandlerFunc
		wantSub string
	}
	cases := []tc{
		{
			"non_2xx_status",
			func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusUnauthorized)
				_, _ = io.WriteString(w, `{"error":"bad key"}`)
			},
			"unexpected status 401",
		},
		{
			"non_json_body",
			func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusOK)
				_, _ = io.WriteString(w, `not-json`)
			},
			"unmarshal",
		},
		{
			"empty_project_id",
			func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusOK)
				_, _ = io.WriteString(w, `{"project":{"id":""},"connection_uris":[{"connection_uri":"u"}]}`)
			},
			"empty project ID",
		},
		{
			"no_connection_uris",
			func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusOK)
				_, _ = io.WriteString(w, `{"project":{"id":"p1"},"connection_uris":[]}`)
			},
			"no connection URI",
		},
		{
			"empty_connection_uri",
			func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusOK)
				_, _ = io.WriteString(w, `{"project":{"id":"p1"},"connection_uris":[{"connection_uri":""}]}`)
			},
			"no connection URI",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			srv := httptest.NewServer(c.handler)
			defer srv.Close()
			b := newNeonBackendForTest(t, srv, "k", "")
			_, err := b.Provision(context.Background(), "tok", "free")
			if err == nil {
				t.Fatalf("want error, got nil")
			}
			if !strings.Contains(err.Error(), c.wantSub) {
				t.Fatalf("err=%q want substr %q", err.Error(), c.wantSub)
			}
		})
	}
}

// TestNeon_Provision_HTTPDoFails — exercise the request-do error branch
// (network unreachable). We close the server before the call.
func TestNeon_Provision_HTTPDoFails(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	srv.Close() // immediately
	b := newNeonBackendForTest(t, srv, "k", "")
	_, err := b.Provision(context.Background(), "tok", "free")
	if err == nil || !strings.Contains(err.Error(), "http") {
		t.Fatalf("want http error, got %v", err)
	}
}

// TestNeon_ProvisionWithExtensions — the vector path returns the docs
// "not yet supported" error AND the underlying creds (so callers see
// what got created in spite of the missing extension).
func TestNeon_ProvisionWithExtensions(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusCreated)
		_, _ = io.WriteString(w, `{"project":{"id":"p"},"connection_uris":[{"connection_uri":"u"}]}`)
	}))
	defer srv.Close()
	b := newNeonBackendForTest(t, srv, "k", "")

	// Disallowed extension is rejected at the validator BEFORE any HTTP call.
	if _, err := b.ProvisionWithExtensions(context.Background(), "tok", "team", []string{"postgis"}); err == nil {
		t.Fatal("want error for disallowed extension")
	}

	// Allowed extension still errors (Neon path not wired) but returns creds.
	creds, err := b.ProvisionWithExtensions(context.Background(), "tok", "team", []string{"vector"})
	if err == nil {
		t.Fatal("want extensions-unsupported error on Neon")
	}
	if !strings.Contains(err.Error(), "not yet supported") {
		t.Fatalf("err=%v", err)
	}
	if creds == nil {
		t.Fatal("expected creds returned alongside error")
	}

	// No-extensions path is a transparent passthrough to Provision.
	creds, err = b.ProvisionWithExtensions(context.Background(), "tok", "team", nil)
	if err != nil {
		t.Fatalf("nil exts: %v", err)
	}
	if creds.ProviderResourceID != "p" {
		t.Fatalf("creds: %+v", creds)
	}
}

// TestNeon_ProvisionWithExtensions_InnerProvisionFails — when the inner
// Provision call errors (e.g. Neon returns 5xx), ProvisionWithExtensions
// must surface that error verbatim (line 52 branch).
func TestNeon_ProvisionWithExtensions_InnerProvisionFails(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
		_, _ = io.WriteString(w, `gateway down`)
	}))
	defer srv.Close()
	b := newNeonBackendForTest(t, srv, "k", "")
	// nil extensions — validator passes, Provision is called, it errors.
	_, err := b.ProvisionWithExtensions(context.Background(), "tok", "team", nil)
	if err == nil || !strings.Contains(err.Error(), "502") {
		t.Fatalf("want 502 propagated, got %v", err)
	}
}

// TestNeon_BodyReadFails — when the upstream closes the connection
// mid-stream during ReadAll, Provision should surface the read error.
// We use a Hijack-and-close handler to slam the socket after writing
// only the headers.
func TestNeon_BodyReadFails(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		// Hijack the underlying conn and write a malformed Content-Length
		// header, then close before sending any body bytes. ReadAll on
		// the resulting body will return an unexpected-EOF error.
		hj, ok := w.(http.Hijacker)
		if !ok {
			t.Errorf("ResponseWriter does not support Hijack")
			return
		}
		conn, _, err := hj.Hijack()
		if err != nil {
			t.Errorf("hijack: %v", err)
			return
		}
		// Tell the client we'll send 100 bytes then bail.
		_, _ = conn.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n"))
		_ = conn.Close()
	}))
	defer srv.Close()
	b := newNeonBackendForTest(t, srv, "k", "")
	_, err := b.Provision(context.Background(), "tok", "free")
	if err == nil {
		t.Fatal("want read-body error")
	}
	// We don't pin the exact substring — different Go versions report
	// the truncation differently — but it must be one of the read-body
	// or http-do error wrappers.
	if !strings.Contains(err.Error(), "read body") && !strings.Contains(err.Error(), "http") {
		t.Fatalf("err=%v", err)
	}
}

// TestNeon_StorageBytes_BodyReadFails — same connection-hang scenario,
// but for the GET /projects/:id path.
func TestNeon_StorageBytes_BodyReadFails(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hj, ok := w.(http.Hijacker)
		if !ok {
			t.Errorf("ResponseWriter does not support Hijack")
			return
		}
		conn, _, err := hj.Hijack()
		if err != nil {
			t.Errorf("hijack: %v", err)
			return
		}
		_, _ = conn.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n"))
		_ = conn.Close()
	}))
	defer srv.Close()
	b := newNeonBackendForTest(t, srv, "k", "")
	if _, err := b.StorageBytes(context.Background(), "tok", "p1"); err == nil {
		t.Fatal("want read-body error")
	}
}

// TestNeon_StorageBytes_HappyPath — GET project, parse usage.
func TestNeon_StorageBytes_HappyPath(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || !strings.HasSuffix(r.URL.Path, "/projects/p1") {
			t.Errorf("unexpected req: %s %s", r.Method, r.URL.Path)
		}
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, `{"project":{"usage":{"data_storage_bytes_hour":98765}}}`)
	}))
	defer srv.Close()
	b := newNeonBackendForTest(t, srv, "k", "")
	got, err := b.StorageBytes(context.Background(), "tok", "p1")
	if err != nil {
		t.Fatalf("StorageBytes: %v", err)
	}
	if got != 98765 {
		t.Fatalf("got %d want 98765", got)
	}
}

// TestNeon_StorageBytes_ErrorBranches — exhaust every error path.
func TestNeon_StorageBytes_ErrorBranches(t *testing.T) {
	// 1) empty providerResourceID — short-circuits before any HTTP call.
	b := newNeonBackend("k", "")
	if _, err := b.StorageBytes(context.Background(), "tok", ""); err == nil {
		t.Fatal("empty prid: want error")
	}

	// 2) non-2xx status.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = io.WriteString(w, `boom`)
	}))
	defer srv.Close()
	b2 := newNeonBackendForTest(t, srv, "k", "")
	if _, err := b2.StorageBytes(context.Background(), "tok", "p1"); err == nil ||
		!strings.Contains(err.Error(), "500") {
		t.Fatalf("non-2xx: err=%v", err)
	}

	// 3) malformed JSON.
	srv2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, `{bad}`)
	}))
	defer srv2.Close()
	b3 := newNeonBackendForTest(t, srv2, "k", "")
	if _, err := b3.StorageBytes(context.Background(), "tok", "p1"); err == nil ||
		!strings.Contains(err.Error(), "unmarshal") {
		t.Fatalf("bad json: err=%v", err)
	}

	// 4) network unreachable.
	srvDead := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	srvDead.Close()
	bDead := newNeonBackendForTest(t, srvDead, "k", "")
	if _, err := bDead.StorageBytes(context.Background(), "tok", "p1"); err == nil {
		t.Fatal("dead server: want error")
	}
}

// TestNeon_StorageBytes_NewRequestFails — providerResourceID containing
// a control character (newline) makes http.NewRequestWithContext bail
// at URL parse before any network call. Exercises the new-request error
// branch.
func TestNeon_StorageBytes_NewRequestFails(t *testing.T) {
	b := newNeonBackend("k", "")
	if _, err := b.StorageBytes(context.Background(), "tok", "bad\nid"); err == nil ||
		!strings.Contains(err.Error(), "new request") {
		t.Fatalf("want new-request error, got %v", err)
	}
}

// TestNeon_Deprovision_NewRequestFails — same control-char trick on the
// DELETE path.
func TestNeon_Deprovision_NewRequestFails(t *testing.T) {
	b := newNeonBackend("k", "")
	if err := b.Deprovision(context.Background(), "tok", "bad\nid"); err == nil ||
		!strings.Contains(err.Error(), "new request") {
		t.Fatalf("want new-request error, got %v", err)
	}
}

// TestNeon_Deprovision — DELETE happy-path + every error branch.
func TestNeon_Deprovision(t *testing.T) {
	// 1) empty providerResourceID — short-circuits.
	b := newNeonBackend("k", "")
	if err := b.Deprovision(context.Background(), "tok", ""); err == nil {
		t.Fatal("empty prid: want error")
	}

	// 2) happy path.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodDelete || !strings.HasSuffix(r.URL.Path, "/projects/p2") {
			t.Errorf("unexpected: %s %s", r.Method, r.URL.Path)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	bOk := newNeonBackendForTest(t, srv, "k", "")
	if err := bOk.Deprovision(context.Background(), "tok", "p2"); err != nil {
		t.Fatalf("happy: %v", err)
	}

	// 3) non-2xx status.
	srvErr := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = io.WriteString(w, `gone`)
	}))
	defer srvErr.Close()
	bErr := newNeonBackendForTest(t, srvErr, "k", "")
	if err := bErr.Deprovision(context.Background(), "tok", "p2"); err == nil ||
		!strings.Contains(err.Error(), "404") {
		t.Fatalf("404: err=%v", err)
	}

	// 4) network unreachable.
	srvDead := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	srvDead.Close()
	bDead := newNeonBackendForTest(t, srvDead, "k", "")
	if err := bDead.Deprovision(context.Background(), "tok", "p3"); err == nil {
		t.Fatal("dead: want error")
	}
}
