package db

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
)

// rtFunc adapts a function to an http.RoundTripper so we can intercept the
// Neon API calls (the base URL is a package const, not injectable, so we swap
// the transport on the backend's *http.Client instead of the URL).
type rtFunc func(*http.Request) (*http.Response, error)

func (f rtFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func resp(status int, body string) *http.Response {
	return &http.Response{
		StatusCode: status,
		Body:       io.NopCloser(strings.NewReader(body)),
		Header:     make(http.Header),
	}
}

// errReader fails on Read so we can exercise the io.ReadAll(body) error paths.
type errReader struct{}

func (errReader) Read([]byte) (int, error) { return 0, io.ErrUnexpectedEOF }
func (errReader) Close() error             { return nil }

func respErrBody(status int) *http.Response {
	return &http.Response{StatusCode: status, Body: errReader{}, Header: make(http.Header)}
}

// TestNeon_ReadBodyErrors covers the io.ReadAll(resp.Body) failure branches in
// both Provision (success-path read) and StorageBytes.
func TestNeon_ReadBodyErrors(t *testing.T) {
	mk := func(fn rtFunc) *NeonBackend {
		b := newNeonBackend("key", "")
		b.client = &http.Client{Transport: fn}
		return b
	}
	ctx := context.Background()

	if _, err := mk(func(*http.Request) (*http.Response, error) {
		return respErrBody(200), nil
	}).Provision(ctx, "t", "x"); err == nil || !strings.Contains(err.Error(), "read body") {
		t.Fatalf("Provision read-body error expected; got %v", err)
	}
	if _, err := mk(func(*http.Request) (*http.Response, error) {
		return respErrBody(200), nil
	}).StorageBytes(ctx, "t", "p"); err == nil || !strings.Contains(err.Error(), "read body") {
		t.Fatalf("StorageBytes read-body error expected; got %v", err)
	}
}

func TestNeon_NewDefaults(t *testing.T) {
	b := newNeonBackend("key", "")
	if b.regionID != defaultNeonRegion {
		t.Fatalf("empty region must default; got %q", b.regionID)
	}
	if b.apiKey != "key" || b.client == nil {
		t.Fatal("apiKey/client not set")
	}
	b2 := newNeonBackend("k", "eu-central-1")
	if b2.regionID != "eu-central-1" {
		t.Fatalf("explicit region lost; got %q", b2.regionID)
	}
}

func TestNeon_Provision_Success(t *testing.T) {
	b := newNeonBackend("key", "")
	b.client = &http.Client{Transport: rtFunc(func(r *http.Request) (*http.Response, error) {
		if r.Method != http.MethodPost || !strings.HasSuffix(r.URL.Path, "/projects") {
			t.Fatalf("unexpected request %s %s", r.Method, r.URL)
		}
		if r.Header.Get("Authorization") != "Bearer key" {
			t.Fatalf("missing bearer; got %q", r.Header.Get("Authorization"))
		}
		return resp(201, `{"project":{"id":"proj-1"},"connection_uris":[{"connection_uri":"postgres://x@neon/db"}]}`), nil
	})}

	creds, err := b.Provision(context.Background(), "tok", "team")
	if err != nil {
		t.Fatalf("Provision: %v", err)
	}
	if creds.ProviderResourceID != "proj-1" || creds.URL != "postgres://x@neon/db" || creds.DatabaseName != "neondb" {
		t.Fatalf("bad creds: %+v", creds)
	}
}

func TestNeon_Provision_ErrorBranches(t *testing.T) {
	mk := func(fn rtFunc) *NeonBackend {
		b := newNeonBackend("key", "")
		b.client = &http.Client{Transport: fn}
		return b
	}
	ctx := context.Background()

	// HTTP transport error.
	if _, err := mk(func(*http.Request) (*http.Response, error) {
		return nil, io.ErrUnexpectedEOF
	}).Provision(ctx, "t", "x"); err == nil {
		t.Fatal("transport error must surface")
	}
	// Non-2xx status.
	if _, err := mk(func(*http.Request) (*http.Response, error) {
		return resp(500, "boom"), nil
	}).Provision(ctx, "t", "x"); err == nil || !strings.Contains(err.Error(), "unexpected status") {
		t.Fatalf("non-2xx must error; got %v", err)
	}
	// Unparseable JSON.
	if _, err := mk(func(*http.Request) (*http.Response, error) {
		return resp(200, "not-json"), nil
	}).Provision(ctx, "t", "x"); err == nil || !strings.Contains(err.Error(), "unmarshal") {
		t.Fatalf("bad json must error; got %v", err)
	}
	// Empty project ID.
	if _, err := mk(func(*http.Request) (*http.Response, error) {
		return resp(200, `{"project":{"id":""},"connection_uris":[{"connection_uri":"x"}]}`), nil
	}).Provision(ctx, "t", "x"); err == nil || !strings.Contains(err.Error(), "empty project ID") {
		t.Fatalf("empty id must error; got %v", err)
	}
	// No connection URI.
	if _, err := mk(func(*http.Request) (*http.Response, error) {
		return resp(200, `{"project":{"id":"p"},"connection_uris":[]}`), nil
	}).Provision(ctx, "t", "x"); err == nil || !strings.Contains(err.Error(), "no connection URI") {
		t.Fatalf("missing uri must error; got %v", err)
	}
}

func TestNeon_ProvisionWithExtensions(t *testing.T) {
	b := newNeonBackend("key", "")
	b.client = &http.Client{Transport: rtFunc(func(*http.Request) (*http.Response, error) {
		return resp(201, `{"project":{"id":"p"},"connection_uris":[{"connection_uri":"u"}]}`), nil
	})}
	ctx := context.Background()

	// Allowlist rejection short-circuits before any HTTP call.
	if _, err := b.ProvisionWithExtensions(ctx, "t", "x", []string{"postgis"}); err == nil || !strings.Contains(err.Error(), "allowlist") {
		t.Fatalf("want allowlist error; got %v", err)
	}
	// No extensions → plain provision succeeds.
	if _, err := b.ProvisionWithExtensions(ctx, "t", "x", nil); err != nil {
		t.Fatalf("no-ext provision: %v", err)
	}
	// Allowed extension → provision succeeds but returns the not-supported error.
	if _, err := b.ProvisionWithExtensions(ctx, "t", "x", []string{"vector"}); err == nil || !strings.Contains(err.Error(), "not yet supported") {
		t.Fatalf("want not-supported error; got %v", err)
	}
}

func TestNeon_ProvisionWithExtensions_ProvisionFails(t *testing.T) {
	b := newNeonBackend("key", "")
	b.client = &http.Client{Transport: rtFunc(func(*http.Request) (*http.Response, error) {
		return resp(500, "down"), nil
	})}
	if _, err := b.ProvisionWithExtensions(context.Background(), "t", "x", []string{"vector"}); err == nil {
		t.Fatal("provision failure must propagate through ProvisionWithExtensions")
	}
}

func TestNeon_StorageBytes(t *testing.T) {
	mk := func(fn rtFunc) *NeonBackend {
		b := newNeonBackend("key", "")
		b.client = &http.Client{Transport: fn}
		return b
	}
	ctx := context.Background()

	// Empty providerResourceID short-circuits.
	if _, err := mk(nil).StorageBytes(ctx, "t", ""); err == nil {
		t.Fatal("empty rid must error")
	}
	// Success.
	n, err := mk(func(r *http.Request) (*http.Response, error) {
		if r.Method != http.MethodGet || !strings.HasSuffix(r.URL.Path, "/projects/proj-9") {
			t.Fatalf("bad request %s %s", r.Method, r.URL)
		}
		return resp(200, `{"project":{"usage":{"data_storage_bytes_hour":4096}}}`), nil
	}).StorageBytes(ctx, "t", "proj-9")
	if err != nil || n != 4096 {
		t.Fatalf("StorageBytes = %d, %v", n, err)
	}
	// Transport error.
	if _, err := mk(func(*http.Request) (*http.Response, error) {
		return nil, io.ErrUnexpectedEOF
	}).StorageBytes(ctx, "t", "p"); err == nil {
		t.Fatal("transport err must surface")
	}
	// Non-2xx.
	if _, err := mk(func(*http.Request) (*http.Response, error) {
		return resp(404, "nope"), nil
	}).StorageBytes(ctx, "t", "p"); err == nil || !strings.Contains(err.Error(), "unexpected status") {
		t.Fatalf("non-2xx must error; got %v", err)
	}
	// Bad JSON.
	if _, err := mk(func(*http.Request) (*http.Response, error) {
		return resp(200, "x"), nil
	}).StorageBytes(ctx, "t", "p"); err == nil || !strings.Contains(err.Error(), "unmarshal") {
		t.Fatalf("bad json must error; got %v", err)
	}
}

func TestNeon_Deprovision(t *testing.T) {
	mk := func(fn rtFunc) *NeonBackend {
		b := newNeonBackend("key", "")
		b.client = &http.Client{Transport: fn}
		return b
	}
	ctx := context.Background()

	// Empty rid short-circuits.
	if err := mk(nil).Deprovision(ctx, "t", ""); err == nil {
		t.Fatal("empty rid must error")
	}
	// Success.
	if err := mk(func(r *http.Request) (*http.Response, error) {
		if r.Method != http.MethodDelete {
			t.Fatalf("want DELETE; got %s", r.Method)
		}
		return resp(200, ""), nil
	}).Deprovision(ctx, "t", "proj-9"); err != nil {
		t.Fatalf("Deprovision: %v", err)
	}
	// Transport error.
	if err := mk(func(*http.Request) (*http.Response, error) {
		return nil, io.ErrUnexpectedEOF
	}).Deprovision(ctx, "t", "p"); err == nil {
		t.Fatal("transport err must surface")
	}
	// Non-2xx.
	if err := mk(func(*http.Request) (*http.Response, error) {
		return resp(403, "denied"), nil
	}).Deprovision(ctx, "t", "p"); err == nil || !strings.Contains(err.Error(), "unexpected status") {
		t.Fatalf("non-2xx must error; got %v", err)
	}
}
