package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestHealthzHandler_ResponseShape pins the JSON contract since dashboards
// and alert rules consume this body shape.
func TestHealthzHandler_ResponseShape(t *testing.T) {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	HealthzHandler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}

	var raw map[string]any
	if err := json.NewDecoder(rec.Body).Decode(&raw); err != nil {
		t.Fatalf("decode: %v", err)
	}

	for _, key := range []string{"ok", "service", "commit_id", "build_time", "version"} {
		if _, ok := raw[key]; !ok {
			t.Errorf("response missing key %q — keys present: %v", key, mapKeys(raw))
		}
	}

	if raw["service"] != "instant-provisioner" {
		t.Errorf("service = %v, want instant-provisioner", raw["service"])
	}
	if raw["ok"] != true {
		t.Errorf("ok = %v, want true", raw["ok"])
	}
}

// TestHealthzHandler_AcceptsAnyMethod confirms HEAD / POST don't 405. The k8s
// liveness probe sends GET but having the endpoint be method-agnostic makes
// it easier to curl from a shell during incidents.
func TestHealthzHandler_AcceptsAnyMethod(t *testing.T) {
	for _, m := range []string{http.MethodGet, http.MethodHead, http.MethodPost} {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(m, "/healthz", nil)
		HealthzHandler().ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Errorf("method %s: status = %d, want 200", m, rec.Code)
		}
	}
}

func mapKeys(m map[string]any) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
