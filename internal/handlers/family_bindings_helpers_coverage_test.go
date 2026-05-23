package handlers

// family_bindings_helpers_coverage_test.go — white-box coverage for the pure
// helpers in family_bindings.go: BindingError.Error, mapBindingError (every
// BindingErrorKind arm + the default), nameOrType, nameOrEmpty. These are
// pure string/translation functions that the deploy-handler flow only reaches
// on a binding error; testing them directly covers every arm deterministically.

import (
	"database/sql"
	"strings"
	"testing"

	"instant.dev/internal/models"
)

func TestBindingError_Error(t *testing.T) {
	e := &BindingError{Kind: BindingErrInvalidUUID, EnvVarKey: "DATABASE_URL", RawValue: "junk", Detail: "bad"}
	got := e.Error()
	if !strings.Contains(got, "DATABASE_URL") || !strings.Contains(got, "junk") {
		t.Errorf("Error() = %q", got)
	}
}

func TestMapBindingError_AllArms(t *testing.T) {
	cases := []struct {
		kind     BindingErrorKind
		wantCode int
	}{
		{BindingErrInvalidUUID, 400},
		{BindingErrInvalidBinding, 400},
		{BindingErrNotFound, 404},
		{BindingErrCrossTeam, 403},
		{BindingErrNoEnvTwin, 409},
		{BindingErrLookupFailed, 503},
		{BindingErrorKind("totally_unknown"), 503}, // default arm
	}
	for _, tc := range cases {
		status, code, msg, action := mapBindingError(&BindingError{
			Kind: tc.kind, EnvVarKey: "DATABASE_URL", RawValue: "v",
			RootID: "root-1", ResourceName: "mydb", Env: "staging", Detail: "boom",
		})
		if status != tc.wantCode {
			t.Errorf("kind=%s status=%d; want %d", tc.kind, status, tc.wantCode)
		}
		if code == "" || msg == "" || action == "" {
			t.Errorf("kind=%s produced empty code/msg/action: %q/%q/%q", tc.kind, code, msg, action)
		}
	}

	// Empty EnvVarKey → "<unknown>" label arm.
	_, _, msg, _ := mapBindingError(&BindingError{Kind: BindingErrInvalidUUID})
	if !strings.Contains(msg, "<unknown>") {
		t.Errorf("empty key label not surfaced: %q", msg)
	}
}

func TestNameOrType(t *testing.T) {
	named := &models.Resource{Name: sql.NullString{String: "primary-db", Valid: true}, ResourceType: "postgres"}
	if got := nameOrType(named); got != "primary-db" {
		t.Errorf("named => %q", got)
	}
	unnamed := &models.Resource{ResourceType: "redis"}
	if got := nameOrType(unnamed); got != "redis" {
		t.Errorf("unnamed => %q", got)
	}
}

func TestNameOrEmpty(t *testing.T) {
	if got := nameOrEmpty("real", "fallback"); got != "real" {
		t.Errorf("non-empty => %q", got)
	}
	if got := nameOrEmpty("", "fallback"); got != "fallback" {
		t.Errorf("empty => %q", got)
	}
}
