package main

import (
	"strings"
	"testing"
)

func TestCanonicalise_SortsKeysAnd2SpaceIndent(t *testing.T) {
	in := `{"z":1,"a":{"y":2,"b":3}}`
	got, err := canonicalise(in)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	out := string(got)

	if !strings.Contains(out, "  \"a\"") || !strings.Contains(out, "    \"b\"") {
		t.Errorf("expected 2-space indent on nested keys, got:\n%s", out)
	}
	idxA := strings.Index(out, "\"a\"")
	idxZ := strings.Index(out, "\"z\"")
	if idxA < 0 || idxZ < 0 || idxA > idxZ {
		t.Errorf("expected keys sorted alphabetically ('a' before 'z'), got:\n%s", out)
	}
	idxB := strings.Index(out, "\"b\"")
	idxY := strings.Index(out, "\"y\"")
	if idxB < 0 || idxY < 0 || idxB > idxY {
		t.Errorf("expected nested keys sorted ('b' before 'y'), got:\n%s", out)
	}
}

func TestCanonicalise_RejectsInvalidJSON(t *testing.T) {
	_, err := canonicalise("not json at all")
	if err == nil {
		t.Fatal("expected error for invalid JSON, got nil")
	}
	if !strings.Contains(err.Error(), "parse spec") {
		t.Errorf("expected wrapped 'parse spec' error, got: %v", err)
	}
}

func TestCanonicalise_DoesNotEscapeHTML(t *testing.T) {
	in := `{"url":"https://instanode.dev/deploy?env=production&plan=hobby"}`
	got, err := canonicalise(in)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	s := string(got)
	if !strings.Contains(s, `&plan=hobby`) {
		t.Errorf("expected literal '&' preserved (HTML escaping disabled), got:\n%s", s)
	}
	if strings.Contains(s, `&`) {
		t.Errorf("expected '&' not to be escaped as \\u0026, got:\n%s", s)
	}
}
