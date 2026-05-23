package handlers

import (
	"io"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gofiber/fiber/v2"
)

// TestSetOpenAPIEnvironment_SetsAndIgnoresEmpty covers SetOpenAPIEnvironment:
// a non-empty value updates the package var; an empty value is a no-op guard.
func TestSetOpenAPIEnvironment_SetsAndIgnoresEmpty(t *testing.T) {
	prev := openAPIEnvironment
	t.Cleanup(func() { openAPIEnvironment = prev })

	SetOpenAPIEnvironment("staging")
	if openAPIEnvironment != "staging" {
		t.Fatalf("SetOpenAPIEnvironment: want staging, got %q", openAPIEnvironment)
	}

	// Empty must NOT clobber the existing value.
	SetOpenAPIEnvironment("")
	if openAPIEnvironment != "staging" {
		t.Fatalf("SetOpenAPIEnvironment(\"\"): want unchanged staging, got %q", openAPIEnvironment)
	}
}

// TestServeOpenAPI_DevelopmentServesRaw covers ServeOpenAPI's development
// branch: the unstripped spec (with /internal/set-tier) is served verbatim.
func TestServeOpenAPI_DevelopmentServesRaw(t *testing.T) {
	prev := openAPIEnvironment
	t.Cleanup(func() { openAPIEnvironment = prev })
	openAPIEnvironment = "development"

	app := fiber.New()
	app.Get("/openapi.json", ServeOpenAPI)
	resp, err := app.Test(httptest.NewRequest("GET", "/openapi.json", nil), 10000)
	if err != nil {
		t.Fatalf("Test: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), `"/internal/set-tier"`) {
		t.Error("development ServeOpenAPI must serve the raw spec including /internal/set-tier")
	}
	if ct := resp.Header.Get("Content-Type"); !strings.Contains(ct, "application/json") {
		t.Errorf("content-type: got %q", ct)
	}
}

// TestServeOpenAPI_ProductionServesStripped covers the production branch +
// the sync.Once-cached stripped spec. Two calls exercise both the Do() body
// and the cached fast-path.
func TestServeOpenAPI_ProductionServesStripped(t *testing.T) {
	prevEnv := openAPIEnvironment
	prevSpec := openAPISpecProd
	t.Cleanup(func() {
		openAPIEnvironment = prevEnv
		openAPISpecProd = prevSpec
		// Reset the Once so a later test re-derives the cache cleanly. We
		// assign a fresh zero-value Once via a helper to avoid copying a
		// lock (go vet copylocks).
		resetOpenAPIOnceForTest()
	})

	openAPIEnvironment = "production"
	openAPISpecProd = ""
	resetOpenAPIOnceForTest()

	app := fiber.New()
	app.Get("/openapi.json", ServeOpenAPI)

	for i := 0; i < 2; i++ { // first populates the cache, second hits it
		resp, err := app.Test(httptest.NewRequest("GET", "/openapi.json", nil), 10000)
		if err != nil {
			t.Fatalf("Test #%d: %v", i, err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if strings.Contains(string(body), `"/internal/set-tier"`) {
			t.Errorf("production ServeOpenAPI #%d leaked /internal/set-tier", i)
		}
	}
}

// TestStripInternalSetTierPath_EdgeGuards covers the early-return guards and
// the brace-mismatch fallback that the existing tests don't reach.
func TestStripInternalSetTierPath_EdgeGuards(t *testing.T) {
	key := `"/internal/set-tier"`
	cases := []struct {
		name, in string
	}{
		// key present but no colon anywhere after it → unchanged.
		{"no_colon", key},
		// key + colon but no opening brace after the colon → unchanged.
		{"no_open_brace", key + `: 123`},
		// key + colon + open brace but never closes → brace-mismatch fallback.
		{"unbalanced", key + `: {"a": 1`},
		// escaped quote + escaped backslash inside the value string exercise
		// the esc / backslash arms of the brace walker; the entry still
		// terminates correctly and is removed.
		{"escaped_string", `{"x":1,` + key + `: {"d":"a\"b\\c}{"}}`},
		// braces inside a plain quoted string must not confuse the walker.
		{"string_with_braces", `{"x":1,` + key + `: {"d":"a}b{c"}}`},
	}
	for _, tc := range cases {
		out := stripInternalSetTierPath(tc.in)
		switch tc.name {
		case "no_colon", "no_open_brace", "unbalanced":
			if out != tc.in {
				t.Errorf("%s: expected unchanged, got %q", tc.name, out)
			}
		case "escaped_string", "string_with_braces":
			if strings.Contains(out, key) {
				t.Errorf("%s: entry not removed: %q", tc.name, out)
			}
		}
	}
}

// TestStripInternalSetTierPath_MiddleEntryEatsTrailingComma covers the branch
// where the stripped block IS followed by a comma (set-tier is not the last
// path entry) — the helper eats that trailing comma to keep JSON valid.
func TestStripInternalSetTierPath_MiddleEntryEatsTrailingComma(t *testing.T) {
	key := `"/internal/set-tier"`
	in := `{"paths":{` + key + `:{"post":{}},"/z":{"get":{}}}}`
	out := stripInternalSetTierPath(in)
	if strings.Contains(out, key) {
		t.Fatalf("entry not removed: %q", out)
	}
	if strings.Contains(out, ":,") || strings.Contains(out, "{,") {
		t.Errorf("malformed comma after strip: %q", out)
	}
	if want := `{"paths":{"/z":{"get":{}}}}`; out != want {
		t.Errorf("middle-entry strip: got %q want %q", out, want)
	}
}

// TestStripInternalSetTierPath_LastEntryTrailingComma covers the "last entry"
// branch where the stripped block has no trailing comma, so the helper trims
// the *preceding* comma to keep the surrounding object valid.
func TestStripInternalSetTierPath_LastEntryTrailingComma(t *testing.T) {
	key := `"/internal/set-tier"`
	// set-tier is the LAST path entry → no trailing comma after its block.
	in := `{"paths":{"/a":{"get":{}},` + key + `:{"post":{}}}}`
	out := stripInternalSetTierPath(in)
	if strings.Contains(out, key) {
		t.Fatalf("entry not removed: %q", out)
	}
	if strings.Contains(out, ",}") {
		t.Errorf("dangling comma before close brace: %q", out)
	}
	if want := `{"paths":{"/a":{"get":{}}}}`; out != want {
		t.Errorf("last-entry strip: got %q want %q", out, want)
	}
}
