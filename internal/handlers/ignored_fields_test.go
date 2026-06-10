package handlers

// ignored_fields_test.go — D7 (2026-06-10): unknown request-body fields are
// echoed back under `ignored_fields` on a successful provision response so an
// agent that sent a typo'd / hallucinated key (e.g. "region", "size") gets a
// signal instead of a silent drop. These are pure unit tests for the
// reflection helpers + the Locals→response decoration; the live/integration
// coverage (POST /db/new {"name":"x","region":"mars"} → 201 with
// ignored_fields:["region"]) lives in the e2e suite.

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/gofiber/fiber/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// decodeInto reads resp.Body into v (and closes it). Local to this file to
// avoid colliding with the package's other decode helpers (different sigs).
func decodeInto(t *testing.T, resp *http.Response, v any) {
	t.Helper()
	require.NoError(t, json.NewDecoder(resp.Body).Decode(v))
}

// TestKnownJSONFields_ProvisionBody asserts every json-tagged field on the
// canonical provisionRequestBody is recognised, and an embedded-struct case is
// flattened correctly.
func TestKnownJSONFields_ProvisionBody(t *testing.T) {
	known := knownJSONFields(&provisionRequestBody{})
	for _, want := range []string{"name", "dedicated", "env", "parent_resource_id"} {
		assert.True(t, known[want], "provisionRequestBody json key %q must be known", want)
	}
	assert.False(t, known["region"], "unknown key 'region' must NOT be in the known set")
	assert.False(t, known["Name"], "knownJSONFields keys on the json TAG, not the Go field name")
}

// TestKnownJSONFields_EmbeddedAndTagVariants covers the tag-parsing edge cases:
// a "-" tag excludes the field, an omitempty option is stripped, an embedded
// anonymous struct is flattened, and a no-tag exported field falls back to its
// Go name.
func TestKnownJSONFields_EmbeddedAndTagVariants(t *testing.T) {
	type embedded struct {
		Inner string `json:"inner"`
	}
	type sample struct {
		embedded
		Tagged   string `json:"tagged,omitempty"`
		Excluded string `json:"-"`
		NoTag    string
	}
	known := knownJSONFields(&sample{})
	assert.True(t, known["inner"], "promoted embedded field must be known")
	assert.True(t, known["tagged"], "omitempty option must be stripped from the key")
	assert.False(t, known["Excluded"], "json:\"-\" field must be excluded")
	assert.True(t, known["NoTag"], "no-tag exported field falls back to its Go name")
}

// TestKnownJSONFields_ReflectionEdgeBranches exercises the defensive reflection
// arms of knownJSONFields + collectJSONFields that the canonical-struct tests
// above don't reach (D7, provision_helper.go):
//
//	knownJSONFields:
//	  - typed nil pointer        → collect on Elem() type, return (1057-1060)
//	  - non-struct (int)         → empty set (1064-1065)
//	collectJSONFields:
//	  - pointer-to-pointer type  → deref loop runs >1 iteration (1076-1077)
//	  - non-struct after deref   → early return (1079-1080)
//	  - anonymous *struct field  → pointer-embedded flatten (1096-1098)
//	  - unexported non-embedded  → PkgPath skip (1104-1105)
func TestKnownJSONFields_ReflectionEdgeBranches(t *testing.T) {
	t.Run("typed nil pointer still collects the pointed-to struct", func(t *testing.T) {
		// A typed nil *provisionRequestBody — the nil-pointer arm collects on
		// the Elem() type rather than dereferencing a nil value.
		var nilPtr *provisionRequestBody
		known := knownJSONFields(nilPtr)
		assert.True(t, known["name"], "nil typed pointer must still yield the struct's keys")
	})

	t.Run("non-struct input yields an empty set", func(t *testing.T) {
		known := knownJSONFields(42)
		assert.Empty(t, known, "a non-struct (int) input must produce no known keys")
	})

	t.Run("pointer-to-pointer struct is fully dereferenced", func(t *testing.T) {
		type inner struct {
			Field string `json:"field"`
		}
		// **inner forces collectJSONFields' deref loop to iterate more than once.
		known := knownJSONFields((**inner)(nil))
		assert.True(t, known["field"], "**struct must deref down to the struct and collect its keys")
	})

	t.Run("anonymous pointer-to-struct embed is flattened", func(t *testing.T) {
		type promoted struct {
			Promoted string `json:"promoted"`
		}
		type holder struct {
			*promoted        // anonymous *struct — exercises the pointer-embed deref
			Own       string `json:"own"`
		}
		known := knownJSONFields(&holder{})
		assert.True(t, known["promoted"], "anonymous *struct embed must be flattened (promoted field known)")
		assert.True(t, known["own"], "the holder's own field must be known")
	})

	t.Run("collectJSONFields on a non-struct type is a no-op", func(t *testing.T) {
		// collectJSONFields' public callers only ever pass a struct (knownJSONFields
		// gates on Kind()==Struct; the recursive embed-flatten gates the same way),
		// so its non-struct guard is reachable only by a direct call. Hit it so the
		// defensive return is covered rather than silently dead.
		known := map[string]bool{}
		collectJSONFields(reflect.TypeOf(0), known)
		assert.Empty(t, known, "collectJSONFields over a non-struct must record no keys")
	})

	t.Run("unexported non-embedded field is skipped", func(t *testing.T) {
		// `secret` is unexported AND not anonymous → PkgPath != "" → skipped.
		// We can't declare such a type inline and read it from another package,
		// but reflect over a locally-declared one still walks its fields.
		type withUnexported struct {
			Exported string `json:"exported"`
			secret   string //nolint:unused // present to exercise the PkgPath skip arm
		}
		known := knownJSONFields(&withUnexported{})
		assert.True(t, known["exported"], "exported field must be known")
		assert.False(t, known["secret"], "unexported non-embedded field must be skipped")
	})
}

// TestStashIgnoredFields_NonObjectBody covers the json.Unmarshal failure arm of
// stashIgnoredFields (provision_helper.go:1023-1027): a body that is valid JSON
// but NOT an object (a bare array) can't be diffed against the struct, so the
// helper is a silent no-op and stashes nothing.
func TestStashIgnoredFields_NonObjectBody(t *testing.T) {
	app := fiber.New()
	app.Post("/probe-array", func(c *fiber.Ctx) error {
		var body provisionRequestBody
		_ = c.BodyParser(&body) // a bare array won't parse into the struct; ignore.
		stashIgnoredFields(c, []byte(`[1,2,3]`), &body)
		_, present := c.Locals(ignoredFieldsKey).([]string)
		return c.JSON(fiber.Map{"present": present})
	})
	req := httptest.NewRequest(http.MethodPost, "/probe-array",
		strings.NewReader(`[1,2,3]`))
	req.Header.Set("Content-Type", "application/json")
	resp, err := app.Test(req, 2000)
	require.NoError(t, err)
	defer resp.Body.Close()
	var out struct {
		Present bool `json:"present"`
	}
	decodeInto(t, resp, &out)
	assert.False(t, out.Present,
		"a non-object JSON body must be a silent no-op (no ignored_fields stashed)")
}

// TestStashIgnoredFields_EmptyObject covers the len(present)==0 early-return
// (provision_helper.go:1028-1030): an empty JSON object has no keys to diff.
func TestStashIgnoredFields_EmptyObject(t *testing.T) {
	app := fiber.New()
	app.Post("/probe-empty", func(c *fiber.Ctx) error {
		var body provisionRequestBody
		_ = c.BodyParser(&body)
		stashIgnoredFields(c, []byte(`{}`), &body)
		_, present := c.Locals(ignoredFieldsKey).([]string)
		return c.JSON(fiber.Map{"present": present})
	})
	req := httptest.NewRequest(http.MethodPost, "/probe-empty",
		strings.NewReader(`{}`))
	req.Header.Set("Content-Type", "application/json")
	resp, err := app.Test(req, 2000)
	require.NoError(t, err)
	defer resp.Body.Close()
	var out struct {
		Present bool `json:"present"`
	}
	decodeInto(t, resp, &out)
	assert.False(t, out.Present, "an empty JSON object must stash nothing")
}

// TestParseProvisionBody_ContentTypeCharset covers the charset-suffix strip in
// parseProvisionBody (provision_helper.go:992-994): a legitimate
// `application/json; charset=utf-8` must have its `; charset=...` suffix stripped
// so the bare media type passes the content-type gate (NOT 415), AND a declared
// non-JSON type (application/xml) must still 415 (provision_helper.go:995-998).
func TestParseProvisionBody_ContentTypeCharset(t *testing.T) {
	app := fiber.New(fiber.Config{
		ErrorHandler: func(c *fiber.Ctx, err error) error {
			if errors.Is(err, ErrResponseWritten) {
				return nil
			}
			return c.Status(fiber.StatusInternalServerError).
				JSON(fiber.Map{"ok": false, "error": err.Error()})
		},
	})
	app.Post("/probe-ct", func(c *fiber.Ctx) error {
		var body provisionRequestBody
		if err := parseProvisionBody(c, &body); err != nil {
			return err
		}
		return c.JSON(fiber.Map{"ok": true, "name": body.Name})
	})

	t.Run("charset suffix is stripped and accepted", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/probe-ct",
			strings.NewReader(`{"name":"x"}`))
		req.Header.Set("Content-Type", "application/json; charset=utf-8")
		resp, err := app.Test(req, 2000)
		require.NoError(t, err)
		defer resp.Body.Close()
		assert.Equal(t, http.StatusOK, resp.StatusCode,
			"application/json; charset=utf-8 must pass the content-type gate")
	})

	t.Run("declared non-JSON content-type is 415", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/probe-ct",
			strings.NewReader(`<x>hello</x>`))
		req.Header.Set("Content-Type", "application/xml; charset=utf-8")
		resp, err := app.Test(req, 2000)
		require.NoError(t, err)
		defer resp.Body.Close()
		assert.Equal(t, http.StatusUnsupportedMediaType, resp.StatusCode,
			"a declared non-JSON content-type must 415 unsupported_media_type")
	})
}

// TestStashIgnoredFields_DetectsUnknownKeys drives stashIgnoredFields directly
// and asserts the sorted unknown set lands in Locals — and that a body with
// only known keys stashes nothing.
func TestStashIgnoredFields_DetectsUnknownKeys(t *testing.T) {
	app := fiber.New()

	t.Run("unknown keys stashed sorted", func(t *testing.T) {
		app.Post("/probe", func(c *fiber.Ctx) error {
			var body provisionRequestBody
			require.NoError(t, c.BodyParser(&body))
			stashIgnoredFields(c, c.Body(), &body)
			v, _ := c.Locals(ignoredFieldsKey).([]string)
			return c.JSON(fiber.Map{"ignored": v})
		})
		req := httptest.NewRequest(http.MethodPost, "/probe",
			strings.NewReader(`{"name":"x","region":"mars","size":"xl"}`))
		req.Header.Set("Content-Type", "application/json")
		resp, err := app.Test(req, 2000)
		require.NoError(t, err)
		defer resp.Body.Close()
		var out struct {
			Ignored []string `json:"ignored"`
		}
		decodeInto(t, resp, &out)
		// Sorted: "region" < "size".
		assert.Equal(t, []string{"region", "size"}, out.Ignored,
			"both unknown keys must be reported in sorted order; known keys (name) excluded")
	})

	t.Run("all-known body stashes nothing", func(t *testing.T) {
		app.Post("/probe2", func(c *fiber.Ctx) error {
			var body provisionRequestBody
			require.NoError(t, c.BodyParser(&body))
			stashIgnoredFields(c, c.Body(), &body)
			v, ok := c.Locals(ignoredFieldsKey).([]string)
			return c.JSON(fiber.Map{"present": ok, "ignored": v})
		})
		req := httptest.NewRequest(http.MethodPost, "/probe2",
			strings.NewReader(`{"name":"x","env":"production","dedicated":true}`))
		req.Header.Set("Content-Type", "application/json")
		resp, err := app.Test(req, 2000)
		require.NoError(t, err)
		defer resp.Body.Close()
		var out struct {
			Present bool     `json:"present"`
			Ignored []string `json:"ignored"`
		}
		decodeInto(t, resp, &out)
		assert.False(t, out.Present, "no ignored_fields must be stashed when every key is recognised")
		assert.Empty(t, out.Ignored)
	})
}

// TestDecorateIgnoredFields_InjectsOnlyWhenPresent asserts the response
// decorator adds the field exactly when (and only when) Locals carries a
// non-empty unknown set — the common all-known path keeps its compact shape.
func TestDecorateIgnoredFields_InjectsOnlyWhenPresent(t *testing.T) {
	app := fiber.New()

	app.Get("/with", func(c *fiber.Ctx) error {
		c.Locals(ignoredFieldsKey, []string{"region"})
		return c.JSON(decorateIgnoredFields(c, fiber.Map{"ok": true}))
	})
	app.Get("/without", func(c *fiber.Ctx) error {
		return c.JSON(decorateIgnoredFields(c, fiber.Map{"ok": true}))
	})
	app.Get("/empty", func(c *fiber.Ctx) error {
		c.Locals(ignoredFieldsKey, []string{})
		return c.JSON(decorateIgnoredFields(c, fiber.Map{"ok": true}))
	})

	for _, tc := range []struct {
		path        string
		wantPresent bool
	}{
		{"/with", true},
		{"/without", false},
		{"/empty", false}, // empty slice must NOT surface the field
	} {
		req := httptest.NewRequest(http.MethodGet, tc.path, nil)
		resp, err := app.Test(req, 2000)
		require.NoError(t, err)
		var out map[string]any
		decodeInto(t, resp, &out)
		_, present := out[ignoredFieldsKey]
		assert.Equal(t, tc.wantPresent, present,
			"%s: ignored_fields presence mismatch", tc.path)
	}
}
