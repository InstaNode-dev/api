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
	"net/http"
	"net/http/httptest"
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
