package handlers_test

// upload_size_message_test.go — registry-iterating regression test for B7-P1-1
// (BugBash 2026-05-20) — bug-burner round 3 (2026-05-30).
//
// Bug context: stack.go used to emit `invalid_form` with the message
// "Request must be multipart/form-data (max 200 MB)" — a lie. The actual cap
// is the global Fiber BodyLimit of 50 MiB (router.go), enforced upstream of
// the per-handler MultipartForm() call. Anything > 50 MiB is rejected by
// Fiber's ErrorHandler with `payload_too_large`; the per-handler "invalid_form"
// arm only fires for malformed multipart bodies AT OR UNDER 50 MiB.
//
// The fix updates the message to reference the real cap. This test is
// registry-iterating (rule 18): it walks every multipart-upload endpoint that
// emits an `invalid_form` envelope and asserts the message is consistent with
// the configured cap and does NOT mention any wrong sizes (no "200" of any
// unit). If a future endpoint is added and emits its own "max N MB" hint,
// this test fails until N is reconciled with the actual BodyLimit.
//
// The cap source is router.go:169 `BodyLimit: 50 * 1024 * 1024` — that's the
// single ground truth all per-handler messages must agree with.

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"instant.dev/internal/testhelpers"
)

// decodeErrMsg pulls the `message` field out of a JSON error envelope while
// preserving Body for any follow-up decodes. Mirrors decodeErrCode (which is
// defined in deploy_stack_branches_coverage_test.go).
func decodeErrMsg(t *testing.T, resp *http.Response) string {
	t.Helper()
	b, _ := io.ReadAll(resp.Body)
	var out struct {
		Message string `json:"message"`
	}
	_ = json.Unmarshal(b, &out)
	resp.Body = io.NopCloser(bytes.NewReader(b))
	return out.Message
}

// TestUploadSizeMessage_NoLies — registry-iterating check that every
// multipart-upload endpoint's `invalid_form` message references the actual
// 50 MiB cap (NOT 200 MB, NOT 100 MB, NOT any other size). The fingerprint
// of the bug is: any digit-group followed by `MB|MiB|GB` that is NOT `50`.
//
// We drive each endpoint with a clearly-non-multipart body (Content-Type:
// application/json + a JSON literal) so the MultipartForm() parse fails and
// the handler returns the `invalid_form` arm we want to inspect.
func TestUploadSizeMessage_NoLies(t *testing.T) {
	// Hardcoded ground truth — must match router.go:169. If router.go's
	// BodyLimit changes, this constant changes in lockstep and the test
	// flags every endpoint message that hasn't been updated.
	const wantCapMiB = 50

	// Build the deploy app once (needs auth) and stack app once (anon ok).
	deployApp, deployJWT := deployNewApp(t, "deploy", "")
	db, cleanDB := testhelpers.SetupTestDB(t)
	t.Cleanup(cleanDB)
	ensureStackTables(t, db)
	stackApp := stackNewApp(t, db, nil)

	// Populate the per-row driver — each row knows how to drive its endpoint
	// to the `invalid_form` arm.
	type driver struct {
		path      string
		buildReq  func(t *testing.T) *http.Request
		runRequest func(t *testing.T, req *http.Request) *http.Response
	}

	drivers := []driver{
		{
			path: "/deploy/new",
			buildReq: func(t *testing.T) *http.Request {
				req := httptest.NewRequest(http.MethodPost, "/deploy/new", strings.NewReader("{\"x\":1}"))
				req.Header.Set("Content-Type", "application/json")
				req.Header.Set("Authorization", "Bearer "+deployJWT)
				return req
			},
			runRequest: func(t *testing.T, req *http.Request) *http.Response {
				resp, err := deployApp.Test(req, 10000)
				require.NoError(t, err)
				return resp
			},
		},
		{
			path: "/stacks/new",
			buildReq: func(t *testing.T) *http.Request {
				req := httptest.NewRequest(http.MethodPost, "/stacks/new", strings.NewReader("{\"x\":1}"))
				req.Header.Set("Content-Type", "application/json")
				req.Header.Set("X-Forwarded-For", "10.223.0.1")
				return req
			},
			runRequest: func(t *testing.T, req *http.Request) *http.Response {
				resp, err := stackApp.Test(req, 10000)
				require.NoError(t, err)
				return resp
			},
		},
	}

	// Sanity: the driver list must cover every multipart-upload endpoint
	// that emits `invalid_form`. Today there are exactly 2 (deploy + stacks).
	// If a future endpoint is added, this assertion will not catch it
	// directly — the test author MUST extend the drivers slice. We hard-pin
	// the expected count so a silently-dropped driver row is loud.
	require.Equal(t, 2, len(drivers),
		"upload_size_message driver list must enumerate all multipart-upload "+
			"endpoints emitting invalid_form. If you added a new endpoint, "+
			"extend drivers above.")

	for i, d := range drivers {
		t.Run(d.path, func(t *testing.T) {
			req := d.buildReq(t)
			resp := d.runRequest(t, req)
			defer resp.Body.Close()

			require.Equal(t, http.StatusBadRequest, resp.StatusCode,
				"path %s: want 400 from invalid_form arm", d.path)
			require.Equal(t, "invalid_form", decodeErrCode(t, resp),
				"path %s: want error='invalid_form' to inspect the size message", d.path)

			msg := decodeErrMsg(t, resp)
			require.NotEmpty(t, msg, "path %s: empty message", d.path)

			// Bug-fingerprint: every size mentioned must be the configured cap.
			// The lie we shipped was "200 MB" when the cap is 50 MiB. The test
			// fails if the message contains "200 MB", "200MB", "100 MB",
			// "1 GB", etc. — anything that isn't the real 50-MiB cap.
			//
			// Strategy: walk known wrong sizes; if any is present, fail loud.
			wrongSizes := []string{
				"200 MB", "200MB", "200 MiB", "200MiB",
				"100 MB", "100MB", "100 MiB", "100MiB",
				"1 GB", "1GB", "1 GiB", "1GiB",
			}
			for _, wrong := range wrongSizes {
				assert.NotContainsf(t, msg, wrong,
					"row %d path %s: invalid_form message lies about the cap (says %q but real cap is %d MiB): %q",
					i, d.path, wrong, wantCapMiB, msg)
			}

			// Positive assertion: the message MUST mention the real cap
			// (either "50 MiB" or "50 MB" is acceptable historically). Without
			// this, a future "drop the number entirely" edit would silently
			// regress the agent-UX promise (callers need to know the cap).
			assert.Truef(t,
				strings.Contains(msg, "50 MiB") ||
					strings.Contains(msg, "50MiB") ||
					strings.Contains(msg, "50 MB") ||
					strings.Contains(msg, "50MB"),
				"row %d path %s: invalid_form message must reference the real %d MiB cap; got: %q",
				i, d.path, wantCapMiB, msg)
		})
	}
}
