package handlers

// github_app_webhook_whitebox_test.go — white-box (package handlers) coverage
// for GitHubAppWebhookHandler.Receive and the two sub-handlers. These tests
// run without a DB; every branch that touches h.db is either excluded here
// (handled in the integration file) or triggered before any DB call.
//
// Branches covered:
//   - flag OFF → 501
//   - body > 25 MiB → 413
//   - bad/missing signature → 401
//   - ping → 200 pong
//   - unknown event → 200 ignored
//   - installation invalid JSON → 400 (no DB touched)
//   - push invalid JSON → 400 (no DB touched)
//   - push non-branch ref (refs/tags/v1) → 200 ignored no_deployable_ref
//   - push branch-delete (after == 0*40) → 200 ignored no_deployable_ref

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gofiber/fiber/v2"

	"instant.dev/internal/config"
)

// whSignBody computes a valid X-Hub-Signature-256 header value for body+secret.
func whSignBody(secret string, body []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	return "sha256=" + hex.EncodeToString(mac.Sum(nil))
}

// whNewHandler builds a GitHubAppWebhookHandler with the given flag + secret;
// db, rdb, and planRegistry are all nil (no DB-touching path is exercised).
func whNewHandler(enabled bool, secret string) *GitHubAppWebhookHandler {
	return NewGitHubAppWebhookHandler(nil, nil, &config.Config{
		GitHubAppEnabled:       enabled,
		GitHubAppWebhookSecret: secret,
	}, nil)
}

// whApp builds a bare fiber.App with no special ErrorHandler (the webhook
// handler uses plain c.SendStatus / c.JSON, not respondError, so the default
// ErrorHandler is fine).
func whApp(h *GitHubAppWebhookHandler) *fiber.App {
	app := fiber.New()
	app.Post("/wh", h.Receive)
	return app
}

// whPost fires a POST /wh with the given body, event header, and signature.
func whPost(t *testing.T, app *fiber.App, body []byte, event, sig, delivery string) *http.Response {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/wh", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	if event != "" {
		req.Header.Set("X-GitHub-Event", event)
	}
	if sig != "" {
		req.Header.Set("X-Hub-Signature-256", sig)
	}
	if delivery != "" {
		req.Header.Set("X-GitHub-Delivery", delivery)
	}
	resp, err := app.Test(req, 5000)
	if err != nil {
		t.Fatalf("whPost: app.Test: %v", err)
	}
	return resp
}

// ── flag OFF → 501 ────────────────────────────────────────────────────────────

func TestGitHubAppWebhook_FlagOff_501(t *testing.T) {
	h := whNewHandler(false, "secret")
	app := whApp(h)

	resp := whPost(t, app, []byte(`{}`), "ping", "sha256=irrelevant", "")
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNotImplemented {
		t.Errorf("flag OFF must return 501, got %d", resp.StatusCode)
	}
}

// ── body > 25 MiB → 413 ──────────────────────────────────────────────────────

func TestGitHubAppWebhook_BodyTooLarge_413(t *testing.T) {
	const secret = "whsec_test"
	h := whNewHandler(true, secret)

	// Override Fiber's global BodyLimit so the giant body actually reaches the
	// handler (not Fiber's middleware layer). The handler's own check fires first.
	app := fiber.New(fiber.Config{BodyLimit: 50 * 1024 * 1024})
	app.Post("/wh", h.Receive)

	oversized := bytes.Repeat([]byte("x"), (25<<20)+1)
	sig := whSignBody(secret, oversized)
	req := httptest.NewRequest(http.MethodPost, "/wh", bytes.NewReader(oversized))
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set("X-GitHub-Event", "push")
	req.Header.Set("X-Hub-Signature-256", sig)

	resp, err := app.Test(req, 10000)
	if err != nil {
		t.Fatalf("app.Test: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Errorf("body > 25 MiB must return 413, got %d", resp.StatusCode)
	}
}

// ── missing/wrong signature → 401 ────────────────────────────────────────────

func TestGitHubAppWebhook_MissingSignature_401(t *testing.T) {
	h := whNewHandler(true, "whsec_test")
	app := whApp(h)

	body := []byte(`{"action":"ping"}`)
	// Send no X-Hub-Signature-256 header at all.
	req := httptest.NewRequest(http.MethodPost, "/wh", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-GitHub-Event", "ping")

	resp, err := app.Test(req, 5000)
	if err != nil {
		t.Fatalf("app.Test: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("missing signature must return 401, got %d", resp.StatusCode)
	}
}

func TestGitHubAppWebhook_WrongSignature_401(t *testing.T) {
	h := whNewHandler(true, "correct_secret")
	app := whApp(h)

	body := []byte(`{"action":"ping"}`)
	wrongSig := whSignBody("wrong_secret", body)

	resp := whPost(t, app, body, "ping", wrongSig, "")
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("wrong signature must return 401, got %d", resp.StatusCode)
	}
}

// ── ping → 200 pong ──────────────────────────────────────────────────────────

func TestGitHubAppWebhook_Ping_200(t *testing.T) {
	const secret = "whsec_ping"
	h := whNewHandler(true, secret)
	app := whApp(h)

	body := []byte(`{"zen":"Keep it logically awesome.","hook_id":42}`)
	sig := whSignBody(secret, body)

	resp := whPost(t, app, body, "ping", sig, "")
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("ping must return 200, got %d", resp.StatusCode)
	}
	var out map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decode ping response: %v", err)
	}
	if ok, _ := out["ok"].(bool); !ok {
		t.Error("ping response must carry ok:true")
	}
	if pong, _ := out["pong"].(bool); !pong {
		t.Error("ping response must carry pong:true")
	}
}

// ── unknown event → 200 ignored ──────────────────────────────────────────────

func TestGitHubAppWebhook_UnknownEvent_200Ignored(t *testing.T) {
	const secret = "whsec_unknown"
	h := whNewHandler(true, secret)
	app := whApp(h)

	body := []byte(`{"action":"opened"}`)
	sig := whSignBody(secret, body)

	// Use an event NOT in knownWebhookEvents so the metric label canonicalizes
	// to "other" (covers canonicalizeWebhookEvent's fallback + the default arm).
	resp := whPost(t, app, body, "workflow_run", sig, "")
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("unknown event must return 200, got %d", resp.StatusCode)
	}
	var out map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decode unknown-event response: %v", err)
	}
	if ignored, _ := out["ignored"].(bool); !ignored {
		t.Error("unknown event response must carry ignored:true")
	}
}

// ── installation with invalid JSON → 400 ─────────────────────────────────────
// ParseInstallationEvent fails; the handler returns 400 without touching h.db.

func TestGitHubAppWebhook_Installation_BadJSON_400(t *testing.T) {
	const secret = "whsec_instbad"
	h := whNewHandler(true, secret)
	app := whApp(h)

	body := []byte(`not-json`)
	sig := whSignBody(secret, body)

	resp := whPost(t, app, body, "installation", sig, "")
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("installation bad JSON must return 400, got %d", resp.StatusCode)
	}
}

// ── installation action "created" with valid JSON ─────────────────────────────
// action "created" is a no-op in handleInstallation (falls through the switch
// without touching h.db), so it returns 200 without needing a DB.

func TestGitHubAppWebhook_Installation_Created_200(t *testing.T) {
	const secret = "whsec_created"
	h := whNewHandler(true, secret)
	app := whApp(h)

	body := []byte(`{"action":"created","installation":{"id":99,"account":{"login":"acme"}}}`)
	sig := whSignBody(secret, body)

	resp := whPost(t, app, body, "installation", sig, "")
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("installation created must return 200, got %d", resp.StatusCode)
	}
}

// ── push with invalid JSON → 400 ─────────────────────────────────────────────

func TestGitHubAppWebhook_Push_BadJSON_400(t *testing.T) {
	const secret = "whsec_pushbad"
	h := whNewHandler(true, secret)
	app := whApp(h)

	body := []byte(`{broken`)
	sig := whSignBody(secret, body)

	resp := whPost(t, app, body, "push", sig, "")
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("push bad JSON must return 400, got %d", resp.StatusCode)
	}
}

// ── push with a tag ref (non-branch) → 200 ignored no_deployable_ref ─────────

func TestGitHubAppWebhook_Push_TagRef_Ignored(t *testing.T) {
	const secret = "whsec_tagref"
	h := whNewHandler(true, secret)
	app := whApp(h)

	body := []byte(`{"ref":"refs/tags/v1.2.3","after":"abc123deadbeef0000000000000000000000000a","repository":{"full_name":"owner/repo"},"installation":{"id":1}}`)
	sig := whSignBody(secret, body)

	resp := whPost(t, app, body, "push", sig, "")
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("push tag ref must return 200, got %d", resp.StatusCode)
	}
	var out map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if reason, _ := out["reason"].(string); reason != "no_deployable_ref" {
		t.Errorf("expected reason=no_deployable_ref, got %q", reason)
	}
}

// ── push branch-delete (after == 0*40) → 200 ignored no_deployable_ref ───────

func TestGitHubAppWebhook_Push_BranchDelete_Ignored(t *testing.T) {
	const secret = "whsec_branchdel"
	h := whNewHandler(true, secret)
	app := whApp(h)

	zeroSHA := strings.Repeat("0", 40)
	bodyStr := `{"ref":"refs/heads/main","after":"` + zeroSHA + `","repository":{"full_name":"owner/repo"},"installation":{"id":1}}`
	body := []byte(bodyStr)
	sig := whSignBody(secret, body)

	resp := whPost(t, app, body, "push", sig, "")
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("branch-delete push must return 200, got %d", resp.StatusCode)
	}
	var out map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if reason, _ := out["reason"].(string); reason != "no_deployable_ref" {
		t.Errorf("expected reason=no_deployable_ref, got %q", reason)
	}
}

// ── push with empty HeadCommitSHA → 200 ignored no_deployable_ref ─────────────

func TestGitHubAppWebhook_Push_EmptySHA_Ignored(t *testing.T) {
	const secret = "whsec_emptysha"
	h := whNewHandler(true, secret)
	app := whApp(h)

	body := []byte(`{"ref":"refs/heads/main","after":"","repository":{"full_name":"owner/repo"},"installation":{"id":1}}`)
	sig := whSignBody(secret, body)

	resp := whPost(t, app, body, "push", sig, "")
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("push with empty SHA must return 200, got %d", resp.StatusCode)
	}
	var out map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if reason, _ := out["reason"].(string); reason != "no_deployable_ref" {
		t.Errorf("expected reason=no_deployable_ref, got %q", reason)
	}
}
