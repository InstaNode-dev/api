package handlers

// github_deploy.go — GitHub auto-deploy endpoints (migration 035).
//
// Lets a customer wire a deployment to a GitHub repo + branch. On every
// push to the tracked branch, GitHub POSTs to /webhooks/github/:webhook_id,
// the API verifies the HMAC-SHA256 signature, and enqueues a row in
// pending_github_deploys for the worker to drain.
//
// Routes (registered in router.go):
//
//   POST   /api/v1/deployments/:id/github   body: {repo, branch}
//                                           returns webhook_url + secret
//                                           (Pro+ — see tier gate)
//   GET    /api/v1/deployments/:id/github   current connection + last deploy
//   DELETE /api/v1/deployments/:id/github   disconnect
//
//   POST   /webhooks/github/:webhook_id     PUBLIC, signed (HMAC-SHA256).
//                                           verifies X-Hub-Signature-256,
//                                           checks branch match + idempotency
//                                           (last_commit_sha), enqueues
//                                           pending_github_deploys row.
//
// Tier gating: Pro+. Hobby tier allows a single deployment total (see
// plans.yaml deployments_apps=1) — connecting a single GitHub repo to that
// single app is permitted; the agent can still rebuild it on every push.
// Anonymous / free are rejected (no deployments at all on those tiers).
//
// Rate limit: max 10 deploys/hour/repo. A noisy PR ladder, force-push loop,
// or webhook replay storm can't burn unbounded build quota. Enforced at
// receive time by counting recent pending_github_deploys rows for the
// connection.

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"

	"instant.dev/internal/config"
	"instant.dev/internal/crypto"
	"instant.dev/internal/middleware"
	"instant.dev/internal/models"
	"instant.dev/internal/plans"
	"instant.dev/internal/safego"
)

// githubMaxDeploysPerHour is the per-repo rate-limit cap. A connection that
// exceeds this in a rolling 1h window gets a 429 + Retry-After at receive
// time. Picked at 10 so a normal "10 commits to main during a heavy day"
// flow still works; a runaway feedback loop or webhook replay storm is
// throttled fast.
const githubMaxDeploysPerHour = 10

// githubRateLimitWindow is the rolling window for githubMaxDeploysPerHour.
const githubRateLimitWindow = time.Hour

// githubMaxWebhookBodyBytes is the hard ceiling on the inbound GitHub
// webhook body. GitHub itself caps push payloads at 25 MiB; we accept up
// to that and reject anything larger with 413 BEFORE HMAC verification
// and JSON unmarshal so a hostile sender cannot make the handler buffer
// and parse an unbounded body.
const githubMaxWebhookBodyBytes = 25 << 20

// githubAllowedTiers names the plan tiers permitted to wire a GitHub
// connection. Anonymous / free are excluded because they can't deploy at
// all (deployments_apps=0). Hobby is allowed because a Hobby team CAN have
// one deployment, and that single deployment ought to be auto-deployable.
// Yearly variants are accepted via plans.CanonicalTier.
var githubAllowedTiers = map[string]bool{
	"hobby":  true,
	"pro":    true,
	"growth": true,
	"team":   true,
}

// githubRepoRegex matches "owner/repo" using the GitHub-allowed alphabet.
// Owner is 1-39 chars; repo is 1-100 chars; both accept ASCII alphanumerics,
// hyphen, underscore, dot. Not exhaustive vs the GitHub-username rules
// (those forbid leading hyphens) but conservative enough to keep injection
// attacks off the archive URL.
var githubRepoRegex = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,38}/[A-Za-z0-9._-]{1,100}$`)

// GitHubDeployHandler owns the /api/v1/deployments/:id/github trio plus the
// PUBLIC receive endpoint at /webhooks/github/:webhook_id. Shares the db
// pool + AES key + plan registry with DeployHandler; intentionally a
// separate type so the surface is auditable in one file.
type GitHubDeployHandler struct {
	db           *sql.DB
	cfg          *config.Config
	planRegistry *plans.Registry
}

// NewGitHubDeployHandler constructs the handler. All three deps are
// required — the receive endpoint reads from the DB, decrypts with cfg.AESKey,
// and the connect endpoint consults planRegistry for the tier gate.
func NewGitHubDeployHandler(db *sql.DB, cfg *config.Config, planRegistry *plans.Registry) *GitHubDeployHandler {
	return &GitHubDeployHandler{db: db, cfg: cfg, planRegistry: planRegistry}
}

// connectGitHubBody is the JSON body for POST /api/v1/deployments/:id/github.
type connectGitHubBody struct {
	Repo           string `json:"repo"`
	Branch         string `json:"branch"`
	InstallationID *int64 `json:"installation_id,omitempty"`
}

// ── POST /api/v1/deployments/:id/github ──────────────────────────────────────

// Connect wires a deployment to a GitHub repo. The :id path param is the
// deployment's app_id (TEXT short slug); we resolve it to deployments.id
// (UUID) for the FK into app_github_connections.
//
// Response: { ok, connection: {...}, webhook_url, webhook_secret }.
//   - webhook_url    is "https://<host>/webhooks/github/<connection_id>"
//     — the customer pastes this into GitHub.
//   - webhook_secret is the plaintext HMAC key — returned ONCE here, never
//     surfaced again. The customer pastes it into GitHub.
//
// Idempotency: a deployment can have AT MOST one connection (unique index
// on app_id). A second POST returns 409 with a clear agent_action telling
// the caller to DELETE first or reuse the existing connection.
func (h *GitHubDeployHandler) Connect(c *fiber.Ctx) error {
	team, err := h.requireTeam(c)
	if err != nil {
		return err
	}

	// Tier gate. plans.CanonicalTier strips "_yearly" so a "pro_yearly"
	// team still passes. The 402 surfaces an upgrade pointer for the agent.
	canon := plans.CanonicalTier(team.PlanTier)
	if !githubAllowedTiers[canon] {
		return respondErrorWithAgentAction(c, fiber.StatusPaymentRequired,
			"github_requires_paid_tier",
			fmt.Sprintf("GitHub auto-deploy is available on Hobby and above. Your team is on %s.", team.PlanTier),
			"Tell the user GitHub auto-deploy requires a paid plan (Hobby and above) — upgrade at https://instanode.dev/pricing.",
			"https://instanode.dev/pricing")
	}

	appID := c.Params("id")
	d, err := models.GetDeploymentByAppID(c.Context(), h.db, appID)
	if err != nil {
		var notFound *models.ErrDeploymentNotFound
		if errors.As(err, &notFound) {
			return respondError(c, fiber.StatusNotFound, "not_found", "Deployment not found")
		}
		return respondError(c, fiber.StatusServiceUnavailable, "fetch_failed", "Failed to fetch deployment")
	}
	if d.TeamID != team.ID {
		// 404 not 403: never confirm the existence of deployments owned
		// by other teams.
		return respondError(c, fiber.StatusNotFound, "not_found", "Deployment not found")
	}

	var body connectGitHubBody
	if err := c.BodyParser(&body); err != nil {
		return respondError(c, fiber.StatusBadRequest, "invalid_body",
			"Request body must be JSON: {\"repo\":\"owner/repo\",\"branch\":\"main\"}")
	}
	repo := strings.TrimSpace(body.Repo)
	branch := strings.TrimSpace(body.Branch)
	if branch == "" {
		branch = "main"
	}
	if repo == "" || !githubRepoRegex.MatchString(repo) {
		return respondError(c, fiber.StatusBadRequest, "invalid_repo",
			"Field 'repo' must be in 'owner/repo' form, e.g. 'octocat/hello-world'")
	}
	if len(branch) > 250 {
		return respondError(c, fiber.StatusBadRequest, "invalid_branch",
			"Branch name must be 250 characters or fewer")
	}

	// Generate a 32-byte HMAC signing key. Same shape as GitHub's
	// recommended webhook secret length. Encoded as hex so the customer
	// can paste it into the GitHub webhook UI verbatim.
	secretBytes := make([]byte, 32)
	if _, err := rand.Read(secretBytes); err != nil {
		return respondError(c, fiber.StatusInternalServerError, "internal_error",
			"Failed to generate webhook secret")
	}
	plaintextSecret := hex.EncodeToString(secretBytes)

	aesKey, keyErr := crypto.ParseAESKey(h.cfg.AESKey)
	if keyErr != nil {
		slog.Error("github.connect.aes_key_unavailable", "error", keyErr)
		return respondError(c, fiber.StatusServiceUnavailable, "encryption_unavailable",
			"Webhook secret encryption is misconfigured on the server")
	}
	ciphertext, encErr := crypto.Encrypt(aesKey, plaintextSecret)
	if encErr != nil {
		return respondError(c, fiber.StatusServiceUnavailable, "encryption_failed",
			"Failed to encrypt webhook secret")
	}

	conn, err := models.CreateGitHubConnection(c.Context(), h.db, models.CreateGitHubConnectionParams{
		AppID:          d.ID,
		TeamID:         team.ID,
		GitHubRepo:     repo,
		Branch:         branch,
		WebhookSecret:  ciphertext,
		InstallationID: body.InstallationID,
	})
	if err != nil {
		// Unique-index collision on (app_id) — already connected.
		if strings.Contains(strings.ToLower(err.Error()), "uq_app_github_connection") ||
			strings.Contains(strings.ToLower(err.Error()), "duplicate key") {
			return respondErrorWithAgentAction(c, fiber.StatusConflict,
				"already_connected",
				"This deployment already has a GitHub connection. Delete it first to reconnect.",
				"Tell the user this deployment already has a GitHub connection — disconnect with DELETE /api/v1/deployments/{id}/github before re-running connect.",
				"")
		}
		slog.Error("github.connect.create_failed", "error", err,
			"team_id", team.ID, "app_id", appID)
		return respondError(c, fiber.StatusServiceUnavailable, "create_failed",
			"Failed to record GitHub connection")
	}

	webhookURL := h.buildWebhookURL(c, conn.ID)

	// audit_log emit — github.connected. Best-effort goroutine.
	h.emitAudit(models.AuditKindGitHubConnected, team.ID, fiber.Map{
		"app_id":        d.AppID,
		"connection_id": conn.ID.String(),
		"github_repo":   repo,
		"branch":        branch,
	})

	slog.Info("github.connected",
		"app_id", appID, "team_id", team.ID,
		"github_repo", repo, "branch", branch,
		"request_id", middleware.GetRequestID(c))

	return c.Status(fiber.StatusCreated).JSON(fiber.Map{
		"ok":             true,
		"connection":     githubConnectionToMap(conn, d.AppID),
		"webhook_url":    webhookURL,
		"webhook_secret": plaintextSecret,
		"note":           "Paste webhook_url and webhook_secret into GitHub → Settings → Webhooks. Content type: application/json. Events: push only.",
	})
}

// ── GET /api/v1/deployments/:id/github ───────────────────────────────────────

// Get returns the current connection (without the webhook secret — that is
// returned exactly once on Connect). Useful for the dashboard's "connected
// to <repo>" tile + last-deploy timestamp.
func (h *GitHubDeployHandler) Get(c *fiber.Ctx) error {
	team, err := h.requireTeam(c)
	if err != nil {
		return err
	}

	appID := c.Params("id")
	d, err := models.GetDeploymentByAppID(c.Context(), h.db, appID)
	if err != nil {
		var notFound *models.ErrDeploymentNotFound
		if errors.As(err, &notFound) {
			return respondError(c, fiber.StatusNotFound, "not_found", "Deployment not found")
		}
		return respondError(c, fiber.StatusServiceUnavailable, "fetch_failed", "Failed to fetch deployment")
	}
	if d.TeamID != team.ID {
		// 404 not 403: never confirm the existence of deployments owned
		// by other teams.
		return respondError(c, fiber.StatusNotFound, "not_found", "Deployment not found")
	}

	conn, err := models.GetGitHubConnectionByAppID(c.Context(), h.db, d.ID)
	if err != nil {
		var notFound *models.ErrGitHubConnectionNotFound
		if errors.As(err, &notFound) {
			return c.JSON(fiber.Map{
				"ok":         true,
				"connected":  false,
				"connection": nil,
			})
		}
		return respondError(c, fiber.StatusServiceUnavailable, "fetch_failed",
			"Failed to fetch GitHub connection")
	}

	return c.JSON(fiber.Map{
		"ok":          true,
		"connected":   true,
		"connection":  githubConnectionToMap(conn, d.AppID),
		"webhook_url": h.buildWebhookURL(c, conn.ID),
	})
}

// ── DELETE /api/v1/deployments/:id/github ────────────────────────────────────

// Disconnect tears down the GitHub connection. The deployment itself stays;
// only the auto-deploy wiring is removed. The customer can run Connect again
// to mint a fresh secret.
func (h *GitHubDeployHandler) Disconnect(c *fiber.Ctx) error {
	team, err := h.requireTeam(c)
	if err != nil {
		return err
	}

	appID := c.Params("id")
	d, err := models.GetDeploymentByAppID(c.Context(), h.db, appID)
	if err != nil {
		var notFound *models.ErrDeploymentNotFound
		if errors.As(err, &notFound) {
			return respondError(c, fiber.StatusNotFound, "not_found", "Deployment not found")
		}
		return respondError(c, fiber.StatusServiceUnavailable, "fetch_failed", "Failed to fetch deployment")
	}
	if d.TeamID != team.ID {
		// 404 not 403: never confirm the existence of deployments owned
		// by other teams.
		return respondError(c, fiber.StatusNotFound, "not_found", "Deployment not found")
	}

	conn, lookupErr := models.GetGitHubConnectionByAppID(c.Context(), h.db, d.ID)
	if lookupErr != nil {
		var notFound *models.ErrGitHubConnectionNotFound
		if errors.As(lookupErr, &notFound) {
			// Idempotent — no connection, nothing to do.
			return c.JSON(fiber.Map{"ok": true, "deleted": false})
		}
		return respondError(c, fiber.StatusServiceUnavailable, "fetch_failed",
			"Failed to fetch GitHub connection")
	}

	if _, err := models.DeleteGitHubConnectionByAppID(c.Context(), h.db, d.ID); err != nil {
		slog.Error("github.disconnect.delete_failed", "error", err,
			"team_id", team.ID, "app_id", appID)
		return respondError(c, fiber.StatusServiceUnavailable, "delete_failed",
			"Failed to remove GitHub connection")
	}

	h.emitAudit(models.AuditKindGitHubDisconnected, team.ID, fiber.Map{
		"app_id":        d.AppID,
		"connection_id": conn.ID.String(),
	})

	slog.Info("github.disconnected",
		"app_id", appID, "team_id", team.ID,
		"request_id", middleware.GetRequestID(c))

	return c.JSON(fiber.Map{"ok": true, "deleted": true})
}

// ── POST /webhooks/github/:webhook_id (PUBLIC) ───────────────────────────────

// githubPushEvent is the slice of the GitHub `push` event we actually care
// about. The full event is much larger; we ignore the rest.
type githubPushEvent struct {
	Ref    string `json:"ref"`    // "refs/heads/main"
	After  string `json:"after"`  // commit SHA after the push
	Before string `json:"before"` // commit SHA before the push (unused but kept for logging)
	Pusher struct {
		Name string `json:"name"`
	} `json:"pusher"`
	Repository struct {
		FullName string `json:"full_name"` // "owner/repo"
	} `json:"repository"`
}

// Receive handles POST /webhooks/github/:webhook_id (PUBLIC, signed).
//
// Steps:
//  1. Parse :webhook_id → uuid.
//  2. Look up the connection row.
//  3. Read body (raw bytes — needed for HMAC).
//  4. Decrypt secret, verify X-Hub-Signature-256.
//  5. Branch on X-GitHub-Event header: ping → 200 OK; push → continue.
//  6. Parse the push event, check ref matches branch.
//  7. Idempotency: if last_commit_sha == push.after → no-op.
//  8. Rate-limit: count recent rows in the window.
//  9. Insert pending_github_deploys row, bump last_deploy_at.
//  10. Emit github.push_received + github.deploy_triggered audit rows.
//
// On signature failure we emit github.signature_failed and return 401.
// Returning a non-2xx tells GitHub the delivery failed; it will retry,
// which surfaces the misconfiguration in the user's GitHub UI.
func (h *GitHubDeployHandler) Receive(c *fiber.Ctx) error {
	webhookID := c.Params("webhook_id")
	connID, err := uuid.Parse(webhookID)
	if err != nil {
		return respondError(c, fiber.StatusNotFound, "not_found", "Webhook not found")
	}

	conn, err := models.GetGitHubConnectionByID(c.Context(), h.db, connID)
	if err != nil {
		var notFound *models.ErrGitHubConnectionNotFound
		if errors.As(err, &notFound) {
			return respondError(c, fiber.StatusNotFound, "not_found", "Webhook not found")
		}
		slog.Error("github.receive.lookup_failed", "error", err, "connection_id", webhookID)
		return respondError(c, fiber.StatusServiceUnavailable, "fetch_failed",
			"Failed to fetch GitHub connection")
	}

	// Decrypt the HMAC secret for signature verification.
	aesKey, keyErr := crypto.ParseAESKey(h.cfg.AESKey)
	if keyErr != nil {
		slog.Error("github.receive.aes_key_unavailable", "error", keyErr)
		return respondError(c, fiber.StatusServiceUnavailable, "encryption_unavailable",
			"Webhook secret encryption is misconfigured on the server")
	}
	plaintextSecret, decErr := crypto.Decrypt(aesKey, conn.WebhookSecret)
	if decErr != nil {
		slog.Error("github.receive.decrypt_failed", "error", decErr,
			"connection_id", conn.ID)
		return respondError(c, fiber.StatusServiceUnavailable, "decrypt_failed",
			"Failed to read webhook secret")
	}

	// Capture the body for HMAC + later JSON parse. Fiber buffers the body
	// internally so c.Body() is safe to call multiple times.
	body := c.Body()

	// P2 (BugBash 2026-05-18): cap the inbound body BEFORE HMAC verify +
	// JSON unmarshal. GitHub itself never sends a push payload over 25 MiB;
	// anything larger is hostile — reject with 413 rather than burning CPU
	// hashing and parsing it.
	if len(body) > githubMaxWebhookBodyBytes {
		slog.Warn("github.receive.body_too_large",
			"connection_id", conn.ID, "bytes", len(body),
			"request_id", middleware.GetRequestID(c))
		return respondError(c, fiber.StatusRequestEntityTooLarge, "payload_too_large",
			"GitHub webhook payload exceeds the 25 MiB cap")
	}

	sigHeader := c.Get("X-Hub-Signature-256")
	if !VerifyGitHubSignature(plaintextSecret, body, sigHeader) {
		h.emitAudit(models.AuditKindGitHubSignatureFailed, conn.TeamID, fiber.Map{
			"connection_id": conn.ID.String(),
			"ip":            c.IP(),
			"user_agent":    c.Get("User-Agent"),
		})
		slog.Warn("github.receive.signature_failed",
			"connection_id", conn.ID, "team_id", conn.TeamID,
			"ip", c.IP(), "request_id", middleware.GetRequestID(c))
		return respondError(c, fiber.StatusUnauthorized, "signature_invalid",
			"X-Hub-Signature-256 did not verify")
	}

	// Ping events are GitHub's "I just created this webhook" handshake.
	// 200 OK with no work.
	event := c.Get("X-GitHub-Event")
	if event == "ping" {
		return c.JSON(fiber.Map{"ok": true, "pong": true})
	}
	if event != "push" {
		// Other events (pull_request, deployment, etc.) — accept but no-op.
		// Returning 2xx avoids GitHub red dots in the customer's webhook UI.
		return c.JSON(fiber.Map{"ok": true, "ignored": true, "event": event})
	}

	var ev githubPushEvent
	if err := json.Unmarshal(body, &ev); err != nil {
		return respondError(c, fiber.StatusBadRequest, "invalid_payload",
			"Push event body is not valid JSON")
	}

	// Branch filter. GitHub's ref is "refs/heads/<branch>" or
	// "refs/tags/<tag>". We only auto-deploy on the tracked branch.
	wantRef := "refs/heads/" + conn.Branch
	if ev.Ref != wantRef {
		return c.JSON(fiber.Map{
			"ok":      true,
			"ignored": true,
			"reason":  "branch_mismatch",
		})
	}

	// Idempotency: if the same commit already triggered a deploy, no-op.
	// last_commit_sha is the most recent enqueued commit; the worker may
	// not have drained yet, but re-enqueuing would be wasted work.
	if conn.LastCommitSHA.Valid && conn.LastCommitSHA.String == ev.After {
		return c.JSON(fiber.Map{
			"ok":        true,
			"duplicate": true,
			"commit":    ev.After,
		})
	}

	// Empty commit SHA (e.g. branch-delete push) — nothing to deploy.
	if ev.After == "" || ev.After == "0000000000000000000000000000000000000000" {
		return c.JSON(fiber.Map{
			"ok":      true,
			"ignored": true,
			"reason":  "no_commit",
		})
	}

	// Emit push_received BEFORE enqueue so the audit trail reflects the
	// signal arriving even if the enqueue fails.
	h.emitAudit(models.AuditKindGitHubPushReceived, conn.TeamID, fiber.Map{
		"connection_id": conn.ID.String(),
		"commit_sha":    ev.After,
		"branch":        conn.Branch,
		"pusher":        ev.Pusher.Name,
	})

	// Rate-limit + enqueue in one serialized transaction. The count and the
	// insert run under a FOR UPDATE lock on the connection row, so two
	// concurrent pushes to the same repo can no longer both pass a stale
	// `recent < cap` check and both enqueue (the count-then-enqueue TOCTOU).
	// Bounded by the 1h window; different connections don't contend.
	since := time.Now().Add(-githubRateLimitWindow)
	pendingID, enqErr := models.CountAndEnqueueGitHubDeployLocked(c.Context(), h.db,
		models.EnqueueGitHubDeployParams{
			ConnectionID: conn.ID,
			AppID:        conn.AppID,
			CommitSHA:    ev.After,
			PusherLogin:  ev.Pusher.Name,
		}, since, githubMaxDeploysPerHour)
	if enqErr != nil {
		var rateLimited *models.ErrGitHubDeployRateLimited
		if errors.As(enqErr, &rateLimited) {
			slog.Info("github.receive.rate_limited",
				"connection_id", conn.ID, "recent", rateLimited.Recent,
				"request_id", middleware.GetRequestID(c))
			return respondErrorWithRetry(c, fiber.StatusTooManyRequests,
				"rate_limited",
				fmt.Sprintf("GitHub deploys for this connection are capped at %d/hour. Try again shortly.", githubMaxDeploysPerHour),
				int(githubRateLimitWindow.Seconds()))
		}
		slog.Error("github.receive.enqueue_failed", "error", enqErr,
			"connection_id", conn.ID, "commit", ev.After)
		return respondError(c, fiber.StatusServiceUnavailable, "enqueue_failed",
			"Failed to enqueue deploy")
	}

	// Bump last_commit_sha so a duplicate redelivery of the same event
	// short-circuits next time.
	if err := models.UpdateGitHubConnectionLastDeploy(c.Context(), h.db, conn.ID, ev.After); err != nil {
		slog.Warn("github.receive.last_deploy_update_failed",
			"error", err, "connection_id", conn.ID)
	}

	h.emitAudit(models.AuditKindGitHubDeployTriggered, conn.TeamID, fiber.Map{
		"connection_id": conn.ID.String(),
		"app_id":        conn.AppID.String(),
		"commit_sha":    ev.After,
		"pending_id":    pendingID.String(),
	})

	slog.Info("github.deploy_triggered",
		"connection_id", conn.ID, "app_id", conn.AppID,
		"commit", ev.After, "pusher", ev.Pusher.Name,
		"request_id", middleware.GetRequestID(c))

	return c.Status(fiber.StatusAccepted).JSON(fiber.Map{
		"ok":            true,
		"deploy_queued": true,
		"pending_id":    pendingID.String(),
		"commit_sha":    ev.After,
		"connection_id": conn.ID.String(),
		"note":          "Deploy will be picked up by the worker shortly. Poll GET /deploy/<app_id> for status.",
	})
}

// ── helpers ─────────────────────────────────────────────────────────────────

// VerifyGitHubSignature returns true when sigHeader is "sha256=<hex>" and
// the HMAC-SHA256 of body with the supplied secret matches in
// constant-time. Exported so unit tests (in handlers_test) can drive it
// directly without going through Fiber.
//
// GitHub formats the header as "sha256=" + hex(HMAC-SHA256(secret, body)).
// We compare byte-for-byte via hmac.Equal to avoid timing leaks.
func VerifyGitHubSignature(secret string, body []byte, sigHeader string) bool {
	const prefix = "sha256="
	if !strings.HasPrefix(sigHeader, prefix) {
		return false
	}
	supplied, err := hex.DecodeString(sigHeader[len(prefix):])
	if err != nil {
		return false
	}
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	expected := mac.Sum(nil)
	return hmac.Equal(supplied, expected)
}

// requireTeam mirrors DeployHandler.requireTeam — extracts the auth team
// from the request context and rejects unauthenticated callers.
func (h *GitHubDeployHandler) requireTeam(c *fiber.Ctx) (*models.Team, error) {
	teamIDStr := middleware.GetTeamID(c)
	if teamIDStr == "" {
		return nil, respondError(c, fiber.StatusUnauthorized, "unauthorized",
			"A session token is required")
	}
	teamUUID, err := parseTeamID(teamIDStr)
	if err != nil {
		return nil, respondError(c, fiber.StatusBadRequest, "invalid_team",
			"Team ID in token is not a valid UUID")
	}
	team, err := models.GetTeamByID(c.Context(), h.db, teamUUID)
	if err != nil {
		return nil, respondError(c, fiber.StatusServiceUnavailable, "team_lookup_failed",
			"Failed to look up team")
	}
	return team, nil
}

// buildWebhookURL constructs the public URL the customer pastes into the
// GitHub webhook UI. c.BaseURL() returns "https://api.instanode.dev" in
// production and "http://localhost:8080" in dev (which is fine — GitHub
// can hit localhost when the developer is testing via ngrok, smee.io,
// etc.).
func (h *GitHubDeployHandler) buildWebhookURL(c *fiber.Ctx, connID uuid.UUID) string {
	return c.BaseURL() + "/webhooks/github/" + connID.String()
}

// githubConnectionToMap renders the connection row for JSON. appID is the
// short slug (TEXT) — included in the response so a dashboard / agent
// doesn't need a second round-trip to learn which deployment the
// connection belongs to.
func githubConnectionToMap(conn *models.AppGitHubConnection, appID string) fiber.Map {
	m := fiber.Map{
		"id":          conn.ID.String(),
		"app_id":      appID,
		"github_repo": conn.GitHubRepo,
		"branch":      conn.Branch,
		"created_at":  conn.CreatedAt,
	}
	if conn.LastDeployAt.Valid {
		m["last_deploy_at"] = conn.LastDeployAt.Time
	}
	if conn.LastCommitSHA.Valid {
		m["last_commit_sha"] = conn.LastCommitSHA.String
	}
	if conn.InstallationID.Valid {
		m["installation_id"] = conn.InstallationID.Int64
	}
	return m
}

// emitAudit writes an audit_log row in a goroutine. Mirrors
// emitDeployAudit's best-effort contract: failures are logged but never
// surface to the caller.
func (h *GitHubDeployHandler) emitAudit(kind string, teamID uuid.UUID, meta fiber.Map) {
	safego.Go("github_deploy.bg", func() {
		blob, _ := json.Marshal(meta)
		ev := models.AuditEvent{
			TeamID:       teamID,
			Actor:        "system",
			Kind:         kind,
			ResourceType: "github_connection",
			Summary:      kind,
			Metadata:     blob,
		}
		ctx, cancel := contextWithTimeout(5 * time.Second)
		defer cancel()
		if err := models.InsertAuditEvent(ctx, h.db, ev); err != nil {
			slog.Warn("github.audit.emit_failed", "kind", kind, "error", err)
		}
	})
}

// contextWithTimeout is a thin alias so the audit goroutine doesn't import
// the bare context package in this file (already imported elsewhere in
// the handlers package). Kept as its own helper so the timeout is named
// at every call site.
func contextWithTimeout(d time.Duration) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), d)
}

// Compile-time guard against accidentally unused imports — http + io are
// reserved for a future tarball fetcher helper that lives inline (the
// worker does the heavy lifting, but the api may need to validate the
// archive URL is reachable before enqueue in a later slice).
var (
	_ = http.StatusOK
	_ = io.EOF
)
