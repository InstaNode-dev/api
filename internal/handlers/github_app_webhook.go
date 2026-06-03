package handlers

// github_app_webhook.go — the single App-level GitHub webhook (P4.2). Distinct
// from the manual per-connection receiver (github_deploy.go Receive, keyed by
// :webhook_id with a per-connection secret): GitHub delivers ALL events for the
// InstaNode App here, signed with the one App webhook secret. On `push` we match
// the repo+branch to connection(s) linked to that installation and enqueue the
// same redeploy the manual path uses; on `installation` lifecycle events we keep
// github_installations in sync (so a deleted/suspended install stops deploying).
//
// Responses are plain statuses for GitHub's consumption (no agent_action
// envelope — GitHub is the only caller). Gated by cfg.GitHubAppEnabled.

import (
	"database/sql"
	"errors"
	"log/slog"
	"regexp"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/redis/go-redis/v9"

	"instant.dev/internal/config"
	"instant.dev/internal/github"
	"instant.dev/internal/metrics"
	"instant.dev/internal/middleware"
	"instant.dev/internal/models"
	"instant.dev/internal/plans"
)

// githubAppDeliveryDedupTTL is how long a processed X-GitHub-Delivery id is
// remembered so a GitHub redelivery is a no-op (well over GitHub's retry window).
const githubAppDeliveryDedupTTL = 24 * time.Hour

// knownWebhookEvents bounds the {event} metric label. The X-GitHub-Event header
// is attacker-controlled and the label is written BEFORE auth (on a bad
// signature), so an unbounded value would let an unauthenticated caller blow up
// Prometheus series cardinality (review MED-1). Anything unrecognised → "other".
var knownWebhookEvents = map[string]bool{
	"push": true, "installation": true, "installation_repositories": true,
	"ping": true, "pull_request": true, "check_run": true, "check_suite": true,
	"create": true, "delete": true, "release": true,
}

func canonicalizeWebhookEvent(event string) string {
	if knownWebhookEvents[event] {
		return event
	}
	return "other"
}

// commitSHARE matches a full 40-hex git SHA. A push payload's `after` is
// attacker-shaped; anything that isn't a real SHA is not deployable (review LOW-2).
var commitSHARE = regexp.MustCompile(`^[0-9a-f]{40}$`)

// GitHubAppWebhookHandler serves POST /webhooks/github.
type GitHubAppWebhookHandler struct {
	db   *sql.DB
	rdb  *redis.Client
	cfg  *config.Config
	plan *plans.Registry
}

// NewGitHubAppWebhookHandler constructs the handler.
func NewGitHubAppWebhookHandler(db *sql.DB, rdb *redis.Client, cfg *config.Config, planRegistry *plans.Registry) *GitHubAppWebhookHandler {
	return &GitHubAppWebhookHandler{db: db, rdb: rdb, cfg: cfg, plan: planRegistry}
}

// Receive verifies the App-level HMAC, dedupes on delivery id, and dispatches.
func (h *GitHubAppWebhookHandler) Receive(c *fiber.Ctx) error {
	if !h.cfg.GitHubAppEnabled {
		metrics.GitHubWebhookReceivedTotal.WithLabelValues("", "disabled").Inc()
		return c.SendStatus(fiber.StatusNotImplemented)
	}

	body := c.Body()
	if len(body) > githubMaxWebhookBodyBytes {
		metrics.GitHubWebhookReceivedTotal.WithLabelValues("", "error").Inc()
		return c.SendStatus(fiber.StatusRequestEntityTooLarge)
	}

	event := c.Get("X-GitHub-Event")
	// metricEvent is the bounded label (raw event drives dispatch only).
	metricEvent := canonicalizeWebhookEvent(event)
	if err := github.VerifyWebhookSignature(body, c.Get("X-Hub-Signature-256"), h.cfg.GitHubAppWebhookSecret); err != nil {
		metrics.GitHubWebhookReceivedTotal.WithLabelValues(metricEvent, "bad_signature").Inc()
		slog.Warn("github_app.webhook.signature_failed",
			"event", metricEvent, "ip", c.IP(), "request_id", middleware.GetRequestID(c))
		return c.SendStatus(fiber.StatusUnauthorized)
	}

	// Idempotency: a redelivered X-GitHub-Delivery is a no-op. SETNX; fail open
	// on a Redis error (a rare double-deploy beats a missed deploy). The header
	// is GitHub-guaranteed; an absent one (or nil rdb) skips dedup by design.
	if delivery := c.Get("X-GitHub-Delivery"); delivery != "" && h.rdb != nil {
		ok, err := h.rdb.SetNX(c.Context(), "ghapp:delivery:"+delivery, "1", githubAppDeliveryDedupTTL).Result()
		if err == nil && !ok {
			metrics.GitHubWebhookReceivedTotal.WithLabelValues(metricEvent, "replay").Inc()
			return c.JSON(fiber.Map{"ok": true, "duplicate": true})
		}
	}

	switch event {
	case "ping":
		metrics.GitHubWebhookReceivedTotal.WithLabelValues(metricEvent, "ok").Inc()
		return c.JSON(fiber.Map{"ok": true, "pong": true})
	case "installation":
		return h.handleInstallation(c, body, metricEvent)
	case "push":
		return h.handlePush(c, body, metricEvent)
	default:
		// pull_request, check_run, etc. — accept (2xx) so GitHub shows green.
		metrics.GitHubWebhookReceivedTotal.WithLabelValues(metricEvent, "ok").Inc()
		return c.JSON(fiber.Map{"ok": true, "ignored": true, "event": event})
	}
}

// handleInstallation keeps github_installations in sync with the App lifecycle.
// created is a no-op here (the install callback already persisted the team
// link; the webhook has no team_id of ours to bind). delete/suspend/unsuspend
// are keyed on installation_id alone and stop/resume deploys.
func (h *GitHubAppWebhookHandler) handleInstallation(c *fiber.Ctx, body []byte, event string) error {
	ev, err := github.ParseInstallationEvent(body)
	if err != nil {
		metrics.GitHubWebhookReceivedTotal.WithLabelValues(event, "error").Inc()
		return c.SendStatus(fiber.StatusBadRequest)
	}
	switch ev.Action {
	case "deleted":
		if _, derr := models.DeleteGitHubInstallation(c.Context(), h.db, ev.InstallationID); derr != nil {
			slog.Warn("github_app.webhook.installation_delete_failed", "error", derr, "installation_id", ev.InstallationID)
		}
	case "suspend":
		if serr := models.SetGitHubInstallationSuspended(c.Context(), h.db, ev.InstallationID, true); serr != nil {
			slog.Warn("github_app.webhook.installation_suspend_failed", "error", serr, "installation_id", ev.InstallationID)
		}
	case "unsuspend":
		if serr := models.SetGitHubInstallationSuspended(c.Context(), h.db, ev.InstallationID, false); serr != nil {
			slog.Warn("github_app.webhook.installation_unsuspend_failed", "error", serr, "installation_id", ev.InstallationID)
		}
	}
	metrics.GitHubWebhookReceivedTotal.WithLabelValues(event, "ok").Inc()
	return c.JSON(fiber.Map{"ok": true, "action": ev.Action})
}

// handlePush matches the push to connection(s) for that repo+branch+installation
// and enqueues a redeploy for each (rate-limited, same path as the manual webhook).
func (h *GitHubAppWebhookHandler) handlePush(c *fiber.Ctx, body []byte, event string) error {
	ev, err := github.ParsePushEvent(body)
	if err != nil {
		metrics.GitHubWebhookReceivedTotal.WithLabelValues(event, "error").Inc()
		return c.SendStatus(fiber.StatusBadRequest)
	}
	branch := ev.Branch()
	// Non-branch ref (tag), branch delete (all-zero SHA), or a non-SHA `after`
	// (hostile payload) → nothing to deploy. commitSHARE rejects the all-zeros
	// delete SHA too (not 40 lowercase hex... it is hex — but a delete carries
	// branch="" only when ref isn't a head; guard both).
	if branch == "" || !commitSHARE.MatchString(ev.HeadCommitSHA) || ev.HeadCommitSHA == "0000000000000000000000000000000000000000" {
		metrics.GitHubWebhookReceivedTotal.WithLabelValues(event, "ok").Inc()
		return c.JSON(fiber.Map{"ok": true, "ignored": true, "reason": "no_deployable_ref"})
	}

	// Security: the installation must exist for us and not be suspended. We never
	// act on a push whose installation we don't own / has been revoked.
	inst, ierr := models.GetGitHubInstallation(c.Context(), h.db, ev.InstallationID)
	if ierr != nil || inst.SuspendedAt.Valid {
		metrics.GitHubWebhookReceivedTotal.WithLabelValues(event, "no_match").Inc()
		return c.JSON(fiber.Map{"ok": true, "ignored": true, "reason": "no_active_installation"})
	}

	conns, cerr := models.FindConnectionsByRepoBranch(c.Context(), h.db, ev.Repo, branch)
	if cerr != nil {
		slog.Error("github_app.webhook.connection_lookup_failed", "error", cerr, "repo", ev.Repo, "branch", branch)
		metrics.GitHubPushDeployTotal.WithLabelValues("error").Inc()
		return c.SendStatus(fiber.StatusServiceUnavailable)
	}

	since := time.Now().Add(-githubRateLimitWindow)
	matched, enqueued := 0, 0
	for _, conn := range conns {
		// The connection MUST belong to the same installation+team the push came
		// from — never deploy a repo for an installation the team doesn't own.
		if !conn.InstallationID.Valid || conn.InstallationID.Int64 != ev.InstallationID || conn.TeamID != inst.TeamID {
			continue
		}
		matched++
		_, enqErr := models.CountAndEnqueueGitHubDeployLocked(c.Context(), h.db, models.EnqueueGitHubDeployParams{
			ConnectionID: conn.ID,
			AppID:        conn.AppID,
			CommitSHA:    ev.HeadCommitSHA,
			PusherLogin:  "",
		}, since, githubMaxDeploysPerHour)
		if enqErr != nil {
			var rl *models.ErrGitHubDeployRateLimited
			if errors.As(enqErr, &rl) {
				metrics.GitHubPushDeployTotal.WithLabelValues("rate_limited").Inc()
				continue
			}
			slog.Error("github_app.webhook.enqueue_failed", "error", enqErr, "connection_id", conn.ID)
			metrics.GitHubPushDeployTotal.WithLabelValues("error").Inc()
			continue
		}
		if uerr := models.UpdateGitHubConnectionLastDeploy(c.Context(), h.db, conn.ID, ev.HeadCommitSHA); uerr != nil {
			slog.Warn("github_app.webhook.last_deploy_update_failed", "error", uerr, "connection_id", conn.ID)
		}
		enqueued++
		metrics.GitHubPushDeployTotal.WithLabelValues("enqueued").Inc()
	}

	if matched == 0 {
		metrics.GitHubWebhookReceivedTotal.WithLabelValues(event, "no_match").Inc()
		metrics.GitHubPushDeployTotal.WithLabelValues("no_connection").Inc()
		return c.JSON(fiber.Map{"ok": true, "ignored": true, "reason": "no_connection"})
	}
	// `enqueued` reports successful enqueues only (≤ matched; the rest were
	// rate-limited/errored and counted in their own metric).
	metrics.GitHubWebhookReceivedTotal.WithLabelValues(event, "ok").Inc()
	return c.Status(fiber.StatusAccepted).JSON(fiber.Map{"ok": true, "matched": matched, "enqueued": enqueued})
}
