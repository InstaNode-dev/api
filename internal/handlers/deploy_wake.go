package handlers

// deploy_wake.go — explicit wake path for scale-to-zero (Task #54).
//
// WHY AN EXPLICIT WAKE (v1 design decision)
//
// instanode.dev serves a deployed app via a k8s Ingress on
// *.deployment.instanode.dev that routes straight to the per-app Service in
// the instant-deploy-<appID> namespace. The api process is NOT in the request
// path. Transparent wake-on-request (a request to a sleeping app
// auto-scales it and holds the connection until ready) therefore requires an
// ACTIVATOR proxy in front of every app — KEDA http-add-on or a Knative-style
// activator. That is a significant new dependency and is explicitly out of
// scope for the scale-to-zero v1.
//
// v1 ships scale-DOWN (worker idle-scaler) + this fast EXPLICIT wake:
//
//   POST /deploy/:id/wake → scales the app back to replicas=1 and returns once
//   the scale patch is accepted by k8s. The pod still needs its normal startup
//   time before it serves traffic, so a request that races the wake gets the
//   app's own cold-start latency (a brief 502/503 from the ingress until the
//   pod is Ready), exactly as a fresh rollout would. Callers/dashboard/agents
//   surface "sleeping — wake" and retry the app URL after waking.
//
// COLD-START CONTRACT (documented v1 limitation)
//
//   - While scaled_to_zero, the app URL returns the ingress's upstream-down
//     response (502/503) because there is no pod. This is the documented v1
//     trade-off of explicit wake vs a transparent activator.
//   - POST /deploy/:id/wake is idempotent: waking an already-awake app just
//     refreshes last_activity_at (so it won't be re-descheduled immediately).
//   - The endpoint is gated by DEPLOY_SCALE_TO_ZERO_ENABLED. With the flag OFF
//     it returns 501 and performs NO scaling and NO DB writes (flag-off inert).

import (
	"errors"
	"log/slog"

	"github.com/gofiber/fiber/v2"

	"instant.dev/internal/middleware"
	"instant.dev/internal/models"
)

// Wake handles POST /deploy/:id/wake. It scales a (possibly scaled-to-zero)
// deployment back to replicas=1 and clears the scaled_to_zero flag, returning
// the refreshed deployment. See the file header for the cold-start contract.
func (h *DeployHandler) Wake(c *fiber.Ctx) error {
	if !h.cfg.DeployScaleToZeroEnabled {
		// Flag OFF → fully inert: no scale call, no DB write.
		return respondError(c, fiber.StatusNotImplemented, "scale_to_zero_disabled",
			"Scale-to-zero is not enabled on this platform")
	}

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
		// 404 not 403: never confirm the existence of another team's deployment.
		return respondError(c, fiber.StatusNotFound, "not_found", "Deployment not found")
	}

	// Scale the k8s Deployment back to 1 replica. A NotFound Deployment is a
	// no-op inside compute.Scale (the row may have been torn down), so this only
	// errors on a real k8s transport failure — surface it so the caller retries.
	if d.ProviderID != "" {
		if scaleErr := h.compute.Scale(c.Context(), appID, 1); scaleErr != nil {
			slog.Warn("deploy.wake.scale_failed",
				"app_id", appID, "provider_id", d.ProviderID, "error", scaleErr,
				"request_id", middleware.GetRequestID(c))
			return respondError(c, fiber.StatusServiceUnavailable, "wake_failed",
				"Failed to wake deployment; please retry")
		}
	}

	// DB half: clear scaled_to_zero + bump last_activity_at so the idle-scaler
	// doesn't immediately re-deschedule the just-woken app.
	if _, dbErr := models.WakeDeployment(c.Context(), h.db, d.ID); dbErr != nil {
		slog.Error("deploy.wake.db_failed",
			"app_id", appID, "error", dbErr,
			"request_id", middleware.GetRequestID(c))
		return respondError(c, fiber.StatusServiceUnavailable, "wake_failed",
			"Failed to record wake; please retry")
	}

	// Re-read so the response reflects the cleared flag + new activity stamp.
	fresh, err := models.GetDeploymentByID(c.Context(), h.db, d.ID)
	if err != nil {
		// The scale + DB write already succeeded; a re-read failure shouldn't
		// fail the wake. Fall back to the pre-read row with the fields we just set.
		d.ScaledToZero = false
		fresh = d
	}

	slog.Info("deploy.woke",
		"app_id", appID, "team_id", team.ID,
		"request_id", middleware.GetRequestID(c))

	return c.JSON(fiber.Map{
		"ok":         true,
		"message":    "Deployment woken — the app will be reachable once its pod is Ready (cold start).",
		"deployment": deploymentToMapWithDB(fresh, h.db),
	})
}
