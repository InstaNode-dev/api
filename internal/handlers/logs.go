package handlers

// logs.go — GET /resources/:token/logs — streams pod logs for growth-tier (isolated) resources.
//
// Only available for growth-tier resources. Shared-tier resources run on
// platform-owned pods shared across customers — those cannot be exposed per-tenant.
//
// Token is the auth credential (same pattern as POST /webhook/receive/:token).
// No team JWT required — the token IS the credential.
//
// Data flow:
//
//	caller
//	  │
//	  │  GET /resources/:token/logs?tail=100
//	  ▼
//	LogsHandler.ResourceLogs
//	  │  1. Parse + validate token
//	  │  2. DB lookup → tier check (growth only) → namespace + resource_type
//	  │  3. LIST pods -n <namespace> -l app=<pod-label>
//	  │  4. GetLogs(pod, follow=false, tail=N)
//	  ▼
//	SSE stream  →  caller reads lines
//	  data: <log line>\n\n
//	  ...
//	  data: [end]\n\n
//
// Resource type → pod app= label (must stay in sync with provisioner k8s backends):
//
//	postgres → app=postgres   (provisioner/internal/backend/postgres/k8s.go)
//	cache    → app=redis      (provisioner/internal/backend/redis/k8s.go)
//	nosql    → app=mongodb    (provisioner/internal/backend/mongo/k8s.go)
//	queue    → app=nats       (provisioner/internal/backend/queue/k8s.go)
//
// Query params:
//
//	?tail=N   — last N lines (default 100, clamped 1–500)

import (
	"bufio"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"strconv"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"

	"instant.dev/common/resourcestatus"
	"instant.dev/internal/models"
)

// resourceTypeToPodLabel maps resource_type to the pod app= label set by the provisioner.
// Must stay in sync with: provisioner/internal/backend/*/k8s.go
var resourceTypeToPodLabel = map[string]string{
	"postgres": "postgres",
	"cache":    "redis",
	"nosql":    "mongodb",
	"queue":    "nats",
}

// LogsHandler handles GET /resources/:token/logs.
type LogsHandler struct {
	db        *sql.DB
	clientset *kubernetes.Clientset // nil when k8s is unavailable (no kubeconfig in local dev)
}

// NewLogsHandler builds a LogsHandler. Falls back gracefully if k8s is unreachable.
func NewLogsHandler(db *sql.DB) *LogsHandler {
	h := &LogsHandler{db: db}
	cs, err := buildLogsK8sClientset()
	if err != nil {
		slog.Warn("logs: k8s unavailable — log streaming disabled", "error", err)
		return h
	}
	h.clientset = cs
	return h
}

// buildLogsK8sClientset prefers in-cluster config, falls back to ~/.kube/config for local dev.
func buildLogsK8sClientset() (*kubernetes.Clientset, error) {
	cfg, err := rest.InClusterConfig()
	if err != nil {
		cfg, err = clientcmd.BuildConfigFromFlags("", clientcmd.RecommendedHomeFile)
		if err != nil {
			return nil, fmt.Errorf("k8s config: %w", err)
		}
	}
	return kubernetes.NewForConfig(cfg)
}

// ResourceLogs handles GET /resources/:token/logs.
func (h *LogsHandler) ResourceLogs(c *fiber.Ctx) error {
	if h.clientset == nil {
		return respondError(c, fiber.StatusServiceUnavailable, "logs_unavailable",
			"Log streaming is not available in this environment")
	}

	tokenStr := c.Params("token")
	tokenUUID, err := uuid.Parse(tokenStr)
	if err != nil {
		return respondError(c, fiber.StatusBadRequest, "invalid_token", "Token must be a valid UUID")
	}

	resource, err := models.GetResourceByToken(c.Context(), h.db, tokenUUID)
	if err != nil {
		var notFound *models.ErrResourceNotFound
		if errors.As(err, &notFound) {
			return respondError(c, fiber.StatusNotFound, "not_found", "Resource not found")
		}
		slog.Error("logs.resource.lookup_failed", "token", tokenStr, "error", err)
		return respondError(c, fiber.StatusServiceUnavailable, "lookup_failed", "Failed to look up resource")
	}

	// A non-active resource (expired / deleted / suspended) has no live pods
	// to stream from — reject early with the same status-guard the webhook
	// Receive/ListRequests paths use, rather than failing opaquely later at
	// the pod-list step.
	if resStatus, _ := resourcestatus.Parse(resource.Status); !resStatus.IsActive() {
		return respondError(c, fiber.StatusConflict, "not_active",
			"Resource is not active (status: "+resource.Status+") — logs are only available for active resources")
	}

	if resource.Tier != "growth" {
		return respondError(c, fiber.StatusBadRequest, "not_growth",
			"Log streaming is only available for growth-tier (isolated) resources. "+
				"Shared-tier resources run on platform pods shared across customers. "+
				"For shared-tier log access, connect your app to a log aggregation service "+
				"(e.g. Splunk, Datadog, Grafana Loki). See https://instanode.dev/docs/logging")
	}

	namespace := resource.ProviderResourceID.String
	if namespace == "" {
		return respondError(c, fiber.StatusConflict, "not_ready",
			"Resource has no provider namespace — it may still be provisioning")
	}

	podLabel, ok := resourceTypeToPodLabel[resource.ResourceType]
	if !ok {
		return respondError(c, fiber.StatusBadRequest, "unsupported_type",
			fmt.Sprintf("Log streaming is not supported for resource type %q", resource.ResourceType))
	}
	labelSelector := "app=" + podLabel

	tail := int64(100)
	if t := c.Query("tail"); t != "" {
		if n, err2 := strconv.ParseInt(t, 10, 64); err2 == nil {
			if n < 1 {
				n = 1
			} else if n > 500 {
				n = 500
			}
			tail = n
		}
	}

	pods, err := h.clientset.CoreV1().Pods(namespace).List(c.Context(), metav1.ListOptions{
		LabelSelector: labelSelector,
	})
	if err != nil {
		slog.Error("logs.resource.list_pods_failed",
			"namespace", namespace, "label", labelSelector, "token", tokenStr, "error", err)
		return respondError(c, fiber.StatusServiceUnavailable, "pods_unavailable",
			"Failed to list pods in resource namespace")
	}
	if len(pods.Items) == 0 {
		return respondError(c, fiber.StatusNotFound, "pod_not_found",
			"No pods found — resource may still be starting up")
	}

	podName := pods.Items[0].Name
	req := h.clientset.CoreV1().Pods(namespace).GetLogs(podName, &corev1.PodLogOptions{
		Follow:    false, // tail-only; no persistent connection to avoid goroutine leaks
		TailLines: &tail,
	})

	// FIX-2: open the log stream with a background-derived context, NOT
	// c.Context(). The SetBodyStreamWriter callback runs after this handler
	// returns, by which point fasthttp may have recycled/cancelled the
	// request context — closing the k8s stream out from under the callback.
	// cancel is invoked by streamLogsSSE when the pump ends.
	streamCtx, cancel := context.WithCancel(context.Background())
	stream, err := req.Stream(streamCtx)
	if err != nil {
		cancel()
		slog.Error("logs.resource.stream_failed",
			"namespace", namespace, "pod", podName, "token", tokenStr, "error", err)
		return respondError(c, fiber.StatusServiceUnavailable, "stream_failed",
			"Failed to stream logs: "+err.Error())
	}
	// stream.Close() + cancel() are called inside SetBodyStreamWriter by
	// streamLogsSSE — NOT via defer here. Defers execute when the handler
	// returns, which is before the callback runs; closing here would give an
	// empty stream.

	slog.Info("logs.resource.stream",
		"token", tokenStr,
		"namespace", namespace,
		"pod", podName,
		"tail", tail,
	)

	c.Set("Content-Type", "text/event-stream")
	c.Set("Cache-Control", "no-cache")
	c.Set("Connection", "keep-alive")
	c.Set("X-Accel-Buffering", "no")

	// streamLogsSSE pumps lines, breaks on client disconnect (FIX-1: a
	// fasthttp mid-stream disconnect is observable only as a write/flush
	// error), and Close()s the stream + cancels streamCtx (FIX-2) when
	// streaming ends.
	c.Context().Response.SetBodyStreamWriter(func(w *bufio.Writer) {
		streamLogsSSE(w, stream, cancel)
	})

	return nil
}
