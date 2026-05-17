// Package safego provides panic-safe wrappers for fire-and-forget goroutines.
//
// Background goroutines launched directly with `go func(){…}()` crash the
// entire process if they panic — there is no enclosing recover() on a fresh
// goroutine stack. P1-B (bug hunt 2026-05-17 round 2): ~45 handler sites
// launched bare goroutines. Routing every one of them through Go recovers the
// panic, logs it with a stack trace, and increments a metric so an alert can
// fire — the pod survives.
package safego

import (
	"log/slog"
	"runtime/debug"

	"instant.dev/internal/metrics"
)

// Go runs fn in a new goroutine with a recover() guard. A panic inside fn is
// recovered, logged via slog at Error level with the full stack trace, and
// counted in the instant_goroutine_panics_total metric under the given task
// label. The pod is never crashed by a fire-and-forget goroutine.
//
// task is a short, low-cardinality identifier for the goroutine (e.g.
// "runDeploy", "audit.emit") used as the metric label and log field.
func Go(task string, fn func()) {
	go Run(task, fn)
}

// Run executes fn synchronously with the same recover() guard as Go. It is the
// building block for Go and is also useful when a caller already controls the
// goroutine (e.g. a goroutine that takes captured arguments) but still wants
// panic protection: `go safego.Run("task", func(){ ... })`.
func Run(task string, fn func()) {
	defer Recover(task)
	fn()
}

// Recover is the deferred recover() guard. Call it as `defer safego.Recover(task)`
// at the top of a goroutine body when Go/Run cannot be used directly.
func Recover(task string) {
	if r := recover(); r != nil {
		metrics.GoroutinePanics.WithLabelValues(task).Inc()
		slog.Error("recovered panic in fire-and-forget goroutine",
			"task", task,
			"panic", r,
			"stack", string(debug.Stack()),
		)
	}
}
