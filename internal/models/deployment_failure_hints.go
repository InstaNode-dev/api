package models

// deployment_failure_hints.go — plain-language hint strings for each
// FailureReason constant.
//
// Hints are the human-readable explanation surfaced in GET /deploy/:id under
// failure.hint. They are written to deployment_events by both the worker's
// deploy_status_reconcile (runtime failures) and the api's build path (build
// failures). Centralising them here means both write paths share the same
// message and tests can iterate the full set.
//
// Keep hints short enough that an agent can relay them to a user without
// further editing. Follow the pattern: "Your app … — remedy or next step."

// FailureHint maps a FailureReason constant to a plain-language explanation.
// The worker and api build-path import this map rather than repeating strings.
var FailureHint = map[string]string{
	FailureReasonOOMKilled: "Your app exceeded its memory limit and was killed by the kernel. " +
		"Reduce memory usage, add GOMEMLIMIT / NODE_OPTIONS --max-old-space-size, " +
		"or upgrade to a tier with a higher memory cap.",

	FailureReasonEvicted: "Your app's pod was evicted from the node — this usually means the node " +
		"ran out of disk space or memory. Check for excessive logging or large temporary files. " +
		"Upgrade your tier for a dedicated node with more headroom.",

	FailureReasonImagePullBackOff: "Kubernetes could not pull your container image. " +
		"This is usually a registry authentication failure or a typo in the image reference. " +
		"Re-deploy with a fresh tarball to trigger a new build and push.",

	FailureReasonCrashLoopBackOff: "Your app container exited non-zero repeatedly. " +
		"Check the last_lines for stack traces or startup errors. " +
		"Common causes: missing environment variable, wrong PORT binding, or a top-level exception at startup.",

	FailureReasonBuildFailed: "The Kaniko image build failed before your app was deployed. " +
		"Check the event field for the build error. " +
		"Common causes: Dockerfile syntax error, missing COPY source file, or a failing RUN command.",

	FailureReasonDeadlineExceeded: "The build or rollout timed out after 10 minutes. " +
		"Large base images or slow package installs can cause this. " +
		"Try a smaller base image (e.g. alpine) and pre-install dependencies in the Dockerfile.",

	FailureReasonStartFailed: "Kubernetes created your app's pod but the container could not start. " +
		"The most common cause is a built image with no CMD/ENTRYPOINT (nothing to run) " +
		"or an invalid container configuration. Make sure your Dockerfile ends with a " +
		"CMD or ENTRYPOINT instruction, then re-deploy.",

	FailureReasonError: "A Kubernetes replica failure was detected. " +
		"This is often a transient scheduling or resource constraint. " +
		"Re-deploy to retry; if it persists, check your Dockerfile for correct CMD/ENTRYPOINT.",

	FailureReasonUnknown: "The failure cause could not be determined automatically. " +
		"Stream the pod logs via GET /deploy/:id/logs and check for error messages at the bottom.",
}

// HintForReason returns the plain-language hint for a given FailureReason.
// Falls back to FailureReasonUnknown's hint for unrecognised reasons so
// the caller never returns an empty string.
func HintForReason(reason string) string {
	if h, ok := FailureHint[reason]; ok {
		return h
	}
	return FailureHint[FailureReasonUnknown]
}
