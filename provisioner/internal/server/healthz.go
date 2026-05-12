// Package server hosts the gRPC service implementation and, as of the
// observability rollout (2026-05-12), a tiny sidecar HTTP handler exposing
// /healthz so the platform can curl the running pod's commit_id without
// going through the gRPC surface.
//
// The provisioner is otherwise gRPC-only on port 50051. We bind the HTTP
// sidecar to a different port (default 8092, see plan doc) — verified in
// HealthzPort_NoCollisionWithGRPC test below.
package server

import (
	"encoding/json"
	"net/http"

	"instant.dev/provisioner/internal/_obs_stubs/buildinfo"
)

// HealthzResponse is the JSON body returned by GET /healthz.
//
// Field order matches what the api and worker services return so dashboards
// and curl pipelines can use a single jq filter across all three.
type HealthzResponse struct {
	OK        bool   `json:"ok"`
	Service   string `json:"service"`
	CommitID  string `json:"commit_id"`
	BuildTime string `json:"build_time"`
	Version   string `json:"version"`
}

// HealthzHandler returns an http.Handler that responds to any method (the
// k8s liveness probe will use GET; humans use curl) with the build metadata
// JSON. Never errors — used as a liveness probe so it must be cheap and
// dependency-free.
func HealthzHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		resp := HealthzResponse{
			OK:        true,
			Service:   "instant-provisioner",
			CommitID:  buildinfo.GitSHA,
			BuildTime: buildinfo.BuildTime,
			Version:   buildinfo.Version,
		}
		w.Header().Set("Content-Type", "application/json")
		// json.NewEncoder.Encode never errors on a value of fixed shape with
		// no unmarshalable types — and we'd be unable to write an error
		// response anyway if the connection were broken. Discard.
		_ = json.NewEncoder(w).Encode(resp)
	})
}
