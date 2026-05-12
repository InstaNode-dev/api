// Track 4 of 8 in the observability rollout (OBSERVABILITY-PLAN-2026-05-12.md).
//
// This module is a self-contained slice of the actual `worker` service
// (InstaNode-dev/worker repo, module instant.dev/worker). It contains ONLY
// the new files added by this track + the local stubs that stand in for
// tracks 1+2 until those land.
//
// Merge story: the merger (track owner for /worker repo) copies the files
// under this directory into the actual worker repo at the same relative
// paths, deletes `internal/_obs_stubs/`, and rewrites the two imports in
// `internal/jobs/middleware.go` + `internal/obs/nr.go` from the stub paths
// to `instant.dev/common/buildinfo` + `instant.dev/common/logctx`. They
// also apply the diffs documented in PR_NOTES.md to `main.go` and
// `internal/jobs/workers.go`.
module instant.dev/worker

go 1.25

require (
	github.com/google/uuid v1.6.0
	github.com/newrelic/go-agent/v3 v3.43.3
	github.com/riverqueue/river v0.11.4
)

require (
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/kr/text v0.2.0 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/riverqueue/river/riverdriver v0.11.4 // indirect
	github.com/riverqueue/river/rivershared v0.11.4 // indirect
	github.com/riverqueue/river/rivertype v0.11.4 // indirect
	github.com/stretchr/testify v1.9.0 // indirect
	go.uber.org/goleak v1.3.0 // indirect
	golang.org/x/net v0.49.0 // indirect
	golang.org/x/sync v0.19.0 // indirect
	golang.org/x/sys v0.40.0 // indirect
	golang.org/x/text v0.33.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20260120221211-b8f7ae30c516 // indirect
	google.golang.org/grpc v1.80.0 // indirect
	google.golang.org/protobuf v1.36.11 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)
