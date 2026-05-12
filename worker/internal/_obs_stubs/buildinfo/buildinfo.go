// Package buildinfo is a TEMPORARY STUB for track 1 of the observability
// rollout (OBSERVABILITY-PLAN-2026-05-12.md). The real package will land at
// `instant.dev/common/buildinfo`. Once track 1 merges, this file is deleted
// and every import is rewritten to point at common.
//
// Until then, this stub lets track 4 (worker) compile and ship a PR
// without blocking on track 1.
//
// TODO(obs): delete after track 1 lands; rewrite imports to common/buildinfo.
package buildinfo

// GitSHA is overwritten at build time via -ldflags
// "-X instant.dev/common/buildinfo.GitSHA=$GIT_SHA". The default value lets
// `go run` and unit tests work without ldflags.
var GitSHA = "dev"

// BuildTime is overwritten at build time via -ldflags.
var BuildTime = "unknown"

// Version is overwritten at build time via -ldflags.
var Version = "dev"
