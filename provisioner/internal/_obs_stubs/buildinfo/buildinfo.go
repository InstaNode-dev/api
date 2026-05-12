// Package buildinfo exposes compile-time build metadata.
//
// STUB: this is a temporary, vendored copy of what will become
// instant.dev/common/buildinfo once track 1 of the observability rollout
// merges. After that PR lands, callers in this service should switch their
// imports from
//
//	"instant.dev/provisioner/internal/_obs_stubs/buildinfo"
//
// to
//
//	"instant.dev/common/buildinfo"
//
// and this directory should be deleted in a follow-up cleanup PR.
//
// The variables are populated at link time via -ldflags. See the Dockerfile
// change shipped in track 1 for the exact command line. When the service is
// built without ldflags (e.g. `go build ./...` during local dev), the values
// fall back to "dev" / "unknown" so the program never panics.
package buildinfo

var (
	// GitSHA is the 7+ char git commit hash this binary was built from.
	// Set via: -ldflags "-X .../buildinfo.GitSHA=$GIT_SHA"
	GitSHA = "dev"

	// BuildTime is the UTC RFC3339 timestamp of the build.
	// Set via: -ldflags "-X .../buildinfo.BuildTime=$BUILD_TIME"
	BuildTime = "unknown"

	// Version is the semver tag of the release, or "dev" for untagged builds.
	// Set via: -ldflags "-X .../buildinfo.Version=$VERSION"
	Version = "dev"
)
