// Package buildinfo is a TEMPORARY local stub of the cross-service
// `instant.dev/common/buildinfo` package that Track 1 of the observability
// rollout introduces. It exists only so the api service's Track 3 work can
// compile and ship in parallel with Tracks 1+2.
//
// TODO(obs-merge): delete this stub and switch imports to
// `instant.dev/common/buildinfo` once Track 1 lands on master.
package buildinfo

// GitSHA / BuildTime / Version are overridden at link time via
//
//	-ldflags "-X instant.dev/common/buildinfo.GitSHA=$SHA ..."
//
// from the Dockerfile (Track 1). Defaults below keep `go run` / `go test`
// honest by surfacing the "dev" sentinel everywhere the wire format
// expects a real value.
var (
	GitSHA    = "dev"
	BuildTime = "unknown"
	Version   = "dev"
)
