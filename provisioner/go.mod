// Module instant.dev/provisioner — observability scaffolding for the
// instant.dev/provisioner gRPC service.
//
// This is a self-contained module (NOT joined with the parent api module)
// so that:
//
//  1. The api repo's `go build ./...` continues to be a pure api build —
//     adding the provisioner subdir doesn't pull NR deps into the api binary.
//  2. The Go files here can be copied verbatim into the real provisioner
//     repo (github.com/InstaNode-dev/provisioner) which already uses the
//     module name `instant.dev/provisioner` — see that repo's go.mod.
//
// When the real provisioner adopts these files, this scaffolding go.mod is
// deleted and the imports resolve against the real provisioner's go.mod.
module instant.dev/provisioner

go 1.25.0

require (
	github.com/newrelic/go-agent/v3 v3.43.3
	github.com/newrelic/go-agent/v3/integrations/nrgrpc v1.4.9
	google.golang.org/grpc v1.80.0
)

require (
	github.com/golang/protobuf v1.5.4 // indirect
	github.com/newrelic/csec-go-agent v1.6.0 // indirect
	golang.org/x/arch v0.27.0 // indirect
	golang.org/x/net v0.49.0 // indirect
	golang.org/x/sys v0.40.0 // indirect
	golang.org/x/text v0.33.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20260120221211-b8f7ae30c516 // indirect
	google.golang.org/protobuf v1.36.11 // indirect
	gopkg.in/yaml.v2 v2.4.0 // indirect
)
