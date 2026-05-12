// Command smoke-buildinfo prints the linked-in buildinfo values to stdout.
//
// Used by `make smoke-buildinfo` to verify the -ldflags -X path actually
// flows through to instant.dev/common/buildinfo at link time. The CI
// signal is "did the override land?" — not how the values are formatted.
package main

import (
	"fmt"

	"instant.dev/common/buildinfo"
)

func main() {
	fmt.Printf("GitSHA=%s BuildTime=%s Version=%s\n",
		buildinfo.GitSHA, buildinfo.BuildTime, buildinfo.Version)
}
