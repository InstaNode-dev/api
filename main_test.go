package main

import (
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestInitNewRelic_FailOpenOnEmptyLicense verifies the contract that
// missing NEW_RELIC_LICENSE_KEY does NOT prevent the api binary from
// booting. Returning nil lets the Fiber middleware and metric helpers
// degrade to no-ops; an error here would crash every CI run and every
// local `make run` (since neither sets the license key).
func TestInitNewRelic_FailOpenOnEmptyLicense(t *testing.T) {
	prev := os.Getenv("NEW_RELIC_LICENSE_KEY")
	t.Cleanup(func() { _ = os.Setenv("NEW_RELIC_LICENSE_KEY", prev) })
	require.NoError(t, os.Unsetenv("NEW_RELIC_LICENSE_KEY"))

	app := initNewRelic("api")
	require.Nil(t, app, "initNewRelic must return nil when NEW_RELIC_LICENSE_KEY is empty (fail-open contract)")
}
