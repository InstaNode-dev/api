package handlers_test

// provision_nr_metrics_wiring_test.go — P1-W3-04 regression.
//
// middleware.RecordProvisionSuccess / RecordProvisionFail feed the New Relic
// provisioning dashboard. They were defined but had ZERO callers, so the
// dashboard was permanently empty. The fix wires them into all six provision
// handlers on the success and 503-failure paths.
//
// The metric helpers no-op without a registered NR app, so there is no
// runtime side effect to assert against. Instead this is a static coverage
// test: it iterates the six provision-handler source files and fails if any
// one of them loses its RecordProvisionSuccess / RecordProvisionFail wiring.
// That makes the regression self-guarding — a future edit that drops the
// call from, say, queue.go breaks this test rather than silently emptying
// the dashboard again.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestProvisionHandlers_WireNRProvisionMetrics(t *testing.T) {
	// The six provision handlers POST /db,/cache,/nosql,/queue,/storage,/webhook.
	handlerFiles := []string{
		"db.go", "cache.go", "nosql.go", "queue.go", "storage.go", "webhook.go",
	}

	for _, f := range handlerFiles {
		f := f
		t.Run(f, func(t *testing.T) {
			src, err := os.ReadFile(filepath.Join(".", f))
			require.NoError(t, err, "reading provision handler source")
			body := string(src)

			assert.True(t, strings.Contains(body, "middleware.RecordProvisionSuccess("),
				"%s must call middleware.RecordProvisionSuccess on the provision success path (P1-W3-04)", f)
			assert.True(t, strings.Contains(body, "middleware.RecordProvisionFail("),
				"%s must call middleware.RecordProvisionFail on the provision 503-failure path (P1-W3-04)", f)
		})
	}
}
