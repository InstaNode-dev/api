package handlers_test

// logs_resourcelogs_twinlogs_test.go — covers the error/edge arms of
// LogsHandler.ResourceLogs (logs.go) that logs_coverage_test.go leaves open:
//
//	logs.go:157-158  — lookup_failed: GetResourceByToken returns a non-NotFound
//	                   error (driven with a closed DB).
//	logs.go:194-196  — tail clamp: ?tail=0 (n<1) clamps up to 1.
//	logs.go:206-211  — pods_unavailable: the pod List call returns an error
//	                   (driven with a PrependReactor on the fake clientset).
//
// The clientset is the in-memory k8s fake (SetClientset seam), so these run
// under CI's postgres-only matrix without a live cluster.

import (
	"errors"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	k8sfake "k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"

	"instant.dev/internal/handlers"
	"instant.dev/internal/testhelpers"
)

// TestLogs_LookupFailed_503 drives logs.go:157-158: a DB error (not a
// not-found) on GetResourceByToken returns 503 lookup_failed. We build the
// handler against a CLOSED *sql.DB so the query fails with a driver error that
// is NOT *models.ErrResourceNotFound.
func TestLogs_LookupFailed_503(t *testing.T) {
	db, _ := testhelpers.SetupTestDB(t)
	h := handlers.NewLogsHandler(db)
	h.SetClientset(k8sfake.NewSimpleClientset())
	// Close the DB now so GetResourceByToken's query returns a driver error
	// (sql.ErrConnDone) — NOT a *models.ErrResourceNotFound — driving the
	// lookup_failed 503 arm rather than the not_found 404 arm.
	require.NoError(t, db.Close())

	app := logsTestApp(t, db, h)
	// A syntactically valid UUID so we pass the parse gate and reach the lookup.
	resp := logsGet(t, app, "11111111-1111-1111-1111-111111111111", "")
	defer resp.Body.Close()
	assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
}

// TestLogs_TailClampLow_StreamsSSE drives logs.go:194-196: ?tail=0 (n<1) clamps
// up to 1 and the happy path still streams. Needs a pod in the fake clientset.
func TestLogs_TailClampLow_StreamsSSE(t *testing.T) {
	db, clean := testhelpers.SetupTestDB(t)
	defer clean()

	const ns = "ns-clamp-low"
	cs := k8sfake.NewSimpleClientset(&corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "postgres-0",
			Namespace: ns,
			Labels:    map[string]string{"app": "postgres"},
		},
	})
	h := handlers.NewLogsHandler(db)
	h.SetClientset(cs)
	app := logsTestApp(t, db, h)

	token := seedLogsResource(t, db, "postgres", "growth", "active", ns)
	resp := logsGet(t, app, token, "tail=0") // n<1 → clamp to 1
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "text/event-stream", resp.Header.Get("Content-Type"))
}

// TestLogs_ListPodsError_503 drives logs.go:206-211: the pod List call errors.
// A PrependReactor on the fake clientset makes List("pods") return an error so
// the pods_unavailable arm runs (distinct from the empty-list pod_not_found arm
// already covered).
func TestLogs_ListPodsError_503(t *testing.T) {
	db, clean := testhelpers.SetupTestDB(t)
	defer clean()

	cs := k8sfake.NewSimpleClientset()
	cs.PrependReactor("list", "pods",
		func(action k8stesting.Action) (handled bool, ret runtime.Object, err error) {
			return true, nil, errors.New("apiserver unreachable")
		})
	h := handlers.NewLogsHandler(db)
	h.SetClientset(cs)
	app := logsTestApp(t, db, h)

	token := seedLogsResource(t, db, "postgres", "growth", "active", "ns-list-err")
	resp := logsGet(t, app, token, "")
	defer resp.Body.Close()
	assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
}
