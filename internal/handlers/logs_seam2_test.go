package handlers_test

// logs_seam2_test.go — seam2 coverage pass for logs.go.
//
// Covers:
//   - NewLogsHandler SUCCESS arm (h.clientset = cs) via the buildLogsClientset
//     seam returning a fake kubernetes.Interface + nil error.
//   - NewLogsHandler error/fallback arm (slog.Warn → return h) via the seam
//     returning an error, AND via the REAL default closure (no cluster in test
//     env) so the default seam body is covered too.
//   - buildLogsK8sClientset in-cluster SUCCESS arm and the in-cluster→kubeconfig
//     FALLBACK arm, driven deterministically through the inClusterConfig /
//     kubeconfigFromFlags seams (no live cluster / kubeconfig required).
//   - The REAL default config-loader closures (covered by invoking them; they
//     may error in a test env — the line still executes).

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/rest"

	"instant.dev/internal/handlers"
	"instant.dev/internal/testhelpers"
)

// TestSeam2_NewLogsHandler_Success — buildLogsClientset returns a fake
// clientset + nil error → NewLogsHandler's success arm runs (h.clientset = cs),
// and the handler streams logs (clientset non-nil).
func TestSeam2_NewLogsHandler_Success(t *testing.T) {
	db, clean := testhelpers.SetupTestDB(t)
	defer clean()

	fakeCS := fake.NewSimpleClientset()
	restore := handlers.SetBuildLogsClientsetForTest(func() (kubernetes.Interface, error) {
		return fakeCS, nil
	})
	defer restore()

	h := handlers.NewLogsHandler(db)
	require.NotNil(t, h)
	assert.NotNil(t, h.ClientsetForTest(), "success arm must set the clientset")
}

// TestSeam2_NewLogsHandler_BuildError — buildLogsClientset returns an error →
// NewLogsHandler's slog.Warn → return-h fallback arm runs, leaving clientset nil.
func TestSeam2_NewLogsHandler_BuildError(t *testing.T) {
	db, clean := testhelpers.SetupTestDB(t)
	defer clean()

	restore := handlers.SetBuildLogsClientsetForTest(func() (kubernetes.Interface, error) {
		return nil, errors.New("forced k8s build error")
	})
	defer restore()

	h := handlers.NewLogsHandler(db)
	require.NotNil(t, h, "constructor must return a handler even when k8s is unavailable")
	assert.Nil(t, h.ClientsetForTest(), "error arm must leave clientset nil")
}

// TestSeam2_NewLogsHandler_DefaultClosure — without overriding the seam,
// NewLogsHandler invokes the REAL default buildLogsClientset closure (which
// calls buildLogsK8sClientset). In a test env with no cluster + no kubeconfig
// this errors, exercising the default closure body + the fallback arm.
func TestSeam2_NewLogsHandler_DefaultClosure(t *testing.T) {
	db, clean := testhelpers.SetupTestDB(t)
	defer clean()

	// Force both real config loaders to error so buildLogsK8sClientset returns
	// an error deterministically regardless of the test host's kubeconfig.
	restore := handlers.SetLogsConfigLoadersForTest(
		func() (*rest.Config, error) { return nil, errors.New("no in-cluster") },
		func() (*rest.Config, error) { return nil, errors.New("no kubeconfig") },
	)
	defer restore()

	h := handlers.NewLogsHandler(db)
	require.NotNil(t, h)
	assert.Nil(t, h.ClientsetForTest())
}

// TestSeam2_BuildLogsK8sClientset_InClusterSuccess — inClusterConfig returns a
// valid *rest.Config → buildLogsK8sClientset takes the in-cluster success arm
// (kubeconfig is NOT consulted) and builds a clientset.
func TestSeam2_BuildLogsK8sClientset_InClusterSuccess(t *testing.T) {
	fromFlagsCalled := false
	restore := handlers.SetLogsConfigLoadersForTest(
		func() (*rest.Config, error) { return &rest.Config{Host: "https://in-cluster.test"}, nil },
		func() (*rest.Config, error) {
			fromFlagsCalled = true
			return nil, errors.New("should not be called")
		},
	)
	defer restore()

	err := handlers.InvokeBuildLogsK8sClientsetForTest()
	require.NoError(t, err, "a valid in-cluster config must build a clientset")
	assert.False(t, fromFlagsCalled, "in-cluster success must NOT fall back to kubeconfig")
}

// TestSeam2_BuildLogsK8sClientset_KubeconfigFallback — inClusterConfig errors,
// kubeconfigFromFlags returns a valid config → buildLogsK8sClientset takes the
// fallback arm and builds a clientset from the kubeconfig path.
func TestSeam2_BuildLogsK8sClientset_KubeconfigFallback(t *testing.T) {
	restore := handlers.SetLogsConfigLoadersForTest(
		func() (*rest.Config, error) { return nil, errors.New("not in cluster") },
		func() (*rest.Config, error) { return &rest.Config{Host: "https://kubeconfig.test"}, nil },
	)
	defer restore()

	err := handlers.InvokeBuildLogsK8sClientsetForTest()
	require.NoError(t, err, "kubeconfig fallback must build a clientset")
}

// TestSeam2_BuildLogsK8sClientset_BothFail — both loaders error →
// buildLogsK8sClientset returns the wrapped "k8s config" error arm.
func TestSeam2_BuildLogsK8sClientset_BothFail(t *testing.T) {
	restore := handlers.SetLogsConfigLoadersForTest(
		func() (*rest.Config, error) { return nil, errors.New("not in cluster") },
		func() (*rest.Config, error) { return nil, errors.New("no kubeconfig file") },
	)
	defer restore()

	err := handlers.InvokeBuildLogsK8sClientsetForTest()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "k8s config")
}

// TestSeam2_DefaultLogsConfigLoaders — invoke the REAL default closures of the
// inClusterConfig + kubeconfigFromFlags seams so their default-value bodies are
// covered. Both may error in a test env — the line still executes.
func TestSeam2_DefaultLogsConfigLoaders(t *testing.T) {
	handlers.InvokeDefaultLogsConfigLoadersForTest()
}
