package handlers

// export_seam2_test.go — test-only seam exporters for the seam2 coverage pass.
//
// Wraps the package-level indirection seams added in seams.go (checkStorageQuota)
// and logs.go (buildLogsClientset / inClusterConfig / kubeconfigFromFlags) so the
// external handlers_test package can drive the otherwise-unreachable
// StorageExceeded warning arms and the NewLogsHandler success / clientset-build
// fallback arms.

import (
	"context"
	"database/sql"

	"github.com/google/uuid"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

// SetCheckStorageQuotaForTest overrides the checkStorageQuota seam (seams.go) so
// a test can force exceeded=true on the provisioning handlers' storage-quota
// gate, exercising the StorageExceeded warning arms of db.go / cache.go /
// nosql.go. Returns a restore func.
func SetCheckStorageQuotaForTest(
	fn func(context.Context, *sql.DB, uuid.UUID, int) (int64, bool, error),
) (restore func()) {
	prev := checkStorageQuota
	checkStorageQuota = fn
	return func() { checkStorageQuota = prev }
}

// ClientsetForTest exposes the (unexported) clientset field on LogsHandler so a
// test can assert NewLogsHandler's success vs. error arm set / left-nil the
// field.
func (h *LogsHandler) ClientsetForTest() kubernetes.Interface {
	return h.clientset
}

// SetBuildLogsClientsetForTest overrides the buildLogsClientset seam (logs.go)
// so a test can drive NewLogsHandler's success arm with an injected fake
// kubernetes.Interface (and its error arm with a forced error). Returns a
// restore func.
func SetBuildLogsClientsetForTest(
	fn func() (kubernetes.Interface, error),
) (restore func()) {
	prev := buildLogsClientset
	buildLogsClientset = fn
	return func() { buildLogsClientset = prev }
}

// SetLogsConfigLoadersForTest overrides the inClusterConfig + kubeconfigFromFlags
// seams (logs.go) so a test can drive both arms of buildLogsK8sClientset's
// in-cluster→kubeconfig fallback deterministically. A nil arg leaves that
// loader at its current value. Returns a restore func.
func SetLogsConfigLoadersForTest(
	inCluster func() (*rest.Config, error),
	fromFlags func() (*rest.Config, error),
) (restore func()) {
	prevIn := inClusterConfig
	prevFlags := kubeconfigFromFlags
	if inCluster != nil {
		inClusterConfig = inCluster
	}
	if fromFlags != nil {
		kubeconfigFromFlags = fromFlags
	}
	return func() {
		inClusterConfig = prevIn
		kubeconfigFromFlags = prevFlags
	}
}

// InvokeBuildLogsK8sClientsetForTest invokes the REAL buildLogsK8sClientset so
// its body is covered. With the config loaders seamed, both the in-cluster
// success arm and the kubeconfig fallback arm are reachable without a live
// cluster or a kubeconfig on disk.
func InvokeBuildLogsK8sClientsetForTest() error {
	_, err := buildLogsK8sClientset()
	return err
}

// InvokeDefaultLogsConfigLoadersForTest invokes the REAL default closures of the
// inClusterConfig + kubeconfigFromFlags seams so their default-value bodies are
// covered. Both may error in a test env (no cluster / no kubeconfig) — the line
// still executes.
func InvokeDefaultLogsConfigLoadersForTest() {
	_, _ = inClusterConfig()
	_, _ = kubeconfigFromFlags()
}
