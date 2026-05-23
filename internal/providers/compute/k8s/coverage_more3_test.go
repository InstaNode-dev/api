package k8s

// coverage_more3_test.go — third wave: drives the remaining uncovered error
// branches in buildImage (namespace create / label upgrade / build NetworkPolicy
// / registry auth / kaniko job create / job-complete failure → snapshotBuildLogs),
// plus the extractTarGz filesystem-error branches and the isUnderDir exact-".."
// guard.

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8sruntime "k8s.io/apimachinery/pkg/runtime"
	clientfake "k8s.io/client-go/kubernetes/fake"
	clienttesting "k8s.io/client-go/testing"
)

// ghcrPullSecret returns the registry-auth secret buildImage copies from the
// instant namespace, so the happy-path copy step succeeds.
func ghcrPullSecret() *corev1.Secret {
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "ghcr-pull", Namespace: "instant"},
		Type:       corev1.SecretTypeDockerConfigJson,
		Data:       map[string][]byte{".dockerconfigjson": []byte(`{"auths":{}}`)},
	}
}

// ── uploadBuildContext happy path + branch coverage ──────────────────────────

// fakeS3Handler returns an http.Handler that satisfies the minimal S3 surface
// minio-go drives in uploadBuildContext: HEAD bucket (exists check), PUT bucket
// (MakeBucket), and PUT object. PresignedGetObject is a local-only signing op.
func fakeS3Handler(bucketExists bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Region-discovery probe (GET /bucket?location=) — answer with us-east-1.
		if r.Method == http.MethodGet && r.URL.Query().Has("location") {
			w.Header().Set("Content-Type", "application/xml")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`<?xml version="1.0" encoding="UTF-8"?><LocationConstraint xmlns="http://s3.amazonaws.com/doc/2006-03-01/"></LocationConstraint>`))
			return
		}
		switch r.Method {
		case http.MethodHead:
			// BucketExists: 200 = exists, 404 = create-then-put.
			if bucketExists {
				w.WriteHeader(http.StatusOK)
			} else {
				w.WriteHeader(http.StatusNotFound)
			}
		case http.MethodPut:
			// Covers both MakeBucket (when bucket absent) and PutObject.
			w.Header().Set("ETag", `"deadbeef"`)
			w.WriteHeader(http.StatusOK)
		default:
			w.WriteHeader(http.StatusOK)
		}
	}
}

// TestUploadBuildContext_HappyBucketExists drives the full success path when the
// bucket already exists: BucketExists → PutObject → PresignedGetObject.
func TestUploadBuildContext_HappyBucketExists(t *testing.T) {
	srv := httptest.NewServer(fakeS3Handler(true))
	defer srv.Close()
	p := &K8sProvider{buildCtx: BuildContextConfig{
		Endpoint:   strings.TrimPrefix(srv.URL, "http://"),
		AccessKey:  "ak",
		SecretKey:  "sk",
		BucketName: "ctx-bucket",
		UseSSL:     false,
	}}
	url, key, err := p.uploadBuildContext(context.Background(), "myapp", []byte("tarball-bytes"))
	if err != nil {
		t.Fatalf("uploadBuildContext: %v", err)
	}
	if url == "" {
		t.Error("expected a presigned URL")
	}
	if !strings.HasPrefix(key, "myapp/") || !strings.HasSuffix(key, ".tar.gz") {
		t.Errorf("unexpected object key %q", key)
	}
}

// TestUploadBuildContext_HappyBucketCreated drives the MakeBucket branch: the
// bucket does not yet exist, so uploadBuildContext creates it before PutObject.
func TestUploadBuildContext_HappyBucketCreated(t *testing.T) {
	srv := httptest.NewServer(fakeS3Handler(false))
	defer srv.Close()
	p := &K8sProvider{buildCtx: BuildContextConfig{
		Endpoint:   strings.TrimPrefix(srv.URL, "http://"),
		AccessKey:  "ak",
		SecretKey:  "sk",
		BucketName: "fresh-bucket",
		UseSSL:     false,
	}}
	url, key, err := p.uploadBuildContext(context.Background(), "app2", []byte("t"))
	if err != nil {
		t.Fatalf("uploadBuildContext (create bucket): %v", err)
	}
	if url == "" || key == "" {
		t.Errorf("url=%q key=%q; want non-empty", url, key)
	}
}

// ── buildImage error branches ────────────────────────────────────────────────

// TestBuildImage_NamespaceCreateError covers the non-AlreadyExists namespace
// create failure (L1421-1423).
func TestBuildImage_NamespaceCreateError(t *testing.T) {
	cs := clientfake.NewSimpleClientset()
	cs.PrependReactor("create", "namespaces", func(_ clienttesting.Action) (bool, k8sruntime.Object, error) {
		return true, nil, errors.New("apiserver down")
	})
	p := &K8sProvider{clientset: cs}
	err := p.buildImage(context.Background(), "instant-deploy-ce", "ce", "ghcr.io/x/y:latest", []byte("t"))
	if err == nil || !strings.Contains(err.Error(), "ensure namespace") {
		t.Fatalf("expected ensure-namespace error; got %v", err)
	}
}

// TestBuildImage_UpgradeNamespaceLabelsError covers the AlreadyExists →
// upgradeNamespaceLabels failure branch (L1425-1427). The namespace pre-exists
// (so Create returns AlreadyExists) but the Get inside upgradeNamespaceLabels
// fails.
func TestBuildImage_UpgradeNamespaceLabelsError(t *testing.T) {
	cs := clientfake.NewSimpleClientset(
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "instant-deploy-ul"}},
	)
	cs.PrependReactor("get", "namespaces", func(_ clienttesting.Action) (bool, k8sruntime.Object, error) {
		return true, nil, errors.New("get blew up")
	})
	p := &K8sProvider{clientset: cs}
	err := p.buildImage(context.Background(), "instant-deploy-ul", "ul", "ghcr.io/x/y:latest", []byte("t"))
	if err == nil || !strings.Contains(err.Error(), "upgrade namespace labels") {
		t.Fatalf("expected upgrade-namespace-labels error; got %v", err)
	}
}

// TestBuildImage_BuildNetworkPolicyError covers the createBuildNetworkPolicy
// failure branch (L1436-1438).
func TestBuildImage_BuildNetworkPolicyError(t *testing.T) {
	cs := clientfake.NewSimpleClientset()
	cs.PrependReactor("create", "networkpolicies", func(_ clienttesting.Action) (bool, k8sruntime.Object, error) {
		return true, nil, errors.New("netpol denied")
	})
	cs.PrependReactor("get", "networkpolicies", func(_ clienttesting.Action) (bool, k8sruntime.Object, error) {
		return true, nil, apierrors.NewNotFound(corev1.Resource("networkpolicies"), "x")
	})
	p := &K8sProvider{clientset: cs}
	err := p.buildImage(context.Background(), "instant-deploy-np", "np", "ghcr.io/x/y:latest", []byte("t"))
	if err == nil || !strings.Contains(err.Error(), "buildImage") {
		t.Fatalf("expected build-networkpolicy error; got %v", err)
	}
}

// TestBuildImage_UpsertBuildContextSecretError covers the Secret-fallback path
// where upsertBuildContextSecret fails (L1448-1450). buildCtx empty → Secret
// path; the Secret create reactor errors.
func TestBuildImage_UpsertBuildContextSecretError(t *testing.T) {
	cs := clientfake.NewSimpleClientset()
	cs.PrependReactor("create", "secrets", func(action clienttesting.Action) (bool, k8sruntime.Object, error) {
		ca := action.(clienttesting.CreateAction)
		if s, ok := ca.GetObject().(*corev1.Secret); ok && strings.HasPrefix(s.Name, "build-ctx-") {
			return true, nil, errors.New("secret create blew up")
		}
		return false, nil, nil
	})
	p := &K8sProvider{clientset: cs}
	err := p.buildImage(context.Background(), "instant-deploy-bs", "bs", "ghcr.io/x/y:latest", []byte("t"))
	if err == nil || !strings.Contains(err.Error(), "build-context secret") {
		t.Fatalf("expected build-context-secret error; got %v", err)
	}
}

// TestBuildImage_RegistryAuthError covers the ensureRegistryAuthInNS failure
// branch (L1472-1474): the source ghcr-pull secret in the instant namespace is
// absent, so the copy fails.
func TestBuildImage_RegistryAuthError(t *testing.T) {
	cs := clientfake.NewSimpleClientset() // no ghcr-pull secret anywhere
	p := &K8sProvider{clientset: cs}
	err := p.buildImage(context.Background(), "instant-deploy-ra", "ra", "ghcr.io/x/y:latest", []byte("t"))
	if err == nil || !strings.Contains(err.Error(), "registry auth") {
		t.Fatalf("expected registry-auth error; got %v", err)
	}
}

// TestBuildImage_CreateKanikoJobError covers the createKanikoJob failure branch
// (L1485-1487).
func TestBuildImage_CreateKanikoJobError(t *testing.T) {
	cs := clientfake.NewSimpleClientset(ghcrPullSecret())
	cs.PrependReactor("create", "jobs", func(_ clienttesting.Action) (bool, k8sruntime.Object, error) {
		return true, nil, errors.New("job create rejected")
	})
	p := &K8sProvider{clientset: cs}
	err := p.buildImage(context.Background(), "instant-deploy-kj", "kj", "ghcr.io/x/y:latest", []byte("t"))
	if err == nil || !strings.Contains(err.Error(), "create kaniko job") {
		t.Fatalf("expected create-kaniko-job error; got %v", err)
	}
}

// TestBuildImage_JobFailsSnapshots covers the waitForJobComplete failure branch
// (L1490-1495) which calls snapshotBuildLogs then returns the kaniko-job error.
func TestBuildImage_JobFailsSnapshots(t *testing.T) {
	cs := clientfake.NewSimpleClientset(
		ghcrPullSecret(),
		&corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "build-jf-pod",
				Namespace: "instant-deploy-jf",
				Labels:    map[string]string{"job-name": "build-jf"},
			},
		},
	)
	// Job is created already Failed so waitForJobComplete returns an error.
	cs.PrependReactor("create", "jobs", func(action clienttesting.Action) (bool, k8sruntime.Object, error) {
		ca := action.(clienttesting.CreateAction)
		job := ca.GetObject().(*batchv1.Job)
		job.Status.Conditions = []batchv1.JobCondition{
			{Type: batchv1.JobFailed, Status: corev1.ConditionTrue, Message: "build step failed"},
		}
		return false, job, nil
	})
	p := &K8sProvider{clientset: cs}
	err := p.buildImage(context.Background(), "instant-deploy-jf", "jf", "ghcr.io/x/y:latest", []byte("t"))
	if err == nil || !strings.Contains(err.Error(), "kaniko job") {
		t.Fatalf("expected kaniko-job failure error; got %v", err)
	}
}

// ── extractTarGz filesystem-error branches ───────────────────────────────────

// TestExtractTarGz_DirMkdirError covers the TypeDir os.MkdirAll error branch
// (L2220-2222): the destination dir is read-only so creating a child dir fails.
func TestExtractTarGz_DirMkdirError(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("permission semantics differ on windows")
	}
	if os.Geteuid() == 0 {
		t.Skip("root bypasses directory permission checks")
	}
	dest := t.TempDir()
	if err := os.Chmod(dest, 0o500); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	defer os.Chmod(dest, 0o700) //nolint:errcheck

	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	_ = tw.WriteHeader(&tar.Header{Name: "newdir", Typeflag: tar.TypeDir, Mode: 0o755})
	_ = tw.Close()
	_ = gz.Close()

	if err := extractTarGz(buf.Bytes(), dest); err == nil || !strings.Contains(err.Error(), "mkdir") {
		t.Fatalf("expected mkdir error; got %v", err)
	}
}

// TestExtractTarGz_FileParentMkdirError covers the TypeReg os.MkdirAll(parent)
// error branch (L2224-2226): a file under a subdir into a read-only dest.
func TestExtractTarGz_FileParentMkdirError(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("permission semantics differ on windows")
	}
	if os.Geteuid() == 0 {
		t.Skip("root bypasses directory permission checks")
	}
	dest := t.TempDir()
	if err := os.Chmod(dest, 0o500); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	defer os.Chmod(dest, 0o700) //nolint:errcheck

	tarball := buildTarGz(t, map[string]string{"sub/app.go": "package main"}, "", false)
	if err := extractTarGz(tarball, dest); err == nil || !strings.Contains(err.Error(), "mkdir") {
		t.Fatalf("expected mkdir-parent error; got %v", err)
	}
}

// TestExtractTarGz_OpenFileError covers the os.OpenFile error branch
// (L2228-2230): the target path already exists as a directory, so opening it
// O_WRONLY fails.
func TestExtractTarGz_OpenFileError(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("permission semantics differ on windows")
	}
	dest := t.TempDir()
	// Pre-create a directory exactly where the tar wants to write a file.
	if err := os.MkdirAll(filepath.Join(dest, "Dockerfile"), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	tarball := buildTarGz(t, map[string]string{"Dockerfile": "FROM alpine"}, "", false)
	if err := extractTarGz(tarball, dest); err == nil || !strings.Contains(err.Error(), "open file") {
		t.Fatalf("expected open-file error; got %v", err)
	}
}

// ── isUnderDir exact-".." guard ──────────────────────────────────────────────

// TestIsUnderDir_ExactDotDot covers the `rel == ".."` short-circuit (the first
// half of the L2255-2257 return) and the `rel[:2] == ".."` prefix guard with a
// deeper escape (e.g. "../../x").
func TestIsUnderDir_ExactDotDot(t *testing.T) {
	base := "/a/b"
	// parent → filepath.Rel("/a/b", "/a") == ".." → false.
	if isUnderDir("/a", base) {
		t.Error("parent of base must not be under base")
	}
	// grandparent escape → rel == "../.." → prefix ".." → false.
	if isUnderDir("/", base) {
		t.Error("root must not be under base")
	}
	// sibling that shares no prefix but cleans to under → true.
	if !isUnderDir("/a/b/c/d", base) {
		t.Error("nested child should be under base")
	}
}
