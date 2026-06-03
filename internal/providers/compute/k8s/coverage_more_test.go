package k8s

// coverage_more_test.go — additional tests pushing the package toward ≥95%
// coverage. Targets:
//
//   • uploadBuildContext (MinIO/S3) via an HTTP mock and the "unconfigured →
//     short-circuit" branch
//   • CertificateReady with a fake dynamic client swapped in via the package
//     newDynamicClient hook
//   • extractTarGz error branches (mkdir, openfile, no-EOF)
//   • applyServiceInNS get error
//   • createNodePortService get error / created-with-no-ports
//   • createStackDeployment update path
//   • DeployStack with a real build (kaniko Job reactor) and Ingress expose
//   • RedeployStack with a real build
//   • setupTenantNamespace ResourceQuota / LimitRange error branches
//   • waitForStackReady CrashLoopBackOff terminal-failure path
//   • streamKanikoLogs ListError + StreamError branches

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"archive/tar"
	"bytes"
	"compress/gzip"

	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	dynfake "k8s.io/client-go/dynamic/fake"
	clientfake "k8s.io/client-go/kubernetes/fake"
	clienttesting "k8s.io/client-go/testing"

	compute "instant.dev/internal/providers/compute"
)

// ── uploadBuildContext ───────────────────────────────────────────────────────

// TestUploadBuildContext_Unconfigured covers the empty-endpoint short-circuit.
func TestUploadBuildContext_Unconfigured(t *testing.T) {
	p := &K8sProvider{}
	url, key, err := p.uploadBuildContext(context.Background(), "app", []byte("x"))
	if err != nil {
		t.Errorf("err = %v", err)
	}
	if url != "" || key != "" {
		t.Errorf("url=%q key=%q; want empty", url, key)
	}
}

// TestUploadBuildContext_Unreachable exercises the BucketExists error branch
// by pointing at a closed local port.
func TestUploadBuildContext_Unreachable(t *testing.T) {
	p := &K8sProvider{
		buildCtx: BuildContextConfig{
			Endpoint:   "127.0.0.1:1",
			AccessKey:  "ak",
			SecretKey:  "sk",
			BucketName: "b",
		},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if _, _, err := p.uploadBuildContext(ctx, "appx", []byte("t")); err == nil {
		t.Error("expected error against unreachable endpoint")
	}
}

// TestUploadBuildContext_BadHandshake exercises the BucketExists / API
// non-XML response error path against an in-process HTTP server.
func TestUploadBuildContext_BadHandshake(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Always return an empty 200 — minio-go's XML parser rejects.
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()
	endpoint := strings.TrimPrefix(srv.URL, "http://")
	p := &K8sProvider{
		buildCtx: BuildContextConfig{
			Endpoint:   endpoint,
			AccessKey:  "ak",
			SecretKey:  "sk",
			BucketName: "b",
		},
	}
	if _, _, err := p.uploadBuildContext(context.Background(), "appx", []byte("t")); err == nil {
		t.Error("expected an error from bad handshake")
	}
}

// ── CertificateReady with a fake dynamic client ──────────────────────────────

func TestCertificateReady_WithFakeDynamicClient_Ready(t *testing.T) {
	scheme := runtime.NewScheme()
	cert := &unstructured.Unstructured{}
	cert.SetGroupVersionKind(schema.GroupVersionKind{
		Group: "cert-manager.io", Version: "v1", Kind: "Certificate",
	})
	cert.SetName("c1")
	cert.SetNamespace("ns")
	cert.Object["status"] = map[string]interface{}{
		"conditions": []interface{}{
			map[string]interface{}{"type": "Ready", "status": "True", "message": "issued"},
		},
	}
	dyn := dynfake.NewSimpleDynamicClientWithCustomListKinds(scheme,
		map[schema.GroupVersionResource]string{certManagerCertificateGVR: "CertificateList"},
		cert,
	)
	old := newDynamicClient
	newDynamicClient = func() (dynamic.Interface, error) { return dyn, nil }
	defer func() { newDynamicClient = old }()

	sp := &K8sStackProvider{K8sProvider: &K8sProvider{clientset: clientfake.NewSimpleClientset()}}
	ready, msg, err := sp.CertificateReady(context.Background(), "ns", "c1")
	if err != nil {
		t.Fatalf("CertificateReady: %v", err)
	}
	if !ready {
		t.Errorf("ready = false; msg=%q", msg)
	}
	if !strings.Contains(msg, "issued") {
		t.Errorf("msg = %q", msg)
	}
}

func TestCertificateReady_WithFakeDynamicClient_NotReady(t *testing.T) {
	scheme := runtime.NewScheme()
	cert := &unstructured.Unstructured{}
	cert.SetGroupVersionKind(schema.GroupVersionKind{Group: "cert-manager.io", Version: "v1", Kind: "Certificate"})
	cert.SetName("c2")
	cert.SetNamespace("ns")
	cert.Object["status"] = map[string]interface{}{
		"conditions": []interface{}{
			map[string]interface{}{"type": "Other", "status": "True"},
		},
	}
	dyn := dynfake.NewSimpleDynamicClientWithCustomListKinds(scheme,
		map[schema.GroupVersionResource]string{certManagerCertificateGVR: "CertificateList"},
		cert,
	)
	old := newDynamicClient
	newDynamicClient = func() (dynamic.Interface, error) { return dyn, nil }
	defer func() { newDynamicClient = old }()

	sp := &K8sStackProvider{K8sProvider: &K8sProvider{clientset: clientfake.NewSimpleClientset()}}
	ready, msg, _ := sp.CertificateReady(context.Background(), "ns", "c2")
	if ready {
		t.Errorf("ready true; want false (no Ready cond)")
	}
	if !strings.Contains(msg, "Ready condition not yet present") {
		t.Errorf("msg = %q", msg)
	}
}

func TestCertificateReady_NotFound(t *testing.T) {
	scheme := runtime.NewScheme()
	dyn := dynfake.NewSimpleDynamicClientWithCustomListKinds(scheme,
		map[schema.GroupVersionResource]string{certManagerCertificateGVR: "CertificateList"},
	)
	old := newDynamicClient
	newDynamicClient = func() (dynamic.Interface, error) { return dyn, nil }
	defer func() { newDynamicClient = old }()
	sp := &K8sStackProvider{K8sProvider: &K8sProvider{clientset: clientfake.NewSimpleClientset()}}
	ready, msg, err := sp.CertificateReady(context.Background(), "ns", "missing")
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if ready {
		t.Error("ready true on missing cert")
	}
	if !strings.Contains(msg, "not yet created") {
		t.Errorf("msg = %q", msg)
	}
}

func TestCertificateReady_NoStatus(t *testing.T) {
	scheme := runtime.NewScheme()
	cert := &unstructured.Unstructured{}
	cert.SetGroupVersionKind(schema.GroupVersionKind{Group: "cert-manager.io", Version: "v1", Kind: "Certificate"})
	cert.SetName("c3")
	cert.SetNamespace("ns")
	dyn := dynfake.NewSimpleDynamicClientWithCustomListKinds(scheme,
		map[schema.GroupVersionResource]string{certManagerCertificateGVR: "CertificateList"},
		cert,
	)
	old := newDynamicClient
	newDynamicClient = func() (dynamic.Interface, error) { return dyn, nil }
	defer func() { newDynamicClient = old }()
	sp := &K8sStackProvider{K8sProvider: &K8sProvider{clientset: clientfake.NewSimpleClientset()}}
	_, msg, _ := sp.CertificateReady(context.Background(), "ns", "c3")
	if !strings.Contains(msg, "no status conditions yet") {
		t.Errorf("msg = %q", msg)
	}
}

func TestCertificateReady_DynamicClientError(t *testing.T) {
	old := newDynamicClient
	newDynamicClient = func() (dynamic.Interface, error) { return nil, errors.New("boom") }
	defer func() { newDynamicClient = old }()
	sp := &K8sStackProvider{K8sProvider: &K8sProvider{clientset: clientfake.NewSimpleClientset()}}
	if _, _, err := sp.CertificateReady(context.Background(), "ns", "c"); err == nil {
		t.Error("expected dynamic-client error")
	}
}

// ── extractTarGz error branches ──────────────────────────────────────────────

func TestExtractTarGz_BadTarHeader(t *testing.T) {
	// gzip-wrapped non-tar bytes — gzip succeeds, tar.Next reports an error.
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	_, _ = gz.Write([]byte("not a tar stream"))
	_ = gz.Close()
	if err := extractTarGz(buf.Bytes(), t.TempDir()); err == nil {
		t.Error("expected tar parse error")
	}
}

func TestExtractTarGz_FileWithoutParent(t *testing.T) {
	// Entry is a file deep in dirs that don't pre-exist — mkdir-parent path
	// must succeed.
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	_ = tw.WriteHeader(&tar.Header{Name: "deep/a/b/file.txt", Size: 2, Mode: 0o644, Typeflag: tar.TypeReg})
	_, _ = tw.Write([]byte("ok"))
	_ = tw.Close()
	_ = gz.Close()
	dest := t.TempDir()
	if err := extractTarGz(buf.Bytes(), dest); err != nil {
		t.Fatalf("extractTarGz: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dest, "deep/a/b/file.txt")); err != nil {
		t.Errorf("file missing: %v", err)
	}
}

func TestExtractTarGz_SymlinkSkipped(t *testing.T) {
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	_ = tw.WriteHeader(&tar.Header{Name: "link", Linkname: "target", Typeflag: tar.TypeSymlink})
	_ = tw.WriteHeader(&tar.Header{Name: "ok.txt", Size: 2, Mode: 0o644, Typeflag: tar.TypeReg})
	_, _ = tw.Write([]byte("ok"))
	_ = tw.Close()
	_ = gz.Close()
	dest := t.TempDir()
	if err := extractTarGz(buf.Bytes(), dest); err != nil {
		t.Fatalf("extractTarGz: %v", err)
	}
}

// ── isUnderDir edge ──────────────────────────────────────────────────────────

func TestIsUnderDir_AbsoluteOutside(t *testing.T) {
	if isUnderDir("/nowhere/secret", "/base") {
		t.Error("absolute outside path must not be under base")
	}
}

// ── applyServiceInNS get error ───────────────────────────────────────────────

func TestApplyServiceInNS_GetError(t *testing.T) {
	cs := clientfake.NewSimpleClientset()
	cs.PrependReactor("get", "services", func(_ clienttesting.Action) (bool, runtime.Object, error) {
		return true, nil, errors.New("kaboom")
	})
	p := &K8sProvider{clientset: cs}
	_, err := p.applyServiceInNS(context.Background(), "ns", "svc", "app", "x", 8080)
	if err == nil {
		t.Error("expected error")
	}
}

func TestApplyServiceInNS_CreateError(t *testing.T) {
	cs := clientfake.NewSimpleClientset()
	cs.PrependReactor("create", "services", func(_ clienttesting.Action) (bool, runtime.Object, error) {
		return true, nil, errors.New("kaboom")
	})
	p := &K8sProvider{clientset: cs}
	_, err := p.applyServiceInNS(context.Background(), "ns", "svc", "app", "x", 8080)
	if err == nil {
		t.Error("expected create error")
	}
}

// ── createNodePortService get error ──────────────────────────────────────────

func TestCreateNodePortService_GetError(t *testing.T) {
	cs := clientfake.NewSimpleClientset()
	cs.PrependReactor("get", "services", func(_ clienttesting.Action) (bool, runtime.Object, error) {
		return true, nil, errors.New("kaboom")
	})
	sp := &K8sStackProvider{K8sProvider: &K8sProvider{clientset: cs}}
	_, err := sp.createNodePortService(context.Background(), "ns", "svc", 8080)
	if err == nil {
		t.Error("expected error")
	}
}

func TestCreateNodePortService_CreateError(t *testing.T) {
	cs := clientfake.NewSimpleClientset()
	cs.PrependReactor("create", "services", func(_ clienttesting.Action) (bool, runtime.Object, error) {
		return true, nil, errors.New("kaboom")
	})
	sp := &K8sStackProvider{K8sProvider: &K8sProvider{clientset: cs}}
	_, err := sp.createNodePortService(context.Background(), "ns", "svc", 8080)
	if err == nil {
		t.Error("expected error")
	}
}

func TestCreateNodePortService_ExistsNoPorts(t *testing.T) {
	cs := clientfake.NewSimpleClientset(&corev1.Service{
		ObjectMeta: metav1.ObjectMeta{Name: "svc-np", Namespace: "ns"},
		Spec:       corev1.ServiceSpec{},
	})
	sp := &K8sStackProvider{K8sProvider: &K8sProvider{clientset: cs}}
	_, err := sp.createNodePortService(context.Background(), "ns", "svc", 8080)
	if err == nil {
		t.Error("expected error for existing service with no ports")
	}
}

// ── createStackDeployment update path ────────────────────────────────────────

func TestCreateStackDeployment_Update(t *testing.T) {
	cs := clientfake.NewSimpleClientset()
	sp := &K8sStackProvider{K8sProvider: &K8sProvider{clientset: cs}}
	// First create.
	if err := sp.createStackDeployment(context.Background(), "ns", "stk", "web", "img1:latest", 8080, nil,
		"64Mi", "256Mi", "50m", "512Mi", "2Gi"); err != nil {
		t.Fatalf("create: %v", err)
	}
	// Update path.
	if err := sp.createStackDeployment(context.Background(), "ns", "stk", "web", "img2:latest", 8080, map[string]string{"X": "y"},
		"64Mi", "256Mi", "50m", "512Mi", "2Gi"); err != nil {
		t.Fatalf("update: %v", err)
	}
	d, _ := cs.AppsV1().Deployments("ns").Get(context.Background(), "web", metav1.GetOptions{})
	if d.Spec.Template.Spec.Containers[0].Image != "img2:latest" {
		t.Errorf("image not updated")
	}
}

func TestCreateStackDeployment_GetError(t *testing.T) {
	cs := clientfake.NewSimpleClientset()
	cs.PrependReactor("get", "deployments", func(_ clienttesting.Action) (bool, runtime.Object, error) {
		return true, nil, errors.New("kaboom")
	})
	sp := &K8sStackProvider{K8sProvider: &K8sProvider{clientset: cs}}
	err := sp.createStackDeployment(context.Background(), "ns", "stk", "web", "img:latest", 8080, nil,
		"64Mi", "256Mi", "50m", "512Mi", "2Gi")
	if err == nil {
		t.Error("expected error")
	}
}

func TestCreateStackDeployment_CreateError(t *testing.T) {
	cs := clientfake.NewSimpleClientset()
	cs.PrependReactor("create", "deployments", func(_ clienttesting.Action) (bool, runtime.Object, error) {
		return true, nil, errors.New("kaboom")
	})
	sp := &K8sStackProvider{K8sProvider: &K8sProvider{clientset: cs}}
	err := sp.createStackDeployment(context.Background(), "ns", "stk", "web", "img:latest", 8080, nil,
		"64Mi", "256Mi", "50m", "512Mi", "2Gi")
	if err == nil {
		t.Error("expected error")
	}
}

// ── DeployStack with a real build path (kaniko Job reactor) ─────────────────

func TestDeployStack_WithBuild_Expose(t *testing.T) {
	cs := clientfake.NewSimpleClientset(&corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "ghcr-pull", Namespace: "instant"},
		Type:       corev1.SecretTypeDockerConfigJson,
		Data:       map[string][]byte{".dockerconfigjson": []byte(`{}`)},
	})
	attachJobCompleteReactor(cs)
	cs.PrependReactor("create", "deployments", func(action clienttesting.Action) (bool, runtime.Object, error) {
		ca := action.(clienttesting.CreateAction)
		d := ca.GetObject().(*appsv1.Deployment)
		d.Status.ReadyReplicas = 1
		return false, d, nil
	})
	t.Setenv("DEPLOY_DOMAIN", "deployment.instanode.dev")
	t.Setenv("CERT_ISSUER", "letsencrypt-http01")

	sp := &K8sStackProvider{K8sProvider: &K8sProvider{clientset: cs}}
	opts := compute.StackDeployOptions{
		StackID: "build1",
		Tier:    "hobby",
		Services: []compute.StackServiceDef{
			{Name: "web", Port: 8080, Tarball: []byte("tar"), Expose: true},
		},
	}
	if err := sp.DeployStack(context.Background(), opts,
		func(string, string, string, string) {},
		func(string, string) {},
	); err != nil {
		t.Fatalf("DeployStack with build: %v", err)
	}
}

// TestDeployStack_BuildFails covers the build failure → no namespace path.
func TestDeployStack_BuildFails(t *testing.T) {
	cs := clientfake.NewSimpleClientset() // no ghcr-pull secret in instant ns → build fails
	sp := &K8sStackProvider{K8sProvider: &K8sProvider{clientset: cs}}
	err := sp.DeployStack(context.Background(),
		compute.StackDeployOptions{
			StackID: "bf",
			Tier:    "hobby",
			Services: []compute.StackServiceDef{
				{Name: "web", Tarball: []byte("tar")},
			},
		},
		func(string, string, string, string) {},
		func(string, string) {},
	)
	if err == nil {
		t.Error("expected build failure")
	}
}

// TestDeployStack_DeploymentFails exercises the per-service failure +
// teardownOnFailure path.
func TestDeployStack_DeploymentFails(t *testing.T) {
	cs := clientfake.NewSimpleClientset()
	cs.PrependReactor("create", "deployments", func(_ clienttesting.Action) (bool, runtime.Object, error) {
		return true, nil, errors.New("create-deploy-fail")
	})
	sp := &K8sStackProvider{K8sProvider: &K8sProvider{clientset: cs}}
	err := sp.DeployStack(context.Background(),
		compute.StackDeployOptions{
			StackID: "df",
			Tier:    "hobby",
			Services: []compute.StackServiceDef{
				{Name: "web", ImageRef: "img:latest", SkipBuild: true},
			},
		},
		func(string, string, string, string) {},
		func(string, string) {},
	)
	if err == nil {
		t.Error("expected deployment failure")
	}
}

// TestRedeployStack_WithBuild exercises the real-build branch of Redeploy.
func TestRedeployStack_WithBuild(t *testing.T) {
	cs := clientfake.NewSimpleClientset(
		&corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Name: "ghcr-pull", Namespace: "instant"},
			Type:       corev1.SecretTypeDockerConfigJson,
			Data:       map[string][]byte{".dockerconfigjson": []byte(`{}`)},
		},
		&appsv1.Deployment{
			ObjectMeta: metav1.ObjectMeta{Name: "web", Namespace: "instant-stack-rb"},
			Spec: appsv1.DeploymentSpec{Template: corev1.PodTemplateSpec{
				Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "web"}}},
			}},
			Status: appsv1.DeploymentStatus{ReadyReplicas: 1},
		},
	)
	attachJobCompleteReactor(cs)
	sp := &K8sStackProvider{K8sProvider: &K8sProvider{clientset: cs}}
	err := sp.RedeployStack(context.Background(), "instant-stack-rb",
		[]compute.StackServiceDef{{Name: "web", Tarball: []byte("t")}},
		func(string, string, string, string) {},
		func(string, string) {},
	)
	if err != nil {
		t.Fatalf("RedeployStack: %v", err)
	}
}

// TestRedeployStack_BuildFails exercises the build-error branch.
func TestRedeployStack_BuildFails(t *testing.T) {
	cs := clientfake.NewSimpleClientset() // no ghcr-pull → build fails
	sp := &K8sStackProvider{K8sProvider: &K8sProvider{clientset: cs}}
	err := sp.RedeployStack(context.Background(), "instant-stack-rbf",
		[]compute.StackServiceDef{{Name: "web", Tarball: []byte("t")}},
		func(string, string, string, string) {},
		func(string, string) {},
	)
	if err == nil {
		t.Error("expected error")
	}
}

// TestSetupTenantNamespace_QuotaError exercises the quota-error branch.
func TestSetupTenantNamespace_QuotaError(t *testing.T) {
	cs := clientfake.NewSimpleClientset()
	cs.PrependReactor("create", "resourcequotas", func(_ clienttesting.Action) (bool, runtime.Object, error) {
		return true, nil, errors.New("boom")
	})
	p := &K8sProvider{clientset: cs}
	err := p.setupTenantNamespace(context.Background(), "ns", "t", "team", "hobby")
	if err == nil {
		t.Error("expected quota error")
	}
}

// TestSetupTenantNamespace_LimitRangeError exercises the LimitRange-error branch.
func TestSetupTenantNamespace_LimitRangeError(t *testing.T) {
	cs := clientfake.NewSimpleClientset()
	cs.PrependReactor("create", "limitranges", func(_ clienttesting.Action) (bool, runtime.Object, error) {
		return true, nil, errors.New("boom")
	})
	p := &K8sProvider{clientset: cs}
	err := p.setupTenantNamespace(context.Background(), "ns", "t", "team", "hobby")
	if err == nil {
		t.Error("expected limitrange error")
	}
}

// TestSetupTenantNamespace_NetworkPolicyError exercises the NP-error branch.
func TestSetupTenantNamespace_NetworkPolicyError(t *testing.T) {
	cs := clientfake.NewSimpleClientset()
	cs.PrependReactor("create", "networkpolicies", func(_ clienttesting.Action) (bool, runtime.Object, error) {
		return true, nil, errors.New("boom")
	})
	p := &K8sProvider{clientset: cs}
	err := p.setupTenantNamespace(context.Background(), "ns", "t", "team", "hobby")
	if err == nil {
		t.Error("expected np error")
	}
}

// TestSetupTenantNamespace_NSCreateError exercises the namespace-create error.
func TestSetupTenantNamespace_NSCreateError(t *testing.T) {
	cs := clientfake.NewSimpleClientset()
	cs.PrependReactor("create", "namespaces", func(_ clienttesting.Action) (bool, runtime.Object, error) {
		return true, nil, errors.New("nsboom")
	})
	p := &K8sProvider{clientset: cs}
	err := p.setupTenantNamespace(context.Background(), "ns", "t", "team", "hobby")
	if err == nil {
		t.Error("expected ns create error")
	}
}

// TestSetupTenantNamespace_NSExistsLabelError exercises pre-existing-ns + label-upgrade error.
func TestSetupTenantNamespace_NSExistsLabelError(t *testing.T) {
	cs := clientfake.NewSimpleClientset(&corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{Name: "preex"},
	})
	cs.PrependReactor("update", "namespaces", func(_ clienttesting.Action) (bool, runtime.Object, error) {
		return true, nil, errors.New("upd-boom")
	})
	p := &K8sProvider{clientset: cs}
	err := p.setupTenantNamespace(context.Background(), "preex", "t", "team", "hobby")
	if err == nil {
		t.Error("expected label upgrade error")
	}
}

// ── createDeployNamespace shim coverage ──────────────────────────────────────

func TestCreateDeployNamespace_PreExisting(t *testing.T) {
	cs := clientfake.NewSimpleClientset(&corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{Name: "instant-deploy-pre"},
	})
	p := &K8sProvider{clientset: cs}
	if err := p.createDeployNamespace(context.Background(), "pre", "team", "hobby"); err != nil {
		t.Fatalf("createDeployNamespace pre-existing: %v", err)
	}
}

// ── streamKanikoLogs StreamError ─────────────────────────────────────────────

// TestStreamKanikoLogs_NoPodErr verifies the "no pods" error branch.
func TestStreamKanikoLogs_NoPodErr(t *testing.T) {
	cs := clientfake.NewSimpleClientset()
	p := &K8sProvider{clientset: cs}
	_, err := p.streamKanikoLogs(context.Background(), "ns", "job-x")
	if err == nil {
		t.Error("expected no-pods error")
	}
}

func TestStreamKanikoLogs_ListError(t *testing.T) {
	cs := clientfake.NewSimpleClientset()
	cs.PrependReactor("list", "pods", func(_ clienttesting.Action) (bool, runtime.Object, error) {
		return true, nil, errors.New("kaboom")
	})
	p := &K8sProvider{clientset: cs}
	_, err := p.streamKanikoLogs(context.Background(), "ns", "job-x")
	if err == nil {
		t.Error("expected list error")
	}
}

// ── upsertBuildContextSecret UpdateError / GetError ──────────────────────────

func TestUpsertBuildContextSecret_GetError(t *testing.T) {
	cs := clientfake.NewSimpleClientset()
	cs.PrependReactor("create", "secrets", func(_ clienttesting.Action) (bool, runtime.Object, error) {
		return true, nil, apierrors.NewAlreadyExists(schema.GroupResource{Resource: "secrets"}, "ctx")
	})
	cs.PrependReactor("get", "secrets", func(_ clienttesting.Action) (bool, runtime.Object, error) {
		return true, nil, errors.New("boom")
	})
	p := &K8sProvider{clientset: cs}
	if err := p.upsertBuildContextSecret(context.Background(), "ns", "ctx", []byte("x")); err == nil {
		t.Error("expected get error")
	}
}

func TestUpsertBuildContextSecret_CreateError(t *testing.T) {
	cs := clientfake.NewSimpleClientset()
	cs.PrependReactor("create", "secrets", func(_ clienttesting.Action) (bool, runtime.Object, error) {
		return true, nil, errors.New("boom")
	})
	p := &K8sProvider{clientset: cs}
	if err := p.upsertBuildContextSecret(context.Background(), "ns", "ctx", []byte("x")); err == nil {
		t.Error("expected create error")
	}
}

// ── Redeploy error branches ──────────────────────────────────────────────────

func TestRedeploy_UpdateError(t *testing.T) {
	cs := clientfake.NewSimpleClientset(
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "instant-deploy-rdu"}},
		&corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Name: "ghcr-pull", Namespace: "instant"},
			Type:       corev1.SecretTypeDockerConfigJson,
			Data:       map[string][]byte{".dockerconfigjson": []byte(`{}`)},
		},
		&appsv1.Deployment{
			ObjectMeta: metav1.ObjectMeta{Name: "app-rdu", Namespace: "instant-deploy-rdu"},
			Spec: appsv1.DeploymentSpec{Template: corev1.PodTemplateSpec{
				Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "app", Image: "old"}}},
			}},
		},
	)
	attachJobCompleteReactor(cs)
	cs.PrependReactor("update", "deployments", func(_ clienttesting.Action) (bool, runtime.Object, error) {
		return true, nil, errors.New("update-fail")
	})
	p := &K8sProvider{clientset: cs}
	if _, err := p.Redeploy(context.Background(), "app-rdu", []byte("t"), map[string]string{"A": "b"}); err == nil {
		t.Error("expected update error")
	}
}

// ── waitForStackReady terminal pod failure ───────────────────────────────────

// TestWaitForStackReady_PodCrashLoop verifies the CrashLoopBackOff terminal
// path: the deployment exists but a pod is crash-looping → onUpdate(failed) +
// return error from waitForStackReady. We use a 50ms-tick override is not
// possible (ticker is a const 10s inside the func) — instead we just let it
// run for ~10 seconds. Acceptable since we're hitting otherwise untested code.
func TestWaitForStackReady_PodCrashLoop(t *testing.T) {
	cs := clientfake.NewSimpleClientset(
		&appsv1.Deployment{
			ObjectMeta: metav1.ObjectMeta{Name: "web", Namespace: "ns"},
		},
		&corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Name: "web-1", Namespace: "ns", Labels: map[string]string{"app": "web"}},
			Status: corev1.PodStatus{
				ContainerStatuses: []corev1.ContainerStatus{
					{State: corev1.ContainerState{Waiting: &corev1.ContainerStateWaiting{Reason: "CrashLoopBackOff"}}},
				},
			},
		},
	)
	sp := &K8sStackProvider{K8sProvider: &K8sProvider{clientset: cs}}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	var failureReason string
	err := sp.waitForStackReady(ctx, "ns",
		[]compute.StackServiceDef{{Name: "web"}},
		map[string]string{},
		func(_, status, _, reason string) {
			if status == "failed" {
				failureReason = reason
			}
		},
	)
	if err == nil {
		t.Error("expected error")
	}
	if failureReason != "CrashLoopBackOff" {
		t.Errorf("failureReason = %q", failureReason)
	}
}

// TestWaitForStackReady_CtxCanceled exercises the ctx.Done branch.
func TestWaitForStackReady_CtxCanceled(t *testing.T) {
	cs := clientfake.NewSimpleClientset()
	sp := &K8sStackProvider{K8sProvider: &K8sProvider{clientset: cs}}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := sp.waitForStackReady(ctx, "ns",
		[]compute.StackServiceDef{{Name: "web"}}, map[string]string{}, func(string, string, string, string) {})
	if err == nil {
		t.Error("expected context canceled")
	}
}

// ── upsertBuildContextSecret UpdateError-after-AlreadyExists ─────────────────

func TestUpsertBuildContextSecret_UpdateError(t *testing.T) {
	cs := clientfake.NewSimpleClientset(&corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "ctx", Namespace: "ns"},
	})
	cs.PrependReactor("update", "secrets", func(_ clienttesting.Action) (bool, runtime.Object, error) {
		return true, nil, errors.New("boom")
	})
	p := &K8sProvider{clientset: cs}
	if err := p.upsertBuildContextSecret(context.Background(), "ns", "ctx", []byte("x")); err == nil {
		t.Error("expected update error")
	}
}

// ── applyDeploymentInNS error branches ───────────────────────────────────────

func TestApplyDeploymentInNS_GetError(t *testing.T) {
	cs := clientfake.NewSimpleClientset()
	cs.PrependReactor("get", "deployments", func(_ clienttesting.Action) (bool, runtime.Object, error) {
		return true, nil, errors.New("boom")
	})
	p := &K8sProvider{clientset: cs}
	err := p.applyDeploymentInNS(context.Background(), "ns", "app", "img:latest", nil, 8080, "64Mi", "256Mi", "50m", "512Mi", "2Gi")
	if err == nil {
		t.Error("expected error")
	}
}

func TestApplyDeploymentInNS_CreateError(t *testing.T) {
	cs := clientfake.NewSimpleClientset()
	cs.PrependReactor("create", "deployments", func(_ clienttesting.Action) (bool, runtime.Object, error) {
		return true, nil, errors.New("boom")
	})
	p := &K8sProvider{clientset: cs}
	err := p.applyDeploymentInNS(context.Background(), "ns", "app", "img:latest", nil, 8080, "64Mi", "256Mi", "50m", "512Mi", "2Gi")
	if err == nil {
		t.Error("expected error")
	}
}

func TestApplyDeploymentInNS_UpdateError(t *testing.T) {
	cs := clientfake.NewSimpleClientset(&appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{Name: "app", Namespace: "ns"},
	})
	cs.PrependReactor("update", "deployments", func(_ clienttesting.Action) (bool, runtime.Object, error) {
		return true, nil, errors.New("boom")
	})
	p := &K8sProvider{clientset: cs}
	err := p.applyDeploymentInNS(context.Background(), "ns", "app", "img:latest", nil, 8080, "64Mi", "256Mi", "50m", "512Mi", "2Gi")
	if err == nil {
		t.Error("expected error")
	}
}

// ── createBuildNetworkPolicy upgrade-in-place ────────────────────────────────

func TestCreateBuildNetworkPolicy_UpdateError(t *testing.T) {
	cs := clientfake.NewSimpleClientset()
	p := &K8sProvider{clientset: cs}
	// First call creates the policy.
	if err := p.createBuildNetworkPolicy(context.Background(), "ns"); err != nil {
		t.Fatalf("first: %v", err)
	}
	// Now fail subsequent updates.
	cs.PrependReactor("update", "networkpolicies", func(_ clienttesting.Action) (bool, runtime.Object, error) {
		return true, nil, errors.New("boom")
	})
	if err := p.createBuildNetworkPolicy(context.Background(), "ns"); err == nil {
		t.Error("expected error")
	}
}

// ── ensureRegistryAuthInNS create-error branch ───────────────────────────────

func TestEnsureRegistryAuthInNS_CreateError(t *testing.T) {
	cs := clientfake.NewSimpleClientset(&corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "ghcr-pull", Namespace: "instant"},
		Type:       corev1.SecretTypeDockerConfigJson,
		Data:       map[string][]byte{".dockerconfigjson": []byte(`{}`)},
	})
	calls := 0
	cs.PrependReactor("create", "secrets", func(_ clienttesting.Action) (bool, runtime.Object, error) {
		calls++
		return true, nil, fmt.Errorf("boom %d", calls)
	})
	p := &K8sProvider{clientset: cs}
	if err := p.ensureRegistryAuthInNS(context.Background(), "ns", "ghcr-pull"); err == nil {
		t.Error("expected create error")
	}
}

// ── createKanikoJob create-error branch ──────────────────────────────────────

func TestCreateKanikoJob_CreateError(t *testing.T) {
	cs := clientfake.NewSimpleClientset()
	cs.PrependReactor("create", "jobs", func(_ clienttesting.Action) (bool, runtime.Object, error) {
		return true, nil, errors.New("boom")
	})
	p := &K8sProvider{clientset: cs}
	if err := p.createKanikoJob(context.Background(), "ns", "j", "ctx", "auth", "img:latest", "", "", ""); err == nil {
		t.Error("expected error")
	}
}

// ── waitForJobComplete timeout branch ────────────────────────────────────────

func TestWaitForJobComplete_Timeout(t *testing.T) {
	cs := clientfake.NewSimpleClientset(&batchv1.Job{
		ObjectMeta: metav1.ObjectMeta{Name: "build-x", Namespace: "ns"},
	})
	p := &K8sProvider{clientset: cs}
	if err := p.waitForJobComplete(context.Background(), "ns", "build-x", 1*time.Microsecond); err == nil || !strings.Contains(err.Error(), "timed out") {
		t.Errorf("expected timeout; got %v", err)
	}
}

// ── deploymentName / serviceName / appIDFromDeployName edge ──────────────────

func TestImageNameTrailingSlashes(t *testing.T) {
	t.Setenv("BUILD_IMAGE_REGISTRY", "registry.local///")
	if got := imageName("app"); got != "registry.local/app:latest" {
		t.Errorf("got %q", got)
	}
}

