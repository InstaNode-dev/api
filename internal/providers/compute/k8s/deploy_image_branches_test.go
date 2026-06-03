package k8s

// deploy_image_branches_test.go — error/edge branches of the P2 source=image
// Deploy path and ensureImagePullSecret, plus the tarball build-error wrap.
// All run against the fake clientset (no real cluster), using reactors to
// force the failure modes that a happy-path test can't reach.

import (
	"context"
	"errors"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8sruntime "k8s.io/apimachinery/pkg/runtime"
	clientfake "k8s.io/client-go/kubernetes/fake"
	clienttesting "k8s.io/client-go/testing"

	"instant.dev/internal/providers/compute"
)

func imageDeployOpts(appID, registryAuth string) compute.DeployOptions {
	return compute.DeployOptions{
		AppID:        appID,
		Source:       "image",
		ImageRef:     "ghcr.io/o/a:1",
		RegistryAuth: registryAuth,
		Port:         8080,
		Tier:         "hobby",
		TeamID:       "11111111-1111-1111-1111-111111111111",
	}
}

// platformGHCRPull is the shared pull secret ensureRegistryAuthInNS copies out
// of the "instant" namespace when a deploy supplies no BYO creds.
func platformGHCRPull() *corev1.Secret {
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "ghcr-pull", Namespace: "instant"},
		Type:       corev1.SecretTypeDockerConfigJson,
		Data:       map[string][]byte{corev1.DockerConfigJsonKey: []byte(`{"auths":{}}`)},
	}
}

// TestDeploy_ImageSource_EmptyAuth_CopiesPlatformSecret — with no BYO creds,
// ensureImagePullSecret copies the platform "ghcr-pull" secret from the
// instant namespace into the deploy namespace (covers the registryAuth=="" arm).
func TestDeploy_ImageSource_EmptyAuth_CopiesPlatformSecret(t *testing.T) {
	cs := clientfake.NewSimpleClientset(platformGHCRPull())
	p := &K8sProvider{clientset: cs}

	if _, err := p.Deploy(context.Background(), imageDeployOpts("imgcopy", "")); err != nil {
		t.Fatalf("Deploy(image, no creds): %v", err)
	}
	ns := deployNamespace("imgcopy")
	if _, err := cs.CoreV1().Secrets(ns).Get(context.Background(), "ghcr-pull", metav1.GetOptions{}); err != nil {
		t.Errorf("platform ghcr-pull should have been copied into %q: %v", ns, err)
	}
}

// TestDeploy_ImageSource_PullSecretAlreadyExists_Updates — when the ghcr-pull
// secret already exists in the deploy namespace, the BYO-creds Create returns
// AlreadyExists and we fall through to Update (covers that arm).
func TestDeploy_ImageSource_PullSecretAlreadyExists_Updates(t *testing.T) {
	ns := deployNamespace("imgupd")
	pre := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "ghcr-pull", Namespace: ns},
		Type:       corev1.SecretTypeDockerConfigJson,
		Data:       map[string][]byte{corev1.DockerConfigJsonKey: []byte(`{"auths":{}}`)},
	}
	cs := clientfake.NewSimpleClientset(pre)
	p := &K8sProvider{clientset: cs}

	if _, err := p.Deploy(context.Background(), imageDeployOpts("imgupd", `{"auths":{"ghcr.io":{"auth":"eA=="}}}`)); err != nil {
		t.Fatalf("Deploy(image, existing secret): %v", err)
	}
	got, err := cs.CoreV1().Secrets(ns).Get(context.Background(), "ghcr-pull", metav1.GetOptions{})
	if err != nil {
		t.Fatalf("get ghcr-pull: %v", err)
	}
	// Update should have overwritten the placeholder with the BYO creds.
	if !strings.Contains(string(got.Data[corev1.DockerConfigJsonKey]), "ghcr.io") {
		t.Errorf("ghcr-pull not updated with BYO creds: %s", got.Data[corev1.DockerConfigJsonKey])
	}
}

// TestDeploy_ImageSource_SetupNamespaceError — a namespace-create failure in the
// image path propagates as a wrapped Deploy error (covers the setup-namespace arm).
func TestDeploy_ImageSource_SetupNamespaceError(t *testing.T) {
	cs := clientfake.NewSimpleClientset()
	cs.PrependReactor("create", "namespaces", func(_ clienttesting.Action) (bool, k8sruntime.Object, error) {
		return true, nil, errors.New("boom-ns")
	})
	p := &K8sProvider{clientset: cs}

	_, err := p.Deploy(context.Background(), imageDeployOpts("imgns", ""))
	if err == nil || !strings.Contains(err.Error(), "setup namespace") {
		t.Fatalf("want wrapped setup-namespace error, got: %v", err)
	}
}

// TestDeploy_ImageSource_PullSecretError — a ghcr-pull secret-create failure in
// the image path propagates as a wrapped Deploy error (covers the pull-secret arm).
func TestDeploy_ImageSource_PullSecretError(t *testing.T) {
	cs := clientfake.NewSimpleClientset()
	cs.PrependReactor("create", "secrets", func(action clienttesting.Action) (bool, k8sruntime.Object, error) {
		ca := action.(clienttesting.CreateAction)
		sec, ok := ca.GetObject().(*corev1.Secret)
		if ok && sec.Name == "ghcr-pull" {
			return true, nil, errors.New("boom-secret")
		}
		return false, nil, nil // let other secret creates proceed
	})
	p := &K8sProvider{clientset: cs}

	// BYO creds → the Create at the secret arm is reached (not the copy arm).
	_, err := p.Deploy(context.Background(), imageDeployOpts("imgsec", `{"auths":{}}`))
	if err == nil || !strings.Contains(err.Error(), "pull secret") {
		t.Fatalf("want wrapped pull-secret error, got: %v", err)
	}
}

// TestDeploy_TarballSource_BuildError — a build-Job create failure on the
// tarball path propagates as a wrapped Deploy build error (covers the build arm
// that moved under the source=tarball branch).
func TestDeploy_TarballSource_BuildError(t *testing.T) {
	cs := clientfake.NewSimpleClientset(platformGHCRPull())
	cs.PrependReactor("create", "jobs", func(_ clienttesting.Action) (bool, k8sruntime.Object, error) {
		return true, nil, errors.New("boom-job")
	})
	p := &K8sProvider{clientset: cs}

	_, err := p.Deploy(context.Background(), compute.DeployOptions{
		AppID:   "tarerr",
		Source:  "tarball",
		Tarball: []byte("not-a-real-tarball"),
		Port:    8080,
		Tier:    "hobby",
		TeamID:  "11111111-1111-1111-1111-111111111111",
	})
	if err == nil || !strings.Contains(err.Error(), "build image") {
		t.Fatalf("want wrapped build-image error, got: %v", err)
	}
}

// TestDeploy_TarballSource_SetupNamespaceErrorAfterBuild — on the tarball path
// the build runs FIRST and setupTenantNamespace SECOND (so the kaniko pod isn't
// constrained by the runtime ResourceQuota). This drives that ordering: the
// build Job auto-completes, then a ResourceQuota-create failure surfaces as the
// wrapped "setup namespace" error (covers the tarball setup-namespace arm).
func TestDeploy_TarballSource_SetupNamespaceErrorAfterBuild(t *testing.T) {
	cs := clientfake.NewSimpleClientset(platformGHCRPull())
	attachJobCompleteReactor(cs) // buildImage succeeds (Job Complete on first poll)
	cs.PrependReactor("create", "resourcequotas", func(_ clienttesting.Action) (bool, k8sruntime.Object, error) {
		return true, nil, errors.New("boom-quota") // setupTenantNamespace creates a quota; buildImage does not
	})
	p := &K8sProvider{clientset: cs}

	_, err := p.Deploy(context.Background(), compute.DeployOptions{
		AppID:   "tarsetup",
		Source:  "tarball",
		Tarball: []byte("t"),
		Port:    8080,
		Tier:    "hobby",
		TeamID:  "11111111-1111-1111-1111-111111111111",
	})
	if err == nil || !strings.Contains(err.Error(), "setup namespace") {
		t.Fatalf("want wrapped setup-namespace error after a successful build, got: %v", err)
	}
}
