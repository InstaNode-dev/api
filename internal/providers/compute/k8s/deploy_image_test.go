package k8s

// deploy_image_test.go — P2 source=image: Deploy must skip Kaniko, deploy the
// prebuilt image directly, and provision a pull secret. Runs against the fake
// clientset (no real cluster).

import (
	"context"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"

	"instant.dev/internal/providers/compute"
)

func TestDeploy_ImageSource_SkipsBuildAndDeploysRef(t *testing.T) {
	cs := fake.NewSimpleClientset()
	p := &K8sProvider{clientset: cs}

	_, err := p.Deploy(context.Background(), compute.DeployOptions{
		AppID:        "imgapp",
		Source:       "image",
		ImageRef:     "ghcr.io/o/a:1",
		RegistryAuth: `{"auths":{"ghcr.io":{"auth":"eA=="}}}`, // BYO creds → no copy from instant ns
		Port:         8080,
		Tier:         "hobby",
		TeamID:       "11111111-1111-1111-1111-111111111111",
	})
	if err != nil {
		t.Fatalf("Deploy(image): %v", err)
	}

	ns := deployNamespace("imgapp")
	// Container runs the prebuilt image (not a built imageName()).
	dep, derr := cs.AppsV1().Deployments(ns).Get(context.Background(), deploymentName("imgapp"), metav1.GetOptions{})
	if derr != nil {
		t.Fatalf("get deployment: %v", derr)
	}
	if img := dep.Spec.Template.Spec.Containers[0].Image; img != "ghcr.io/o/a:1" {
		t.Errorf("container image = %q, want the prebuilt ref ghcr.io/o/a:1", img)
	}
	// No Kaniko build Job for source=image.
	jobs, _ := cs.BatchV1().Jobs(ns).List(context.Background(), metav1.ListOptions{})
	if len(jobs.Items) != 0 {
		t.Errorf("source=image must NOT create a build Job; got %d", len(jobs.Items))
	}
	// BYO pull secret written into the namespace.
	if _, serr := cs.CoreV1().Secrets(ns).Get(context.Background(), "ghcr-pull", metav1.GetOptions{}); serr != nil {
		t.Errorf("ghcr-pull pull secret not created: %v", serr)
	}
}
