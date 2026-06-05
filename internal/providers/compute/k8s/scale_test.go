package k8s

// scale_test.go — unit tests for K8sProvider.Scale (scale-to-zero, Task #54).
//
// Covers: scale-down patches replicas to 0, wake patches back to 1, an
// already-at-target call is a no-op (no Update), a NotFound Deployment is a
// no-op success (the idle-scaler must not wedge on a stale row), and a
// transport-level Get/Update error is surfaced.

import (
	"context"
	"errors"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	clientfake "k8s.io/client-go/kubernetes/fake"
	clienttesting "k8s.io/client-go/testing"
)

// seedScalableDeployment creates an app-<appID> Deployment in instant-deploy-<appID>
// with the given replica count so Scale has something to patch.
func seedScalableDeployment(cs *clientfake.Clientset, appID string, replicas int32) error {
	ns := deployNamespace(appID)
	r := replicas
	_, err := cs.AppsV1().Deployments(ns).Create(context.Background(), &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{Name: deploymentName(appID), Namespace: ns},
		Spec:       appsv1.DeploymentSpec{Replicas: &r},
	}, metav1.CreateOptions{})
	return err
}

func currentReplicas(t *testing.T, cs *clientfake.Clientset, appID string) int32 {
	t.Helper()
	d, err := cs.AppsV1().Deployments(deployNamespace(appID)).Get(
		context.Background(), deploymentName(appID), metav1.GetOptions{})
	if err != nil {
		t.Fatalf("get deployment: %v", err)
	}
	if d.Spec.Replicas == nil {
		return -1
	}
	return *d.Spec.Replicas
}

func TestScale_DownThenWake(t *testing.T) {
	cs := clientfake.NewSimpleClientset()
	if err := seedScalableDeployment(cs, "abc", 1); err != nil {
		t.Fatalf("seed: %v", err)
	}
	p := &K8sProvider{clientset: cs}

	// Scale down to 0 (idle descheduling).
	if err := p.Scale(context.Background(), "abc", 0); err != nil {
		t.Fatalf("Scale(0): %v", err)
	}
	if got := currentReplicas(t, cs, "abc"); got != 0 {
		t.Errorf("after Scale(0): replicas = %d; want 0", got)
	}

	// Wake back to 1.
	if err := p.Scale(context.Background(), "abc", 1); err != nil {
		t.Fatalf("Scale(1): %v", err)
	}
	if got := currentReplicas(t, cs, "abc"); got != 1 {
		t.Errorf("after Scale(1): replicas = %d; want 1", got)
	}
}

func TestScale_AlreadyAtTargetNoUpdate(t *testing.T) {
	cs := clientfake.NewSimpleClientset()
	if err := seedScalableDeployment(cs, "abc", 0); err != nil {
		t.Fatalf("seed: %v", err)
	}
	// Fail any Update so the test proves the idempotent branch skips it.
	cs.PrependReactor("update", "deployments", func(_ clienttesting.Action) (bool, runtime.Object, error) {
		return true, nil, errors.New("update should not be called when already at target")
	})
	p := &K8sProvider{clientset: cs}

	if err := p.Scale(context.Background(), "abc", 0); err != nil {
		t.Fatalf("Scale(0) on already-zero deployment should be a no-op, got: %v", err)
	}
}

func TestScale_NotFoundIsNoOp(t *testing.T) {
	cs := clientfake.NewSimpleClientset()
	p := &K8sProvider{clientset: cs}
	// No seeded deployment → Get returns NotFound → Scale must succeed (no-op).
	if err := p.Scale(context.Background(), "missing", 0); err != nil {
		t.Errorf("Scale on missing deployment should be no-op success, got: %v", err)
	}
}

func TestScale_GetErrorSurfaced(t *testing.T) {
	cs := clientfake.NewSimpleClientset()
	cs.PrependReactor("get", "deployments", func(_ clienttesting.Action) (bool, runtime.Object, error) {
		return true, nil, errors.New("boom")
	})
	p := &K8sProvider{clientset: cs}
	if err := p.Scale(context.Background(), "abc", 0); err == nil {
		t.Error("Scale should surface a transport-level Get error")
	}
}

func TestScale_UpdateErrorSurfaced(t *testing.T) {
	cs := clientfake.NewSimpleClientset()
	if err := seedScalableDeployment(cs, "abc", 1); err != nil {
		t.Fatalf("seed: %v", err)
	}
	cs.PrependReactor("update", "deployments", func(_ clienttesting.Action) (bool, runtime.Object, error) {
		return true, nil, errors.New("boom")
	})
	p := &K8sProvider{clientset: cs}
	if err := p.Scale(context.Background(), "abc", 0); err == nil {
		t.Error("Scale should surface a transport-level Update error")
	}
}
