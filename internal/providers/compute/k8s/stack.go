package k8s

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"golang.org/x/sync/errgroup"
	"golang.org/x/sync/semaphore"

	compute "instant.dev/internal/providers/compute"
)

const (
	labelStack   = "instant.dev/stack"
	stackIngHost = "instant.dev"
)

// K8sStackProvider implements compute.StackProvider using the local k8s cluster.
// Embeds K8sProvider to reuse clientset and namespace helpers.
type K8sStackProvider struct {
	*K8sProvider
}

// NewStackProvider creates a K8sStackProvider.
func NewStackProvider(namespace string) (*K8sStackProvider, error) {
	base, err := New(namespace)
	if err != nil {
		return nil, fmt.Errorf("k8s.NewStackProvider: %w", err)
	}
	return &K8sStackProvider{K8sProvider: base}, nil
}

// stackImageTag returns the docker image tag for a stack service.
func stackImageTag(stackID, svcName string) string {
	return "instant-stack-" + stackID + "-" + svcName + ":latest"
}

// DeployStack builds all images in parallel, creates the stack namespace with
// security primitives, deploys all Deployments/Services/Ingresses, then waits
// until all pods are healthy (up to 10 minutes).
func (p *K8sStackProvider) DeployStack(
	ctx context.Context,
	opts compute.StackDeployOptions,
	onUpdate func(svcName, status, appURL, errMsg string),
) error {
	stackNamespace := compute.StackNamespace(opts.StackID)

	// ── Step 1: Parallel image builds ────────────────────────────────────────

	maxConcurrent := runtime.NumCPU() / 2
	if maxConcurrent < 1 {
		maxConcurrent = 1
	}
	if maxConcurrent > 4 {
		maxConcurrent = 4
	}
	if v := os.Getenv("MAX_CONCURRENT_BUILDS"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			maxConcurrent = n
		}
	}

	sem := semaphore.NewWeighted(int64(maxConcurrent))
	eg, buildCtx := errgroup.WithContext(ctx)

	for _, svc := range opts.Services {
		svc := svc // capture
		eg.Go(func() error {
			if err := sem.Acquire(buildCtx, 1); err != nil {
				return err
			}
			defer sem.Release(1)

			onUpdate(svc.Name, "building", "", "")
			tag := stackImageTag(opts.StackID, svc.Name)
			if err := p.buildImage(buildCtx, svc.Name+"-"+opts.StackID, tag, svc.Tarball); err != nil {
				return fmt.Errorf("build %q: %w", svc.Name, err)
			}
			return nil
		})
	}

	if err := eg.Wait(); err != nil {
		// Build failed — do NOT create namespace.
		return fmt.Errorf("k8s.DeployStack: image build failed: %w", err)
	}

	// ── Step 2: Create stack namespace with security primitives ──────────────

	if err := p.setupTenantNamespace(ctx, stackNamespace, opts.StackID, opts.Tier); err != nil {
		return fmt.Errorf("k8s.DeployStack: setup namespace: %w", err)
	}

	teardownOnFailure := func() {
		if teardownErr := p.TeardownStack(ctx, stackNamespace); teardownErr != nil {
			slog.Error("k8s.DeployStack: teardown after failure",
				"namespace", stackNamespace,
				"teardown_error", teardownErr,
			)
		}
	}

	// ── Step 3: Create k8s objects for each service ──────────────────────────

	serviceURLs := make(map[string]string, len(opts.Services))

	memReq, memLimit, cpuReq := compute.TierResources(opts.Tier)

	for _, svc := range opts.Services {
		port := svc.Port
		if port == 0 {
			port = 8080
		}

		tag := stackImageTag(opts.StackID, svc.Name)

		// Deployment
		if err := p.createStackDeployment(ctx, stackNamespace, opts.StackID, svc.Name, tag, port, svc.EnvVars, memReq, memLimit, cpuReq); err != nil {
			onUpdate(svc.Name, "failed", "", err.Error())
			teardownOnFailure()
			return fmt.Errorf("k8s.DeployStack: create deployment %q: %w", svc.Name, err)
		}

		// Service + expose: NodePort for local dev (no DNS needed) or Ingress via Traefik.
		appURL := ""
		if svc.Expose && os.Getenv("STACK_EXPOSE_VIA") == "nodeport" {
			// NodePort mode: expose directly on a random port, return http://localhost:{port}.
			// No DNS or ingress controller required — useful for local k8s dev clusters.
			nodePort, err := p.createNodePortService(ctx, stackNamespace, svc.Name, port)
			if err != nil {
				onUpdate(svc.Name, "failed", "", err.Error())
				teardownOnFailure()
				return fmt.Errorf("k8s.DeployStack: create nodeport service %q: %w", svc.Name, err)
			}
			appURL = fmt.Sprintf("http://localhost:%d", nodePort)
		} else {
			// Default: ClusterIP service + optional Ingress via Traefik.
			if err := p.createClusterIPService(ctx, stackNamespace, svc.Name, port); err != nil {
				onUpdate(svc.Name, "failed", "", err.Error())
				teardownOnFailure()
				return fmt.Errorf("k8s.DeployStack: create service %q: %w", svc.Name, err)
			}
			if svc.Expose {
				u, err := p.createIngress(ctx, stackNamespace, opts.StackID, svc.Name, port)
				if err != nil {
					onUpdate(svc.Name, "failed", "", err.Error())
					teardownOnFailure()
					return fmt.Errorf("k8s.DeployStack: create ingress %q: %w", svc.Name, err)
				}
				appURL = u
			}
		}
		serviceURLs[svc.Name] = appURL
		onUpdate(svc.Name, "deploying", appURL, "")
	}

	// ── Step 4: Wait for all pods to be ready ────────────────────────────────

	if err := p.waitForStackReady(ctx, stackNamespace, opts.Services, serviceURLs, onUpdate); err != nil {
		teardownOnFailure()
		return fmt.Errorf("k8s.DeployStack: pods not ready: %w", err)
	}

	return nil
}

// TeardownStack deletes the stack namespace and everything inside it.
func (p *K8sStackProvider) TeardownStack(ctx context.Context, stackNamespace string) error {
	err := p.clientset.CoreV1().Namespaces().Delete(ctx, stackNamespace, metav1.DeleteOptions{})
	if err != nil && !apierrors.IsNotFound(err) {
		return fmt.Errorf("k8s.TeardownStack: delete namespace %q: %w", stackNamespace, err)
	}
	slog.Info("k8s.TeardownStack: deleted", "namespace", stackNamespace)
	return nil
}

// ServiceLogs streams logs from a specific service pod within a stack namespace.
func (p *K8sStackProvider) ServiceLogs(ctx context.Context, stackNamespace, svcName string, follow bool) (io.ReadCloser, error) {
	pods, err := p.clientset.CoreV1().Pods(stackNamespace).List(ctx, metav1.ListOptions{
		LabelSelector: fmt.Sprintf("app=%s", svcName),
	})
	if err != nil {
		return nil, fmt.Errorf("k8s.ServiceLogs: list pods for %q in %q: %w", svcName, stackNamespace, err)
	}
	if len(pods.Items) == 0 {
		return io.NopCloser(strings.NewReader("no pods found")), nil
	}

	podName := pods.Items[0].Name
	req := p.clientset.CoreV1().Pods(stackNamespace).GetLogs(podName, &corev1.PodLogOptions{
		Follow:    follow,
		TailLines: int64Ptr(200),
	})
	stream, err := req.Stream(ctx)
	if err != nil {
		return nil, fmt.Errorf("k8s.ServiceLogs: stream logs for pod %q: %w", podName, err)
	}
	return stream, nil
}

// RedeployStack rebuilds all images in parallel and patches the existing Deployments
// to trigger a rolling update.
func (p *K8sStackProvider) RedeployStack(
	ctx context.Context,
	stackNamespace string,
	services []compute.StackServiceDef,
	onUpdate func(svcName, status, appURL, errMsg string),
) error {
	// Derive stackID from namespace name: "instant-stack-{stackID}"
	stackID := strings.TrimPrefix(stackNamespace, "instant-stack-")

	maxConcurrent := runtime.NumCPU() / 2
	if maxConcurrent < 1 {
		maxConcurrent = 1
	}
	if maxConcurrent > 4 {
		maxConcurrent = 4
	}
	if v := os.Getenv("MAX_CONCURRENT_BUILDS"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			maxConcurrent = n
		}
	}

	sem := semaphore.NewWeighted(int64(maxConcurrent))
	eg, buildCtx := errgroup.WithContext(ctx)

	for _, svc := range services {
		svc := svc
		eg.Go(func() error {
			if err := sem.Acquire(buildCtx, 1); err != nil {
				return err
			}
			defer sem.Release(1)

			onUpdate(svc.Name, "building", "", "")
			tag := stackImageTag(stackID, svc.Name)
			if err := p.buildImage(buildCtx, svc.Name+"-"+stackID, tag, svc.Tarball); err != nil {
				return fmt.Errorf("rebuild %q: %w", svc.Name, err)
			}
			return nil
		})
	}

	if err := eg.Wait(); err != nil {
		return fmt.Errorf("k8s.RedeployStack: image build failed: %w", err)
	}

	// Patch each Deployment to force a rolling update.
	for _, svc := range services {
		tag := stackImageTag(stackID, svc.Name)

		deploy, err := p.clientset.AppsV1().Deployments(stackNamespace).Get(ctx, svc.Name, metav1.GetOptions{})
		if err != nil {
			return fmt.Errorf("k8s.RedeployStack: get deployment %q: %w", svc.Name, err)
		}

		if deploy.Spec.Template.Annotations == nil {
			deploy.Spec.Template.Annotations = map[string]string{}
		}
		deploy.Spec.Template.Annotations["instant.dev/redeploy-at"] = time.Now().Format(time.RFC3339)

		if len(deploy.Spec.Template.Spec.Containers) > 0 {
			deploy.Spec.Template.Spec.Containers[0].Image = tag
			if len(svc.EnvVars) > 0 {
				deploy.Spec.Template.Spec.Containers[0].Env = envVarsToK8s(svc.EnvVars)
			}
		}

		if _, err := p.clientset.AppsV1().Deployments(stackNamespace).Update(ctx, deploy, metav1.UpdateOptions{}); err != nil {
			return fmt.Errorf("k8s.RedeployStack: update deployment %q: %w", svc.Name, err)
		}

		onUpdate(svc.Name, "deploying", "", "")
	}

	// Wait for all pods to become healthy.
	serviceURLs := make(map[string]string, len(services))
	if err := p.waitForStackReady(ctx, stackNamespace, services, serviceURLs, onUpdate); err != nil {
		return fmt.Errorf("k8s.RedeployStack: pods not ready: %w", err)
	}

	return nil
}

// ── Private helpers ───────────────────────────────────────────────────────────

// createStackDeployment creates a k8s Deployment for a stack service.
func (p *K8sStackProvider) createStackDeployment(
	ctx context.Context,
	ns, stackID, svcName, imageTag string,
	port int,
	envVars map[string]string,
	memReq, memLimit, cpuReq string,
) error {
	replicas := int32(1)
	pullPolicy := corev1.PullIfNotPresent
	saFalse := false

	desired := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:      svcName,
			Namespace: ns,
			Labels: map[string]string{
				"app":      svcName,
				labelStack: stackID,
			},
		},
		Spec: appsv1.DeploymentSpec{
			Replicas: &replicas,
			Selector: &metav1.LabelSelector{
				MatchLabels: map[string]string{
					"app": svcName,
				},
			},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels: map[string]string{
						"app":      svcName,
						labelStack: stackID,
					},
				},
				Spec: corev1.PodSpec{
					AutomountServiceAccountToken: &saFalse,
					Containers: []corev1.Container{
						{
							Name:            svcName,
							Image:           imageTag,
							ImagePullPolicy: pullPolicy,
							Ports: []corev1.ContainerPort{
								{ContainerPort: int32(port), Protocol: corev1.ProtocolTCP},
							},
							Env: envVarsToK8s(envVars),
							Resources: corev1.ResourceRequirements{
								Requests: corev1.ResourceList{
									corev1.ResourceMemory: resource.MustParse(memReq),
									corev1.ResourceCPU:    resource.MustParse(cpuReq),
								},
								Limits: corev1.ResourceList{
									corev1.ResourceMemory: resource.MustParse(memLimit),
								},
							},
						},
					},
				},
			},
		},
	}

	_, err := p.clientset.AppsV1().Deployments(ns).Get(ctx, svcName, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		_, err = p.clientset.AppsV1().Deployments(ns).Create(ctx, desired, metav1.CreateOptions{})
		if err != nil {
			return fmt.Errorf("create deployment %q in %q: %w", svcName, ns, err)
		}
		return nil
	}
	if err != nil {
		return fmt.Errorf("get deployment %q in %q: %w", svcName, ns, err)
	}
	_, err = p.clientset.AppsV1().Deployments(ns).Update(ctx, desired, metav1.UpdateOptions{})
	if err != nil {
		return fmt.Errorf("update deployment %q in %q: %w", svcName, ns, err)
	}
	return nil
}

// createClusterIPService creates a ClusterIP Service for a stack service.
// Unlike single-service (NodePort), stacks use ClusterIP for internal routing.
func (p *K8sStackProvider) createClusterIPService(ctx context.Context, ns, name string, port int) error {
	desired := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: ns,
			Labels: map[string]string{
				"app": name,
			},
		},
		Spec: corev1.ServiceSpec{
			Type: corev1.ServiceTypeClusterIP,
			Selector: map[string]string{
				"app": name,
			},
			Ports: []corev1.ServicePort{
				{
					Port:       int32(port),
					TargetPort: intstr.FromInt(port),
					Protocol:   corev1.ProtocolTCP,
				},
			},
		},
	}

	_, err := p.clientset.CoreV1().Services(ns).Get(ctx, name, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		_, err = p.clientset.CoreV1().Services(ns).Create(ctx, desired, metav1.CreateOptions{})
		if err != nil {
			return fmt.Errorf("create clusterip service %q in %q: %w", name, ns, err)
		}
		return nil
	}
	if err != nil {
		return fmt.Errorf("get service %q in %q: %w", name, ns, err)
	}
	// Already exists — leave it in place (ClusterIP is immutable).
	return nil
}

// createNodePortService creates a NodePort Service for an exposed stack service.
// Returns the assigned nodePort (30000-32767) which is directly accessible at
// http://localhost:{nodePort} on Rancher Desktop / k3s without DNS or an ingress controller.
func (p *K8sStackProvider) createNodePortService(ctx context.Context, ns, name string, port int) (int, error) {
	desired := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name + "-np",
			Namespace: ns,
			Labels: map[string]string{
				"app": name,
			},
		},
		Spec: corev1.ServiceSpec{
			Type: corev1.ServiceTypeNodePort,
			Selector: map[string]string{
				"app": name,
			},
			Ports: []corev1.ServicePort{
				{
					Port:       int32(port),
					TargetPort: intstr.FromInt(port),
					Protocol:   corev1.ProtocolTCP,
				},
			},
		},
	}

	// Check if already exists — return existing nodePort.
	existing, err := p.clientset.CoreV1().Services(ns).Get(ctx, name+"-np", metav1.GetOptions{})
	if err == nil {
		if len(existing.Spec.Ports) > 0 {
			return int(existing.Spec.Ports[0].NodePort), nil
		}
		return 0, fmt.Errorf("nodeport service %q has no ports", name+"-np")
	}
	if !apierrors.IsNotFound(err) {
		return 0, fmt.Errorf("get nodeport service %q in %q: %w", name+"-np", ns, err)
	}

	created, err := p.clientset.CoreV1().Services(ns).Create(ctx, desired, metav1.CreateOptions{})
	if err != nil {
		return 0, fmt.Errorf("create nodeport service %q in %q: %w", name+"-np", ns, err)
	}
	if len(created.Spec.Ports) == 0 {
		return 0, fmt.Errorf("nodeport service %q created but has no ports", name+"-np")
	}
	return int(created.Spec.Ports[0].NodePort), nil
}

// createIngress creates a k8s Ingress for an exposed stack service.
// Returns the app URL on success.
func (p *K8sStackProvider) createIngress(ctx context.Context, ns, stackID, svcName string, port int) (string, error) {
	host := svcName + "-" + stackID + "." + stackIngHost
	appURL := "http://" + host
	pathType := networkingv1.PathTypePrefix

	ing := &networkingv1.Ingress{
		ObjectMeta: metav1.ObjectMeta{
			Name:      svcName,
			Namespace: ns,
			Labels: map[string]string{
				"app":      svcName,
				labelStack: stackID,
			},
		},
		Spec: networkingv1.IngressSpec{
			Rules: []networkingv1.IngressRule{
				{
					Host: host,
					IngressRuleValue: networkingv1.IngressRuleValue{
						HTTP: &networkingv1.HTTPIngressRuleValue{
							Paths: []networkingv1.HTTPIngressPath{
								{
									Path:     "/",
									PathType: &pathType,
									Backend: networkingv1.IngressBackend{
										Service: &networkingv1.IngressServiceBackend{
											Name: svcName,
											Port: networkingv1.ServiceBackendPort{
												Number: int32(port),
											},
										},
									},
								},
							},
						},
					},
				},
			},
		},
	}

	_, err := p.clientset.NetworkingV1().Ingresses(ns).Create(ctx, ing, metav1.CreateOptions{})
	if err != nil {
		if apierrors.IsAlreadyExists(err) {
			return appURL, nil
		}
		if apierrors.IsForbidden(err) {
			return "", fmt.Errorf("create ingress %q in %q: RBAC forbidden — ensure the service account has networking.k8s.io/ingresses create permission: %w", svcName, ns, err)
		}
		return "", fmt.Errorf("create ingress %q in %q: %w", svcName, ns, err)
	}
	return appURL, nil
}

// waitForStackReady polls until all services have ReadyReplicas == 1 or 10 min timeout.
// Calls onUpdate for each service on healthy or failed transitions.
func (p *K8sStackProvider) waitForStackReady(
	ctx context.Context,
	ns string,
	services []compute.StackServiceDef,
	serviceURLs map[string]string,
	onUpdate func(svcName, status, appURL, errMsg string),
) error {
	deadline := time.Now().Add(10 * time.Minute)
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	healthy := make(map[string]bool, len(services))

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}

		if time.Now().After(deadline) {
			return fmt.Errorf("pods not ready after 10 minutes in namespace %q", ns)
		}

		for _, svc := range services {
			if healthy[svc.Name] {
				continue
			}

			deploy, err := p.clientset.AppsV1().Deployments(ns).Get(ctx, svc.Name, metav1.GetOptions{})
			if err != nil {
				continue // transient — try again next tick
			}

			// Check for terminal pod failures.
			if reason := p.checkPodFailure(ctx, ns, svc.Name); reason != "" {
				onUpdate(svc.Name, "failed", "", reason)
				return fmt.Errorf("service %q failed: %s", svc.Name, reason)
			}

			if deploy.Status.ReadyReplicas >= 1 {
				healthy[svc.Name] = true
				onUpdate(svc.Name, "healthy", serviceURLs[svc.Name], "")
			}
		}

		// All healthy?
		allHealthy := true
		for _, svc := range services {
			if !healthy[svc.Name] {
				allHealthy = false
				break
			}
		}
		if allHealthy {
			return nil
		}
	}
}

// checkPodFailure returns a non-empty reason string if any pod for the given
// service is in ImagePullBackOff or CrashLoopBackOff; otherwise returns "".
func (p *K8sStackProvider) checkPodFailure(ctx context.Context, ns, svcName string) string {
	pods, err := p.clientset.CoreV1().Pods(ns).List(ctx, metav1.ListOptions{
		LabelSelector: fmt.Sprintf("app=%s", svcName),
	})
	if err != nil || len(pods.Items) == 0 {
		return ""
	}
	for _, pod := range pods.Items {
		for _, cs := range pod.Status.ContainerStatuses {
			if cs.State.Waiting != nil {
				reason := cs.State.Waiting.Reason
				if reason == "ImagePullBackOff" || reason == "CrashLoopBackOff" || reason == "ErrImagePull" {
					return reason
				}
			}
		}
	}
	return ""
}
