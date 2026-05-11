// Package k8s implements the compute.Provider interface using the local Kubernetes
// cluster (Rancher Desktop / k3s). Images are built via a docker subprocess and
// are available to k3s because Rancher Desktop shares the Docker image store.
package k8s

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"

	compute "instant.dev/internal/providers/compute"
)

const (
	imageRegistry = "instant-apps"
	labelApp      = "instant-app"
	labelAppID    = "instant-app-id"
)

// BuildContextConfig holds the MinIO/S3 settings used to deliver the kaniko
// build context. When Endpoint is empty, the K8sProvider falls back to the
// legacy k8s-Secret delivery (capped at ~1 MiB by etcd's object size limit).
// When set, the tarball is uploaded to MinIO and kaniko is pointed at the
// resulting s3:// URL — lifting the practical cap to the multipart limit
// enforced in the handler (currently 50 MiB).
type BuildContextConfig struct {
	Endpoint   string // host:port of MinIO server (e.g. "minio.instant-data.svc.cluster.local:9000")
	AccessKey  string // MinIO admin access key
	SecretKey  string // MinIO admin secret key
	BucketName string // bucket for build contexts (e.g. "instant-build-contexts")
	UseSSL     bool   // false for in-cluster MinIO; true for TLS-terminated endpoints
}

// K8sProvider implements compute.Provider using the local k8s cluster.
type K8sProvider struct {
	clientset kubernetes.Interface // accepts both *Clientset and *fake.Clientset (tests)
	namespace string               // shared namespace (legacy fallback); per-deploy namespaces are preferred
	buildCtx  BuildContextConfig   // MinIO settings for kaniko build context delivery
}

// New creates a K8sProvider targeting the given namespace.
// buildCtx is optional — when unset, builds fall back to the 1 MiB Secret path.
// Returns an error if the k8s clientset cannot be initialized; the caller
// should fall back to noop in that case.
func New(namespace string, buildCtx BuildContextConfig) (*K8sProvider, error) {
	if namespace == "" {
		namespace = "instant-apps"
	}
	cs, err := newClientset()
	if err != nil {
		return nil, fmt.Errorf("k8s.New: %w", err)
	}
	p := &K8sProvider{
		clientset: cs,
		namespace: namespace,
		buildCtx:  buildCtx,
	}
	// Ensure the shared namespace exists (idempotent).
	if err := p.ensureNamespace(context.Background()); err != nil {
		return nil, fmt.Errorf("k8s.New: ensure namespace: %w", err)
	}
	return p, nil
}

// newClientset builds a *kubernetes.Clientset, preferring in-cluster config and
// falling back to the default kubeconfig file for local development.
func newClientset() (*kubernetes.Clientset, error) {
	cfg, err := rest.InClusterConfig()
	if err != nil {
		// Fall back to kubeconfig (local dev)
		cfg, err = clientcmd.BuildConfigFromFlags("", clientcmd.RecommendedHomeFile)
		if err != nil {
			return nil, fmt.Errorf("k8s config: %w", err)
		}
	}
	return kubernetes.NewForConfig(cfg)
}

// ensureNamespace creates the shared namespace if it doesn't already exist.
func (p *K8sProvider) ensureNamespace(ctx context.Context) error {
	ns := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: p.namespace,
			Labels: map[string]string{
				"managed-by": "instant.dev",
			},
		},
	}
	_, err := p.clientset.CoreV1().Namespaces().Create(ctx, ns, metav1.CreateOptions{})
	if err != nil && !apierrors.IsAlreadyExists(err) {
		return fmt.Errorf("create namespace %q: %w", p.namespace, err)
	}
	return nil
}

// deployNamespace returns the per-deployment namespace name for an appID.
// Format: "instant-deploy-{appID}"
func deployNamespace(appID string) string {
	return "instant-deploy-" + appID
}

// setupTenantNamespace creates a namespace with all required security primitives:
// PSS baseline labels, default-deny NetworkPolicy, ResourceQuota, LimitRange.
// namespaceName: the k8s namespace name (e.g. "instant-deploy-abc" or "instant-stack-xyz")
// tenantID: used for labels (instant.dev/tenant label)
// tier: "hobby"|"pro"|"team" — controls ResourceQuota and LimitRange sizes
func (p *K8sProvider) setupTenantNamespace(ctx context.Context, namespaceName, tenantID, tier string) error {
	// Step 1: Create namespace with PSS labels.
	ns := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: namespaceName,
			Labels: map[string]string{
				// Pod Security Standards: enforce baseline, warn on restricted.
				// "baseline" blocks known privilege escalation vectors (host namespaces,
				// privileged containers, hostPath) while allowing /tmp writes, etc.
				"pod-security.kubernetes.io/enforce": "baseline",
				"pod-security.kubernetes.io/warn":    "restricted",
				// Tenant labels for auditing and network policy selectors.
				"instant.dev/tenant":  tenantID,
				"instant.dev/tier":    tier,
				"managed-by":          "instant.dev",
			},
		},
	}
	_, err := p.clientset.CoreV1().Namespaces().Create(ctx, ns, metav1.CreateOptions{})
	if err != nil && !apierrors.IsAlreadyExists(err) {
		return fmt.Errorf("create namespace %q: %w", namespaceName, err)
	}

	// Step 2: Default-deny NetworkPolicy with targeted allow rules.
	if err := p.createNetworkPolicyInNS(ctx, namespaceName); err != nil {
		return fmt.Errorf("create network policy in %q: %w", namespaceName, err)
	}

	// Step 3: ResourceQuota per tier.
	if err := p.createResourceQuotaInNS(ctx, namespaceName, tier); err != nil {
		return fmt.Errorf("create resource quota in %q: %w", namespaceName, err)
	}

	// Step 4: LimitRange with per-pod defaults.
	if err := p.createLimitRangeForNS(ctx, namespaceName, tier); err != nil {
		return fmt.Errorf("create limit range in %q: %w", namespaceName, err)
	}

	return nil
}

// createDeployNamespace creates a per-deployment namespace with Pod Security Standards
// labels and relevant tenant labels. Uses "baseline" enforcement (not "restricted")
// because restricted blocks legitimate patterns like writing to /tmp.
func (p *K8sProvider) createDeployNamespace(ctx context.Context, appID, tier string) error {
	return p.setupTenantNamespace(ctx, deployNamespace(appID), appID, tier)
}

// ptrProto / ptrPort — addressable temporaries for inline NetworkPolicyPort literals.
// Avoids the "address of unaddressable value" compile error when building Protocol/Port
// pointer fields without naming each one separately.
func ptrProto(p corev1.Protocol) *corev1.Protocol { return &p }
func ptrPort(p int) *intstr.IntOrString          { v := intstr.FromInt(p); return &v }

// createNetworkPolicyInNS installs a default-deny NetworkPolicy in the given namespace
// and adds targeted allow rules:
//   - Allow DNS egress to kube-system (UDP+TCP port 53) — required for hostname resolution
//   - Allow intra-namespace pod-to-pod communication
//   - Allow ingress from the "instant" namespace (API health checks)
//
// This blocks user app pods from reaching postgres-platform, redis, or other tenant namespaces.
func (p *K8sProvider) createNetworkPolicyInNS(ctx context.Context, ns string) error {
	proto53UDP := corev1.ProtocolUDP
	proto53TCP := corev1.ProtocolTCP
	port53 := intstr.FromInt(53)

	np := &networkingv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "instant-isolation",
			Namespace: ns,
		},
		Spec: networkingv1.NetworkPolicySpec{
			// Select all pods in the namespace.
			PodSelector: metav1.LabelSelector{},
			PolicyTypes: []networkingv1.PolicyType{
				networkingv1.PolicyTypeIngress,
				networkingv1.PolicyTypeEgress,
			},
			Ingress: []networkingv1.NetworkPolicyIngressRule{
				{
					// Allow intra-namespace pod-to-pod (e.g., multi-container apps).
					From: []networkingv1.NetworkPolicyPeer{
						{
							PodSelector: &metav1.LabelSelector{},
						},
					},
				},
				{
					// Allow ingress from the "instant" API namespace (health checks, proxying).
					From: []networkingv1.NetworkPolicyPeer{
						{
							NamespaceSelector: &metav1.LabelSelector{
								MatchLabels: map[string]string{
									"kubernetes.io/metadata.name": "instant",
								},
							},
						},
					},
				},
				{
					// Allow ingress from kube-system (ingress controller / Traefik).
					From: []networkingv1.NetworkPolicyPeer{
						{
							NamespaceSelector: &metav1.LabelSelector{
								MatchLabels: map[string]string{
									"kubernetes.io/metadata.name": "kube-system",
								},
							},
						},
					},
				},
				{
					// Allow ingress from nginx-ingress namespace. Required because
					// Cilium-backed clusters (DOKS default) do NOT match in-cluster
					// pod IPs against an "0.0.0.0/0" ipBlock — nginx-ingress traffic
					// would otherwise be blocked.
					From: []networkingv1.NetworkPolicyPeer{
						{
							NamespaceSelector: &metav1.LabelSelector{
								MatchLabels: map[string]string{
									"kubernetes.io/metadata.name": "ingress-nginx",
								},
							},
						},
					},
				},
				{
					// Allow external ingress (NodePort traffic from the host / Lima VM).
					// Required when STACK_EXPOSE_VIA=nodeport; harmless when using Ingress.
					From: []networkingv1.NetworkPolicyPeer{
						{
							IPBlock: &networkingv1.IPBlock{
								CIDR: "0.0.0.0/0",
								// Keep internal instant namespaces isolated — only block egress there.
							},
						},
					},
				},
			},
			Egress: []networkingv1.NetworkPolicyEgressRule{
				{
					// Allow intra-namespace egress (pod-to-pod within the deployment namespace).
					To: []networkingv1.NetworkPolicyPeer{
						{
							PodSelector: &metav1.LabelSelector{},
						},
					},
				},
				{
					// Allow egress to dedicated DB pods in customer-resource namespaces
					// on the data ports. Each /db/new, /cache/new, etc. creates a namespace
					// labelled "instant.dev/role=customer-resource" — this rule lets the
					// stack's app pods reach the postgres/redis/mongo/nats pod they `needs:`.
					// Without this, Cilium-backed clusters (DOKS) silently drop service-IP
					// traffic even though the broad `0.0.0.0/0` rule below ought to cover it.
					To: []networkingv1.NetworkPolicyPeer{
						{
							NamespaceSelector: &metav1.LabelSelector{
								MatchLabels: map[string]string{
									"instant.dev/role": "customer-resource",
								},
							},
						},
					},
					Ports: []networkingv1.NetworkPolicyPort{
						{Protocol: ptrProto(corev1.ProtocolTCP), Port: ptrPort(5432)},  // postgres
						{Protocol: ptrProto(corev1.ProtocolTCP), Port: ptrPort(6379)},  // redis
						{Protocol: ptrProto(corev1.ProtocolTCP), Port: ptrPort(27017)}, // mongo
						{Protocol: ptrProto(corev1.ProtocolTCP), Port: ptrPort(4222)},  // nats
					},
				},
				{
					// Allow egress to the `instant` namespace on data ports, so stacks can
					// reach the in-cluster pg-proxy (and future redis/mongo/nats proxies).
					To: []networkingv1.NetworkPolicyPeer{
						{
							NamespaceSelector: &metav1.LabelSelector{
								MatchLabels: map[string]string{
									"kubernetes.io/metadata.name": "instant",
								},
							},
						},
					},
					Ports: []networkingv1.NetworkPolicyPort{
						{Protocol: ptrProto(corev1.ProtocolTCP), Port: ptrPort(5432)},
						{Protocol: ptrProto(corev1.ProtocolTCP), Port: ptrPort(6379)},
						{Protocol: ptrProto(corev1.ProtocolTCP), Port: ptrPort(27017)},
						{Protocol: ptrProto(corev1.ProtocolTCP), Port: ptrPort(4222)},
					},
				},
				{
					// Allow DNS resolution via kube-dns in kube-system (UDP + TCP port 53).
					// Without this, hostname resolution fails entirely.
					To: []networkingv1.NetworkPolicyPeer{
						{
							NamespaceSelector: &metav1.LabelSelector{
								MatchLabels: map[string]string{
									"kubernetes.io/metadata.name": "kube-system",
								},
							},
						},
					},
					Ports: []networkingv1.NetworkPolicyPort{
						{Protocol: &proto53UDP, Port: &port53},
						{Protocol: &proto53TCP, Port: &port53},
					},
				},
				{
					// Allow general internet egress (user apps need to call external APIs).
					// We block specific internal namespaces via ingress rules on those namespaces,
					// not here — network policies are additive and ingress-side deny is the right place.
					To: []networkingv1.NetworkPolicyPeer{
						{
							// Block only internal instant namespaces from receiving traffic.
							// ipBlock allows all non-cluster traffic (external internet).
							IPBlock: &networkingv1.IPBlock{
								CIDR: "0.0.0.0/0",
								Except: []string{
									// k3s default pod CIDR — adjust if cluster uses different range.
									// This prevents user apps from reaching internal cluster IPs
									// (postgres-platform, redis, instant-infra, instant-data).
									"10.42.0.0/16",
									"10.43.0.0/16",
								},
							},
						},
					},
				},
			},
		},
	}
	_, err := p.clientset.NetworkingV1().NetworkPolicies(ns).Create(ctx, np, metav1.CreateOptions{})
	if err != nil && !apierrors.IsAlreadyExists(err) {
		return fmt.Errorf("create network policy in %q: %w", ns, err)
	}
	return nil
}

// createDefaultDenyNetworkPolicy is a backward-compat shim over createNetworkPolicyInNS.
func (p *K8sProvider) createDefaultDenyNetworkPolicy(ctx context.Context, appID string) error {
	return p.createNetworkPolicyInNS(ctx, deployNamespace(appID))
}

// createResourceQuotaInNS installs a ResourceQuota in the given namespace.
// Limits include headroom (~256Mi + 1 pod) for cert-manager HTTP-01 ACME
// solver pods that spawn briefly when issuing/renewing TLS certs.
//   - hobby: 512Mi RAM, 500m CPU, 6 pods max
//   - pro:   1Gi RAM,   1 CPU,    11 pods max
//   - team:  3Gi RAM,   3 CPU,    21 pods max
func (p *K8sProvider) createResourceQuotaInNS(ctx context.Context, ns, tier string) error {
	var memLimit, cpuLimit string
	var maxPods string
	switch tier {
	case "pro":
		memLimit = "1Gi"
		cpuLimit = "1"
		maxPods = "11"
	case "team":
		memLimit = "3Gi"
		cpuLimit = "3"
		maxPods = "21"
	default: // hobby + anonymous
		memLimit = "512Mi"
		cpuLimit = "500m"
		maxPods = "6"
	}

	quota := &corev1.ResourceQuota{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "instant-quota",
			Namespace: ns,
		},
		Spec: corev1.ResourceQuotaSpec{
			Hard: corev1.ResourceList{
				corev1.ResourceRequestsMemory: resource.MustParse(memLimit),
				corev1.ResourceLimitsMemory:   resource.MustParse(memLimit),
				corev1.ResourceRequestsCPU:    resource.MustParse(cpuLimit),
				corev1.ResourceLimitsCPU:      resource.MustParse(cpuLimit),
				corev1.ResourcePods:           resource.MustParse(maxPods),
			},
		},
	}
	_, err := p.clientset.CoreV1().ResourceQuotas(ns).Create(ctx, quota, metav1.CreateOptions{})
	if err != nil && !apierrors.IsAlreadyExists(err) {
		return fmt.Errorf("create resource quota in %q: %w", ns, err)
	}
	return nil
}

// createResourceQuota is a backward-compat shim over createResourceQuotaInNS.
func (p *K8sProvider) createResourceQuota(ctx context.Context, appID, tier string) error {
	return p.createResourceQuotaInNS(ctx, deployNamespace(appID), tier)
}

// createLimitRangeForNS installs per-pod default resource requests/limits in the
// given namespace so pods without explicit resources get sensible defaults.
func (p *K8sProvider) createLimitRangeForNS(ctx context.Context, ns, tier string) error {
	memReq, memLimit, cpuReq := compute.TierResources(tier)

	lr := &corev1.LimitRange{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "instant-limits",
			Namespace: ns,
		},
		Spec: corev1.LimitRangeSpec{
			Limits: []corev1.LimitRangeItem{
				{
					Type: corev1.LimitTypeContainer,
					Default: corev1.ResourceList{
						corev1.ResourceMemory: resource.MustParse(memLimit),
						corev1.ResourceCPU:    resource.MustParse(cpuReq),
					},
					DefaultRequest: corev1.ResourceList{
						corev1.ResourceMemory: resource.MustParse(memReq),
						corev1.ResourceCPU:    resource.MustParse(cpuReq),
					},
				},
			},
		},
	}
	_, err := p.clientset.CoreV1().LimitRanges(ns).Create(ctx, lr, metav1.CreateOptions{})
	if err != nil && !apierrors.IsAlreadyExists(err) {
		return fmt.Errorf("create limit range in %q: %w", ns, err)
	}
	return nil
}

// createLimitRangeInNS is a backward-compat shim over createLimitRangeForNS.
func (p *K8sProvider) createLimitRangeInNS(ctx context.Context, appID, tier string) error {
	return p.createLimitRangeForNS(ctx, deployNamespace(appID), tier)
}

// teardownDeployNamespace deletes the entire per-deployment namespace and all
// resources inside it. Best-effort: logs errors but does not return them.
func (p *K8sProvider) teardownDeployNamespace(ctx context.Context, appID string) error {
	ns := deployNamespace(appID)
	err := p.clientset.CoreV1().Namespaces().Delete(ctx, ns, metav1.DeleteOptions{})
	if err != nil && !apierrors.IsNotFound(err) {
		return fmt.Errorf("delete namespace %q: %w", ns, err)
	}
	return nil
}

// Deploy builds the container image from the tarball, creates the per-deployment
// namespace with security primitives, then creates the Deployment and Service.
// Returns immediately with Status="building"; caller polls Status().
func (p *K8sProvider) Deploy(ctx context.Context, opts compute.DeployOptions) (*compute.AppDeployment, error) {
	if opts.Port == 0 {
		opts.Port = 8080
	}

	imageTag := imageName(opts.AppID)
	ns := deployNamespace(opts.AppID)

	// Step 1: Build the Docker image from the tarball.
	if err := p.buildImage(ctx, deployNamespace(opts.AppID), opts.AppID, imageTag, opts.Tarball); err != nil {
		return nil, fmt.Errorf("k8s.Deploy: build image: %w", err)
	}

	// Step 2: Create per-deployment namespace with all security primitives.
	if err := p.setupTenantNamespace(ctx, ns, opts.AppID, opts.Tier); err != nil {
		return nil, fmt.Errorf("k8s.Deploy: setup namespace: %w", err)
	}

	deployName := deploymentName(opts.AppID)
	svcName := serviceName(opts.AppID)

	memReq, memLimit, cpuReq := compute.TierResources(opts.Tier)

	// Step 6: Create Deployment in the per-deployment namespace.
	if err := p.applyDeploymentInNS(ctx, ns, deployName, imageTag, opts.EnvVars, opts.Port, memReq, memLimit, cpuReq); err != nil {
		return nil, fmt.Errorf("k8s.Deploy: apply deployment: %w", err)
	}

	// Step 7: Create Service (NodePort) in the per-deployment namespace.
	nodePort, err := p.applyServiceInNS(ctx, ns, svcName, deployName, opts.AppID, opts.Port)
	if err != nil {
		return nil, fmt.Errorf("k8s.Deploy: apply service: %w", err)
	}

	// Step 8: Create Ingress (+ cert-manager TLS) when DEPLOY_DOMAIN is set.
	// Falls back to the NodePort URL on local clusters that don't have an
	// ingress controller or public domain configured.
	ingressURL, err := p.applyIngressForDeploy(ctx, ns, svcName, opts.AppID, opts.Port)
	if err != nil {
		return nil, fmt.Errorf("k8s.Deploy: apply ingress: %w", err)
	}

	publicURL := ingressURL
	if publicURL == "" {
		publicURL = appURL(nodePort)
	}

	slog.Info("k8s.Deploy: deployment created",
		"app_id", opts.AppID,
		"image", imageTag,
		"namespace", ns,
		"node_port", nodePort,
		"ingress_url", ingressURL,
		"url", publicURL,
	)

	return &compute.AppDeployment{
		ProviderID: deployName,
		AppURL:     publicURL,
		Status:     "building",
		UpdatedAt:  time.Now(),
	}, nil
}

// Status returns the current deployment state by inspecting Deployment conditions
// and AvailableReplicas in the per-deployment namespace.
func (p *K8sProvider) Status(ctx context.Context, providerID string) (*compute.AppDeployment, error) {
	appID := appIDFromDeployName(providerID)
	ns := deployNamespace(appID)

	deploy, err := p.clientset.AppsV1().Deployments(ns).Get(ctx, providerID, metav1.GetOptions{})
	if err != nil {
		if apierrors.IsNotFound(err) {
			return &compute.AppDeployment{
				ProviderID: providerID,
				AppURL:     "",
				Status:     "stopped",
				UpdatedAt:  time.Now(),
			}, nil
		}
		return nil, fmt.Errorf("k8s.Status: get deployment %q in %q: %w", providerID, ns, err)
	}

	status := deploymentStatus(deploy)

	// Resolve the NodePort from the associated Service.
	svcName := serviceName(appID)
	nodePort := 0
	svc, err := p.clientset.CoreV1().Services(ns).Get(ctx, svcName, metav1.GetOptions{})
	if err == nil && len(svc.Spec.Ports) > 0 {
		nodePort = int(svc.Spec.Ports[0].NodePort)
	}

	// Prefer the public Ingress URL when DEPLOY_DOMAIN is configured; fall
	// back to the NodePort URL for local dev.
	publicURL := deployIngressURL(appID)
	if publicURL == "" {
		publicURL = appURL(nodePort)
	}

	return &compute.AppDeployment{
		ProviderID: providerID,
		AppURL:     publicURL,
		Status:     status,
		UpdatedAt:  deploy.CreationTimestamp.Time,
	}, nil
}

// Logs returns a ReadCloser that streams pod logs for the given deployment.
// follow=true tails the stream; follow=false returns the current buffer.
func (p *K8sProvider) Logs(ctx context.Context, providerID string, follow bool) (io.ReadCloser, error) {
	appID := appIDFromDeployName(providerID)
	ns := deployNamespace(appID)

	// Find the first running pod for this deployment.
	pods, err := p.clientset.CoreV1().Pods(ns).List(ctx, metav1.ListOptions{
		LabelSelector: fmt.Sprintf("%s=%s", labelAppID, appID),
	})
	if err != nil {
		return nil, fmt.Errorf("k8s.Logs: list pods for %q in %q: %w", providerID, ns, err)
	}
	if len(pods.Items) == 0 {
		return io.NopCloser(strings.NewReader("no pods found")), nil
	}

	podName := pods.Items[0].Name
	req := p.clientset.CoreV1().Pods(ns).GetLogs(podName, &corev1.PodLogOptions{
		Follow:    follow,
		TailLines: int64Ptr(200),
	})
	stream, err := req.Stream(ctx)
	if err != nil {
		return nil, fmt.Errorf("k8s.Logs: stream logs for pod %q: %w", podName, err)
	}
	return stream, nil
}

// Teardown deletes the entire per-deployment namespace and all resources inside it.
func (p *K8sProvider) Teardown(ctx context.Context, providerID string) error {
	appID := appIDFromDeployName(providerID)

	if err := p.teardownDeployNamespace(ctx, appID); err != nil {
		return fmt.Errorf("k8s.Teardown: %w", err)
	}

	slog.Info("k8s.Teardown: deleted deployment namespace",
		"provider_id", providerID,
		"namespace", deployNamespace(appID),
	)
	return nil
}

// Redeploy builds a new image from the tarball and triggers a rolling update
// on the existing Deployment.
func (p *K8sProvider) Redeploy(ctx context.Context, providerID string, tarball []byte, envVars map[string]string) (*compute.AppDeployment, error) {
	appID := appIDFromDeployName(providerID)
	imageTag := imageName(appID)
	ns := deployNamespace(appID)

	if err := p.buildImage(ctx, deployNamespace(appID), appID, imageTag, tarball); err != nil {
		return nil, fmt.Errorf("k8s.Redeploy: build image: %w", err)
	}

	// Patch the Deployment to force a rollout (update an annotation).
	deploy, err := p.clientset.AppsV1().Deployments(ns).Get(ctx, providerID, metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("k8s.Redeploy: get deployment %q in %q: %w", providerID, ns, err)
	}

	if deploy.Spec.Template.Annotations == nil {
		deploy.Spec.Template.Annotations = map[string]string{}
	}
	deploy.Spec.Template.Annotations["instant.dev/redeploy-at"] = time.Now().Format(time.RFC3339)

	// Update env vars if provided.
	if len(envVars) > 0 && len(deploy.Spec.Template.Spec.Containers) > 0 {
		deploy.Spec.Template.Spec.Containers[0].Env = envVarsToK8s(envVars)
	}

	_, err = p.clientset.AppsV1().Deployments(ns).Update(ctx, deploy, metav1.UpdateOptions{})
	if err != nil {
		return nil, fmt.Errorf("k8s.Redeploy: update deployment %q: %w", providerID, err)
	}

	// Resolve current NodePort.
	svcName := serviceName(appID)
	nodePort := 0
	svc, err := p.clientset.CoreV1().Services(ns).Get(ctx, svcName, metav1.GetOptions{})
	if err == nil && len(svc.Spec.Ports) > 0 {
		nodePort = int(svc.Spec.Ports[0].NodePort)
	}

	// Prefer the public Ingress URL when DEPLOY_DOMAIN is configured.
	publicURL := deployIngressURL(appID)
	if publicURL == "" {
		publicURL = appURL(nodePort)
	}

	slog.Info("k8s.Redeploy: rolling update triggered",
		"provider_id", providerID,
		"namespace", ns,
		"url", publicURL,
	)

	return &compute.AppDeployment{
		ProviderID: providerID,
		AppURL:     publicURL,
		Status:     "deploying",
		UpdatedAt:  time.Now(),
	}, nil
}

// buildImage builds the user's container image using kaniko inside k8s and
// pushes it to the configured registry. Works on any k8s cluster (containerd,
// docker, etc.) because the build runs as a Pod, not a subprocess on a node.
//
// Caller passes ns explicitly because the stack flow uses
// "instant-stack-<id>" while the single-app flow uses "instant-deploy-<id>".
func (p *K8sProvider) buildImage(ctx context.Context, ns, appID, imageTag string, tarball []byte) error {
	jobName := "build-" + sanitizeName(appID)
	ctxSecret := "build-ctx-" + sanitizeName(appID)
	authSecret := "ghcr-pull"

	slog.Info("k8s.buildImage: starting kaniko build",
		"app_id", appID, "image", imageTag, "namespace", ns)

	// 0. Ensure the namespace exists. The stack pipeline normally creates it
	//    via setupTenantNamespace AFTER the build step, so we need to be the
	//    first to bring it up. Idempotent.
	nsObj := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{
		Name:   ns,
		Labels: map[string]string{"managed-by": "instant.dev", "instant.dev/component": "build-staging"},
	}}
	if _, err := p.clientset.CoreV1().Namespaces().Create(ctx, nsObj, metav1.CreateOptions{}); err != nil && !apierrors.IsAlreadyExists(err) {
		return fmt.Errorf("k8s.buildImage: ensure namespace %q: %w", ns, err)
	}

	// 1. Tarball delivery. Prefer S3 when MinIO is configured (no 1 MiB cap);
	//    fall back to the legacy Secret path when not.
	s3URL, _, err := p.uploadBuildContext(ctx, appID, tarball)
	if err != nil {
		return fmt.Errorf("k8s.buildImage: upload build context: %w", err)
	}
	useSecret := s3URL == ""
	if useSecret {
		if err := p.upsertBuildContextSecret(ctx, ns, ctxSecret, tarball); err != nil {
			return fmt.Errorf("k8s.buildImage: build-context secret: %w", err)
		}
	}

	// 2. Ensure registry auth secret exists in this namespace (copied from instant ns).
	if err := p.ensureRegistryAuthInNS(ctx, ns, authSecret); err != nil {
		return fmt.Errorf("k8s.buildImage: registry auth: %w", err)
	}

	// 3. Create the kaniko Job (delete first if it exists from a previous attempt).
	prop := metav1.DeletePropagationBackground
	_ = p.clientset.BatchV1().Jobs(ns).Delete(ctx, jobName, metav1.DeleteOptions{
		PropagationPolicy: &prop,
	})
	if err := p.createKanikoJob(ctx, ns, jobName, ctxSecret, authSecret, imageTag, s3URL); err != nil {
		return fmt.Errorf("k8s.buildImage: create kaniko job: %w", err)
	}

	// 4. Wait for Job completion (poll status).
	if err := p.waitForJobComplete(ctx, ns, jobName, 10*time.Minute); err != nil {
		return fmt.Errorf("k8s.buildImage: kaniko job: %w", err)
	}

	slog.Info("k8s.buildImage: kaniko build complete", "app_id", appID, "image", imageTag)
	return nil
}

// sanitizeName lowercases and DNS-1123-cleans an appID for use in resource names.
func sanitizeName(s string) string {
	out := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'A' && c <= 'Z':
			out = append(out, c+32)
		case (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-':
			out = append(out, c)
		default:
			out = append(out, '-')
		}
	}
	return string(out)
}

// upsertBuildContextSecret writes the tarball into a Secret under key "context.tar.gz".
func (p *K8sProvider) upsertBuildContextSecret(ctx context.Context, ns, name string, tarball []byte) error {
	sec := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
			Labels: map[string]string{
				"app.kubernetes.io/managed-by": "instant",
				"instant.dev/component":        "build-context",
			},
		},
		Data: map[string][]byte{"context.tar.gz": tarball},
		Type: corev1.SecretTypeOpaque,
	}
	_, err := p.clientset.CoreV1().Secrets(ns).Create(ctx, sec, metav1.CreateOptions{})
	if err == nil {
		return nil
	}
	if !apierrors.IsAlreadyExists(err) {
		return err
	}
	existing, err := p.clientset.CoreV1().Secrets(ns).Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("get existing: %w", err)
	}
	existing.Data = sec.Data
	_, err = p.clientset.CoreV1().Secrets(ns).Update(ctx, existing, metav1.UpdateOptions{})
	return err
}

// ensureRegistryAuthInNS copies the dockerconfigjson auth secret from the
// "instant" namespace into the deploy namespace if missing.
func (p *K8sProvider) ensureRegistryAuthInNS(ctx context.Context, ns, name string) error {
	if _, err := p.clientset.CoreV1().Secrets(ns).Get(ctx, name, metav1.GetOptions{}); err == nil {
		return nil
	}
	src, err := p.clientset.CoreV1().Secrets("instant").Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("source registry-auth secret %q in instant ns: %w", name, err)
	}
	dst := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Type:       src.Type,
		Data:       src.Data,
	}
	_, err = p.clientset.CoreV1().Secrets(ns).Create(ctx, dst, metav1.CreateOptions{})
	if err != nil && !apierrors.IsAlreadyExists(err) {
		return err
	}
	return nil
}

// createKanikoJob spawns a one-shot Job that builds and pushes the image.
// When s3ContextURL is non-empty kaniko reads the build context directly from
// MinIO via the S3 path (no 1 MiB cap); when empty it falls back to reading a
// tar Secret mounted at /workspace.
func (p *K8sProvider) createKanikoJob(ctx context.Context, ns, jobName, ctxSecret, authSecret, imageTag, s3ContextURL string) error {
	backoff := int32(0)
	ttl := int32(300)

	useS3 := s3ContextURL != ""
	contextArg := "--context=tar:///workspace/context.tar.gz"
	if useS3 {
		contextArg = "--context=" + s3ContextURL
	}

	// AWS env so kaniko's S3 reader talks to in-cluster MinIO rather than the
	// AWS metadata endpoint. Honored only when --context=s3://, harmless
	// otherwise — applied unconditionally to keep the spec simple.
	envVars := []corev1.EnvVar{
		{Name: "AWS_ACCESS_KEY_ID", Value: p.buildCtx.AccessKey},
		{Name: "AWS_SECRET_ACCESS_KEY", Value: p.buildCtx.SecretKey},
		{Name: "AWS_REGION", Value: "us-east-1"},
		{Name: "S3_FORCE_PATH_STYLE", Value: "true"},
		{Name: "AWS_S3_ENDPOINT", Value: "http://" + p.buildCtx.Endpoint},
		{Name: "AWS_ENDPOINT_URL_S3", Value: "http://" + p.buildCtx.Endpoint},
	}

	volumes := []corev1.Volume{{
		Name: "registry-auth",
		VolumeSource: corev1.VolumeSource{
			Secret: &corev1.SecretVolumeSource{
				SecretName: authSecret,
				Items: []corev1.KeyToPath{
					{Key: ".dockerconfigjson", Path: "config.json"},
				},
			},
		},
	}}
	mounts := []corev1.VolumeMount{
		{Name: "registry-auth", MountPath: "/kaniko/.docker"},
	}
	if !useS3 {
		volumes = append(volumes, corev1.Volume{
			Name: "build-context",
			VolumeSource: corev1.VolumeSource{
				Secret: &corev1.SecretVolumeSource{SecretName: ctxSecret},
			},
		})
		mounts = append(mounts, corev1.VolumeMount{Name: "build-context", MountPath: "/workspace"})
	}

	job := &batchv1.Job{
		ObjectMeta: metav1.ObjectMeta{
			Name: jobName,
			Labels: map[string]string{
				"app.kubernetes.io/managed-by": "instant",
				"instant.dev/component":        "build",
			},
		},
		Spec: batchv1.JobSpec{
			BackoffLimit:            &backoff,
			TTLSecondsAfterFinished: &ttl,
			Template: corev1.PodTemplateSpec{
				Spec: corev1.PodSpec{
					RestartPolicy: corev1.RestartPolicyNever,
					Containers: []corev1.Container{{
						Name:  "kaniko",
						Image: "gcr.io/kaniko-project/executor:v1.23.2",
						Args: []string{
							contextArg,
							"--destination=" + imageTag,
							"--snapshot-mode=redo",
							"--cache=false",
							"--single-snapshot",
							"--cleanup",
						},
						Env: envVars,
						// Explicit resources override the per-namespace LimitRange
						// default (hobby tier defaults to 50m/256Mi which throttles
						// kaniko + npm install to 5+ minutes). 250m/512Mi keeps a
						// medium npm install under a minute without inflating the
						// app's own quota: builds run as a Job, not part of the
						// app's permanent footprint.
						Resources: corev1.ResourceRequirements{
							Requests: corev1.ResourceList{
								corev1.ResourceCPU:    resource.MustParse("250m"),
								corev1.ResourceMemory: resource.MustParse("256Mi"),
							},
							Limits: corev1.ResourceList{
								corev1.ResourceCPU:    resource.MustParse("1"),
								corev1.ResourceMemory: resource.MustParse("512Mi"),
							},
						},
						VolumeMounts: mounts,
					}},
					Volumes: volumes,
				},
			},
		},
	}
	_, err := p.clientset.BatchV1().Jobs(ns).Create(ctx, job, metav1.CreateOptions{})
	return err
}

// waitForJobComplete polls a Job until success or failure.
func (p *K8sProvider) waitForJobComplete(ctx context.Context, ns, jobName string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for {
		if time.Now().After(deadline) {
			return fmt.Errorf("job %q timed out after %s", jobName, timeout)
		}
		job, err := p.clientset.BatchV1().Jobs(ns).Get(ctx, jobName, metav1.GetOptions{})
		if err != nil {
			return fmt.Errorf("poll job: %w", err)
		}
		for _, c := range job.Status.Conditions {
			if c.Type == batchv1.JobComplete && c.Status == corev1.ConditionTrue {
				return nil
			}
			if c.Type == batchv1.JobFailed && c.Status == corev1.ConditionTrue {
				return fmt.Errorf("job %q failed: %s", jobName, c.Message)
			}
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(3 * time.Second):
		}
	}
}

// applyDeploymentInNS creates or updates the k8s Deployment for an app in the
// given namespace (the per-deployment namespace).
func (p *K8sProvider) applyDeploymentInNS(
	ctx context.Context,
	ns, name, imageTag string,
	envVars map[string]string,
	port int,
	memReq, memLimit, cpuReq string,
) error {
	replicas := int32(1)
	// PullAlways because images are pushed under a single :latest tag — without
	// Always, k8s caches the old image on nodes and redeploys silently serve
	// stale content. Future: sha-pin the tag and switch back to IfNotPresent.
	pullPolicy := corev1.PullAlways
	saFalse := false
	appID := appIDFromDeployName(name)

	desired := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: ns,
			Labels: map[string]string{
				labelApp:   "true",
				labelAppID: appID,
			},
		},
		Spec: appsv1.DeploymentSpec{
			Replicas: &replicas,
			Selector: &metav1.LabelSelector{
				MatchLabels: map[string]string{
					labelAppID: appID,
				},
			},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels: map[string]string{
						labelApp:   "true",
						labelAppID: appID,
					},
				},
				Spec: corev1.PodSpec{
					// Disable service account token auto-mount for security.
					AutomountServiceAccountToken: &saFalse,
					ImagePullSecrets: []corev1.LocalObjectReference{
						{Name: "ghcr-pull"},
					},
					Containers: []corev1.Container{
						{
							Name:            "app",
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

	_, err := p.clientset.AppsV1().Deployments(ns).Get(ctx, name, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		_, err = p.clientset.AppsV1().Deployments(ns).Create(ctx, desired, metav1.CreateOptions{})
		if err != nil {
			return fmt.Errorf("create deployment %q in %q: %w", name, ns, err)
		}
		return nil
	}
	if err != nil {
		return fmt.Errorf("get deployment %q in %q: %w", name, ns, err)
	}

	// Already exists — update.
	_, err = p.clientset.AppsV1().Deployments(ns).Update(ctx, desired, metav1.UpdateOptions{})
	if err != nil {
		return fmt.Errorf("update deployment %q in %q: %w", name, ns, err)
	}
	return nil
}

// applyServiceInNS creates or updates a NodePort Service in the per-deployment namespace.
// Returns the assigned NodePort (0 if service already existed).
func (p *K8sProvider) applyServiceInNS(ctx context.Context, ns, name, deployName, appID string, port int) (int, error) {
	desired := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: ns,
			Labels: map[string]string{
				labelApp:   "true",
				labelAppID: appID,
			},
		},
		Spec: corev1.ServiceSpec{
			Type: corev1.ServiceTypeNodePort,
			Selector: map[string]string{
				labelAppID: appID,
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

	existing, err := p.clientset.CoreV1().Services(ns).Get(ctx, name, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		svc, createErr := p.clientset.CoreV1().Services(ns).Create(ctx, desired, metav1.CreateOptions{})
		if createErr != nil {
			return 0, fmt.Errorf("create service %q in %q: %w", name, ns, createErr)
		}
		if len(svc.Spec.Ports) > 0 {
			return int(svc.Spec.Ports[0].NodePort), nil
		}
		return 0, nil
	}
	if err != nil {
		return 0, fmt.Errorf("get service %q in %q: %w", name, ns, err)
	}

	// Already exists — preserve the existing NodePort.
	nodePort := 0
	if len(existing.Spec.Ports) > 0 {
		nodePort = int(existing.Spec.Ports[0].NodePort)
	}
	return nodePort, nil
}

// applyIngressForDeploy creates an Ingress for a single-service /deploy/new app.
//
// Mirrors the pattern used by K8sStackProvider.createIngress: when DEPLOY_DOMAIN
// is set, the ingress is exposed at "<app-id>.<DEPLOY_DOMAIN>" and (if CERT_ISSUER
// is set) annotated for cert-manager so a Let's Encrypt cert is issued via the
// configured cluster-issuer (HTTP-01 by default). When DEPLOY_DOMAIN is empty
// (e.g. local Rancher Desktop), no ingress is created and the caller falls back
// to the NodePort URL.
//
// Returns the public URL on success, or "" if no ingress was created (callers
// should then fall back to the NodePort URL).
func (p *K8sProvider) applyIngressForDeploy(ctx context.Context, ns, svcName, appID string, port int) (string, error) {
	domain := os.Getenv("DEPLOY_DOMAIN")
	if domain == "" {
		// No public domain configured — skip ingress creation (local dev path).
		return "", nil
	}
	host := appID + "." + domain
	pathType := networkingv1.PathTypePrefix

	annotations := map[string]string{}
	var tls []networkingv1.IngressTLS
	scheme := "http"
	if certIssuer := os.Getenv("CERT_ISSUER"); certIssuer != "" {
		annotations["cert-manager.io/cluster-issuer"] = certIssuer
		tls = []networkingv1.IngressTLS{{
			Hosts:      []string{host},
			SecretName: "app-" + appID + "-tls",
		}}
		scheme = "https"
	}
	publicURL := scheme + "://" + host

	ing := &networkingv1.Ingress{
		ObjectMeta: metav1.ObjectMeta{
			Name:        "app-" + appID,
			Namespace:   ns,
			Annotations: annotations,
			Labels: map[string]string{
				labelApp:   "true",
				labelAppID: appID,
			},
		},
		Spec: networkingv1.IngressSpec{
			TLS: tls,
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
			return publicURL, nil
		}
		if apierrors.IsForbidden(err) {
			return "", fmt.Errorf("create ingress %q in %q: RBAC forbidden — ensure the service account has networking.k8s.io/ingresses create permission: %w", "app-"+appID, ns, err)
		}
		return "", fmt.Errorf("create ingress %q in %q: %w", "app-"+appID, ns, err)
	}
	return publicURL, nil
}

// deployIngressURL returns the public Ingress URL for an appID if DEPLOY_DOMAIN
// is configured. Caller uses this to compute the AppURL during Status/Redeploy
// without re-querying the k8s API (the value is deterministic from env + appID).
func deployIngressURL(appID string) string {
	domain := os.Getenv("DEPLOY_DOMAIN")
	if domain == "" {
		return ""
	}
	scheme := "http"
	if os.Getenv("CERT_ISSUER") != "" {
		scheme = "https"
	}
	return scheme + "://" + appID + "." + domain
}

// deploymentStatus translates k8s Deployment conditions and replica counts into
// one of: building|deploying|healthy|failed|stopped.
func deploymentStatus(deploy *appsv1.Deployment) string {
	// Check for failure conditions first.
	for _, cond := range deploy.Status.Conditions {
		if cond.Type == appsv1.DeploymentReplicaFailure && cond.Status == corev1.ConditionTrue {
			return "failed"
		}
	}

	if deploy.Status.AvailableReplicas >= 1 {
		return "healthy"
	}
	if deploy.Status.UpdatedReplicas > 0 || deploy.Status.UnavailableReplicas > 0 {
		return "deploying"
	}
	// No replicas scheduled yet.
	return "building"
}

// extractTarGz extracts a gzipped tar archive to destDir.
func extractTarGz(data []byte, destDir string) error {
	gr, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("gzip reader: %w", err)
	}
	defer gr.Close()

	tr := tar.NewReader(gr)
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return fmt.Errorf("tar next: %w", err)
		}

		target := filepath.Join(destDir, hdr.Name)
		// Guard against zip-slip.
		if !isUnderDir(target, destDir) {
			return fmt.Errorf("tar entry %q attempts path traversal", hdr.Name)
		}

		switch hdr.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, 0o755); err != nil {
				return fmt.Errorf("mkdir %q: %w", target, err)
			}
		case tar.TypeReg:
			if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
				return fmt.Errorf("mkdir parent %q: %w", filepath.Dir(target), err)
			}
			f, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, os.FileMode(hdr.Mode))
			if err != nil {
				return fmt.Errorf("open file %q: %w", target, err)
			}
			if _, err := io.Copy(f, tr); err != nil {
				f.Close()
				return fmt.Errorf("write file %q: %w", target, err)
			}
			f.Close()
		}
	}
	return nil
}

// isUnderDir returns true if path is under (or equal to) base after cleaning.
func isUnderDir(path, base string) bool {
	rel, err := filepath.Rel(base, path)
	if err != nil {
		return false
	}
	return rel != ".." && len(rel) >= 2 && rel[:2] != ".."
}

// envVarsToK8s converts a string map to k8s EnvVar slice.
func envVarsToK8s(vars map[string]string) []corev1.EnvVar {
	result := make([]corev1.EnvVar, 0, len(vars))
	for k, v := range vars {
		result = append(result, corev1.EnvVar{Name: k, Value: v})
	}
	return result
}

// Naming helpers.

func deploymentName(appID string) string { return "app-" + appID }
func serviceName(appID string) string    { return "svc-" + appID }
func imageName(appID string) string {
	if reg := os.Getenv("BUILD_IMAGE_REGISTRY"); reg != "" {
		for len(reg) > 0 && reg[len(reg)-1] == '/' {
			reg = reg[:len(reg)-1]
		}
		return reg + "/" + appID + ":latest"
	}
	return imageRegistry + "/" + appID + ":latest"
}

func appIDFromDeployName(name string) string {
	if len(name) > 4 && name[:4] == "app-" {
		return name[4:]
	}
	return name
}

func appURL(nodePort int) string {
	if nodePort == 0 {
		return "http://localhost:0"
	}
	return fmt.Sprintf("http://localhost:%d", nodePort)
}

func int64Ptr(v int64) *int64 { return &v }
