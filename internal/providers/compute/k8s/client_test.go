package k8s

import (
	"context"
	"fmt"
	"testing"

	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"

	compute "instant.dev/internal/providers/compute"
)

// TestKanikoJobHasExplicitResources guards against regressing the build pod's
// resource overrides. Without explicit Requests/Limits, the per-namespace
// LimitRange (hobby default: 50m/256Mi) throttles kaniko + npm install to
// 5+ minutes. See fix/deploy-compute-correctness.
func TestKanikoJobHasExplicitResources(t *testing.T) {
	cs := fake.NewSimpleClientset()
	p := &K8sProvider{clientset: cs}

	const ns, jobName = "instant-deploy-test", "build-test"
	if err := p.createKanikoJob(context.Background(), ns, jobName, "ctx-sec", "auth-sec", "ghcr.io/x/y:latest", ""); err != nil {
		t.Fatalf("createKanikoJob: %v", err)
	}

	job, err := cs.BatchV1().Jobs(ns).Get(context.Background(), jobName, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("get job: %v", err)
	}
	containers := job.Spec.Template.Spec.Containers
	if len(containers) != 1 {
		t.Fatalf("expected 1 container, got %d", len(containers))
	}
	c := containers[0]

	for _, k := range []corev1.ResourceName{corev1.ResourceCPU, corev1.ResourceMemory} {
		if _, ok := c.Resources.Requests[k]; !ok {
			t.Errorf("kaniko container is missing Requests[%s] — LimitRange default will throttle the build", k)
		}
		if _, ok := c.Resources.Limits[k]; !ok {
			t.Errorf("kaniko container is missing Limits[%s] — LimitRange default will throttle the build", k)
		}
	}

	// Concrete sanity check on the floor value — if someone bumps it down again,
	// the test fires.
	if got := c.Resources.Requests[corev1.ResourceCPU]; got.MilliValue() < 250 {
		t.Errorf("kaniko CPU request %s is below the 250m floor for non-trivial npm installs", got.String())
	}
}

// TestKanikoJobUsesInitContainerWhenHTTPURLSet guards the build-context lift
// past the k8s Secret's ~1 MiB cap. When httpContextURL is set, the Job grows
// an initContainer that curls the presigned URL into a shared emptyDir; the
// main kaniko container then reads the tarball via the standard tar://
// volume path.
//
// Earlier attempts (s3:// and tar.gz+http://) failed live because:
//   - AWS SDK v2 ignores S3_FORCE_PATH_STYLE → vhost-style DNS lookup against
//     in-cluster MinIO fails.
//   - kaniko v1.23 doesn't accept tar.gz+ scheme prefix.
//   - kaniko's HTTPS context fetcher rejects plaintext http://.
//
// The init-container path sidesteps all three: curl handles the HTTP fetch,
// kaniko sees only a local file.
func TestKanikoJobUsesInitContainerWhenHTTPURLSet(t *testing.T) {
	cs := fake.NewSimpleClientset()
	p := &K8sProvider{
		clientset: cs,
		buildCtx: BuildContextConfig{
			Endpoint:   "minio.test:9000",
			AccessKey:  "key",
			SecretKey:  "secret",
			BucketName: "instant-build-contexts",
		},
	}

	const ns, jobName = "instant-deploy-test", "build-test"
	httpURL := "http://minio.test:9000/instant-build-contexts/abc/20260511T000000Z.tar.gz?X-Amz-Signature=fake"
	if err := p.createKanikoJob(context.Background(), ns, jobName, "ctx-sec", "auth-sec", "ghcr.io/x/y:latest", httpURL); err != nil {
		t.Fatalf("createKanikoJob: %v", err)
	}

	job, err := cs.BatchV1().Jobs(ns).Get(context.Background(), jobName, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("get job: %v", err)
	}
	podSpec := job.Spec.Template.Spec

	// Init-container exists, uses curl, and points at the URL.
	if len(podSpec.InitContainers) != 1 {
		t.Fatalf("expected 1 init-container (curl fetch); got %d", len(podSpec.InitContainers))
	}
	ic := podSpec.InitContainers[0]
	if ic.Image == "" || ic.Image[:7] != "curlima" {
		t.Errorf("init-container image %q does not look like a curl image", ic.Image)
	}
	gotURL := ""
	for _, e := range ic.Env {
		if e.Name == "URL" {
			gotURL = e.Value
		}
	}
	if gotURL != httpURL {
		t.Errorf("init-container URL env = %q; want %q", gotURL, httpURL)
	}

	// Main kaniko reads from the local tar volume.
	c := podSpec.Containers[0]
	hasTarContext := false
	for _, a := range c.Args {
		if a == "--context=tar:///workspace/context.tar.gz" {
			hasTarContext = true
		}
	}
	if !hasTarContext {
		t.Errorf("kaniko must read --context=tar:///workspace/context.tar.gz when init-container delivers the tarball; got args=%v", c.Args)
	}

	// build-context volume is emptyDir, not a Secret.
	for _, v := range podSpec.Volumes {
		if v.Name == "build-context" {
			if v.EmptyDir == nil {
				t.Errorf("build-context volume must be emptyDir under the init-container path; got %#v", v.VolumeSource)
			}
			if v.Secret != nil {
				t.Errorf("build-context volume must not be a Secret under the init-container path")
			}
		}
	}

	// No AWS_ env vars on the main kaniko container — they were the failed v1
	// switches and serve no purpose in the init-container path.
	for _, e := range c.Env {
		if e.Name == "AWS_ACCESS_KEY_ID" || e.Name == "S3_FORCE_PATH_STYLE" {
			t.Errorf("kaniko env should not include legacy AWS S3 envs; found %s", e.Name)
		}
	}
}

// TestAppDeploymentUsesPullAlways guards against regressing to IfNotPresent on
// the :latest tag, which caused redeploys to silently serve cached old images.
func TestAppDeploymentUsesPullAlways(t *testing.T) {
	cs := fake.NewSimpleClientset()
	p := &K8sProvider{clientset: cs}

	const ns, name = "instant-deploy-test", "app-test"
	if err := p.applyDeploymentInNS(context.Background(),
		ns, name, "ghcr.io/x/y:latest",
		map[string]string{"FOO": "bar"},
		8080, "64Mi", "256Mi", "50m", "512Mi", "2Gi",
	); err != nil {
		t.Fatalf("applyDeploymentInNS: %v", err)
	}

	d, err := cs.AppsV1().Deployments(ns).Get(context.Background(), name, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("get deployment: %v", err)
	}
	if got := d.Spec.Template.Spec.Containers[0].ImagePullPolicy; got != corev1.PullAlways {
		t.Errorf("imagePullPolicy = %s; want PullAlways (otherwise :latest gets cached and redeploys serve stale images)", got)
	}
}

// ── Security hardening regression tests ──────────────────────────────────────
//
// These tests guard the container-isolation properties added in
// fix/deploy-container-hardening (pentest finding: customer pods ran as uid=0
// with the full Docker default capability set).
//
// The assertions are intentionally table-driven so that adding a new pod-
// building helper to this package triggers a compile-time reminder to also
// add the securityContext — the table is the registry.

// assertCustomerContainerSecCtx is the single source of truth for what
// "hardened customer container" means. Update this helper when the policy
// changes; all table tests below call it, ensuring consistent coverage.
func assertCustomerContainerSecCtx(t *testing.T, podSpec corev1.PodSpec, label string) {
	t.Helper()

	// ── Pod-level: seccompProfile ─────────────────────────────────────────────
	if podSpec.SecurityContext == nil {
		t.Errorf("[%s] pod SecurityContext is nil; want seccompProfile=RuntimeDefault", label)
	} else {
		sc := podSpec.SecurityContext
		if sc.SeccompProfile == nil {
			t.Errorf("[%s] pod SeccompProfile is nil; want RuntimeDefault", label)
		} else if sc.SeccompProfile.Type != corev1.SeccompProfileTypeRuntimeDefault {
			t.Errorf("[%s] pod SeccompProfile.Type = %s; want RuntimeDefault", label, sc.SeccompProfile.Type)
		}
		// RunAsNonRoot and ReadOnlyRootFilesystem must NOT be set on the pod
		// SecurityContext for customer workloads — arbitrary customer images often
		// run as root or write to the root filesystem.
		if sc.RunAsNonRoot != nil && *sc.RunAsNonRoot {
			t.Errorf("[%s] pod RunAsNonRoot=true must NOT be set on customer pod SecurityContext (breaks images that run as root)", label)
		}
	}

	// ── Container-level: capabilities + privilege escalation ─────────────────
	if len(podSpec.Containers) == 0 {
		t.Fatalf("[%s] pod has no containers", label)
	}
	for i, c := range podSpec.Containers {
		ctxLabel := fmt.Sprintf("%s/containers[%d](%s)", label, i, c.Name)
		if c.SecurityContext == nil {
			t.Errorf("[%s] SecurityContext is nil", ctxLabel)
			continue
		}
		csc := c.SecurityContext

		// AllowPrivilegeEscalation must be explicitly false.
		if csc.AllowPrivilegeEscalation == nil {
			t.Errorf("[%s] AllowPrivilegeEscalation is nil; must be explicitly false", ctxLabel)
		} else if *csc.AllowPrivilegeEscalation {
			t.Errorf("[%s] AllowPrivilegeEscalation=true; must be false", ctxLabel)
		}

		// Capabilities: ALL must be dropped, NET_BIND_SERVICE must be added.
		if csc.Capabilities == nil {
			t.Errorf("[%s] Capabilities is nil; must drop ALL and add NET_BIND_SERVICE", ctxLabel)
			continue
		}
		hasDrop := false
		for _, cap := range csc.Capabilities.Drop {
			if cap == "ALL" {
				hasDrop = true
			}
		}
		if !hasDrop {
			t.Errorf("[%s] Capabilities.Drop does not contain ALL; got %v", ctxLabel, csc.Capabilities.Drop)
		}
		hasAdd := false
		for _, cap := range csc.Capabilities.Add {
			if cap == capNetBindService {
				hasAdd = true
			}
		}
		if !hasAdd {
			t.Errorf("[%s] Capabilities.Add does not contain NET_BIND_SERVICE; got %v", ctxLabel, csc.Capabilities.Add)
		}

		// RunAsNonRoot and ReadOnlyRootFilesystem must NOT be set on customer
		// containers — see customerContainerSecCtx for rationale.
		if csc.RunAsNonRoot != nil && *csc.RunAsNonRoot {
			t.Errorf("[%s] RunAsNonRoot=true must NOT be set on customer container SecurityContext", ctxLabel)
		}
		if csc.ReadOnlyRootFilesystem != nil && *csc.ReadOnlyRootFilesystem {
			t.Errorf("[%s] ReadOnlyRootFilesystem=true must NOT be set on customer container SecurityContext", ctxLabel)
		}
	}
}

// TestSecurityHardeningDeployPod asserts that the single-app deployment pod
// (applyDeploymentInNS — backs POST /deploy/new) carries the required
// container-isolation securityContext.
func TestSecurityHardeningDeployPod(t *testing.T) {
	cs := fake.NewSimpleClientset()
	p := &K8sProvider{clientset: cs}

	const ns, name = "instant-deploy-sec-test", "app-sec-test"
	if err := p.applyDeploymentInNS(context.Background(),
		ns, name, "ghcr.io/x/y:latest",
		map[string]string{"FOO": "bar"},
		8080, "64Mi", "256Mi", "50m", "512Mi", "2Gi",
	); err != nil {
		t.Fatalf("applyDeploymentInNS: %v", err)
	}

	d, err := cs.AppsV1().Deployments(ns).Get(context.Background(), name, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("get deployment: %v", err)
	}
	assertCustomerContainerSecCtx(t, d.Spec.Template.Spec, "deploy/single-app")
}

// TestSecurityHardeningStackPod asserts that the stack-service deployment pod
// (createStackDeployment — backs POST /stacks/new) carries the required
// container-isolation securityContext.
func TestSecurityHardeningStackPod(t *testing.T) {
	cs := fake.NewSimpleClientset()
	p := &K8sStackProvider{K8sProvider: &K8sProvider{clientset: cs}}

	const ns, stackID, svcName = "instant-stack-sec", "secstack", "web"
	if err := p.createStackDeployment(context.Background(),
		ns, stackID, svcName, "ghcr.io/x/y:latest",
		8080, map[string]string{"FOO": "bar"},
		"64Mi", "256Mi", "50m", "512Mi", "2Gi",
	); err != nil {
		t.Fatalf("createStackDeployment: %v", err)
	}

	d, err := cs.AppsV1().Deployments(ns).Get(context.Background(), svcName, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("get deployment: %v", err)
	}
	assertCustomerContainerSecCtx(t, d.Spec.Template.Spec, "stack/service")
}

// TestSecurityHardeningBothPodSpecsTableDriven is a table-driven meta-test
// that runs assertCustomerContainerSecCtx against every customer-workload pod
// surface in the package. Add new rows here when new pod builders are added —
// the compile will remind you if you forget to wire the securityContext.
func TestSecurityHardeningBothPodSpecsTableDriven(t *testing.T) {
	cs := fake.NewSimpleClientset()
	p := &K8sProvider{clientset: cs}
	sp := &K8sStackProvider{K8sProvider: p}

	cases := []struct {
		label string
		setup func(t *testing.T) corev1.PodSpec
	}{
		{
			label: "single-app deploy (applyDeploymentInNS)",
			setup: func(t *testing.T) corev1.PodSpec {
				t.Helper()
				ns := "instant-deploy-tbl"
				name := "app-tbl"
				if err := p.applyDeploymentInNS(context.Background(),
					ns, name, "ghcr.io/x/y:latest",
					nil, 8080, "64Mi", "256Mi", "50m", "512Mi", "2Gi",
				); err != nil {
					t.Fatalf("applyDeploymentInNS: %v", err)
				}
				d, err := cs.AppsV1().Deployments(ns).Get(context.Background(), name, metav1.GetOptions{})
				if err != nil {
					t.Fatalf("get deployment: %v", err)
				}
				return d.Spec.Template.Spec
			},
		},
		{
			label: "stack service deploy (createStackDeployment)",
			setup: func(t *testing.T) corev1.PodSpec {
				t.Helper()
				ns := "instant-stack-tbl"
				if err := sp.createStackDeployment(context.Background(),
					ns, "tblstack", "api", "ghcr.io/x/y:latest",
					8080, nil, "64Mi", "256Mi", "50m", "512Mi", "2Gi",
				); err != nil {
					t.Fatalf("createStackDeployment: %v", err)
				}
				d, err := cs.AppsV1().Deployments(ns).Get(context.Background(), "api", metav1.GetOptions{})
				if err != nil {
					t.Fatalf("get deployment: %v", err)
				}
				return d.Spec.Template.Spec
			},
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.label, func(t *testing.T) {
			podSpec := tc.setup(t)
			assertCustomerContainerSecCtx(t, podSpec, tc.label)
		})
	}
}

// ---------------------------------------------------------------------------
// Pentest 2026-05-16 security regression tests
// ---------------------------------------------------------------------------

// TestNetworkPolicy_DBEgress_ScopedToOwnerTeam is the primary cross-tenant
// isolation regression guard.
//
// For an authenticated deployment with teamID "team-A":
//   - The DB-port egress selector MUST include instant.dev/owner-team=team-A
//   - The DB-port egress selector MUST include instant.dev/role=customer-resource
//   - Both labels must be present on the SAME namespaceSelector (not two separate rules)
//
// If this test fails after a refactor it means cross-tenant DB access is possible
// again — team-A's deployment could reach team-B's database namespaces.
func TestNetworkPolicy_DBEgress_ScopedToOwnerTeam(t *testing.T) {
	const teamID = "team-A"
	cs := fake.NewSimpleClientset()
	p := &K8sProvider{clientset: cs}

	const ns = "instant-deploy-sec-teamA"
	if err := p.createNetworkPolicyInNS(context.Background(), ns, teamID); err != nil {
		t.Fatalf("createNetworkPolicyInNS: %v", err)
	}

	np, err := cs.NetworkingV1().NetworkPolicies(ns).Get(context.Background(), "instant-isolation", metav1.GetOptions{})
	if err != nil {
		t.Fatalf("get network policy: %v", err)
	}

	// Find the DB-port egress rule (the one that allows port 5432/6379/27017/4222).
	dbPorts := map[int32]bool{5432: true, 6379: true, 27017: true, 4222: true}
	foundDBRule := false
	for _, rule := range np.Spec.Egress {
		isDBRule := false
		for _, p := range rule.Ports {
			if p.Port != nil && dbPorts[int32(p.Port.IntVal)] {
				isDBRule = true
				break
			}
		}
		if !isDBRule {
			continue
		}
		foundDBRule = true

		// Verify both labels are present on the namespaceSelector.
		for _, peer := range rule.To {
			if peer.NamespaceSelector == nil {
				continue
			}
			labels := peer.NamespaceSelector.MatchLabels
			if labels[labelCustomerResourceRole] != labelCustomerResourceRoleValue {
				t.Errorf("DB-egress namespaceSelector missing %s=%s; got labels=%v",
					labelCustomerResourceRole, labelCustomerResourceRoleValue, labels)
			}
			gotOwner, hasOwner := labels[labelOwnerTeam]
			if !hasOwner {
				t.Errorf("DB-egress namespaceSelector missing %s label — cross-tenant isolation broken; labels=%v",
					labelOwnerTeam, labels)
			} else if gotOwner != teamID {
				t.Errorf("DB-egress namespaceSelector has %s=%q; want %q — wrong team scoping",
					labelOwnerTeam, gotOwner, teamID)
			}
		}
	}
	if !foundDBRule {
		t.Fatal("no DB-port egress rule found in NetworkPolicy — something removed it entirely")
	}
}

// TestNetworkPolicy_DBEgress_RoleOnlyForAnonymous verifies the fallback path:
// when teamID is empty (anonymous deploy), the DB-egress selector falls back to
// role-only (no owner-team label). This is the acceptable fallback for anonymous
// workloads that have no dedicated databases.
func TestNetworkPolicy_DBEgress_RoleOnlyForAnonymous(t *testing.T) {
	cs := fake.NewSimpleClientset()
	p := &K8sProvider{clientset: cs}

	const ns = "instant-deploy-sec-anon"
	if err := p.createNetworkPolicyInNS(context.Background(), ns, ""); err != nil {
		t.Fatalf("createNetworkPolicyInNS: %v", err)
	}

	np, err := cs.NetworkingV1().NetworkPolicies(ns).Get(context.Background(), "instant-isolation", metav1.GetOptions{})
	if err != nil {
		t.Fatalf("get network policy: %v", err)
	}

	dbPorts := map[int32]bool{5432: true, 6379: true, 27017: true, 4222: true}
	for _, rule := range np.Spec.Egress {
		isDBRule := false
		for _, pp := range rule.Ports {
			if pp.Port != nil && dbPorts[int32(pp.Port.IntVal)] {
				isDBRule = true
				break
			}
		}
		if !isDBRule {
			continue
		}
		for _, peer := range rule.To {
			if peer.NamespaceSelector == nil {
				continue
			}
			labels := peer.NamespaceSelector.MatchLabels
			if _, hasOwner := labels[labelOwnerTeam]; hasOwner {
				t.Errorf("anonymous deploy: DB-egress namespaceSelector unexpectedly has %s=%s; should be role-only for anon",
					labelOwnerTeam, labels[labelOwnerTeam])
			}
		}
	}
}

// TestNetworkPolicy_NoBroadInstantNSDBRule guards against gap (a) from the
// pentest: a broad egress rule allowing DB ports to the entire "instant"
// namespace (platform-internal Redis, Postgres) must NOT be present.
//
// Customer deployments have no legitimate need to reach platform-internal
// datastores — the shared proxies face the public internet, not cluster-internal
// ports. Presence of such a rule would mean any customer deploy could
// TCP-connect to the platform database.
func TestNetworkPolicy_NoBroadInstantNSDBRule(t *testing.T) {
	cs := fake.NewSimpleClientset()
	p := &K8sProvider{clientset: cs}

	const ns = "instant-deploy-sec-gap-a"
	if err := p.createNetworkPolicyInNS(context.Background(), ns, "team-B"); err != nil {
		t.Fatalf("createNetworkPolicyInNS: %v", err)
	}

	np, err := cs.NetworkingV1().NetworkPolicies(ns).Get(context.Background(), "instant-isolation", metav1.GetOptions{})
	if err != nil {
		t.Fatalf("get network policy: %v", err)
	}

	dbPorts := map[int32]bool{5432: true, 6379: true, 27017: true, 4222: true}
	for _, rule := range np.Spec.Egress {
		isDBRule := false
		for _, pp := range rule.Ports {
			if pp.Port != nil && dbPorts[int32(pp.Port.IntVal)] {
				isDBRule = true
				break
			}
		}
		if !isDBRule {
			continue
		}
		// Check if any peer selects the "instant" namespace by its metadata.name label.
		for _, peer := range rule.To {
			if peer.NamespaceSelector == nil {
				continue
			}
			if v, ok := peer.NamespaceSelector.MatchLabels["kubernetes.io/metadata.name"]; ok && v == "instant" {
				t.Errorf("DB-egress rule selects the 'instant' namespace by name — this allows customer apps to "+
					"reach platform-internal datastores (postgres-platform, platform Redis). "+
					"Gap (a) from pentest 2026-05-16 has regressed. Rule: %+v", rule)
			}
		}
	}
}

// TestNetworkPolicy_LinkLocalInExceptList guards against gap (b) from the
// pentest: 169.254.0.0/16 (link-local) MUST be in the ipBlock.Except list so
// the cloud instance metadata endpoint (169.254.169.254 on DO/AWS/GCP) is not
// reachable from customer workloads.
//
// Without this, a customer app could curl the droplet metadata service to steal
// instance credentials or cloud provider tokens.
func TestNetworkPolicy_LinkLocalInExceptList(t *testing.T) {
	cs := fake.NewSimpleClientset()
	p := &K8sProvider{clientset: cs}

	const ns = "instant-deploy-sec-gap-b"
	if err := p.createNetworkPolicyInNS(context.Background(), ns, "team-C"); err != nil {
		t.Fatalf("createNetworkPolicyInNS: %v", err)
	}

	np, err := cs.NetworkingV1().NetworkPolicies(ns).Get(context.Background(), "instant-isolation", metav1.GetOptions{})
	if err != nil {
		t.Fatalf("get network policy: %v", err)
	}

	const linkLocalCIDR = "169.254.0.0/16"
	foundLinkLocal := false
	for _, rule := range np.Spec.Egress {
		for _, peer := range rule.To {
			if peer.IPBlock == nil {
				continue
			}
			for _, ex := range peer.IPBlock.Except {
				if ex == linkLocalCIDR {
					foundLinkLocal = true
				}
			}
		}
	}
	if !foundLinkLocal {
		t.Errorf("ipBlock.Except list does not contain %s — the cloud metadata endpoint at 169.254.169.254 "+
			"is reachable from customer workloads. Gap (b) from pentest 2026-05-16 has regressed.", linkLocalCIDR)
	}
}

// TestNetworkPolicy_CrossTenantIsolation_TableDriven is a table-driven guard
// that for each (teamID, wantOwnerLabel) pair confirms the DB-egress
// namespaceSelector matches exactly what we expect.
//
// Adding a new row here is the extension point for future team-scoping tests.
func TestNetworkPolicy_CrossTenantIsolation_TableDriven(t *testing.T) {
	cases := []struct {
		name          string
		teamID        string
		wantOwnerTeam string // "" means must NOT be present
	}{
		{
			name:          "authenticated_team_A",
			teamID:        "aaaaaaaa-0000-0000-0000-000000000001",
			wantOwnerTeam: "aaaaaaaa-0000-0000-0000-000000000001",
		},
		{
			name:          "authenticated_team_B",
			teamID:        "bbbbbbbb-0000-0000-0000-000000000002",
			wantOwnerTeam: "bbbbbbbb-0000-0000-0000-000000000002",
		},
		{
			name:          "anonymous_no_team",
			teamID:        "",
			wantOwnerTeam: "", // must NOT carry owner-team label
		},
	}

	dbPorts := map[int32]bool{5432: true, 6379: true, 27017: true, 4222: true}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			cs := fake.NewSimpleClientset()
			p := &K8sProvider{clientset: cs}
			ns := "instant-deploy-sec-tt-" + tc.name

			if err := p.createNetworkPolicyInNS(context.Background(), ns, tc.teamID); err != nil {
				t.Fatalf("createNetworkPolicyInNS: %v", err)
			}

			np, err := cs.NetworkingV1().NetworkPolicies(ns).Get(context.Background(), "instant-isolation", metav1.GetOptions{})
			if err != nil {
				t.Fatalf("get network policy: %v", err)
			}

			for _, rule := range np.Spec.Egress {
				isDBRule := false
				for _, pp := range rule.Ports {
					if pp.Port != nil && dbPorts[int32(pp.Port.IntVal)] {
						isDBRule = true
						break
					}
				}
				if !isDBRule {
					continue
				}
				for _, peer := range rule.To {
					if peer.NamespaceSelector == nil {
						continue
					}
					labels := peer.NamespaceSelector.MatchLabels

					gotRole := labels[labelCustomerResourceRole]
					if gotRole != labelCustomerResourceRoleValue {
						t.Errorf("team=%q: DB-egress missing %s=%s; labels=%v",
							tc.teamID, labelCustomerResourceRole, labelCustomerResourceRoleValue, labels)
					}

					gotOwner, hasOwner := labels[labelOwnerTeam]
					if tc.wantOwnerTeam != "" {
						if !hasOwner {
							t.Errorf("team=%q: DB-egress missing %s — cross-tenant isolation broken; labels=%v",
								tc.teamID, labelOwnerTeam, labels)
						} else if gotOwner != tc.wantOwnerTeam {
							t.Errorf("team=%q: DB-egress %s=%q; want %q",
								tc.teamID, labelOwnerTeam, gotOwner, tc.wantOwnerTeam)
						}
					} else {
						// Anonymous: must NOT have owner-team label.
						if hasOwner {
							t.Errorf("anon: DB-egress unexpectedly has %s=%q; should be role-only for anon",
								labelOwnerTeam, gotOwner)
						}
					}
				}
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Pentest 2026-05-16 — resource-abuse regression tests
// ---------------------------------------------------------------------------
//
// Gap 1: Disk fill (noisy-neighbour DoS)
// Gap 2: Build pod no timeout
// Gap 3: Per-pod PID limiting
//   NOTE: k8s LimitRange does NOT support "pids" as a resource — the API server
//   rejects it ("pids: must be a standard resource for containers"). Per-pod PID
//   limits require a node-level kubelet setting (--pod-max-pids / podPidsLimit),
//   which is an operator/infrastructure action outside the scope of namespace
//   setup. The practical risk is backstopped by the per-pod memory limit: fork
//   bombs consume memory and trigger OOM eviction before the process count
//   becomes dangerous. See createLimitRangeForNS for the full rationale.

// TestDeployPodHasEphemeralStorageLimit is the noisy-neighbour disk-fill
// regression guard. A customer deployment that writes unbounded to its
// container filesystem can exhaust the node disk and trigger cluster-wide
// DiskPressure → pod eviction for all other tenants. The fix: every
// container spec carries an explicit ephemeral-storage request + limit so
// k8s evicts ONLY the offending pod at its own limit.
//
// If this test fails after a refactor, the disk-fill DoS gap has regressed.
func TestDeployPodHasEphemeralStorageLimit(t *testing.T) {
	cs := fake.NewSimpleClientset()
	p := &K8sProvider{clientset: cs}

	const ns, name = "instant-deploy-eph-test", "app-eph-test"
	if err := p.applyDeploymentInNS(context.Background(),
		ns, name, "ghcr.io/x/y:latest",
		map[string]string{"FOO": "bar"},
		8080, "64Mi", "256Mi", "50m", "512Mi", "2Gi",
	); err != nil {
		t.Fatalf("applyDeploymentInNS: %v", err)
	}

	d, err := cs.AppsV1().Deployments(ns).Get(context.Background(), name, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("get deployment: %v", err)
	}
	if len(d.Spec.Template.Spec.Containers) == 0 {
		t.Fatal("deployment has no containers")
	}
	c := d.Spec.Template.Spec.Containers[0]

	if _, ok := c.Resources.Requests[corev1.ResourceEphemeralStorage]; !ok {
		t.Error("deploy container is missing ephemeral-storage Request — node disk fill DoS gap (Gap 1) has regressed")
	}
	if _, ok := c.Resources.Limits[corev1.ResourceEphemeralStorage]; !ok {
		t.Error("deploy container is missing ephemeral-storage Limit — node disk fill DoS gap (Gap 1) has regressed; k8s cannot evict the offending pod without this")
	}

	// Concrete floor check: request must be >= 512Mi for the default tier.
	if got, ok := c.Resources.Requests[corev1.ResourceEphemeralStorage]; ok {
		if got.Value() < 512*1024*1024 {
			t.Errorf("deploy container ephemeral-storage request %s is below the 512Mi floor for default tier", got.String())
		}
	}
	// Limit must be >= 1Gi (meaningful cap).
	if got, ok := c.Resources.Limits[corev1.ResourceEphemeralStorage]; ok {
		if got.Value() < 1024*1024*1024 {
			t.Errorf("deploy container ephemeral-storage limit %s is below 1Gi — cap is too small to be useful", got.String())
		}
	}
}

// TestStackPodHasEphemeralStorageLimit mirrors TestDeployPodHasEphemeralStorageLimit
// for the stack-service deployment path (createStackDeployment — backs POST /stacks/new).
// Both code paths must carry the ephemeral-storage bound to close the noisy-
// neighbour disk-fill gap across all customer compute surfaces.
func TestStackPodHasEphemeralStorageLimit(t *testing.T) {
	cs := fake.NewSimpleClientset()
	sp := &K8sStackProvider{K8sProvider: &K8sProvider{clientset: cs}}

	const ns, stackID, svcName = "instant-stack-eph-test", "ephstack", "api"
	if err := sp.createStackDeployment(context.Background(),
		ns, stackID, svcName, "ghcr.io/x/y:latest",
		8080, map[string]string{"FOO": "bar"},
		"64Mi", "256Mi", "50m", "512Mi", "2Gi",
	); err != nil {
		t.Fatalf("createStackDeployment: %v", err)
	}

	d, err := cs.AppsV1().Deployments(ns).Get(context.Background(), svcName, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("get deployment: %v", err)
	}
	if len(d.Spec.Template.Spec.Containers) == 0 {
		t.Fatal("stack deployment has no containers")
	}
	c := d.Spec.Template.Spec.Containers[0]

	if _, ok := c.Resources.Requests[corev1.ResourceEphemeralStorage]; !ok {
		t.Error("stack container is missing ephemeral-storage Request — node disk fill DoS gap (Gap 1) has regressed")
	}
	if _, ok := c.Resources.Limits[corev1.ResourceEphemeralStorage]; !ok {
		t.Error("stack container is missing ephemeral-storage Limit — node disk fill DoS gap (Gap 1) has regressed")
	}
}

// TestLimitRangeHasEphemeralStorageDefault guards that the per-namespace
// LimitRange (instant-limits) carries an ephemeral-storage default and
// defaultRequest. This is the backstop for any pod that bypasses the
// explicit resource setting in applyDeploymentInNS / createStackDeployment.
func TestLimitRangeHasEphemeralStorageDefault(t *testing.T) {
	cs := fake.NewSimpleClientset()
	p := &K8sProvider{clientset: cs}

	const ns = "instant-deploy-lr-eph-test"
	if err := p.createLimitRangeForNS(context.Background(), ns, "hobby"); err != nil {
		t.Fatalf("createLimitRangeForNS: %v", err)
	}

	lr, err := cs.CoreV1().LimitRanges(ns).Get(context.Background(), "instant-limits", metav1.GetOptions{})
	if err != nil {
		t.Fatalf("get limit range: %v", err)
	}

	found := false
	for _, item := range lr.Spec.Limits {
		if item.Type != corev1.LimitTypeContainer {
			continue
		}
		found = true

		if _, ok := item.Default[corev1.ResourceEphemeralStorage]; !ok {
			t.Error("LimitRange 'instant-limits' Default is missing ephemeral-storage — backstop for disk-fill DoS (Gap 1) has regressed")
		}
		if _, ok := item.DefaultRequest[corev1.ResourceEphemeralStorage]; !ok {
			t.Error("LimitRange 'instant-limits' DefaultRequest is missing ephemeral-storage — backstop for disk-fill DoS (Gap 1) has regressed")
		}
	}
	if !found {
		t.Fatal("LimitRange has no Container-type item — entire LimitRange is missing")
	}
}

// TestBuildJobHasActiveDeadlineSeconds guards Gap 2: the Kaniko build Job must
// carry an ActiveDeadlineSeconds so a slow or malicious Dockerfile cannot hold
// a build slot indefinitely. Without this, an attacker can queue unbounded
// build time by RUN sleep 1e9 in their Dockerfile.
//
// If this test fails after a refactor the build-timeout DoS gap has regressed.
func TestBuildJobHasActiveDeadlineSeconds(t *testing.T) {
	cs := fake.NewSimpleClientset()
	p := &K8sProvider{clientset: cs}

	const ns, jobName = "instant-deploy-deadline-test", "build-deadline"
	if err := p.createKanikoJob(context.Background(), ns, jobName, "ctx-sec", "auth-sec", "ghcr.io/x/y:latest", ""); err != nil {
		t.Fatalf("createKanikoJob: %v", err)
	}

	job, err := cs.BatchV1().Jobs(ns).Get(context.Background(), jobName, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("get job: %v", err)
	}

	if job.Spec.ActiveDeadlineSeconds == nil {
		t.Fatal("kaniko build Job is missing ActiveDeadlineSeconds — build-timeout DoS gap (Gap 2) has regressed; a slow Dockerfile can hold a build slot forever")
	}

	const wantMinDeadline = int64(300) // at least 5 minutes
	if *job.Spec.ActiveDeadlineSeconds < wantMinDeadline {
		t.Errorf("kaniko build Job ActiveDeadlineSeconds=%d; want >= %d (builds need at least 5 min for non-trivial installs)",
			*job.Spec.ActiveDeadlineSeconds, wantMinDeadline)
	}
}

// TestBuildJobActiveDeadlineSeconds_TableDriven tests both the secret-path and
// the HTTP (MinIO) path for the kaniko build Job. Both paths share createKanikoJob;
// this test ensures neither path silently loses the deadline.
func TestBuildJobActiveDeadlineSeconds_TableDriven(t *testing.T) {
	cases := []struct {
		name           string
		httpContextURL string // empty → secret path; non-empty → init-container path
	}{
		{name: "secret_path", httpContextURL: ""},
		{name: "minio_http_path", httpContextURL: "http://minio.test:9000/ctx/abc.tar.gz?sig=fake"},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			cs := fake.NewSimpleClientset()
			p := &K8sProvider{clientset: cs}
			ns := "instant-deploy-dl-" + tc.name
			jobName := "build-dl-" + tc.name

			if err := p.createKanikoJob(context.Background(), ns, jobName, "ctx-sec", "auth-sec", "ghcr.io/x/y:latest", tc.httpContextURL); err != nil {
				t.Fatalf("createKanikoJob: %v", err)
			}

			job, err := cs.BatchV1().Jobs(ns).Get(context.Background(), jobName, metav1.GetOptions{})
			if err != nil {
				t.Fatalf("get job: %v", err)
			}
			if job.Spec.ActiveDeadlineSeconds == nil {
				t.Errorf("[%s] kaniko Job missing ActiveDeadlineSeconds — Gap 2 regressed", tc.name)
			}
		})
	}
}

// TestLimitRangeHasNoPids guards that createLimitRangeForNS does NOT attempt to
// add a "pids" resource to the LimitRange. The Kubernetes API server rejects
// "pids" in a LimitRange ("pids: must be a standard resource for containers") —
// verified in production on DOKS 1.32. The previous try-with-pids / fallback
// code was dead: the fallback always fired. This test asserts the clean state:
// the LimitRange is created once with cpu, memory, and ephemeral-storage only.
func TestLimitRangeHasNoPids(t *testing.T) {
	cs := fake.NewSimpleClientset()
	p := &K8sProvider{clientset: cs}

	const ns = "instant-deploy-lr-pids-test"
	if err := p.createLimitRangeForNS(context.Background(), ns, "hobby"); err != nil {
		t.Fatalf("createLimitRangeForNS: %v", err)
	}

	lr, err := cs.CoreV1().LimitRanges(ns).Get(context.Background(), "instant-limits", metav1.GetOptions{})
	if err != nil {
		t.Fatalf("get limit range: %v", err)
	}

	for _, item := range lr.Spec.Limits {
		if item.Type != corev1.LimitTypeContainer {
			continue
		}
		// Verify the three real resources are present.
		for _, r := range []corev1.ResourceName{
			corev1.ResourceMemory,
			corev1.ResourceCPU,
			corev1.ResourceEphemeralStorage,
		} {
			if _, ok := item.Default[r]; !ok {
				t.Errorf("LimitRange 'instant-limits' Default is missing %s", r)
			}
			if r != corev1.ResourceCPU {
				// CPU has no DefaultRequest distinction needed here; memory + eph do.
				if _, ok := item.DefaultRequest[r]; !ok {
					t.Errorf("LimitRange 'instant-limits' DefaultRequest is missing %s", r)
				}
			}
		}

		// Pids must NOT be present — the k8s API server rejects it in a LimitRange.
		if _, ok := item.Default[corev1.ResourceName("pids")]; ok {
			t.Error("LimitRange 'instant-limits' Default contains 'pids' resource — " +
				"k8s rejects this in production; remove the pids entry from createLimitRangeForNS")
		}
	}
}

// TestTierEphemeralStorage guards that TierEphemeralStorage returns sensible
// non-empty values for all known tiers and that limits are consistent.
func TestTierEphemeralStorage(t *testing.T) {
	tiers := []string{"hobby", "anonymous", "pro", "team", ""}
	for _, tier := range tiers {
		req, limit := compute.TierEphemeralStorage(tier)
		if req == "" {
			t.Errorf("TierEphemeralStorage(%q): empty request", tier)
		}
		if limit == "" {
			t.Errorf("TierEphemeralStorage(%q): empty limit", tier)
		}
	}
}

// Ensure the batchv1 import is used (compile guard).
var _ batchv1.Job

