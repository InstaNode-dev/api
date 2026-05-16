package k8s

import (
	"context"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

// ---------------------------------------------------------------------------
// Security regression tests — pentest 2026-05-16
//
// These tests guard three specific gaps closed by fix/deploy-scoped-netpol:
//
//   Gap main: DB-port egress was role-only (any deployment could reach any
//             other team's databases).
//   Gap (a):  Broad egress to the "instant" namespace on DB ports was present
//             (customer apps could reach platform-internal datastores).
//   Gap (b):  169.254.0.0/16 (link-local / cloud metadata) was not in the
//             ipBlock Except list.
//
// IMPORTANT: If any test below regresses (starts failing), it means a code
// change removed or weakened the cross-tenant isolation fix. Do NOT remove
// or soften these tests without a documented security review.
// ---------------------------------------------------------------------------

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
		8080, "64Mi", "256Mi", "50m",
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
