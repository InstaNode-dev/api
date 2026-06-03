package k8s

// deploy_git_test.go — P3 source=git: Deploy builds a repo via kaniko's git
// context (no tarball upload), with optional private-repo token. All against
// the fake clientset; the build Job is auto-completed by attachJobCompleteReactor.

import (
	"context"
	"errors"
	"strings"
	"testing"

	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8sruntime "k8s.io/apimachinery/pkg/runtime"
	clientfake "k8s.io/client-go/kubernetes/fake"
	clienttesting "k8s.io/client-go/testing"

	"instant.dev/internal/providers/compute"
)

func gitDeployOpts(appID, gitAuth string) compute.DeployOptions {
	return compute.DeployOptions{
		AppID:   appID,
		Source:  "git",
		GitURL:  "https://github.com/owner/repo",
		GitRef:  "main",
		GitAuth: gitAuth,
		Port:    8080,
		Tier:    "hobby",
		TeamID:  "11111111-1111-1111-1111-111111111111",
	}
}

// ── pure helpers ─────────────────────────────────────────────────────────────

func TestGitCloneContext(t *testing.T) {
	cases := map[string]struct{ url, ref, want string }{
		"with ref":  {"https://github.com/o/r", "main", "git://github.com/o/r#main"},
		"dot-git":   {"https://github.com/o/r.git", "", "git://github.com/o/r.git"},
		"http":      {"http://h:8080/g/p", "v1", "git://h:8080/g/p#v1"},
		"no scheme": {"github.com/o/r", "", "git://github.com/o/r"},
	}
	for name, c := range cases {
		if got := gitCloneContext(c.url, c.ref); got != c.want {
			t.Errorf("%s: gitCloneContext(%q,%q)=%q want %q", name, c.url, c.ref, got, c.want)
		}
	}
}

func TestKanikoContextArg(t *testing.T) {
	if got := kanikoContextArg(true, "git://h/p#r"); got != "--context=git://h/p#r" {
		t.Errorf("git context arg: %q", got)
	}
	if got := kanikoContextArg(false, ""); got != "--context=tar:///workspace/context.tar.gz" {
		t.Errorf("tar context arg: %q", got)
	}
}

func TestKanikoGitEnv(t *testing.T) {
	if kanikoGitEnv(false, "s") != nil {
		t.Error("non-git build must have no GIT env")
	}
	if kanikoGitEnv(true, "") != nil {
		t.Error("public git build (no secret) must have no GIT env")
	}
	env := kanikoGitEnv(true, "git-auth-x")
	if len(env) != 2 || env[0].Name != "GIT_USERNAME" || env[1].Name != "GIT_PASSWORD" {
		t.Fatalf("private git env shape: %+v", env)
	}
	if env[1].ValueFrom == nil || env[1].ValueFrom.SecretKeyRef.Name != "git-auth-x" {
		t.Errorf("GIT_PASSWORD must come from the git-auth secret: %+v", env[1])
	}
}

// ── Deploy(git) happy paths ──────────────────────────────────────────────────

// TestDeploy_GitSource_PublicRepo builds + deploys a public repo: a kaniko Job
// is created with a git:// context and NO build-context volume, no git-auth
// secret, and the runtime Deployment runs the built image.
func TestDeploy_GitSource_PublicRepo(t *testing.T) {
	cs := clientfake.NewSimpleClientset(platformGHCRPull())
	attachJobCompleteReactor(cs)
	p := &K8sProvider{clientset: cs}

	if _, err := p.Deploy(context.Background(), gitDeployOpts("gitpub", "")); err != nil {
		t.Fatalf("Deploy(git, public): %v", err)
	}
	ns := deployNamespace("gitpub")
	jobs, _ := cs.BatchV1().Jobs(ns).List(context.Background(), metav1.ListOptions{})
	if len(jobs.Items) != 1 {
		t.Fatalf("expected 1 build Job, got %d", len(jobs.Items))
	}
	kaniko := jobs.Items[0].Spec.Template.Spec.Containers[0]
	var gotCtx string
	for _, a := range kaniko.Args {
		if strings.HasPrefix(a, "--context=") {
			gotCtx = a
		}
	}
	if gotCtx != "--context=git://github.com/owner/repo#main" {
		t.Errorf("kaniko git context = %q", gotCtx)
	}
	// public repo → no GIT_* env, no build-context volume
	for _, e := range kaniko.Env {
		if e.Name == "GIT_PASSWORD" {
			t.Error("public repo must not set GIT_PASSWORD")
		}
	}
	for _, v := range jobs.Items[0].Spec.Template.Spec.Volumes {
		if v.Name == "build-context" {
			t.Error("git build must NOT mount a build-context volume")
		}
	}
}

// TestDeploy_GitSource_PrivateRepo wires the encrypted token into a git-auth
// Secret consumed via GIT_PASSWORD on the kaniko Job.
func TestDeploy_GitSource_PrivateRepo(t *testing.T) {
	cs := clientfake.NewSimpleClientset(platformGHCRPull())
	attachJobCompleteReactor(cs)
	p := &K8sProvider{clientset: cs}

	if _, err := p.Deploy(context.Background(), gitDeployOpts("gitpriv", "ghp_secrettoken")); err != nil {
		t.Fatalf("Deploy(git, private): %v", err)
	}
	ns := deployNamespace("gitpriv")
	jobs, _ := cs.BatchV1().Jobs(ns).List(context.Background(), metav1.ListOptions{})
	if len(jobs.Items) != 1 {
		t.Fatalf("expected 1 build Job, got %d", len(jobs.Items))
	}
	kaniko := jobs.Items[0].Spec.Template.Spec.Containers[0]
	var hasGitPass bool
	for _, e := range kaniko.Env {
		if e.Name == "GIT_PASSWORD" && e.ValueFrom != nil &&
			e.ValueFrom.SecretKeyRef.Name == "git-auth-"+sanitizeName("gitpriv") {
			hasGitPass = true
		}
	}
	if !hasGitPass {
		t.Errorf("private repo build must set GIT_PASSWORD from the git-auth secret; env=%+v", kaniko.Env)
	}
}

// existing git-auth secret → Update arm.
func TestDeploy_GitSource_PrivateRepo_SecretAlreadyExists(t *testing.T) {
	ns := deployNamespace("gitupd")
	pre := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "git-auth-" + sanitizeName("gitupd"), Namespace: ns},
		Data: map[string][]byte{"token": []byte("old")}}
	cs := clientfake.NewSimpleClientset(platformGHCRPull(), pre)
	attachJobCompleteReactor(cs)
	p := &K8sProvider{clientset: cs}
	if _, err := p.Deploy(context.Background(), gitDeployOpts("gitupd", "ghp_new")); err != nil {
		t.Fatalf("Deploy(git, existing secret): %v", err)
	}
}

// ── Deploy(git) error arms ───────────────────────────────────────────────────

func TestDeploy_GitSource_NamespaceError(t *testing.T) {
	cs := clientfake.NewSimpleClientset(platformGHCRPull())
	cs.PrependReactor("create", "namespaces", func(_ clienttesting.Action) (bool, k8sruntime.Object, error) {
		return true, nil, errors.New("boom-ns")
	})
	p := &K8sProvider{clientset: cs}
	if _, err := p.Deploy(context.Background(), gitDeployOpts("gitnserr", "")); err == nil ||
		!strings.Contains(err.Error(), "ensure namespace") {
		t.Fatalf("want ensure-namespace error, got: %v", err)
	}
}

func TestDeploy_GitSource_RegistryAuthError(t *testing.T) {
	// No platform ghcr-pull seeded in the instant ns → ensureRegistryAuthInNS fails.
	cs := clientfake.NewSimpleClientset()
	p := &K8sProvider{clientset: cs}
	if _, err := p.Deploy(context.Background(), gitDeployOpts("gitraerr", "")); err == nil ||
		!strings.Contains(err.Error(), "registry auth") {
		t.Fatalf("want registry-auth error, got: %v", err)
	}
}

func TestDeploy_GitSource_GitAuthSecretError(t *testing.T) {
	cs := clientfake.NewSimpleClientset(platformGHCRPull())
	cs.PrependReactor("create", "secrets", func(action clienttesting.Action) (bool, k8sruntime.Object, error) {
		sec := action.(clienttesting.CreateAction).GetObject().(*corev1.Secret)
		if strings.HasPrefix(sec.Name, "git-auth-") {
			return true, nil, errors.New("boom-gitsecret")
		}
		return false, nil, nil
	})
	p := &K8sProvider{clientset: cs}
	if _, err := p.Deploy(context.Background(), gitDeployOpts("gitsecerr", "ghp_x")); err == nil ||
		!strings.Contains(err.Error(), "git auth secret") {
		t.Fatalf("want git-auth-secret error, got: %v", err)
	}
}

// namespace pre-exists → upgradeNamespaceLabels arm.
func TestDeploy_GitSource_NamespaceAlreadyExists(t *testing.T) {
	ns := deployNamespace("gitnsx")
	preNS := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: ns}}
	cs := clientfake.NewSimpleClientset(platformGHCRPull(), preNS)
	attachJobCompleteReactor(cs)
	p := &K8sProvider{clientset: cs}
	if _, err := p.Deploy(context.Background(), gitDeployOpts("gitnsx", "")); err != nil {
		t.Fatalf("Deploy(git, pre-existing ns): %v", err)
	}
}

// namespace pre-exists AND the label-upgrade Get fails → upgrade-labels error arm.
func TestDeploy_GitSource_UpgradeNamespaceLabelsError(t *testing.T) {
	ns := deployNamespace("gitulerr")
	cs := clientfake.NewSimpleClientset(platformGHCRPull(),
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: ns}})
	cs.PrependReactor("get", "namespaces", func(_ clienttesting.Action) (bool, k8sruntime.Object, error) {
		return true, nil, errors.New("get blew up")
	})
	p := &K8sProvider{clientset: cs}
	if _, err := p.Deploy(context.Background(), gitDeployOpts("gitulerr", "")); err == nil ||
		!strings.Contains(err.Error(), "upgrade namespace labels") {
		t.Fatalf("want upgrade-namespace-labels error, got: %v", err)
	}
}

// git-auth secret exists AND Update fails → git-auth-secret-update error arm.
func TestDeploy_GitSource_GitAuthSecretUpdateError(t *testing.T) {
	ns := deployNamespace("gitupderr")
	pre := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "git-auth-" + sanitizeName("gitupderr"), Namespace: ns},
		Data: map[string][]byte{"token": []byte("old")}}
	cs := clientfake.NewSimpleClientset(platformGHCRPull(), pre)
	cs.PrependReactor("update", "secrets", func(_ clienttesting.Action) (bool, k8sruntime.Object, error) {
		return true, nil, errors.New("boom-update")
	})
	p := &K8sProvider{clientset: cs}
	if _, err := p.Deploy(context.Background(), gitDeployOpts("gitupderr", "ghp_x")); err == nil ||
		!strings.Contains(err.Error(), "git auth secret update") {
		t.Fatalf("want git-auth-secret-update error, got: %v", err)
	}
}

// private repo + the deferred git-auth Secret cleanup Delete fails (non-NotFound)
// → the warn-log arm in the defer runs (build still succeeds).
func TestDeploy_GitSource_GitAuthSecretCleanupDeleteError(t *testing.T) {
	cs := clientfake.NewSimpleClientset(platformGHCRPull())
	attachJobCompleteReactor(cs)
	cs.PrependReactor("delete", "secrets", func(_ clienttesting.Action) (bool, k8sruntime.Object, error) {
		return true, nil, errors.New("boom-delete")
	})
	p := &K8sProvider{clientset: cs}
	if _, err := p.Deploy(context.Background(), gitDeployOpts("gitdelerr", "ghp_x")); err != nil {
		t.Fatalf("deferred-delete failure must NOT fail the deploy: %v", err)
	}
}

// build NetworkPolicy create failure arm.
func TestDeploy_GitSource_BuildNetworkPolicyError(t *testing.T) {
	cs := clientfake.NewSimpleClientset(platformGHCRPull())
	cs.PrependReactor("create", "networkpolicies", func(_ clienttesting.Action) (bool, k8sruntime.Object, error) {
		return true, nil, errors.New("boom-np")
	})
	p := &K8sProvider{clientset: cs}
	if _, err := p.Deploy(context.Background(), gitDeployOpts("gitnperr", "")); err == nil ||
		!strings.Contains(err.Error(), "buildImageFromGit") {
		t.Fatalf("want build-NP error, got: %v", err)
	}
}

// build Job is created but reports Failed → waitForJobComplete error + snapshot.
func TestDeploy_GitSource_BuildJobFailed(t *testing.T) {
	cs := clientfake.NewSimpleClientset(platformGHCRPull())
	cs.PrependReactor("create", "jobs", func(action clienttesting.Action) (bool, k8sruntime.Object, error) {
		job := action.(clienttesting.CreateAction).GetObject().(*batchv1.Job)
		job.Status.Conditions = []batchv1.JobCondition{
			{Type: batchv1.JobFailed, Status: corev1.ConditionTrue, Message: "git clone failed"},
		}
		return false, job, nil
	})
	p := &K8sProvider{clientset: cs}
	if _, err := p.Deploy(context.Background(), gitDeployOpts("gitfail", "")); err == nil ||
		!strings.Contains(err.Error(), "kaniko job") {
		t.Fatalf("want kaniko-job wait failure, got: %v", err)
	}
}

func TestDeploy_GitSource_KanikoJobError(t *testing.T) {
	cs := clientfake.NewSimpleClientset(platformGHCRPull())
	cs.PrependReactor("create", "jobs", func(_ clienttesting.Action) (bool, k8sruntime.Object, error) {
		return true, nil, errors.New("boom-job")
	})
	p := &K8sProvider{clientset: cs}
	if _, err := p.Deploy(context.Background(), gitDeployOpts("gitjoberr", "")); err == nil ||
		!strings.Contains(err.Error(), "create kaniko job") {
		t.Fatalf("want kaniko-job error, got: %v", err)
	}
}

// build succeeds, then setupTenantNamespace fails (ResourceQuota create) → the
// Deploy(git) setup-namespace arm.
func TestDeploy_GitSource_SetupNamespaceErrorAfterBuild(t *testing.T) {
	cs := clientfake.NewSimpleClientset(platformGHCRPull())
	attachJobCompleteReactor(cs)
	cs.PrependReactor("create", "resourcequotas", func(_ clienttesting.Action) (bool, k8sruntime.Object, error) {
		return true, nil, errors.New("boom-quota")
	})
	p := &K8sProvider{clientset: cs}
	if _, err := p.Deploy(context.Background(), gitDeployOpts("gitsetup", "")); err == nil ||
		!strings.Contains(err.Error(), "setup namespace") {
		t.Fatalf("want setup-namespace error, got: %v", err)
	}
}
