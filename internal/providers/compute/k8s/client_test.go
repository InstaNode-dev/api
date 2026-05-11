package k8s

import (
	"context"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
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

// TestKanikoJobUsesS3ContextWhenURLSet guards the build-context lift past the
// k8s Secret's ~1 MiB cap (etcd object size limit). When s3ContextURL is set,
// kaniko's --context arg becomes the s3:// URL and the build-context Secret
// volume is absent; AWS env vars are set so kaniko's S3 reader talks to MinIO.
func TestKanikoJobUsesS3ContextWhenURLSet(t *testing.T) {
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
	s3URL := "s3://instant-build-contexts/abc/20260511T000000Z.tar.gz"
	if err := p.createKanikoJob(context.Background(), ns, jobName, "ctx-sec", "auth-sec", "ghcr.io/x/y:latest", s3URL); err != nil {
		t.Fatalf("createKanikoJob: %v", err)
	}

	job, err := cs.BatchV1().Jobs(ns).Get(context.Background(), jobName, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("get job: %v", err)
	}
	c := job.Spec.Template.Spec.Containers[0]

	// --context arg points at the s3:// URL, not the tar:// volume mount.
	hasS3Context := false
	for _, a := range c.Args {
		if a == "--context="+s3URL {
			hasS3Context = true
		}
		if a == "--context=tar:///workspace/context.tar.gz" {
			t.Errorf("kaniko still references tar:// mount when s3ContextURL is set; args=%v", c.Args)
		}
	}
	if !hasS3Context {
		t.Errorf("kaniko --context flag missing for s3URL %q; args=%v", s3URL, c.Args)
	}

	// AWS env so kaniko talks to MinIO, not the AWS metadata endpoint.
	env := map[string]string{}
	for _, e := range c.Env {
		env[e.Name] = e.Value
	}
	for _, must := range []string{"AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_S3_ENDPOINT", "S3_FORCE_PATH_STYLE"} {
		if env[must] == "" {
			t.Errorf("kaniko env var %s is empty — S3 reader will fall back to AWS metadata", must)
		}
	}
	if got := env["AWS_S3_ENDPOINT"]; got != "http://minio.test:9000" {
		t.Errorf("AWS_S3_ENDPOINT = %q; want http://minio.test:9000", got)
	}

	// No build-context Secret volume when using S3.
	for _, v := range job.Spec.Template.Spec.Volumes {
		if v.Name == "build-context" {
			t.Errorf("build-context Secret volume should be absent when using S3, but found one")
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
