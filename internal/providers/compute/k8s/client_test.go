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
