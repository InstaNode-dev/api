package handlers

// deploy_image_source_test.go — unit tests for P2 source=image validation.

import "testing"

func TestValidateImageRef(t *testing.T) {
	ok := []string{
		"ghcr.io/owner/app:v1",
		"ghcr.io/owner/app@sha256:abc",
		"docker.io/library/nginx:latest",
		"registry.example.com:5000/team/app:tag",
		"localhost/dev/app:1",
	}
	for _, r := range ok {
		if got, err := validateImageRef(r); err != nil || got != r {
			t.Errorf("validateImageRef(%q) = (%q,%v), want (%q,nil)", r, got, err, r)
		}
	}
	bad := map[string]string{
		"":                  "empty",
		"nginx":             "bare name (no host)",
		"owner/repo:tag":    "Docker Hub implicit namespace (no explicit host)",
		"owner/repo":        "no host, no tag",
		"ghcr.io/o/a:t ag":  "whitespace",
	}
	for ref, why := range bad {
		if _, err := validateImageRef(ref); err == nil {
			t.Errorf("validateImageRef(%q) should fail (%s) but passed", ref, why)
		}
	}
}

func TestDeploymentSourceOrDefault(t *testing.T) {
	if deploymentSourceOrDefault("") != "tarball" {
		t.Error("empty source must normalise to tarball")
	}
	if deploymentSourceOrDefault("image") != "image" {
		t.Error("explicit source must pass through")
	}
}
