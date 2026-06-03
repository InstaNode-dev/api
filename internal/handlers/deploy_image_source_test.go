package handlers

// deploy_image_source_test.go — unit tests for P2 source=image validation.

import (
	"testing"

	"instant.dev/internal/models"
)

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

func TestDeploymentToMap_ImageSource(t *testing.T) {
	img := &models.Deployment{Source: "image", ImageRef: "ghcr.io/o/a:1", RegistryCredsEnc: "ciphertext", EnvVars: map[string]string{}}
	m := deploymentToMap(img)
	if m["source"] != "image" {
		t.Errorf("source: got %v want image", m["source"])
	}
	if m["image_ref"] != "ghcr.io/o/a:1" {
		t.Errorf("image_ref: got %v", m["image_ref"])
	}
	if m["registry_creds_set"] != true {
		t.Errorf("registry_creds_set: got %v want true", m["registry_creds_set"])
	}
	// creds must NEVER be echoed
	if _, leaked := m["registry_creds"]; leaked {
		t.Error("registry_creds must never appear in the response map")
	}

	// tarball deploy: source normalises, no image_ref/registry_creds_set keys.
	tb := &models.Deployment{Source: "tarball", EnvVars: map[string]string{}}
	m2 := deploymentToMap(tb)
	if m2["source"] != "tarball" {
		t.Errorf("tarball source: got %v", m2["source"])
	}
	if _, ok := m2["image_ref"]; ok {
		t.Error("tarball deploy must not emit image_ref")
	}
	if _, ok := m2["registry_creds_set"]; ok {
		t.Error("tarball deploy must not emit registry_creds_set")
	}
}
