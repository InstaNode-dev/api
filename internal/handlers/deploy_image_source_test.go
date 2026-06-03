package handlers

// deploy_image_source_test.go — unit tests for P2 source=image validation.

import (
	"strings"
	"testing"

	"instant.dev/internal/crypto"
	"instant.dev/internal/models"
	"instant.dev/internal/providers/compute"
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

func TestValidateImageRef_TooLong(t *testing.T) {
	long := "ghcr.io/o/" + strings.Repeat("a", 600) // valid host, but >512 total
	if _, err := validateImageRef(long); err == nil {
		t.Error("an image_ref over 512 chars must be rejected")
	}
}

func TestApplyImageSourceOpts(t *testing.T) {
	const keyHex = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
	key, _ := crypto.ParseAESKey(keyHex)
	cipher, _ := crypto.Encrypt(key, `{"auths":{}}`)

	// non-image → no-op (tarball deploy untouched)
	o := compute.DeployOptions{Tarball: []byte("x")}
	applyImageSourceOpts(&o, &models.Deployment{Source: "tarball"}, keyHex)
	if o.Source != "" || o.Tarball == nil {
		t.Errorf("tarball deploy must be untouched, got %+v", o)
	}

	// image, no creds → Source/ImageRef set, Tarball cleared, no RegistryAuth
	o = compute.DeployOptions{Tarball: []byte("x")}
	applyImageSourceOpts(&o, &models.Deployment{Source: "image", ImageRef: "ghcr.io/o/a:1"}, keyHex)
	if o.Source != "image" || o.ImageRef != "ghcr.io/o/a:1" || o.Tarball != nil || o.RegistryAuth != "" {
		t.Errorf("image no-creds: %+v", o)
	}

	// image + creds → RegistryAuth decrypted
	o = compute.DeployOptions{}
	applyImageSourceOpts(&o, &models.Deployment{Source: "image", ImageRef: "r", RegistryCredsEnc: cipher}, keyHex)
	if o.RegistryAuth != `{"auths":{}}` {
		t.Errorf("creds decrypt: got %q", o.RegistryAuth)
	}

	// image + bad ciphertext → decrypt fails → no RegistryAuth (fallback)
	o = compute.DeployOptions{}
	applyImageSourceOpts(&o, &models.Deployment{Source: "image", RegistryCredsEnc: "not-valid-base64!!"}, keyHex)
	if o.RegistryAuth != "" {
		t.Error("bad ciphertext must not set RegistryAuth")
	}

	// bad AES key → no RegistryAuth
	o = compute.DeployOptions{}
	applyImageSourceOpts(&o, &models.Deployment{Source: "image", RegistryCredsEnc: cipher}, "tooshort")
	if o.RegistryAuth != "" {
		t.Error("bad AES key must not set RegistryAuth")
	}
}
