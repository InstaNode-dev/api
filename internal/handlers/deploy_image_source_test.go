package handlers

// deploy_image_source_test.go — unit tests for P2 source=image validation.

import (
	"errors"
	"net"
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
		"":                 "empty",
		"nginx":            "bare name (no host)",
		"owner/repo:tag":   "Docker Hub implicit namespace (no explicit host)",
		"owner/repo":       "no host, no tag",
		"ghcr.io/o/a:t ag": "whitespace",
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

func TestEncryptDeploySecret(t *testing.T) {
	const keyHex = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
	// bad key (not 64 hex chars) → ParseAESKey error path.
	if _, err := encryptDeploySecret("tooshort", `{"auths":{}}`); err == nil {
		t.Error("a malformed AES key must return an error")
	}
	// good key → ciphertext that round-trips.
	ct, err := encryptDeploySecret(keyHex, `{"auths":{"ghcr.io":{}}}`)
	if err != nil {
		t.Fatalf("encryptDeploySecret(good key): %v", err)
	}
	if ct == "" {
		t.Fatal("ciphertext must be non-empty")
	}
	key, _ := crypto.ParseAESKey(keyHex)
	plain, derr := crypto.Decrypt(key, ct)
	if derr != nil || plain != `{"auths":{"ghcr.io":{}}}` {
		t.Errorf("round-trip failed: plain=%q err=%v", plain, derr)
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

func TestValidateGitURL(t *testing.T) {
	// Stub DNS so hostname cases are deterministic: every name resolves to a
	// public IP. Literal-IP cases below bypass this (net.ParseIP short-circuits).
	orig := gitHostLookupIP
	gitHostLookupIP = func(string) ([]net.IP, error) { return []net.IP{net.ParseIP("93.184.216.34")}, nil }
	defer func() { gitHostLookupIP = orig }()

	ok := []string{
		"https://github.com/owner/repo",
		"https://github.com/owner/repo.git",
		"http://gitlab.example.com:8080/group/proj",
		"https://bitbucket.org/team/repo",
		"https://93.184.216.34/owner/repo", // public literal IP (no DNS, not blocked)
	}
	for _, u := range ok {
		if got, err := validateGitURL(u); err != nil || got != u {
			t.Errorf("validateGitURL(%q) = (%q,%v), want (%q,nil)", u, got, err, u)
		}
	}
	bad := map[string]string{
		"":                                  "empty",
		"git@github.com:owner/repo.git":     "ssh scheme",
		"git://github.com/owner/repo":       "git scheme",
		"ftp://h/x":                         "non-http scheme",
		"https://":                          "no host",
		"https://u:p@github.com/owner/repo": "embedded credentials",
		"https://github.com/owner/repo a":   "whitespace",
		// SSRF: literal internal IPs (no DNS) must be rejected.
		"http://127.0.0.1/o/r":       "loopback",
		"http://169.254.169.254/o/r": "cloud metadata (link-local)",
		"http://10.0.0.5/o/r":        "RFC1918 10/8",
		"http://192.168.1.1/o/r":     "RFC1918 192.168/16",
		"http://172.16.5.5/o/r":      "RFC1918 172.16/12",
		"http://[::1]/o/r":           "IPv6 loopback",
		"http://0.0.0.0/o/r":         "unspecified",
		"http://:8080/o/r":           "host with port but empty hostname",
	}
	for u, why := range bad {
		if _, err := validateGitURL(u); err == nil {
			t.Errorf("validateGitURL(%q) should fail (%s) but passed", u, why)
		}
	}
	// over-length
	if _, err := validateGitURL("https://github.com/o/" + strings.Repeat("a", 600)); err == nil {
		t.Error("an over-length git_url must be rejected")
	}

	// SSRF: a hostname that RESOLVES to an internal IP is rejected.
	gitHostLookupIP = func(string) ([]net.IP, error) { return []net.IP{net.ParseIP("10.1.2.3")}, nil }
	if _, err := validateGitURL("https://evil.example.com/o/r"); err == nil {
		t.Error("a host resolving to an internal IP must be rejected")
	}
	// SSRF: resolution failure is fail-closed.
	gitHostLookupIP = func(string) ([]net.IP, error) { return nil, errors.New("nxdomain") }
	if _, err := validateGitURL("https://nope.example.com/o/r"); err == nil {
		t.Error("an unresolvable host must be rejected (fail-closed)")
	}
}

func TestApplyGitSourceOpts(t *testing.T) {
	const keyHex = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
	key, _ := crypto.ParseAESKey(keyHex)
	cipher, _ := crypto.Encrypt(key, "ghp_token")

	// non-git → no-op
	o := compute.DeployOptions{Tarball: []byte("x")}
	applyGitSourceOpts(&o, &models.Deployment{Source: "tarball"}, keyHex)
	if o.Source != "" || o.Tarball == nil {
		t.Errorf("non-git must be untouched, got %+v", o)
	}

	// git, no token → Source/GitURL/GitRef set, Tarball cleared, no GitAuth
	o = compute.DeployOptions{Tarball: []byte("x")}
	applyGitSourceOpts(&o, &models.Deployment{Source: "git", GitURL: "https://github.com/o/r", GitRef: "main"}, keyHex)
	if o.Source != "git" || o.GitURL != "https://github.com/o/r" || o.GitRef != "main" || o.Tarball != nil || o.GitAuth != "" {
		t.Errorf("git no-token: %+v", o)
	}

	// git + token → GitAuth decrypted
	o = compute.DeployOptions{}
	applyGitSourceOpts(&o, &models.Deployment{Source: "git", GitURL: "r", GitTokenEnc: cipher}, keyHex)
	if o.GitAuth != "ghp_token" {
		t.Errorf("token decrypt: got %q", o.GitAuth)
	}

	// git + bad ciphertext → no GitAuth (fallback to public clone)
	o = compute.DeployOptions{}
	applyGitSourceOpts(&o, &models.Deployment{Source: "git", GitTokenEnc: "not-valid-base64!!"}, keyHex)
	if o.GitAuth != "" {
		t.Error("bad ciphertext must not set GitAuth")
	}

	// bad AES key → no GitAuth
	o = compute.DeployOptions{}
	applyGitSourceOpts(&o, &models.Deployment{Source: "git", GitTokenEnc: cipher}, "tooshort")
	if o.GitAuth != "" {
		t.Error("bad AES key must not set GitAuth")
	}
}

func TestDeploymentToMap_GitSource(t *testing.T) {
	g := &models.Deployment{Source: "git", GitURL: "https://github.com/o/r", GitRef: "main", GitTokenEnc: "ciphertext", EnvVars: map[string]string{}}
	m := deploymentToMap(g)
	if m["source"] != "git" {
		t.Errorf("source: got %v want git", m["source"])
	}
	if m["git_url"] != "https://github.com/o/r" {
		t.Errorf("git_url: got %v", m["git_url"])
	}
	if m["git_ref"] != "main" {
		t.Errorf("git_ref: got %v", m["git_ref"])
	}
	if m["git_token_set"] != true {
		t.Errorf("git_token_set: got %v want true", m["git_token_set"])
	}
	if _, leaked := m["git_token"]; leaked {
		t.Error("git_token must never appear in the response map")
	}
	// tarball deploy emits no git_* keys
	tb := &models.Deployment{Source: "tarball", EnvVars: map[string]string{}}
	if _, ok := deploymentToMap(tb)["git_url"]; ok {
		t.Error("tarball deploy must not emit git_url")
	}
}
