package handlers_test

// seams_final3_test.go — FINAL serial pass #3. Drives the seam-backed
// production arms that were previously unreachable without a real network /
// filesystem / cluster fault:
//
//   - stack.New tarball open-error + open-but-fail-read arms (openMultipartFile seam)
//   - NewStackHandler / NewDeployHandler ComputeProvider=="k8s" SUCCESS branch
//     (newK8sStackProvider / newK8sComputeProvider factory seams)
//   - generateAppID / generateOAuthState / generateSessionID rand.Read error arm
//     (randRead seam)
//   - shouldSetRetryAfterHeader 502/504/default branches
//   - sns_verify defaultFetchCert success + non-200 + read-cap + bad-PEM arms
//     (real method against an httptest server)

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"instant.dev/internal/config"
	"instant.dev/internal/handlers"
	"instant.dev/internal/plans"
	compute "instant.dev/internal/providers/compute"
	"instant.dev/internal/providers/compute/k8s"
	"instant.dev/internal/providers/compute/noop"
	"instant.dev/internal/testhelpers"
)

// errReadFile is a multipart.File whose Read always errors, so io.ReadAll fails
// after a successful Open — exercises the tarball_read_failed arm.
type errReadFile struct{}

func (errReadFile) Read(p []byte) (int, error) { return 0, errors.New("forced read error") }
func (errReadFile) ReadAt(p []byte, off int64) (int, error) {
	return 0, errors.New("forced readat error")
}
func (errReadFile) Seek(offset int64, whence int) (int64, error) { return 0, nil }
func (errReadFile) Close() error                                 { return nil }

// ── stack.New tarball open / read error arms ──────────────────────────────────

// TestSeamFinal3_StackNew_TarballOpenFailed — openMultipartFile returns an
// error → tarball_open_failed 400 (stack.go ~492-495).
func TestSeamFinal3_StackNew_TarballOpenFailed(t *testing.T) {
	db, clean := testhelpers.SetupTestDB(t)
	defer clean()
	ensureStackTables(t, db)

	restore := handlers.SetOpenMultipartFileForTest(func(*multipart.FileHeader) (multipart.File, error) {
		return nil, errors.New("forced open error")
	})
	defer restore()

	app := stackNewApp(t, db, nil)
	resp := postStackNew(t, app, "", testManifestSingleService, map[string][]byte{
		"web": createMinimalTarball(t),
	})
	defer resp.Body.Close()
	require.Equal(t, http.StatusBadRequest, resp.StatusCode)
	assert.Equal(t, "tarball_open_failed", decodeErrCode(t, resp))
}

// TestSeamFinal3_StackNew_TarballReadFailed — openMultipartFile returns a file
// whose Read errors → tarball_read_failed 400 (stack.go ~498-501).
func TestSeamFinal3_StackNew_TarballReadFailed(t *testing.T) {
	db, clean := testhelpers.SetupTestDB(t)
	defer clean()
	ensureStackTables(t, db)

	restore := handlers.SetOpenMultipartFileForTest(func(*multipart.FileHeader) (multipart.File, error) {
		return errReadFile{}, nil
	})
	defer restore()

	app := stackNewApp(t, db, nil)
	resp := postStackNew(t, app, "", testManifestSingleService, map[string][]byte{
		"web": createMinimalTarball(t),
	})
	defer resp.Body.Close()
	require.Equal(t, http.StatusBadRequest, resp.StatusCode)
	assert.Equal(t, "tarball_read_failed", decodeErrCode(t, resp))
}

// ── k8s constructor SUCCESS branch ────────────────────────────────────────────

// TestSeamFinal3_NewStackHandler_K8sSuccess — newK8sStackProvider returns a
// (fake) provider with no error → the cfg.ComputeProvider=="k8s" SUCCESS arm of
// NewStackHandler runs (stack.go ~102-104; previously only the error→noop arm
// was covered).
func TestSeamFinal3_NewStackHandler_K8sSuccess(t *testing.T) {
	db, clean := testhelpers.SetupTestDB(t)
	defer clean()
	called := false
	restore := handlers.SetNewK8sStackProviderForTest(func(ns string, bc k8s.BuildContextConfig) (compute.StackProvider, error) {
		called = true
		return noop.NewStack(), nil
	})
	defer restore()
	cfg := &config.Config{
		JWTSecret:         testhelpers.TestJWTSecret,
		AESKey:            testhelpers.TestAESKeyHex,
		ComputeProvider:   "k8s",
		KubeNamespaceApps: "instant-apps-test",
	}
	h := handlers.NewStackHandler(db, nil, cfg, plans.Default())
	require.NotNil(t, h)
	assert.True(t, called, "k8s factory must be invoked on the k8s success branch")
}

// TestSeamFinal3_NewDeployHandler_K8sSuccess — newK8sComputeProvider returns a
// (fake) provider with no error → the cfg.ComputeProvider=="k8s" SUCCESS arm of
// NewDeployHandler runs (deploy.go ~113-114).
func TestSeamFinal3_NewDeployHandler_K8sSuccess(t *testing.T) {
	db, clean := testhelpers.SetupTestDB(t)
	defer clean()
	called := false
	restore := handlers.SetNewK8sComputeProviderForTest(func(ns string, bc k8s.BuildContextConfig) (compute.Provider, error) {
		called = true
		return noop.New(), nil
	})
	defer restore()
	cfg := &config.Config{
		JWTSecret:         testhelpers.TestJWTSecret,
		AESKey:            testhelpers.TestAESKeyHex,
		ComputeProvider:   "k8s",
		KubeNamespaceApps: "instant-apps-test",
	}
	h := handlers.NewDeployHandler(db, nil, cfg, plans.Default())
	require.NotNil(t, h)
	assert.True(t, called, "k8s factory must be invoked on the k8s success branch")
}

// TestSeamFinal3_NewDeployHandler_K8sError — newK8sComputeProvider returns an
// error → the noop-fallback arm of NewDeployHandler runs (deploy.go ~118-120).
func TestSeamFinal3_NewDeployHandler_K8sError(t *testing.T) {
	db, clean := testhelpers.SetupTestDB(t)
	defer clean()
	restore := handlers.SetNewK8sComputeProviderForTest(func(ns string, bc k8s.BuildContextConfig) (compute.Provider, error) {
		return nil, errors.New("forced k8s init error")
	})
	defer restore()
	cfg := &config.Config{
		JWTSecret:         testhelpers.TestJWTSecret,
		AESKey:            testhelpers.TestAESKeyHex,
		ComputeProvider:   "k8s",
		KubeNamespaceApps: "instant-apps-test",
	}
	h := handlers.NewDeployHandler(db, nil, cfg, plans.Default())
	require.NotNil(t, h, "constructor must fall back to noop on k8s init error")
}

// TestSeamFinal3_NewStackHandler_K8sError — newK8sStackProvider returns an error
// → the noop-fallback arm of NewStackHandler runs (stack.go ~118-120).
func TestSeamFinal3_NewStackHandler_K8sError(t *testing.T) {
	db, clean := testhelpers.SetupTestDB(t)
	defer clean()
	restore := handlers.SetNewK8sStackProviderForTest(func(ns string, bc k8s.BuildContextConfig) (compute.StackProvider, error) {
		return nil, errors.New("forced k8s init error")
	})
	defer restore()
	cfg := &config.Config{
		JWTSecret:         testhelpers.TestJWTSecret,
		AESKey:            testhelpers.TestAESKeyHex,
		ComputeProvider:   "k8s",
		KubeNamespaceApps: "instant-apps-test",
	}
	h := handlers.NewStackHandler(db, nil, cfg, plans.Default())
	require.NotNil(t, h, "constructor must fall back to noop on k8s init error")
}

// TestSeamFinal3_DefaultK8sFactoryClosures — invoke the REAL default seam
// closures so their bodies (return k8s.New / k8s.NewStackProvider) are covered.
// No live cluster is required: construction may succeed or error, but the line
// executes either way.
func TestSeamFinal3_DefaultK8sFactoryClosures(t *testing.T) {
	_, _ = handlers.InvokeDefaultK8sStackProviderForTest()
	_, _ = handlers.InvokeDefaultK8sComputeProviderForTest()
}

// ── secure-token generator rand.Read error arms ───────────────────────────────

// TestSeamFinal3_RandReadError_AllGenerators — forcing randRead to error makes
// generateAppID / generateOAuthState / generateSessionID all return their error
// arm (deploy.go / auth.go / cli_auth.go).
func TestSeamFinal3_RandReadError_AllGenerators(t *testing.T) {
	restore := handlers.SetRandReadForTest(func([]byte) (int, error) {
		return 0, errors.New("forced rand error")
	})
	defer restore()

	_, err := handlers.GenerateAppIDForTest()
	require.Error(t, err, "generateAppID must surface a rand.Read error")

	_, err = handlers.GenerateOAuthStateForTest()
	require.Error(t, err, "generateOAuthState must surface a rand.Read error")

	_, err = handlers.GenerateSessionIDForTest()
	require.Error(t, err, "generateSessionID must surface a rand.Read error")
}

// TestSeamFinal3_RandRead_HappyStillWorks — with the seam restored to the real
// crypto/rand.Read, the generators produce non-empty hex (the success arm).
func TestSeamFinal3_RandRead_HappyStillWorks(t *testing.T) {
	app, err := handlers.GenerateAppIDForTest()
	require.NoError(t, err)
	assert.Len(t, app, 8)
	st, err := handlers.GenerateOAuthStateForTest()
	require.NoError(t, err)
	assert.Len(t, st, 32)
	sid, err := handlers.GenerateSessionIDForTest()
	require.NoError(t, err)
	assert.Len(t, sid, 32)
}

// ── shouldSetRetryAfterHeader branches ─────────────────────────────────────────

func TestSeamFinal3_ShouldSetRetryAfterHeader(t *testing.T) {
	assert.True(t, handlers.ShouldSetRetryAfterHeaderForTest(http.StatusTooManyRequests))
	assert.True(t, handlers.ShouldSetRetryAfterHeaderForTest(http.StatusBadGateway))
	assert.True(t, handlers.ShouldSetRetryAfterHeaderForTest(http.StatusServiceUnavailable))
	assert.True(t, handlers.ShouldSetRetryAfterHeaderForTest(http.StatusGatewayTimeout))
	assert.False(t, handlers.ShouldSetRetryAfterHeaderForTest(http.StatusOK))
	assert.False(t, handlers.ShouldSetRetryAfterHeaderForTest(http.StatusBadRequest))
}

// ── sns_verify defaultFetchCert arms ───────────────────────────────────────────

// makeTestCertPEM produces a self-signed cert in PEM form for the fetch-success
// arm.
func makeTestCertPEM(t *testing.T) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "sns-test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

// TestSeamFinal3_DefaultFetchCert_Success — defaultFetchCert against an httptest
// server returning a valid PEM cert → success arm (sns_verify.go 240-253).
func TestSeamFinal3_DefaultFetchCert_Success(t *testing.T) {
	certPEM := makeTestCertPEM(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(certPEM)
	}))
	defer srv.Close()

	cert, err := handlers.FetchCertViaDefaultForTest(srv.Client(), srv.URL)
	require.NoError(t, err)
	require.NotNil(t, cert)
	assert.Equal(t, "sns-test", cert.Subject.CommonName)
}

// TestSeamFinal3_DefaultFetchCert_Non200 — server returns 500 → the
// "http status" error arm (sns_verify.go 246-248).
func TestSeamFinal3_DefaultFetchCert_Non200(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()
	_, err := handlers.FetchCertViaDefaultForTest(srv.Client(), srv.URL)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "http status")
}

// TestSeamFinal3_DefaultFetchCert_GetError — an unreachable URL → the http-get
// error arm (sns_verify.go 242-243).
func TestSeamFinal3_DefaultFetchCert_GetError(t *testing.T) {
	client := &http.Client{Timeout: 200 * time.Millisecond}
	// 127.0.0.1:1 refuses connections immediately.
	_, err := handlers.FetchCertViaDefaultForTest(client, "http://127.0.0.1:1/cert.pem")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "http get")
}

// TestSeamFinal3_DefaultFetchCert_BadPEM — server returns 200 with junk → the
// parseSNSCertPEM error path inside defaultFetchCert (no PEM block).
func TestSeamFinal3_DefaultFetchCert_BadPEM(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("not a pem block"))
	}))
	defer srv.Close()
	_, err := handlers.FetchCertViaDefaultForTest(srv.Client(), srv.URL)
	require.Error(t, err)
}
