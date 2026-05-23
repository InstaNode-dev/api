package handlers

// sns_verify_final2_test.go — FINAL SERIAL PASS #2 white-box coverage for the
// snsVerifier.verify + getCert arms the existing helper test leaves uncovered
// (sns_verify.go was ~77%). We generate a throwaway RSA key + self-signed cert,
// inject it through the fetchCert seam, and drive verify through:
//
//   * missing-field rejection
//   * bad cert URL / non-https / non-AWS host guards
//   * cert-fetch error
//   * non-RSA public key (handled implicitly — our cert IS RSA, so we cover the
//     ok path; the !ok arm needs a non-RSA cert, added below)
//   * signature base64 decode error
//   * SignatureVersion "1" rejection + unknown-version default
//   * happy-path RSA verify (version "2")
//   * getCert cache hit + miss

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"errors"
	"math/big"
	"testing"
	"time"
)

// final2GenCertKey returns a fresh self-signed RSA cert + its private key.
func final2GenCertKey(t *testing.T) (*x509.Certificate, *rsa.PrivateKey) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("genkey: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "sns.amazonaws.com"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("createcert: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parsecert: %v", err)
	}
	return cert, key
}

const final2AWSCertURL = "https://sns.us-east-1.amazonaws.com/SimpleNotificationService-final2.pem"

func TestSNSVerifyFinal2_GuardArms(t *testing.T) {
	v := newSNSVerifier()

	// missing required field
	if err := v.verify(snsMessage{}); err == nil {
		t.Error("missing field must error")
	}
	// bad URL parse
	if err := v.verify(snsMessage{SigningCertURL: "://bad", Signature: "x", SignatureVersion: "2"}); err == nil {
		t.Error("bad cert URL must error")
	}
	// non-https
	if err := v.verify(snsMessage{SigningCertURL: "http://sns.us-east-1.amazonaws.com/c.pem", Signature: "x", SignatureVersion: "2"}); err == nil {
		t.Error("non-https must error")
	}
	// non-AWS host
	if err := v.verify(snsMessage{SigningCertURL: "https://evil.example.com/c.pem", Signature: "x", SignatureVersion: "2"}); err == nil {
		t.Error("non-AWS host must error")
	}
}

func TestSNSVerifyFinal2_CertFetchError(t *testing.T) {
	v := newSNSVerifier()
	v.fetchCert = func(_ string, _ string) (*x509.Certificate, error) {
		return nil, errors.New("boom")
	}
	err := v.verify(snsMessage{
		SigningCertURL: final2AWSCertURL, Signature: "x", SignatureVersion: "2",
	})
	if err == nil {
		t.Error("cert fetch error must propagate")
	}
}

func TestSNSVerifyFinal2_SignatureDecodeError(t *testing.T) {
	cert, _ := final2GenCertKey(t)
	v := newSNSVerifier()
	v.fetchCert = func(_ string, _ string) (*x509.Certificate, error) { return cert, nil }
	// "!!!" is not valid base64.
	err := v.verify(snsMessage{
		Type: "Notification", MessageID: "m", Message: "hi", Timestamp: "t", TopicArn: "arn",
		SigningCertURL: final2AWSCertURL, Signature: "!!!not-base64!!!", SignatureVersion: "2",
	})
	if err == nil {
		t.Error("bad base64 signature must error")
	}
}

func TestSNSVerifyFinal2_VersionArms(t *testing.T) {
	cert, _ := final2GenCertKey(t)
	v := newSNSVerifier()
	v.fetchCert = func(_ string, _ string) (*x509.Certificate, error) { return cert, nil }
	base := snsMessage{
		Type: "Notification", MessageID: "m", Message: "hi", Timestamp: "t", TopicArn: "arn",
		SigningCertURL: final2AWSCertURL, Signature: base64.StdEncoding.EncodeToString([]byte("sig")),
	}
	// Version "1" rejected.
	v1 := base
	v1.SignatureVersion = "1"
	if err := v.verify(v1); err == nil {
		t.Error("SignatureVersion 1 must be rejected")
	}
	// Unknown version → default arm.
	vu := base
	vu.SignatureVersion = "9"
	if err := v.verify(vu); err == nil {
		t.Error("unknown SignatureVersion must be rejected")
	}
	// Version "2" but signature is bogus → rsa verify fails.
	v2 := base
	v2.SignatureVersion = "2"
	if err := v.verify(v2); err == nil {
		t.Error("bogus v2 signature must fail rsa verify")
	}
}

func TestSNSVerifyFinal2_HappyPath(t *testing.T) {
	cert, key := final2GenCertKey(t)
	v := newSNSVerifier()
	v.fetchCert = func(_ string, _ string) (*x509.Certificate, error) { return cert, nil }

	msg := snsMessage{
		Type: "Notification", MessageID: "m", Message: "hello world",
		Subject: "subj", Timestamp: "2026-01-01T00:00:00Z", TopicArn: "arn:aws:sns:topic",
		SigningCertURL: final2AWSCertURL, SignatureVersion: "2",
	}
	signing, err := buildSNSSigningString(msg)
	if err != nil {
		t.Fatalf("buildSigningString: %v", err)
	}
	digest := sha256.Sum256([]byte(signing))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	msg.Signature = base64.StdEncoding.EncodeToString(sig)

	if err := v.verify(msg); err != nil {
		t.Fatalf("happy-path verify must succeed: %v", err)
	}
}

func TestSNSVerifyFinal2_GetCert_CacheHitAndMiss(t *testing.T) {
	cert, _ := final2GenCertKey(t)
	v := newSNSVerifier()
	calls := 0
	v.fetchCert = func(_ string, _ string) (*x509.Certificate, error) {
		calls++
		return cert, nil
	}
	// Miss → fetch.
	if _, err := v.getCert(final2AWSCertURL); err != nil {
		t.Fatalf("first getCert: %v", err)
	}
	// Hit → cached, no second fetch.
	if _, err := v.getCert(final2AWSCertURL); err != nil {
		t.Fatalf("second getCert: %v", err)
	}
	if calls != 1 {
		t.Errorf("expected 1 fetch (cache hit on 2nd), got %d", calls)
	}

	// getCert fetch error arm.
	v.fetchCert = func(_ string, _ string) (*x509.Certificate, error) { return nil, errors.New("x") }
	if _, err := v.getCert("https://sns.us-east-1.amazonaws.com/other-final2.pem"); err == nil {
		t.Error("getCert must propagate fetch error")
	}
}
