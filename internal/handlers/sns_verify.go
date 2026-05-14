package handlers

// sns_verify.go — full AWS SNS signature verification.
//
// AWS SNS signs every Notification, SubscriptionConfirmation, and
// UnsubscribeConfirmation message with an RSA private key whose public
// certificate is hosted at SigningCertURL. The verifier here:
//
//   1. Validates SigningCertURL's host matches sns.<region>.amazonaws.com
//      (refuses arbitrary URLs — otherwise an attacker who knows the
//      topic ARN could host their own cert + signature pair).
//   2. Fetches the certificate (HTTPS only, 5s timeout, response capped
//      at 32KB to limit blast radius if the URL ever returns garbage).
//   3. Builds the canonical signing string per AWS SNS docs, with the
//      field order specific to the message Type.
//   4. RSA-verifies. SignatureVersion=1 → SHA1 (legacy), =2 → SHA256.
//      Empty / unknown version → reject.
//
// The verifier is wired into the SES endpoint (email_webhooks.go) AFTER
// the TopicArn check, so a drive-by attacker who guesses the ARN still
// hits the signature check before any DB write. ARN match alone was the
// pre-existing weak gate; SNS signature verification is the strong one.
//
// PERFORMANCE — cert downloads are cached in-process by URL for 24h.
// The same topic typically uses one cert for its full rotation window,
// so the steady state is one HTTP fetch per process startup.

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

// snsSigningCertHostRegex enforces "sns.<region>.amazonaws.com" hostnames
// so SigningCertURL can't be set to attacker-controlled domains. AWS region
// names are `[a-z]{2,}-[a-z]+-[0-9]` (us-east-1, eu-central-1, ap-south-1, etc.).
// The leading "sns." anchors the subdomain; we also accept "sns-fips." for
// FIPS endpoints. The trailing `.amazonaws.com` is fixed.
var snsSigningCertHostRegex = regexp.MustCompile(
	`^sns(-fips)?\.[a-z0-9-]+\.amazonaws\.com$`,
)

// snsCertCacheEntry holds a parsed certificate and its expiry-from-cache time.
// We keep the certificate object, not the public key alone, so future
// freshness checks can inspect cert.NotAfter.
type snsCertCacheEntry struct {
	cert    *x509.Certificate
	fetched time.Time
}

// snsCertCacheTTL keeps a fetched cert in memory for 24h. Outside that
// window the next verification refetches — handles AWS's periodic cert
// rotation transparently.
const snsCertCacheTTL = 24 * time.Hour

// snsMaxCertBytes caps the SigningCertURL response body. A well-formed
// cert is ~1-2KB; we allow up to 32KB to leave headroom for chain
// concatenation. Anything beyond is rejected — protects against an
// attacker tricking the verifier into downloading multi-GB payloads.
const snsMaxCertBytes = 32 * 1024

// snsCertHTTPTimeout caps the cert-fetch HTTP call. SNS messages have
// their own deadline (~30s before AWS retries) so we leave 25s for the
// rest of the handler.
const snsCertHTTPTimeout = 5 * time.Second

// snsVerifier verifies AWS SNS message signatures. The httpClient and
// certCache are exported as fields (lowercased) for the test path to
// inject a mock fetcher; production callers use NewSNSVerifier with
// defaults.
type snsVerifier struct {
	httpClient *http.Client

	// fetchCert is the indirection seam for tests — production sets this
	// to httpFetchCert which goes over the network. Tests override with
	// an in-memory cert.
	fetchCert func(ctx string, certURL string) (*x509.Certificate, error)

	mu        sync.RWMutex
	certCache map[string]snsCertCacheEntry
}

// newSNSVerifier returns a verifier with production defaults.
func newSNSVerifier() *snsVerifier {
	v := &snsVerifier{
		httpClient: &http.Client{Timeout: snsCertHTTPTimeout},
		certCache:  make(map[string]snsCertCacheEntry),
	}
	v.fetchCert = v.defaultFetchCert
	return v
}

// snsMessage is the subset of SNS envelope fields the verifier reads.
// The verifier accepts a map[string]string (raw fields) rather than a
// struct so callers can pass either Notification, SubscriptionConfirmation,
// or UnsubscribeConfirmation envelopes without re-parsing.
type snsMessage struct {
	Type             string
	MessageID        string
	Token            string // present on SubscriptionConfirmation only
	TopicArn         string
	Subject          string // optional
	Message          string
	Timestamp        string
	SignatureVersion string
	Signature        string
	SigningCertURL   string
	SubscribeURL     string // present on SubscriptionConfirmation only
}

// snsSigningFieldsByType lists, in canonical order, which fields go into
// the signing string for each envelope Type. AWS docs:
// https://docs.aws.amazon.com/sns/latest/dg/sns-verify-signature-of-message.html
var snsSigningFieldsByType = map[string][]string{
	"Notification": {
		"Message", "MessageId", "Subject", "Timestamp", "TopicArn", "Type",
	},
	"SubscriptionConfirmation": {
		"Message", "MessageId", "SubscribeURL", "Timestamp", "Token", "TopicArn", "Type",
	},
	"UnsubscribeConfirmation": {
		"Message", "MessageId", "SubscribeURL", "Timestamp", "Token", "TopicArn", "Type",
	},
}

// errSNSVerification is returned for every verification failure path.
// The handler logs the detailed reason at WARN; the response surface
// stays opaque (HTTP 401) so an attacker can't probe which check failed.
var errSNSVerification = errors.New("sns: signature verification failed")

// verify performs the full SNS signature check on msg.
//
// Returns nil iff:
//   - SigningCertURL is HTTPS and host matches snsSigningCertHostRegex.
//   - Cert fetches successfully and is parseable as x509.
//   - Signature decodes from base64.
//   - SignatureVersion is "1" (RSA-SHA1) or "2" (RSA-SHA256).
//   - The canonical signing string verifies against the cert's public key.
//
// Any other state → errSNSVerification with a wrapped cause.
func (v *snsVerifier) verify(msg snsMessage) error {
	if msg.SigningCertURL == "" || msg.Signature == "" || msg.SignatureVersion == "" {
		return fmt.Errorf("%w: missing required field", errSNSVerification)
	}

	// 1. SigningCertURL hostname guard — refuse non-AWS hosts.
	parsed, err := url.Parse(msg.SigningCertURL)
	if err != nil {
		return fmt.Errorf("%w: bad cert URL: %v", errSNSVerification, err)
	}
	if parsed.Scheme != "https" {
		return fmt.Errorf("%w: cert URL not https", errSNSVerification)
	}
	if !snsSigningCertHostRegex.MatchString(parsed.Host) {
		return fmt.Errorf("%w: cert URL host %q not AWS SNS", errSNSVerification, parsed.Host)
	}

	// 2. Cert fetch (cached).
	cert, err := v.getCert(msg.SigningCertURL)
	if err != nil {
		return fmt.Errorf("%w: cert fetch: %v", errSNSVerification, err)
	}
	rsaPub, ok := cert.PublicKey.(*rsa.PublicKey)
	if !ok {
		return fmt.Errorf("%w: cert public key is not RSA", errSNSVerification)
	}

	// 3. Signature decode.
	sig, err := base64.StdEncoding.DecodeString(msg.Signature)
	if err != nil {
		return fmt.Errorf("%w: signature base64 decode: %v", errSNSVerification, err)
	}

	// 4. Build canonical string + verify.
	signingString, err := buildSNSSigningString(msg)
	if err != nil {
		return fmt.Errorf("%w: build signing string: %v", errSNSVerification, err)
	}

	var hashAlgo crypto.Hash
	var digest []byte
	switch msg.SignatureVersion {
	case "1":
		h := sha1.Sum([]byte(signingString))
		hashAlgo = crypto.SHA1
		digest = h[:]
	case "2":
		h := sha256.Sum256([]byte(signingString))
		hashAlgo = crypto.SHA256
		digest = h[:]
	default:
		return fmt.Errorf("%w: unsupported SignatureVersion %q", errSNSVerification, msg.SignatureVersion)
	}

	if err := rsa.VerifyPKCS1v15(rsaPub, hashAlgo, digest, sig); err != nil {
		return fmt.Errorf("%w: rsa verify: %v", errSNSVerification, err)
	}
	return nil
}

// getCert returns a cached certificate or fetches it via fetchCert.
func (v *snsVerifier) getCert(certURL string) (*x509.Certificate, error) {
	v.mu.RLock()
	entry, ok := v.certCache[certURL]
	v.mu.RUnlock()
	if ok && time.Since(entry.fetched) < snsCertCacheTTL {
		return entry.cert, nil
	}

	cert, err := v.fetchCert("sns", certURL)
	if err != nil {
		return nil, err
	}

	v.mu.Lock()
	v.certCache[certURL] = snsCertCacheEntry{cert: cert, fetched: time.Now()}
	v.mu.Unlock()
	return cert, nil
}

// defaultFetchCert fetches the PEM cert at certURL and returns the first
// certificate block parsed. snsMaxCertBytes caps the response size.
func (v *snsVerifier) defaultFetchCert(_ string, certURL string) (*x509.Certificate, error) {
	resp, err := v.httpClient.Get(certURL)
	if err != nil {
		return nil, fmt.Errorf("http get: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("http status %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, snsMaxCertBytes))
	if err != nil {
		return nil, fmt.Errorf("read body: %w", err)
	}
	return parseSNSCertPEM(body)
}

// parseSNSCertPEM decodes the first CERTIFICATE block from PEM-encoded
// bytes and returns the parsed x509.Certificate. Public so the test
// path can build a fake fetcher.
func parseSNSCertPEM(pemBytes []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.New("no PEM block found in cert body")
	}
	if block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("expected CERTIFICATE PEM block, got %q", block.Type)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse x509: %w", err)
	}
	return cert, nil
}

// buildSNSSigningString assembles the canonical string per AWS docs.
// Field order matters and is type-specific. Missing optional fields
// (e.g. Subject on a notification without a subject) are skipped per
// the AWS verification spec.
func buildSNSSigningString(msg snsMessage) (string, error) {
	fields, ok := snsSigningFieldsByType[msg.Type]
	if !ok {
		return "", fmt.Errorf("unknown SNS Type %q", msg.Type)
	}

	// Defensive copy so the in-place sort below doesn't mutate the
	// package-level slice. (snsSigningFieldsByType is already sorted but
	// we re-sort for safety.)
	keys := make([]string, len(fields))
	copy(keys, fields)
	sort.Strings(keys)

	var sb strings.Builder
	for _, k := range keys {
		val := snsFieldValue(msg, k)
		// SNS skips Subject when absent on Notification.
		if k == "Subject" && val == "" && msg.Type == "Notification" {
			continue
		}
		sb.WriteString(k)
		sb.WriteByte('\n')
		sb.WriteString(val)
		sb.WriteByte('\n')
	}
	return sb.String(), nil
}

// snsFieldValue is a switch from canonical field name to msg field. We
// don't reflect — keeping the switch explicit catches typos at compile
// time and makes the signing-string contract grep-able.
func snsFieldValue(msg snsMessage, key string) string {
	switch key {
	case "Message":
		return msg.Message
	case "MessageId":
		return msg.MessageID
	case "Subject":
		return msg.Subject
	case "SubscribeURL":
		return msg.SubscribeURL
	case "Timestamp":
		return msg.Timestamp
	case "Token":
		return msg.Token
	case "TopicArn":
		return msg.TopicArn
	case "Type":
		return msg.Type
	default:
		return ""
	}
}
