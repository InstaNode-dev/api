package handlers

// sns_verify_helpers_coverage_test.go — white-box coverage for the pure SNS
// helpers (sns_verify.go): parseSNSCertPEM (bad/wrong-type/garbage),
// buildSNSSigningString (notification with + without subject, confirmation,
// unknown type), and snsFieldValue (every field + default). These don't need a
// network fetch — that path (defaultFetchCert) stays uncovered by design.

import (
	"strings"
	"testing"
)

func TestParseSNSCertPEM_Arms(t *testing.T) {
	if _, err := parseSNSCertPEM([]byte("not a pem")); err == nil {
		t.Error("garbage PEM must error")
	}
	wrongType := "-----BEGIN PUBLIC KEY-----\nMFkw\n-----END PUBLIC KEY-----\n"
	if _, err := parseSNSCertPEM([]byte(wrongType)); err == nil {
		t.Error("wrong PEM block type must error")
	}
	// A CERTIFICATE block with non-cert bytes → x509 parse error.
	badCert := "-----BEGIN CERTIFICATE-----\nQUJD\n-----END CERTIFICATE-----\n"
	if _, err := parseSNSCertPEM([]byte(badCert)); err == nil {
		t.Error("malformed certificate bytes must error")
	}
}

func TestBuildSNSSigningString_Arms(t *testing.T) {
	// Unknown type → error.
	if _, err := buildSNSSigningString(snsMessage{Type: "Bogus"}); err == nil {
		t.Error("unknown SNS type must error")
	}

	// Notification with subject → includes Subject line.
	withSub := snsMessage{
		Type: "Notification", MessageID: "m1", Message: "hi",
		Subject: "subj", Timestamp: "t", TopicArn: "arn",
	}
	s, err := buildSNSSigningString(withSub)
	if err != nil {
		t.Fatalf("notification w/ subject: %v", err)
	}
	if !strings.Contains(s, "Subject\nsubj\n") {
		t.Errorf("subject not included: %q", s)
	}

	// Notification WITHOUT subject → Subject line skipped.
	noSub := withSub
	noSub.Subject = ""
	s2, err := buildSNSSigningString(noSub)
	if err != nil {
		t.Fatalf("notification no subject: %v", err)
	}
	if strings.Contains(s2, "Subject\n") {
		t.Errorf("absent subject must be skipped: %q", s2)
	}

	// SubscriptionConfirmation → includes Token + SubscribeURL.
	conf := snsMessage{
		Type: "SubscriptionConfirmation", MessageID: "m2", Message: "x",
		Token: "tok", SubscribeURL: "https://sub", Timestamp: "t", TopicArn: "arn",
	}
	s3, err := buildSNSSigningString(conf)
	if err != nil {
		t.Fatalf("subscription confirmation: %v", err)
	}
	if !strings.Contains(s3, "Token\ntok\n") || !strings.Contains(s3, "SubscribeURL\nhttps://sub\n") {
		t.Errorf("confirmation missing Token/SubscribeURL: %q", s3)
	}
}

func TestSNSFieldValue_AllFields(t *testing.T) {
	msg := snsMessage{
		Message: "M", MessageID: "MID", Subject: "S", SubscribeURL: "U",
		Timestamp: "T", Token: "TOK", TopicArn: "ARN", Type: "Notification",
	}
	cases := map[string]string{
		"Message": "M", "MessageId": "MID", "Subject": "S", "SubscribeURL": "U",
		"Timestamp": "T", "Token": "TOK", "TopicArn": "ARN", "Type": "Notification",
		"UnknownField": "",
	}
	for k, want := range cases {
		if got := snsFieldValue(msg, k); got != want {
			t.Errorf("snsFieldValue(%q) = %q; want %q", k, got, want)
		}
	}
}
