package github

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"testing"
)

// makeHMAC computes the sha256= signature the same way GitHub does.
func makeHMAC(secret string, body []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	return "sha256=" + hex.EncodeToString(mac.Sum(nil))
}

func TestVerifyWebhookSignature(t *testing.T) {
	body := []byte(`{"action":"created"}`)
	secret := "super-secret"
	goodSig := makeHMAC(secret, body)

	tests := []struct {
		name      string
		body      []byte
		header    string
		secret    string
		wantErr   bool
		errSubstr string
	}{
		{
			name:    "valid signature",
			body:    body,
			header:  goodSig,
			secret:  secret,
			wantErr: false,
		},
		{
			name:      "empty header",
			body:      body,
			header:    "",
			secret:    secret,
			wantErr:   true,
			errSubstr: "missing",
		},
		{
			name:      "wrong prefix",
			body:      body,
			header:    "md5=" + hex.EncodeToString([]byte("whatever")),
			secret:    secret,
			wantErr:   true,
			errSubstr: "prefix",
		},
		{
			name:      "non-hex value after prefix",
			body:      body,
			header:    "sha256=notvalidhex!!",
			secret:    secret,
			wantErr:   true,
			errSubstr: "not valid hex",
		},
		{
			name:      "signature mismatch — wrong secret",
			body:      body,
			header:    makeHMAC("wrong-secret", body),
			secret:    secret,
			wantErr:   true,
			errSubstr: "mismatch",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := VerifyWebhookSignature(tc.body, tc.header, tc.secret)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error containing %q, got nil", tc.errSubstr)
				}
				if tc.errSubstr != "" && !containsStr(err.Error(), tc.errSubstr) {
					t.Fatalf("error %q does not contain %q", err.Error(), tc.errSubstr)
				}
			} else {
				if err != nil {
					t.Fatalf("expected nil error, got: %v", err)
				}
			}
		})
	}
}

func TestParsePushEvent(t *testing.T) {
	t.Run("valid push payload", func(t *testing.T) {
		payload := map[string]interface{}{
			"ref":   "refs/heads/main",
			"after": "abc123def456",
			"repository": map[string]interface{}{
				"full_name": "acme/my-app",
			},
			"installation": map[string]interface{}{
				"id": float64(42),
			},
		}
		body, _ := json.Marshal(payload)

		ev, err := ParsePushEvent(body)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if ev.Repo != "acme/my-app" {
			t.Errorf("Repo: got %q, want %q", ev.Repo, "acme/my-app")
		}
		if ev.Ref != "refs/heads/main" {
			t.Errorf("Ref: got %q, want %q", ev.Ref, "refs/heads/main")
		}
		if ev.HeadCommitSHA != "abc123def456" {
			t.Errorf("HeadCommitSHA: got %q, want %q", ev.HeadCommitSHA, "abc123def456")
		}
		if ev.InstallationID != 42 {
			t.Errorf("InstallationID: got %d, want %d", ev.InstallationID, 42)
		}
		if got := ev.Branch(); got != "main" {
			t.Errorf("Branch(): got %q, want %q", got, "main")
		}
	})

	t.Run("tag ref → Branch returns empty string", func(t *testing.T) {
		payload := map[string]interface{}{
			"ref":   "refs/tags/v1.0",
			"after": "deadbeef",
			"repository": map[string]interface{}{
				"full_name": "acme/my-app",
			},
			"installation": map[string]interface{}{
				"id": float64(1),
			},
		}
		body, _ := json.Marshal(payload)
		ev, err := ParsePushEvent(body)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got := ev.Branch(); got != "" {
			t.Errorf("Branch(): got %q, want empty string for tag ref", got)
		}
	})

	t.Run("invalid JSON", func(t *testing.T) {
		_, err := ParsePushEvent([]byte(`{not json`))
		if err == nil {
			t.Fatal("expected error for invalid JSON, got nil")
		}
	})
}

func TestParseInstallationEvent(t *testing.T) {
	t.Run("valid installation payload", func(t *testing.T) {
		payload := map[string]interface{}{
			"action": "created",
			"installation": map[string]interface{}{
				"id": float64(99),
				"account": map[string]interface{}{
					"login": "acme-org",
				},
			},
		}
		body, _ := json.Marshal(payload)

		ev, err := ParseInstallationEvent(body)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if ev.Action != "created" {
			t.Errorf("Action: got %q, want %q", ev.Action, "created")
		}
		if ev.InstallationID != 99 {
			t.Errorf("InstallationID: got %d, want %d", ev.InstallationID, 99)
		}
		if ev.AccountLogin != "acme-org" {
			t.Errorf("AccountLogin: got %q, want %q", ev.AccountLogin, "acme-org")
		}
	})

	t.Run("invalid JSON", func(t *testing.T) {
		_, err := ParseInstallationEvent([]byte(`[bad`))
		if err == nil {
			t.Fatal("expected error for invalid JSON, got nil")
		}
	})
}

// containsStr is a simple substring helper kept here to avoid importing
// strings in the test for just one call.
func containsStr(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || len(sub) == 0 ||
		func() bool {
			for i := 0; i <= len(s)-len(sub); i++ {
				if s[i:i+len(sub)] == sub {
					return true
				}
			}
			return false
		}())
}
