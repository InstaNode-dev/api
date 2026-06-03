// Webhook verification and event parsing helpers for the InstaNode GitHub App
// (P4.2). These functions are called by the HTTP handler that receives
// X-GitHub-Event deliveries; they must be called before any payload processing
// so an unverified payload is never acted on.
package github

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
)

// VerifyWebhookSignature checks the X-Hub-Signature-256 header GitHub sends
// with every delivery. It returns nil only when the HMAC-SHA256 computed from
// body and secret matches the signature in signatureHeader; any other condition
// (missing header, bad prefix, non-hex value, or mismatch) returns an error.
// Comparison is constant-time (hmac.Equal) so this is safe against timing
// attacks. Error messages never echo the secret or the expected signature.
func VerifyWebhookSignature(body []byte, signatureHeader, secret string) error {
	if signatureHeader == "" {
		return fmt.Errorf("github webhook: missing X-Hub-Signature-256 header")
	}
	const prefix = "sha256="
	if !strings.HasPrefix(signatureHeader, prefix) {
		return fmt.Errorf("github webhook: signature header has wrong prefix (expected sha256=)")
	}
	hexSig := signatureHeader[len(prefix):]
	gotSig, err := hex.DecodeString(hexSig)
	if err != nil {
		return fmt.Errorf("github webhook: signature is not valid hex")
	}

	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	wantSig := mac.Sum(nil)

	if !hmac.Equal(wantSig, gotSig) {
		return fmt.Errorf("github webhook: signature mismatch")
	}
	return nil
}

// pushEventWire is the minimal shape of a GitHub push event we need.
type pushEventWire struct {
	Ref        string `json:"ref"`
	After      string `json:"after"`
	Repository struct {
		FullName string `json:"full_name"`
	} `json:"repository"`
	Installation struct {
		ID int64 `json:"id"`
	} `json:"installation"`
}

// PushEvent holds the normalised fields from a GitHub push webhook payload.
type PushEvent struct {
	// Repo is repository.full_name, e.g. "acme/my-app".
	Repo string
	// Ref is the full ref string, e.g. "refs/heads/main" or "refs/tags/v1.0".
	Ref string
	// HeadCommitSHA is the "after" field — the SHA of the head commit after the push.
	HeadCommitSHA string
	// InstallationID is installation.id from the delivery envelope.
	InstallationID int64
}

// Branch returns the short branch name extracted from Ref (e.g. "main" from
// "refs/heads/main"). It returns "" when Ref is not a branch ref (e.g. a tag
// or an empty string).
func (e *PushEvent) Branch() string {
	const branchPrefix = "refs/heads/"
	if strings.HasPrefix(e.Ref, branchPrefix) {
		return e.Ref[len(branchPrefix):]
	}
	return ""
}

// ParsePushEvent decodes a GitHub push event payload. Only the fields InstaNode
// needs for a build dispatch are populated; every other field is ignored.
func ParsePushEvent(body []byte) (*PushEvent, error) {
	var w pushEventWire
	if err := json.Unmarshal(body, &w); err != nil {
		return nil, fmt.Errorf("github webhook: parse push event: %w", err)
	}
	return &PushEvent{
		Repo:           w.Repository.FullName,
		Ref:            w.Ref,
		HeadCommitSHA:  w.After,
		InstallationID: w.Installation.ID,
	}, nil
}

// installationEventWire is the minimal shape of a GitHub installation event.
type installationEventWire struct {
	Action       string `json:"action"`
	Installation struct {
		ID      int64 `json:"id"`
		Account struct {
			Login string `json:"login"`
		} `json:"account"`
	} `json:"installation"`
}

// InstallationEvent holds the normalised fields from a GitHub installation
// webhook payload (created / deleted / suspend / unsuspend).
type InstallationEvent struct {
	// Action is the lifecycle verb: "created", "deleted", "suspend", or "unsuspend".
	Action string
	// InstallationID is installation.id.
	InstallationID int64
	// AccountLogin is installation.account.login — the GitHub user or org that owns the install.
	AccountLogin string
}

// ParseInstallationEvent decodes a GitHub installation event payload.
func ParseInstallationEvent(body []byte) (*InstallationEvent, error) {
	var w installationEventWire
	if err := json.Unmarshal(body, &w); err != nil {
		return nil, fmt.Errorf("github webhook: parse installation event: %w", err)
	}
	return &InstallationEvent{
		Action:         w.Action,
		InstallationID: w.Installation.ID,
		AccountLogin:   w.Installation.Account.Login,
	}, nil
}
