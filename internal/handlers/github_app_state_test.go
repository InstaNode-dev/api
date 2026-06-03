package handlers

// github_app_state_test.go — unit tests for the GitHub App install state token
// (sign/verify), P4.1. No DB.

import (
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v4"
)

const ghStateSecret = "test-github-app-state-secret-0123456789"

func TestGitHubAppState_RoundTrip(t *testing.T) {
	tok, err := signGitHubAppState(ghStateSecret, "team-abc", time.Now())
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	got, err := verifyGitHubAppState(ghStateSecret, tok)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if got != "team-abc" {
		t.Errorf("team_id = %q want team-abc", got)
	}
}

func TestGitHubAppState_Rejections(t *testing.T) {
	// empty
	if _, err := verifyGitHubAppState(ghStateSecret, ""); err == nil {
		t.Error("empty state must error")
	}
	// expired (signed 1h in the past → exp 50m ago)
	expired, _ := signGitHubAppState(ghStateSecret, "t", time.Now().Add(-time.Hour))
	if _, err := verifyGitHubAppState(ghStateSecret, expired); err == nil {
		t.Error("expired state must error")
	}
	// wrong secret
	good, _ := signGitHubAppState(ghStateSecret, "t", time.Now())
	if _, err := verifyGitHubAppState("a-different-secret-aaaaaaaaaaaaaaaa", good); err == nil {
		t.Error("wrong secret must error")
	}
	// garbage
	if _, err := verifyGitHubAppState(ghStateSecret, "not.a.jwt"); err == nil {
		t.Error("garbage must error")
	}
}

func TestGitHubAppState_PurposeAndTeamGuards(t *testing.T) {
	// wrong purpose
	wrongPurpose := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"team_id": "t", "purpose": "session", "exp": time.Now().Add(time.Hour).Unix(),
	})
	wp, _ := wrongPurpose.SignedString([]byte(ghStateSecret))
	if _, err := verifyGitHubAppState(ghStateSecret, wp); err == nil {
		t.Error("wrong purpose must error")
	}
	// missing team_id
	noTeam := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"purpose": githubAppStatePurpose, "exp": time.Now().Add(time.Hour).Unix(),
	})
	nt, _ := noTeam.SignedString([]byte(ghStateSecret))
	if _, err := verifyGitHubAppState(ghStateSecret, nt); err == nil {
		t.Error("missing team_id must error")
	}
}

func TestGitHubAppState_RejectsNonHS256(t *testing.T) {
	// A token using "none" alg must be rejected by WithValidMethods.
	tok := jwt.NewWithClaims(jwt.SigningMethodNone, jwt.MapClaims{
		"team_id": "t", "purpose": githubAppStatePurpose, "exp": time.Now().Add(time.Hour).Unix(),
	})
	none, _ := tok.SignedString(jwt.UnsafeAllowNoneSignatureType)
	if _, err := verifyGitHubAppState(ghStateSecret, none); err == nil {
		t.Error("alg=none must be rejected")
	}
}
