package handlers

import (
	"strings"
	"testing"
	"time"
)

// These guard the project decision recorded in
// memory/project_no_trial_pay_day_one.md: anonymous (24h TTL) is the trial;
// hobby/pro/team are paid from day one. Prior copy said "14-day trial, then
// $9/mo" — that's the bug PR #9 fixed. These tests stop it regressing.

func TestUpgradeNote_DoesNotMentionTrial(t *testing.T) {
	cases := []struct {
		name, in string
	}{
		{"with url", "https://instanode.dev/start?t=jwt"},
		{"empty url falls back to bare link", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := upgradeNote(c.in)
			lower := strings.ToLower(got)
			for _, banned := range []string{"14-day trial", "14 day trial", "14-day", "trial,"} {
				if strings.Contains(lower, banned) {
					t.Errorf("upgradeNote(%q) contains banned phrase %q — copy regressed to trial framing; got: %s", c.in, banned, got)
				}
			}
			if !strings.Contains(got, "Claim to keep") {
				t.Errorf("upgradeNote must include 'Claim to keep' CTA; got: %s", got)
			}
			if !strings.Contains(got, "$9/mo") {
				t.Errorf("upgradeNote must include the $9/mo price anchor; got: %s", got)
			}
			if strings.Contains(got, "instant.dev/start") {
				t.Errorf("upgradeNote leaked old domain instant.dev/start; got: %s", got)
			}
		})
	}
}

func TestLimitExceededNote_DoesNotMentionTrial(t *testing.T) {
	exp := time.Now().Add(20 * time.Hour)
	cases := []struct {
		name, url string
		expires   time.Time
	}{
		{"with url and expiry", "https://instanode.dev/start?t=jwt", exp},
		{"with url no expiry", "https://instanode.dev/start?t=jwt", time.Time{}},
		{"empty url with expiry", "", exp},
		{"empty url no expiry", "", time.Time{}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := limitExceededNote(c.url, c.expires)
			for _, banned := range []string{"14-day trial", "14 day trial", "14-day", "trial,"} {
				if strings.Contains(strings.ToLower(got), banned) {
					t.Errorf("limitExceededNote contains banned phrase %q; got: %s", banned, got)
				}
			}
			if !strings.Contains(got, "Returning your existing resource") {
				t.Errorf("limitExceededNote must explain dedup; got: %s", got)
			}
			if !strings.Contains(got, "Claim to keep") {
				t.Errorf("limitExceededNote must include 'Claim to keep' CTA; got: %s", got)
			}
			if strings.Contains(got, "instant.dev/start") {
				t.Errorf("limitExceededNote leaked old domain; got: %s", got)
			}
		})
	}
}
