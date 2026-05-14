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

// TestSanitizeName_StripsXSSVectors is the W9 audit regression test: resource
// names land in audit_log.summary (which the dashboard renders via
// dangerouslySetInnerHTML on its activity-feed fallback path) and in JSON
// responses across CLI/email/slack surfaces. The strip is defence-in-depth —
// even if downstream renderers later add escaping, the four HTML-special
// characters never make it into stored state.
//
// `&` is deliberately preserved (legitimate in names like "Smith & Co
// Postgres"); React's text rendering already escapes it.
func TestSanitizeName_StripsXSSVectors(t *testing.T) {
	cases := []struct {
		name, in, want string
	}{
		{"plain name", "my-db", "my-db"},
		{"empty", "", ""},
		{"strips angle brackets", "<script>alert(1)</script>", "scriptalert(1)/script"},
		{"strips double quote", "name\"value", "namevalue"},
		{"strips single quote", "it's mine", "its mine"},
		{"strips mixed", "<img src=\"x\" onerror='alert(1)'>", "img src=x onerror=alert(1)"},
		{"preserves ampersand", "Smith & Co", "Smith & Co"},
		{"caps at 120 chars", strings.Repeat("a", 200), strings.Repeat("a", 120)},
		{"strip before truncate", "<" + strings.Repeat("a", 200) + ">", strings.Repeat("a", 120)},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := sanitizeName(c.in)
			if got != c.want {
				t.Errorf("sanitizeName(%q) = %q, want %q", c.in, got, c.want)
			}
			// Hard assertion: stripped output MUST NOT contain any HTML-special char.
			for _, banned := range []string{"<", ">", "\"", "'"} {
				if strings.Contains(got, banned) {
					t.Errorf("sanitizeName(%q) leaked %q in output %q — XSS sink regressed", c.in, banned, got)
				}
			}
		})
	}
}
