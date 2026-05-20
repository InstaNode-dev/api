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
		{"with url", "https://api.instanode.dev/start?t=jwt"},
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
		{"with url and expiry", "https://api.instanode.dev/start?t=jwt", exp},
		{"with url no expiry", "https://api.instanode.dev/start?t=jwt", time.Time{}},
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
		// B18 M2 (BugBash 2026-05-20): sanitizeName no longer truncates at
		// 120 bytes — requireName's 64-rune gate is the single source of
		// truth on length. sanitizeName is now responsible only for
		// stripping control + HTML-special chars; length enforcement
		// (and the 400 invalid_name response) belongs to requireName.
		{"passes 200-char input through unchanged", strings.Repeat("a", 200), strings.Repeat("a", 200)},
		{"strips angle brackets, length preserved", "<" + strings.Repeat("a", 200) + ">", strings.Repeat("a", 200)},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := sanitizeName(c.in)
			if err != nil {
				t.Fatalf("sanitizeName(%q) unexpected error: %v", c.in, err)
			}
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

// TestSanitizeName_RejectsInvalidUTF8 covers Wave FIX-D #Q70. JSON-decoded
// strings can contain invalid UTF-8 bytes (Go's encoder replaces them with
// U+FFFD when re-serialising, but the raw byte slice passed through to
// resources.name TEXT until this guard landed). We reject at the boundary.
func TestSanitizeName_RejectsInvalidUTF8(t *testing.T) {
	// 0xff is not a valid UTF-8 byte.
	invalid := string([]byte{0xff, 0xfe, 'h', 'i'})
	got, err := sanitizeName(invalid)
	if err == nil {
		t.Fatalf("sanitizeName(invalid utf-8) returned (%q, nil) — expected an error", got)
	}
}

// TestSanitizeName_StripsControlChars covers Wave FIX-D #Q71. CRLF + other
// C0 control characters silently passed through before; they break log lines
// and audit summaries. Stripped (not rejected) so a stray \r from a paste
// doesn't 400 the caller.
func TestSanitizeName_StripsControlChars(t *testing.T) {
	cases := []struct {
		name, in, want string
	}{
		{"CRLF", "ab\r\ncd", "abcd"},
		{"NUL", "a\x00b", "ab"},
		{"BEL", "a\x07b", "ab"},
		{"DEL", "a\x7fb", "ab"},
		{"TAB", "a\tb", "ab"},
		{"mixed control + html", "<\x00name\r>", "name"},
		{"keeps high ascii", "café", "café"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := sanitizeName(c.in)
			if err != nil {
				t.Fatalf("sanitizeName(%q) unexpected error: %v", c.in, err)
			}
			if got != c.want {
				t.Errorf("sanitizeName(%q) = %q, want %q", c.in, got, c.want)
			}
		})
	}
}

// TestEnvOverrideReason covers Wave FIX-D #Q15. When the caller sends no env
// (neither query nor body) and we default to EnvDefault, the reason field
// surfaces "default_no_env_specified" so the agent knows the bucket choice
// wasn't theirs. When they pass an explicit env, the reason is empty.
func TestEnvOverrideReason(t *testing.T) {
	cases := []struct {
		name                       string
		rawQuery, rawBody, resolved string
		want                       string
	}{
		{"empty defaults to development", "", "", "development", "default_no_env_specified"},
		{"explicit production not an override", "", "production", "production", ""},
		{"explicit development not an override", "", "development", "development", ""},
		{"query wins", "staging", "production", "staging", ""},
		{"empty body + production resolved (defensive — shouldn't happen)", "", "", "production", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := envOverrideReason(c.rawQuery, c.rawBody, c.resolved)
			if got != c.want {
				t.Errorf("envOverrideReason(%q,%q,%q) = %q, want %q",
					c.rawQuery, c.rawBody, c.resolved, got, c.want)
			}
		})
	}
}
