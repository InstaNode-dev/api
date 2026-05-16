package handlers

// deploy_env_redact.go — Outbound redaction of sensitive env-var values in
// deployment API responses.
//
// Defence-in-depth layer 1 of 2: the API redacts secret-bearing values
// before they leave the server. The dashboard provides layer 2 (mask-by-
// default with a per-row reveal toggle). Even if the dashboard layer is
// bypassed (e.g. a raw curl), credentials never appear in cleartext.
//
// ONLY the OUTBOUND JSON is redacted. The stored value in the deployments
// row (env_vars JSONB) is untouched — the build pipeline must read the
// plaintext to inject it into the container.
//
// Two-pass heuristic:
//  1. Key heuristic  — uppercase key contains any of secretKeyFragments,
//     or ends with any of secretKeySuffixes → mask.
//  2. Value heuristic — value matches a credential-bearing URL scheme
//     (scheme://...@... pattern) → mask.
//
// vault:// refs are left untouched: they are already safe (no credential
// embedded) and the dashboard needs to read them to show the "vault" badge.

import (
	"regexp"
	"strings"
)

// envRedactedMask is the replacement string used for sensitive env values
// in outbound API responses. Short and unambiguous — agents can branch on it.
const envRedactedMask = "***"

// secretKeyFragments is the set of substrings that, when present in an
// uppercased env-var key, classify the value as a secret. Use named
// constants — not scattered string literals — per project convention.
//
// Extend this slice (not inline call sites) when adding new heuristics.
var secretKeyFragments = []string{
	"SECRET",
	"PASSWORD",
	"PASSWD",
	"PWD",
	"TOKEN",
	"_KEY",
	"APIKEY",
}

// secretKeySuffixes is the set of uppercase suffixes that classify a value
// as a secret regardless of what precedes them. Kept separate from
// secretKeyFragments so the match logic stays readable.
var secretKeySuffixes = []string{
	"URL",
	"URI",
	"DSN",
}

// credentialURLRe matches any URL scheme that may carry credentials
// (user:pass@host) — these schemes are the ones resource_bindings resolves
// from AES-encrypted connection strings. The pattern requires an "@" so
// scheme-only refs like "redis://localhost" (no credentials) pass through.
//
// Anchored at the start; does not require end-of-string so embedded newlines
// or trailing content don't defeat the check.
var credentialURLRe = regexp.MustCompile(
	`^(?:postgres|postgresql|rediss?|mongodb(?:\+srv)?|amqps?|mysql)://[^@]+@`,
)

// vaultRefRe matches vault://env/KEY refs, which are already safe to surface.
// This mirrors the frontend VAULT_REF_RE so we never accidentally redact a
// vault ref (which contains no credentials).
var vaultRefRe = regexp.MustCompile(`^vault://`)

// isSecretKey reports whether the env-var key should be treated as a secret
// based on the key name alone. Case-insensitive.
func isSecretKey(key string) bool {
	upper := strings.ToUpper(key)
	for _, frag := range secretKeyFragments {
		if strings.Contains(upper, frag) {
			return true
		}
	}
	for _, suf := range secretKeySuffixes {
		if strings.HasSuffix(upper, suf) {
			return true
		}
	}
	return false
}

// isCredentialURL reports whether the value looks like a connection string
// that embeds credentials (scheme://user:pass@host pattern).
func isCredentialURL(value string) bool {
	return credentialURLRe.MatchString(value)
}

// redactEnvVars returns a copy of the env map with sensitive values replaced
// by envRedactedMask. vault:// refs are always left untouched.
//
// The original map is never mutated — a new map is always returned.
func redactEnvVars(env map[string]string) map[string]string {
	if len(env) == 0 {
		return env
	}
	out := make(map[string]string, len(env))
	for k, v := range env {
		switch {
		case vaultRefRe.MatchString(v):
			// vault refs are safe — pass through unchanged.
			out[k] = v
		case isSecretKey(k) || isCredentialURL(v):
			out[k] = envRedactedMask
		default:
			out[k] = v
		}
	}
	return out
}
