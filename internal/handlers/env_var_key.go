package handlers

import "strconv"

// env_var_key.go — POSIX env-var key validation for user-supplied env_vars.
//
// T13 P2-T13-04 (BugHunt 2026-05-20): the `env_vars` and stack `env`
// maps accepted by /deploy/new and /stacks/new were forwarded straight
// into a `corev1.EnvVar{Name:k}` slice. K8s rejects names that fail the
// C_IDENTIFIER regex at apply time, but that failure surfaced as an
// opaque async build error in the runDeploy goroutine — the caller saw
// a 202, then a silent build-failure minutes later, with no signal that
// the cause was a malformed env-var key.
//
// `isValidEnvKey` validates against the POSIX env-var rule:
//
//     [A-Z_][A-Z0-9_]*
//
// rather than the looser C_IDENTIFIER (`[A-Za-z_][A-Za-z0-9_]*`) k8s
// honours. POSIX upper-case-only is the standard portable shape
// (`man env`); it covers every legitimate user env var while rejecting
// the most common typos (lowercase, hyphens, dots). Callers that
// genuinely need lowercase keys (rare — typically a misuse of env vars
// for non-env config) can lift the constraint with prejudice.
//
// We deliberately accept the existing carve-outs:
//   - empty key  → caller's deserialiser already rejects
//   - `_`-prefix → already silently dropped (reserved for internal use)
// so the validator only fires on keys that look like env vars but
// aren't POSIX-compliant.
//
// Returns (false, key) for the first invalid key encountered so the
// 400 response can name the offender. (true, "") on full success.

const maxEnvKeyLen = 256 // defensive upper bound; k8s itself caps at 253

// isValidEnvKey reports whether k matches `^[A-Z_][A-Z0-9_]*$`.
//
// Hot path — avoid regexp.Compile cost on every request by walking
// runes directly. Matches the regex stated in the file header.
func isValidEnvKey(k string) bool {
	if k == "" || len(k) > maxEnvKeyLen {
		return false
	}
	for i, r := range k {
		switch {
		case r == '_':
			// always allowed (first or interior)
		case r >= 'A' && r <= 'Z':
			// always allowed
		case r >= '0' && r <= '9':
			if i == 0 {
				return false // POSIX: must not lead with a digit
			}
		default:
			return false
		}
	}
	return true
}

// quoteForError safely JSON-quotes a (possibly attacker-controlled)
// env-var key for inclusion in an error message. strconv.Quote escapes
// any control characters / quotes / non-printable bytes so the offender
// can be named in the 400 body without log-injection.
func quoteForError(s string) string {
	return strconv.Quote(s)
}

// validateEnvVarKeys returns (true, "") if every non-reserved key in m
// satisfies isValidEnvKey, otherwise (false, "<offending-key>"). Keys
// prefixed with "_" are skipped — they're internal reserved names
// dropped silently by the deploy/stack handlers (see deploy.go).
//
// Order of map iteration is unspecified; tests rely on validity, not
// on which invalid key is named first.
func validateEnvVarKeys(m map[string]string) (bool, string) {
	for k := range m {
		// Skip reserved underscore-prefix keys — they're stripped by
		// callers before reaching k8s, so a malformed `_x.y` never
		// becomes a k8s apply failure.
		if len(k) > 0 && k[0] == '_' {
			continue
		}
		if !isValidEnvKey(k) {
			return false, k
		}
	}
	return true, ""
}
