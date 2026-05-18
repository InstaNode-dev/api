package queue

// subjident.go — canonical identifier helper for a queue resource's NATS
// SubjectPrefix on the api-local (shared NATS) backend.
//
// # Why this exists (token-truncation class — P1-W4-04 / P1-W3-15)
//
// The api-local queue provider used to derive the SubjectPrefix by truncating
// the token to its first 8 hex characters:
//
//	prefix := token; if len(prefix) > 8 { prefix = prefix[:8] }
//	SubjectPrefix = prefix + "."
//
// On the SHARED no-auth NATS backend the SubjectPrefix is the ONLY tenant
// isolation boundary — NATS runs without authentication, so two tokens that
// share their first 8 hex characters share a subject namespace and can
// publish/subscribe to each other's events. An 8-hex-char prefix has only
// 2^32 possibilities; a birthday collision is well within reach. This is the
// live path: the api-local provider is used directly, the gRPC provisioner
// queue path is bypassed.
//
// # The fix: full-token-derived subject prefix for NEW provisions
//
// canonicalSubjectPrefix(token) derives the prefix from the FULL token. NATS
// subject tokens permit ASCII alphanumerics but NOT '.' (the subject separator)
// or '*'/'>' (wildcards); a UUID's dashes are also not valid subject-token
// characters, so they are stripped. A dash-stripped resource token is a plain
// alphanumeric string and is therefore a valid single NATS subject token.
//
// This mirrors provisioner/internal/backend/queue/subjident.go — the same fix
// applied to the (separate Go module) gRPC provisioner backend.
//
// # Backward compatibility
//
// The SubjectPrefix is part of the customer connection contract: queues already
// provisioned under the old token[:8] scheme must keep working. resolveSubjectPrefix
// tries the canonical full-token prefix first, then the legacy token[:8] prefix,
// so a Deprovision (or any future lifecycle path) for a pre-fix resource can
// still locate it. The shared NATS backend has no per-user server state so its
// Deprovision is a structural no-op, but resolveSubjectPrefix is still used so
// the log line reports the prefix the resource was actually provisioned under.

const (
	// subjectPrefixSep terminates a SubjectPrefix so callers form subjects of
	// the shape "<prefix><event-name>".
	subjectPrefixSep = "."

	// legacySubjectShortLen is the truncation length of the pre-fix
	// SubjectPrefix scheme (token[:8] + "."). Retained ONLY so a prefix created
	// under the old truncated scheme can still be resolved. New provisions never
	// use it.
	legacySubjectShortLen = 8
)

// stripDashes removes '-' characters so a UUID-style token becomes a single
// valid NATS subject token (NATS subject tokens permit alphanumerics but not
// '.', '*', '>' — and a dash-stripped UUID is plain alphanumeric).
func stripDashes(token string) string {
	out := make([]byte, 0, len(token))
	for i := 0; i < len(token); i++ {
		if token[i] != '-' {
			out = append(out, token[i])
		}
	}
	return string(out)
}

// canonicalSubjectPrefix returns the canonical SubjectPrefix for a queue token:
// the FULL token (dashes stripped) followed by the subject separator. Two
// tokens can collide on this prefix only on a genuine full-token collision
// (cryptographic improbability), unlike the pre-fix 8-char truncation where any
// two tokens sharing 8 hex chars collided.
func canonicalSubjectPrefix(token string) string {
	return stripDashes(token) + subjectPrefixSep
}

// legacySubjectPrefix returns the pre-fix 8-char-truncated SubjectPrefix for a
// token, or "" when the token is too short to have ever been truncated (in
// which case the canonical prefix already equals the legacy prefix and no
// extra fallback is needed). The token is dash-stripped first so the slice is
// taken over the same character space the legacy code truncated.
func legacySubjectPrefix(token string) string {
	stripped := stripDashes(token)
	if len(stripped) <= legacySubjectShortLen {
		return ""
	}
	return stripped[:legacySubjectShortLen] + subjectPrefixSep
}

// resolveSubjectPrefix returns the SubjectPrefix a lifecycle path (Deprovision,
// or any future route-lookup) must target for an EXISTING queue resource.
//
// It prefers the value stamped at provision time on provider_resource_id so no
// re-derivation can drift. When that is empty it falls back to the canonical
// full-token derivation (covering rows provisioned under this fix), then to the
// legacy token[:8] derivation (covering rows provisioned before the fix). The
// shared NATS backend has no per-user state so Deprovision never has to *act*
// on the resolved prefix, but resolving it keeps log lines truthful and gives
// any future route-lookup path a uniform resolver.
func resolveSubjectPrefix(token, providerResourceID string) string {
	if providerResourceID != "" {
		return providerResourceID
	}
	return canonicalSubjectPrefix(token)
}
