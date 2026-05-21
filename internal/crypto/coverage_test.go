package crypto_test

import (
	"encoding/base64"
	"encoding/hex"
	"errors"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"instant.dev/internal/crypto"
)

const coverageKeyHexA = "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"
const coverageKeyHexB = "2122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f40"
const coverageJWTSecret = "coverage-jwt-secret-32-bytes-min!!!"

func mustKey(t *testing.T, h string) []byte {
	t.Helper()
	k, err := crypto.ParseAESKey(h)
	require.NoError(t, err)
	return k
}

// ─────────────────────────────────────────────────────────────────
// Error wrapping — Error() + Unwrap() across all three error types.
// ─────────────────────────────────────────────────────────────────

func TestErrDecrypt_ErrorAndUnwrap(t *testing.T) {
	root := errors.New("root cause")
	e := &crypto.ErrDecrypt{Cause: root}

	assert.Contains(t, e.Error(), "aes-gcm decrypt failed")
	assert.Contains(t, e.Error(), "root cause")
	assert.ErrorIs(t, e, root, "Unwrap must expose the root cause via errors.Is")
}

func TestErrEncrypt_ErrorAndUnwrap(t *testing.T) {
	root := errors.New("encrypt-root")
	e := &crypto.ErrEncrypt{Cause: root}

	assert.Contains(t, e.Error(), "aes-gcm encrypt failed")
	assert.Contains(t, e.Error(), "encrypt-root")
	assert.ErrorIs(t, e, root)
}

func TestErrJWTSign_ErrorAndUnwrap(t *testing.T) {
	root := errors.New("sign-root")
	e := &crypto.ErrJWTSign{Cause: root}

	assert.Contains(t, e.Error(), "jwt sign failed")
	assert.Contains(t, e.Error(), "sign-root")
	assert.ErrorIs(t, e, root)
}

func TestErrJWTVerify_ErrorAndUnwrap(t *testing.T) {
	root := errors.New("verify-root")
	e := &crypto.ErrJWTVerify{Cause: root}

	assert.Contains(t, e.Error(), "jwt verify failed")
	assert.Contains(t, e.Error(), "verify-root")
	assert.ErrorIs(t, e, root)
}

func TestErrTokenGenerate_ErrorAndUnwrap(t *testing.T) {
	root := errors.New("token-root")
	e := &crypto.ErrTokenGenerate{Cause: root}

	assert.Contains(t, e.Error(), "token generation failed")
	assert.Contains(t, e.Error(), "token-root")
	assert.ErrorIs(t, e, root)
}

// ─────────────────────────────────────────────────────────────────
// AES — Decrypt error branches.
// ─────────────────────────────────────────────────────────────────

func TestAES_Decrypt_BadBase64(t *testing.T) {
	key := mustKey(t, coverageKeyHexA)
	_, err := crypto.Decrypt(key, "!!!not-base64!!!")
	require.Error(t, err)
	var de *crypto.ErrDecrypt
	assert.ErrorAs(t, err, &de)
}

func TestAES_Decrypt_BadKeyLength(t *testing.T) {
	// 24-byte key fails aes.NewCipher (only 16/24/32 valid — 24 IS valid for AES-192).
	// Use a non-AES length to force aes.NewCipher to fail.
	pt := "hello"
	keyA := mustKey(t, coverageKeyHexA)
	ct, err := crypto.Encrypt(keyA, pt)
	require.NoError(t, err)

	// 5-byte key — invalid for AES.
	badKey := []byte{1, 2, 3, 4, 5}
	_, err = crypto.Decrypt(badKey, ct)
	require.Error(t, err)
	var de *crypto.ErrDecrypt
	assert.ErrorAs(t, err, &de)
}

func TestAES_Encrypt_BadKeyLength(t *testing.T) {
	badKey := []byte{1, 2, 3, 4, 5}
	_, err := crypto.Encrypt(badKey, "hello")
	require.Error(t, err)
	var ee *crypto.ErrEncrypt
	assert.ErrorAs(t, err, &ee)
}

func TestAES_Decrypt_TooShortCiphertext(t *testing.T) {
	key := mustKey(t, coverageKeyHexA)
	// 4 raw bytes — far shorter than a 12-byte GCM nonce.
	short := base64.URLEncoding.EncodeToString([]byte{0xaa, 0xbb, 0xcc, 0xdd})
	_, err := crypto.Decrypt(key, short)
	require.Error(t, err)
	var de *crypto.ErrDecrypt
	assert.ErrorAs(t, err, &de)
	assert.Contains(t, err.Error(), "ciphertext too short")
}

// ─────────────────────────────────────────────────────────────────
// AES Keyring — happy path + error branches + multi-key fallthrough.
// ─────────────────────────────────────────────────────────────────

func TestKeyring_NewKeyring_Valid(t *testing.T) {
	keyA := mustKey(t, coverageKeyHexA)
	keyB := mustKey(t, coverageKeyHexB)

	kr, err := crypto.NewKeyring('2', map[byte][]byte{'1': keyA, '2': keyB})
	require.NoError(t, err)
	require.NotNil(t, kr)
	assert.Equal(t, byte('2'), kr.ActiveVersion())
}

func TestKeyring_NewKeyring_ActiveOutOfRange(t *testing.T) {
	keyA := mustKey(t, coverageKeyHexA)
	_, err := crypto.NewKeyring('0', map[byte][]byte{'1': keyA})
	require.Error(t, err)

	_, err = crypto.NewKeyring('a', map[byte][]byte{'1': keyA})
	require.Error(t, err)
}

func TestKeyring_NewKeyring_EmptyKeys(t *testing.T) {
	_, err := crypto.NewKeyring('1', nil)
	require.Error(t, err)

	_, err = crypto.NewKeyring('1', map[byte][]byte{})
	require.Error(t, err)
}

func TestKeyring_NewKeyring_VersionOutOfRange(t *testing.T) {
	keyA := mustKey(t, coverageKeyHexA)
	_, err := crypto.NewKeyring('1', map[byte][]byte{'1': keyA, 'x': keyA})
	require.Error(t, err)
}

func TestKeyring_NewKeyring_WrongKeyLength(t *testing.T) {
	bad := []byte{1, 2, 3}
	_, err := crypto.NewKeyring('1', map[byte][]byte{'1': bad})
	require.Error(t, err)
}

func TestKeyring_NewKeyring_ActiveMissingFromKeys(t *testing.T) {
	keyA := mustKey(t, coverageKeyHexA)
	_, err := crypto.NewKeyring('2', map[byte][]byte{'1': keyA})
	require.Error(t, err)
}

func TestKeyring_EncryptVersioned_NilKeyring(t *testing.T) {
	_, err := crypto.EncryptVersioned(nil, "x")
	require.Error(t, err)
	var ee *crypto.ErrEncrypt
	assert.ErrorAs(t, err, &ee)
}

func TestKeyring_EncryptVersioned_Roundtrip(t *testing.T) {
	keyA := mustKey(t, coverageKeyHexA)
	keyB := mustKey(t, coverageKeyHexB)
	kr, err := crypto.NewKeyring('2', map[byte][]byte{'1': keyA, '2': keyB})
	require.NoError(t, err)

	envelope, err := crypto.EncryptVersioned(kr, "secret-payload")
	require.NoError(t, err)
	require.True(t, strings.HasPrefix(envelope, "v2."), "envelope must carry the active version: %s", envelope)

	got, err := kr.Decrypt(envelope)
	require.NoError(t, err)
	assert.Equal(t, "secret-payload", got)
}

func TestKeyring_EncryptVersioned_AllVersionsRoundtrip(t *testing.T) {
	keyA := mustKey(t, coverageKeyHexA)
	for _, v := range []byte{'1', '5', '9'} {
		kr, err := crypto.NewKeyring(v, map[byte][]byte{v: keyA})
		require.NoError(t, err, "version %q", v)

		envelope, err := crypto.EncryptVersioned(kr, "payload")
		require.NoError(t, err)
		assert.True(t, strings.HasPrefix(envelope, "v"+string(v)+"."), "envelope %q", envelope)

		got, err := kr.Decrypt(envelope)
		require.NoError(t, err)
		assert.Equal(t, "payload", got)
	}
}

func TestKeyring_Decrypt_OldKeyFallthrough(t *testing.T) {
	// Key-rotation scenario: data was encrypted under v1, then active flipped to v2.
	// The keyring must still decrypt the v1 envelope.
	keyA := mustKey(t, coverageKeyHexA)
	keyB := mustKey(t, coverageKeyHexB)

	krV1, err := crypto.NewKeyring('1', map[byte][]byte{'1': keyA})
	require.NoError(t, err)
	envelopeV1, err := crypto.EncryptVersioned(krV1, "rotated-secret")
	require.NoError(t, err)

	// Now active=v2, but v1 still in the keyring as legacy decrypt-only.
	krRotated, err := crypto.NewKeyring('2', map[byte][]byte{'1': keyA, '2': keyB})
	require.NoError(t, err)

	got, err := krRotated.Decrypt(envelopeV1)
	require.NoError(t, err, "rotated keyring must still decrypt old v1 envelope")
	assert.Equal(t, "rotated-secret", got)

	// New writes under the rotated keyring are v2.
	envelopeV2, err := crypto.EncryptVersioned(krRotated, "new-secret")
	require.NoError(t, err)
	got2, err := krRotated.Decrypt(envelopeV2)
	require.NoError(t, err)
	assert.Equal(t, "new-secret", got2)
}

func TestKeyring_Decrypt_LegacyUnversioned(t *testing.T) {
	// Envelope without a "vN." prefix — produced by raw Encrypt before rotation
	// was introduced. Keyring.Decrypt must fall back to the active key.
	keyA := mustKey(t, coverageKeyHexA)
	legacy, err := crypto.Encrypt(keyA, "pre-rotation-secret")
	require.NoError(t, err)
	require.False(t, strings.HasPrefix(legacy, "v"))

	kr, err := crypto.NewKeyring('1', map[byte][]byte{'1': keyA})
	require.NoError(t, err)

	got, err := kr.Decrypt(legacy)
	require.NoError(t, err)
	assert.Equal(t, "pre-rotation-secret", got)
}

func TestKeyring_Decrypt_NilKeyring(t *testing.T) {
	var kr *crypto.Keyring
	_, err := kr.Decrypt("v1.foo")
	require.Error(t, err)
	var de *crypto.ErrDecrypt
	assert.ErrorAs(t, err, &de)
}

func TestKeyring_Decrypt_UnknownVersion(t *testing.T) {
	keyA := mustKey(t, coverageKeyHexA)
	kr, err := crypto.NewKeyring('1', map[byte][]byte{'1': keyA})
	require.NoError(t, err)

	// Synthesize a v9 envelope when keyring only has v1.
	body, err := crypto.Encrypt(keyA, "payload")
	require.NoError(t, err)
	envelope := "v9." + body

	_, err = kr.Decrypt(envelope)
	require.Error(t, err)
	var de *crypto.ErrDecrypt
	assert.ErrorAs(t, err, &de)
	assert.Contains(t, err.Error(), "unknown key version")
}

func TestKeyring_ActiveVersion_Nil(t *testing.T) {
	var kr *crypto.Keyring
	assert.Equal(t, byte(0), kr.ActiveVersion())
}

func TestKeyring_Decrypt_LegacyDecryptViaLegacyHelper(t *testing.T) {
	// The legacy `Decrypt(key, encoded)` helper tolerates a "vN." prefix so old
	// callers can read a versioned envelope. Cover that branch.
	keyA := mustKey(t, coverageKeyHexA)
	kr, err := crypto.NewKeyring('1', map[byte][]byte{'1': keyA})
	require.NoError(t, err)
	envelope, err := crypto.EncryptVersioned(kr, "v-prefixed-payload")
	require.NoError(t, err)
	require.True(t, strings.HasPrefix(envelope, "v1."))

	got, err := crypto.Decrypt(keyA, envelope)
	require.NoError(t, err, "legacy Decrypt must strip vN. prefix and decode")
	assert.Equal(t, "v-prefixed-payload", got)
}

// ─────────────────────────────────────────────────────────────────
// JWT — SignJWT / VerifyJWT (the basic InstantClaims path; the
// onboarding path is already covered by jwt_test.go).
// ─────────────────────────────────────────────────────────────────

func TestSignJWT_AutoGeneratesJTI(t *testing.T) {
	claims := crypto.InstantClaims{Fingerprint: "fp-auto-jti"}
	tok, err := crypto.SignJWT([]byte(coverageJWTSecret), claims)
	require.NoError(t, err)
	require.NotEmpty(t, tok)

	got, err := crypto.VerifyJWT([]byte(coverageJWTSecret), tok)
	require.NoError(t, err)
	assert.NotEmpty(t, got.ID, "SignJWT must auto-generate a JTI when one is not set")
}

func TestSignJWT_PreservesExistingJTI(t *testing.T) {
	claims := crypto.InstantClaims{
		Fingerprint: "fp-preserve",
		RegisteredClaims: jwt.RegisteredClaims{
			ID:       "preset-jti-abc",
			IssuedAt: jwt.NewNumericDate(time.Now().UTC()),
		},
	}
	tok, err := crypto.SignJWT([]byte(coverageJWTSecret), claims)
	require.NoError(t, err)

	got, err := crypto.VerifyJWT([]byte(coverageJWTSecret), tok)
	require.NoError(t, err)
	assert.Equal(t, "preset-jti-abc", got.ID)
}

func TestSignJWT_AutoStampsIssuedAt(t *testing.T) {
	claims := crypto.InstantClaims{Fingerprint: "fp-iat"}
	before := time.Now().UTC().Add(-1 * time.Second)
	tok, err := crypto.SignJWT([]byte(coverageJWTSecret), claims)
	require.NoError(t, err)
	after := time.Now().UTC().Add(1 * time.Second)

	got, err := crypto.VerifyJWT([]byte(coverageJWTSecret), tok)
	require.NoError(t, err)
	require.NotNil(t, got.IssuedAt)
	assert.True(t, !got.IssuedAt.Time.Before(before) && !got.IssuedAt.Time.After(after),
		"IssuedAt must be auto-stamped to ~now")
}

func TestVerifyJWT_RejectsNoneAlg(t *testing.T) {
	// Build a token with alg:none — RFC 8725 §3.1 attack vector.
	// header = {"alg":"none","typ":"JWT"}
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","typ":"JWT"}`))
	payload := base64.RawURLEncoding.EncodeToString([]byte(`{"fp":"attacker","jti":"x"}`))
	tok := header + "." + payload + "." // empty signature
	_, err := crypto.VerifyJWT([]byte(coverageJWTSecret), tok)
	require.Error(t, err, "VerifyJWT must reject alg:none tokens")

	_, err = crypto.VerifyOnboardingJWT([]byte(coverageJWTSecret), tok)
	require.Error(t, err, "VerifyOnboardingJWT must reject alg:none tokens")
}

func TestVerifyJWT_GarbageInput(t *testing.T) {
	_, err := crypto.VerifyJWT([]byte(coverageJWTSecret), "not.a.valid.token")
	require.Error(t, err)
}

func TestVerifyJWT_WrongSecret(t *testing.T) {
	claims := crypto.InstantClaims{Fingerprint: "fp"}
	tok, err := crypto.SignJWT([]byte(coverageJWTSecret), claims)
	require.NoError(t, err)

	_, err = crypto.VerifyJWT([]byte("wrong-secret-for-verify-32-chars!!"), tok)
	require.Error(t, err)
}

func TestVerifyJWT_ExpiredReturnsValidationError(t *testing.T) {
	past := time.Now().Add(-2 * time.Hour)
	claims := crypto.InstantClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			IssuedAt:  jwt.NewNumericDate(past),
			ExpiresAt: jwt.NewNumericDate(past.Add(15 * time.Minute)),
			ID:        "expired-jti",
		},
	}
	tok, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString([]byte(coverageJWTSecret))
	require.NoError(t, err)

	_, err = crypto.VerifyJWT([]byte(coverageJWTSecret), tok)
	require.Error(t, err)
	assert.ErrorIs(t, err, jwt.ErrTokenExpired,
		"VerifyJWT must surface jwt.ErrTokenExpired via errors.Is")
}

func TestVerifyJWT_FutureIssuedAt(t *testing.T) {
	future := time.Now().Add(30 * time.Minute)
	claims := crypto.InstantClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			IssuedAt:  jwt.NewNumericDate(future),
			ExpiresAt: jwt.NewNumericDate(future.Add(time.Hour)),
			ID:        "fut",
		},
	}
	tok, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString([]byte(coverageJWTSecret))
	require.NoError(t, err)

	_, err = crypto.VerifyJWT([]byte(coverageJWTSecret), tok)
	require.Error(t, err, "future IssuedAt must be rejected")
}

func TestVerifyJWT_RejectsNonHS256HMAC(t *testing.T) {
	now := time.Now().UTC()
	for _, method := range []*jwt.SigningMethodHMAC{jwt.SigningMethodHS384, jwt.SigningMethodHS512} {
		claims := crypto.InstantClaims{
			Fingerprint: "fp",
			RegisteredClaims: jwt.RegisteredClaims{
				ID:        "jti-" + method.Alg(),
				IssuedAt:  jwt.NewNumericDate(now),
				ExpiresAt: jwt.NewNumericDate(now.Add(time.Hour)),
			},
		}
		tok, err := jwt.NewWithClaims(method, claims).SignedString([]byte(coverageJWTSecret))
		require.NoError(t, err)

		_, err = crypto.VerifyJWT([]byte(coverageJWTSecret), tok)
		assert.Error(t, err, "VerifyJWT must reject %s tokens", method.Alg())
	}
}

// ─────────────────────────────────────────────────────────────────
// Fingerprint — ParseIP + FingerprintIP coverage.
// ─────────────────────────────────────────────────────────────────

func TestParseIP_Valid(t *testing.T) {
	ip := crypto.ParseIP("192.168.1.1")
	require.NotNil(t, ip)
	assert.Equal(t, "192.168.1.1", ip.String())

	ip6 := crypto.ParseIP("2001:db8::1")
	require.NotNil(t, ip6)
}

func TestParseIP_Invalid(t *testing.T) {
	assert.Nil(t, crypto.ParseIP("not-an-ip"))
	assert.Nil(t, crypto.ParseIP(""))
	assert.Nil(t, crypto.ParseIP("999.999.999.999"))
}

func TestFingerprintIP_PlainASN(t *testing.T) {
	fp, err := crypto.FingerprintIP("203.0.113.10", "12345")
	require.NoError(t, err)
	require.NotEmpty(t, fp)

	// Equivalent to Fingerprint(ip, 12345).
	want := crypto.Fingerprint(net.ParseIP("203.0.113.10"), 12345)
	assert.Equal(t, want, fp)
}

func TestFingerprintIP_ASNPrefix(t *testing.T) {
	fpUpper, err := crypto.FingerprintIP("203.0.113.10", "AS12345")
	require.NoError(t, err)

	fpLower, err := crypto.FingerprintIP("203.0.113.10", "as12345")
	require.NoError(t, err)

	plain, err := crypto.FingerprintIP("203.0.113.10", "12345")
	require.NoError(t, err)

	assert.Equal(t, plain, fpUpper, "AS12345 must equal plain 12345")
	assert.Equal(t, plain, fpLower, "as12345 must equal plain 12345")
}

func TestFingerprintIP_EmptyASN(t *testing.T) {
	fp, err := crypto.FingerprintIP("203.0.113.10", "")
	require.NoError(t, err)

	want := crypto.Fingerprint(net.ParseIP("203.0.113.10"), 0)
	assert.Equal(t, want, fp, "empty ASN must equal asn=0")
}

func TestFingerprintIP_InvalidIP(t *testing.T) {
	_, err := crypto.FingerprintIP("not-an-ip", "12345")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid IP address")
}

func TestFingerprintIP_GarbageASN(t *testing.T) {
	// "ASxyz" — Sscan won't parse, asn stays 0 (no error).
	fp, err := crypto.FingerprintIP("203.0.113.10", "ASxyz")
	require.NoError(t, err)
	want := crypto.Fingerprint(net.ParseIP("203.0.113.10"), 0)
	assert.Equal(t, want, fp)
}

func TestFingerprintIP_IPv6(t *testing.T) {
	fp, err := crypto.FingerprintIP("2001:db8::1", "AS64512")
	require.NoError(t, err)
	require.NotEmpty(t, fp)

	want := crypto.Fingerprint(net.ParseIP("2001:db8::1"), 64512)
	assert.Equal(t, want, fp)
}

func TestFingerprintIP_ShortPrefixNoStrip(t *testing.T) {
	// "AS" with only 2 chars total — strip path skips, Sscan reads "AS" and fails → asn=0.
	fp, err := crypto.FingerprintIP("203.0.113.10", "AS")
	require.NoError(t, err)
	want := crypto.Fingerprint(net.ParseIP("203.0.113.10"), 0)
	assert.Equal(t, want, fp)
}

// ─────────────────────────────────────────────────────────────────
// GenerateAPIKey
// ─────────────────────────────────────────────────────────────────

func TestGenerateAPIKey_Format(t *testing.T) {
	k, err := crypto.GenerateAPIKey()
	require.NoError(t, err)
	require.NotEmpty(t, k)

	assert.True(t, strings.HasPrefix(k, "inst_live_"), "key must carry inst_live_ prefix: %s", k)

	body := strings.TrimPrefix(k, "inst_live_")
	decoded, err := base64.RawURLEncoding.DecodeString(body)
	require.NoError(t, err, "key body must be raw-base64url")
	assert.Len(t, decoded, 32, "key body must decode to 32 random bytes")
}

func TestGenerateAPIKey_Unique(t *testing.T) {
	const n = 100
	seen := make(map[string]struct{}, n)
	for i := 0; i < n; i++ {
		k, err := crypto.GenerateAPIKey()
		require.NoError(t, err)
		_, dup := seen[k]
		require.False(t, dup, "API key collision at iteration %d: %s", i, k)
		seen[k] = struct{}{}
	}
}

// ─────────────────────────────────────────────────────────────────
// Sanity — make sure the keyring carries 32-byte keys end-to-end.
// ─────────────────────────────────────────────────────────────────

func TestKeyring_KeyMaterialMatchesHex(t *testing.T) {
	keyA := mustKey(t, coverageKeyHexA)
	want, _ := hex.DecodeString(coverageKeyHexA)
	assert.Equal(t, want, keyA, "ParseAESKey output must match raw decoded bytes")
	assert.Len(t, keyA, 32)
}

// TestKeyring_EncryptVersioned_ActiveKeyMissing constructs a Keyring directly
// (bypassing NewKeyring's validation) with an Active byte that has no entry
// in Keys — the "active key missing" branch in EncryptVersioned.
func TestKeyring_EncryptVersioned_ActiveKeyMissing(t *testing.T) {
	keyA := mustKey(t, coverageKeyHexA)
	kr := &crypto.Keyring{
		Active: '5',
		Keys:   map[byte][]byte{'1': keyA},
	}
	_, err := crypto.EncryptVersioned(kr, "payload")
	require.Error(t, err)
	var ee *crypto.ErrEncrypt
	assert.ErrorAs(t, err, &ee)
}

// TestSplitVersionedEnvelope_NonDigitVersion covers the v<not-digit>. path —
// "vA.foo" looks like a versioned envelope structurally but version byte
// is not '1'..'9', so the helper returns (0, encoded, false) and Decrypt
// treats it as a legacy unprefixed envelope.
func TestSplitVersionedEnvelope_NonDigitVersion(t *testing.T) {
	key := mustKey(t, coverageKeyHexA)
	// "vA.something" — looks like envelope, but A is not a digit. The legacy
	// Decrypt path then tries to base64-decode "vA.something" which fails.
	_, err := crypto.Decrypt(key, "vA.something-base64")
	require.Error(t, err, "non-digit version must drop to legacy branch and fail base64")
	var de *crypto.ErrDecrypt
	assert.ErrorAs(t, err, &de)
}

// TestSplitVersionedEnvelope_ShortInput covers the `len(encoded) < 3` branch
// in the helper — an empty / 1-char / 2-char input is treated as legacy.
func TestSplitVersionedEnvelope_ShortInput(t *testing.T) {
	key := mustKey(t, coverageKeyHexA)
	for _, short := range []string{"", "v", "v1"} {
		_, err := crypto.Decrypt(key, short)
		require.Error(t, err, "input %q must error", short)
	}
}

// TestSplitVersionedEnvelope_MissingDot covers the no-dot-at-position-2 branch.
func TestSplitVersionedEnvelope_MissingDot(t *testing.T) {
	key := mustKey(t, coverageKeyHexA)
	// "v1xfoo" — no dot at position 2, falls through to legacy base64 decode.
	_, err := crypto.Decrypt(key, "v1xfoo")
	require.Error(t, err)
}

// TestVerifyJWT_InvalidClaimsType covers the parsed.Claims type-assertion
// failure branch — synthesise a token with HS256 + valid signature but a
// payload missing required fields so Valid=false on the resulting struct.
// (Easiest reproduction: corrupt the signature so Valid=false but ParseError
// surfaces as a ValidationError unwrapped through errors.As — already
// covered by the wrong-secret test. This test pins the explicit !Valid path
// when ParseWithClaims succeeds.)
func TestVerifyJWT_NotBeforeFuture(t *testing.T) {
	// NotBefore in the future → ValidationError but not ErrTokenExpired.
	future := time.Now().Add(30 * time.Minute)
	claims := crypto.InstantClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        "nbf-future",
			IssuedAt:  jwt.NewNumericDate(time.Now().Add(-time.Hour)),
			NotBefore: jwt.NewNumericDate(future),
			ExpiresAt: jwt.NewNumericDate(future.Add(time.Hour)),
		},
	}
	tok, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString([]byte(coverageJWTSecret))
	require.NoError(t, err)

	_, err = crypto.VerifyJWT([]byte(coverageJWTSecret), tok)
	require.Error(t, err, "NotBefore-in-future must reject")
}

// TestVerifyOnboardingJWT_NotBeforeFuture mirrors the same for the onboarding
// path so both Verify* funcs hit the ValidationError unwrap branch.
func TestVerifyOnboardingJWT_NotBeforeFuture(t *testing.T) {
	future := time.Now().Add(30 * time.Minute)
	claims := crypto.OnboardingClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        "nbf-future-onb",
			IssuedAt:  jwt.NewNumericDate(time.Now().Add(-time.Hour)),
			NotBefore: jwt.NewNumericDate(future),
			ExpiresAt: jwt.NewNumericDate(future.Add(time.Hour)),
		},
	}
	tok, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString([]byte(coverageJWTSecret))
	require.NoError(t, err)

	_, err = crypto.VerifyOnboardingJWT([]byte(coverageJWTSecret), tok)
	require.Error(t, err)
}

// TestVerifyJWT_GarbageReturnsRawError forces an error path through
// ParseWithClaims that is NOT a *jwt.ValidationError — exercises the
// `return nil, err` (non-errors.As) branch.
func TestVerifyJWT_MalformedHeader(t *testing.T) {
	// "..."  → 3 empty parts, no JSON header — produces a non-ValidationError.
	_, err := crypto.VerifyJWT([]byte(coverageJWTSecret), "...")
	require.Error(t, err)
}

// TestKeyring_EncryptVersioned_BadKeyMaterial constructs a Keyring with
// undersized key bytes (bypassing NewKeyring) so the inner Encrypt call
// fails — covers the `return "", err` branch.
func TestKeyring_EncryptVersioned_BadKeyMaterial(t *testing.T) {
	kr := &crypto.Keyring{
		Active: '1',
		Keys:   map[byte][]byte{'1': {1, 2, 3, 4, 5}}, // invalid AES key length
	}
	_, err := crypto.EncryptVersioned(kr, "payload")
	require.Error(t, err)
	var ee *crypto.ErrEncrypt
	assert.ErrorAs(t, err, &ee)
}

// TestVerifyOnboardingJWT_FutureIssuedAt covers the future-IssuedAt branch
// in VerifyOnboardingJWT (mirrored from VerifyJWT).
func TestVerifyOnboardingJWT_FutureIssuedAt_Direct(t *testing.T) {
	future := time.Now().Add(30 * time.Minute)
	claims := crypto.OnboardingClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			IssuedAt:  jwt.NewNumericDate(future),
			ExpiresAt: jwt.NewNumericDate(future.Add(time.Hour)),
			ID:        "iat-future",
		},
	}
	tok, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString([]byte(coverageJWTSecret))
	require.NoError(t, err)

	_, err = crypto.VerifyOnboardingJWT([]byte(coverageJWTSecret), tok)
	require.Error(t, err)
}
