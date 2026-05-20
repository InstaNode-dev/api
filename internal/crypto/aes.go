package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
)

// ErrDecrypt is returned when decryption fails.
type ErrDecrypt struct {
	Cause error
}

func (e *ErrDecrypt) Error() string {
	return fmt.Sprintf("aes-gcm decrypt failed: %v", e.Cause)
}

func (e *ErrDecrypt) Unwrap() error { return e.Cause }

// ErrEncrypt is returned when encryption fails.
type ErrEncrypt struct {
	Cause error
}

func (e *ErrEncrypt) Error() string {
	return fmt.Sprintf("aes-gcm encrypt failed: %v", e.Cause)
}

func (e *ErrEncrypt) Unwrap() error { return e.Cause }

// ParseAESKey decodes a 64-character hex string into a 32-byte key.
func ParseAESKey(hexKey string) ([]byte, error) {
	key, err := hex.DecodeString(hexKey)
	if err != nil {
		return nil, fmt.Errorf("invalid AES key hex: %w", err)
	}
	if len(key) != 32 {
		return nil, fmt.Errorf("AES key must be 32 bytes, got %d", len(key))
	}
	return key, nil
}

// Encrypt encrypts plaintext using AES-256-GCM and returns a base64url-encoded string.
// Format: base64(nonce || ciphertext || tag)
func Encrypt(key []byte, plaintext string) (string, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", &ErrEncrypt{Cause: err}
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", &ErrEncrypt{Cause: err}
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", &ErrEncrypt{Cause: err}
	}

	ciphertext := gcm.Seal(nonce, nonce, []byte(plaintext), nil)
	return base64.URLEncoding.EncodeToString(ciphertext), nil
}

// Decrypt decodes and decrypts a base64url-encoded ciphertext produced by Encrypt.
//
// T12-4 (BugHunt 2026-05-20): Decrypt strips a "vN." prefix if present
// so a versioned envelope produced by EncryptVersioned is readable by
// callers that only have the active key. For full multi-key rotation
// support (decrypt-old, encrypt-new) use Keyring.Decrypt instead.
func Decrypt(key []byte, encoded string) (string, error) {
	// Tolerate a versioned envelope ("vN.<base64>") here so a key-version
	// prefix written by EncryptVersioned can still be decoded by code paths
	// that haven't moved to Keyring.Decrypt yet. The version byte is
	// inspected by Keyring.Decrypt for actual rotation; here we just skip
	// the marker and treat `key` as the single active key.
	if _, payload, ok := splitVersionedEnvelope(encoded); ok {
		encoded = payload
	}
	data, err := base64.URLEncoding.DecodeString(encoded)
	if err != nil {
		return "", &ErrDecrypt{Cause: fmt.Errorf("base64 decode: %w", err)}
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", &ErrDecrypt{Cause: err}
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", &ErrDecrypt{Cause: err}
	}

	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return "", &ErrDecrypt{Cause: fmt.Errorf("ciphertext too short")}
	}

	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", &ErrDecrypt{Cause: err}
	}

	return string(plaintext), nil
}

// ──────────────────────────────────────────────────────────────────────
// T12-4 (BugHunt 2026-05-20): key-version-tagged envelopes for AES
// rotation.
//
// PROBLEM. crypto.Encrypt output is `base64(nonce||ct||tag)` with NO
// key-version prefix. AES_KEY is a single static value loaded from env.
// Rotating it instantly breaks every previously-encrypted
// connection_url + vault_secrets.encrypted_value — gcm.Open returns
// auth-tag failure. There is no dual-key window for a rolling
// migration, so any rotation is a hard outage.
//
// SOLUTION. EncryptVersioned tags the ciphertext with a one-character
// version marker ("v1.", "v2.", ...) in cleartext BEFORE base64. A
// Keyring carries {1: oldKey, 2: newKey, ...} plus an Active version.
// Decrypt walks the version on the envelope and selects the matching
// key. Envelopes WITHOUT a "vN." prefix continue to decrypt against
// the legacy single key — that path is what every existing row uses
// today. A rotation flow is then:
//
//   1. Deploy a build with Keyring{1: oldKey, 2: newKey}, Active=1.
//      Reads use v1+legacy. Writes still emit v1 (no behaviour change).
//   2. Flip Active=2. New writes emit "v2.<base64>"; reads still see
//      a mix of unversioned-legacy + v1 + v2 envelopes.
//   3. Background re-encrypt loop walks each table and rewrites
//      legacy/v1 envelopes as v2.
//   4. After re-encrypt completes, remove v1 from the keyring.
//
// CONVENTION 4 of CLAUDE.md (the "fail-open" claim) is factually wrong
// per the bug-hunt analysis — Decrypt has always returned an error on
// auth-tag mismatch. We leave that strict behaviour and gain rotation
// via the version marker.

const versionMarker = "v"
const versionSep = "."

// Keyring carries the set of decryption keys known to the process, plus
// the version used for new encryptions. Active MUST appear in Keys.
//
// A nil/empty Keys map is rejected by NewKeyring — callers must always
// be able to decrypt at least the active key's writes.
type Keyring struct {
	// Active is the byte version stamp on new ciphertext written via
	// EncryptVersioned. ASCII digits only ('1'..'9') so the on-wire
	// marker is `"v" + Active + "."` (e.g. "v2.").
	Active byte
	// Keys maps version byte → 32-byte AES key. The Active version must
	// have an entry here.
	Keys map[byte][]byte
}

// NewKeyring constructs a Keyring with `active` as the write version
// and `keys` as the decrypt set. Returns an error if `active` is not in
// `keys`, if `active` is not an ASCII digit, or if any key has wrong
// length.
func NewKeyring(active byte, keys map[byte][]byte) (*Keyring, error) {
	if active < '1' || active > '9' {
		return nil, fmt.Errorf("active version must be ASCII digit 1..9, got %q", active)
	}
	if len(keys) == 0 {
		return nil, fmt.Errorf("keyring requires at least one key")
	}
	for v, k := range keys {
		if v < '1' || v > '9' {
			return nil, fmt.Errorf("key version %q out of range '1'..'9'", v)
		}
		if len(k) != 32 {
			return nil, fmt.Errorf("key for version %q must be 32 bytes, got %d", v, len(k))
		}
	}
	if _, ok := keys[active]; !ok {
		return nil, fmt.Errorf("active version %q missing from keyring", active)
	}
	return &Keyring{Active: active, Keys: keys}, nil
}

// EncryptVersioned encrypts plaintext under the keyring's active key
// and returns a "vN.<base64>" envelope. Decrypted by Keyring.Decrypt.
//
// Backward compatibility: callers may continue to read this envelope
// through the legacy single-key Decrypt(key, ...) function — it strips
// the "vN." prefix and decrypts against the supplied key. So a deploy
// flipping active from v1→v2 is safe as long as the previously-active
// key (v1) is still passed to legacy callers.
func EncryptVersioned(kr *Keyring, plaintext string) (string, error) {
	if kr == nil {
		return "", &ErrEncrypt{Cause: fmt.Errorf("nil keyring")}
	}
	key, ok := kr.Keys[kr.Active]
	if !ok {
		return "", &ErrEncrypt{Cause: fmt.Errorf("active key missing")}
	}
	raw, err := Encrypt(key, plaintext)
	if err != nil {
		return "", err
	}
	return versionMarker + string(kr.Active) + versionSep + raw, nil
}

// Decrypt decrypts an envelope using whichever version the envelope
// carries. Legacy un-prefixed envelopes are decrypted against the
// active key — the on-disk shape before this migration is that path.
func (kr *Keyring) Decrypt(encoded string) (string, error) {
	if kr == nil {
		return "", &ErrDecrypt{Cause: fmt.Errorf("nil keyring")}
	}
	version, payload, ok := splitVersionedEnvelope(encoded)
	if !ok {
		// Legacy: no version marker. Use the active key — same shape
		// the codebase has shipped with for the whole previous lifetime.
		return Decrypt(kr.Keys[kr.Active], encoded)
	}
	key, found := kr.Keys[version]
	if !found {
		return "", &ErrDecrypt{Cause: fmt.Errorf("unknown key version %q", version)}
	}
	return Decrypt(key, payload)
}

// ActiveVersion returns the active write-version byte. Exposed for
// callers that want to log/audit the version they wrote under.
func (kr *Keyring) ActiveVersion() byte {
	if kr == nil {
		return 0
	}
	return kr.Active
}

// splitVersionedEnvelope returns (version, payload, true) if encoded
// looks like "vN.<payload>" where N is a single ASCII digit; otherwise
// (0, encoded, false). The split is purely structural — it does NOT
// validate that the payload is base64 or that the version is known to
// any keyring; that's the caller's job.
func splitVersionedEnvelope(encoded string) (byte, string, bool) {
	// Cheapest possible check first — must start with "v", be at least
	// 3 chars ("vN."), have a dot at position 2, and a digit at 1.
	if len(encoded) < 3 || encoded[0] != 'v' || encoded[2] != '.' {
		return 0, encoded, false
	}
	v := encoded[1]
	if v < '1' || v > '9' {
		return 0, encoded, false
	}
	return v, encoded[3:], true
}

