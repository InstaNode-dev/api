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
func Decrypt(key []byte, encoded string) (string, error) {
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
