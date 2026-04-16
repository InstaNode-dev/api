package crypto

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
)

const tokenPrefix = "inst_live_"

// ErrTokenGenerate is returned when secure random bytes cannot be read.
type ErrTokenGenerate struct {
	Cause error
}

func (e *ErrTokenGenerate) Error() string {
	return fmt.Sprintf("token generation failed: %v", e.Cause)
}

func (e *ErrTokenGenerate) Unwrap() error { return e.Cause }

// GenerateAPIKey produces a secure API key of the form inst_live_<base64url(32 random bytes)>.
func GenerateAPIKey() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", &ErrTokenGenerate{Cause: err}
	}
	return tokenPrefix + base64.RawURLEncoding.EncodeToString(b), nil
}
