package crypto

import (
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/google/uuid"
)

// OnboardingClaims holds the JWT payload for anonymous-to-registered conversion.
type OnboardingClaims struct {
	Fingerprint   string   `json:"fp"`
	Country       string   `json:"co"`
	CloudVendor   string   `json:"cv"`
	OrgName       string   `json:"org"`
	Tokens        []string `json:"tok"`
	ResourceTypes []string `json:"rt"`
	SuggestedPlan string   `json:"plan"`
	jwt.RegisteredClaims
}

// InstantClaims is an alias for OnboardingClaims for use by the public API and tests.
type InstantClaims = OnboardingClaims

// ErrJWTSign is returned when signing a JWT fails.
type ErrJWTSign struct {
	Cause error
}

func (e *ErrJWTSign) Error() string { return fmt.Sprintf("jwt sign failed: %v", e.Cause) }
func (e *ErrJWTSign) Unwrap() error { return e.Cause }

// ErrJWTVerify is returned when JWT verification fails.
type ErrJWTVerify struct {
	Cause error
}

func (e *ErrJWTVerify) Error() string { return fmt.Sprintf("jwt verify failed: %v", e.Cause) }
func (e *ErrJWTVerify) Unwrap() error { return e.Cause }

// SignJWT signs an InstantClaims JWT, auto-generating a JTI if one is not already set.
// Returns the signed token string. The JTI can be retrieved from claims.ID after parsing.
func SignJWT(secret []byte, claims InstantClaims) (string, error) {
	if claims.ID == "" {
		claims.ID = uuid.New().String()
	}
	if claims.IssuedAt == nil {
		claims.IssuedAt = jwt.NewNumericDate(time.Now().UTC())
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := token.SignedString(secret)
	if err != nil {
		return "", &ErrJWTSign{Cause: err}
	}
	return signed, nil
}

// VerifyJWT parses and verifies an InstantClaims JWT.
// Errors from the underlying jwt library are returned unwrapped so callers can
// use errors.Is(err, jwt.ErrTokenExpired) etc.
func VerifyJWT(secret []byte, tokenStr string) (*InstantClaims, error) {
	parsed, err := jwt.ParseWithClaims(tokenStr, &InstantClaims{}, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return secret, nil
	})
	if err != nil {
		// Return jwt.ValidationError directly so callers can use errors.Is
		// with sentinels like jwt.ErrTokenExpired.
		var ve *jwt.ValidationError
		if errors.As(err, &ve) {
			return nil, ve
		}
		return nil, err
	}
	claims, ok := parsed.Claims.(*InstantClaims)
	if !ok || !parsed.Valid {
		return nil, &ErrJWTVerify{Cause: fmt.Errorf("invalid token claims")}
	}
	// Enforce IssuedAt must not be in the future (jwt/v4 doesn't check iat by default).
	if claims.IssuedAt != nil && time.Now().UTC().Before(claims.IssuedAt.Time) {
		return nil, jwt.NewValidationError("token issued in the future", jwt.ValidationErrorIssuedAt)
	}
	return claims, nil
}

// SignOnboardingJWT creates a signed HMAC-SHA256 JWT with a 7-day TTL.
// A unique JTI is generated and embedded in the claims — callers must persist it to onboarding_events.
func SignOnboardingJWT(secret []byte, claims OnboardingClaims) (string, string, error) {
	jti := uuid.New().String()
	now := time.Now().UTC()

	claims.RegisteredClaims = jwt.RegisteredClaims{
		ID:        jti,
		IssuedAt:  jwt.NewNumericDate(now),
		ExpiresAt: jwt.NewNumericDate(now.Add(7 * 24 * time.Hour)),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := token.SignedString(secret)
	if err != nil {
		return "", "", &ErrJWTSign{Cause: err}
	}

	return signed, jti, nil
}

// VerifyOnboardingJWT parses and verifies an onboarding JWT, returning the embedded claims.
func VerifyOnboardingJWT(secret []byte, tokenStr string) (*OnboardingClaims, error) {
	parsed, err := jwt.ParseWithClaims(tokenStr, &OnboardingClaims{}, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return secret, nil
	})
	if err != nil {
		return nil, &ErrJWTVerify{Cause: err}
	}

	claims, ok := parsed.Claims.(*OnboardingClaims)
	if !ok || !parsed.Valid {
		return nil, &ErrJWTVerify{Cause: fmt.Errorf("invalid token claims")}
	}

	// Enforce IssuedAt must not be in the future (jwt/v4 does not check iat by default).
	if claims.IssuedAt != nil && time.Now().UTC().Before(claims.IssuedAt.Time) {
		return nil, jwt.NewValidationError("token issued in the future", jwt.ValidationErrorIssuedAt)
	}

	return claims, nil
}
