package crypto

import (
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

// jwtSigningAlg is the single HMAC variant InstantNode mints with. VerifyJWT /
// VerifyOnboardingJWT pin to exactly this via jwt.WithValidMethods (RFC 8725
// §3.1) — restricting to the SigningMethodHMAC family alone still accepts
// HS384/HS512, an attacker-selectable alg downgrade we don't want.
const jwtSigningAlg = "HS256"

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
// Errors from the underlying jwt library are returned as *jwt.ValidationError
// so callers can use errors.Is(err, jwt.ErrTokenExpired) etc.
//
// jwt/v4 validates exp / iat / nbf in RegisteredClaims.Valid(), so no follow-up
// time check is needed here. WithValidMethods pins HS256 — any other alg is
// rejected before the keyfunc runs, so the keyfunc just returns the secret.
// jwt/v4 ParseWithClaims always returns a *jwt.ValidationError on failure (see
// parser.go) and Valid=true on success with the concrete claims type we pass —
// so we don't need a !ok || !parsed.Valid fallback.
func VerifyJWT(secret []byte, tokenStr string) (*InstantClaims, error) {
	parsed, err := jwt.ParseWithClaims(tokenStr, &InstantClaims{}, func(t *jwt.Token) (interface{}, error) {
		return secret, nil
	}, jwt.WithValidMethods([]string{jwtSigningAlg}))
	if err != nil {
		// jwt/v4's *jwt.ValidationError implements errors.Is for its bitfield
		// of sentinels (ErrTokenExpired, ErrTokenNotValidYet, ...), so callers
		// can do errors.Is(err, jwt.ErrTokenExpired) without unwrapping here.
		return nil, err
	}
	return parsed.Claims.(*InstantClaims), nil
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

// VerifyOnboardingJWT parses and verifies an onboarding JWT, returning the
// embedded claims. WithValidMethods pins HS256 and jwt/v4's
// RegisteredClaims.Valid() handles exp / iat / nbf — see VerifyJWT for the
// same simplification rationale.
func VerifyOnboardingJWT(secret []byte, tokenStr string) (*OnboardingClaims, error) {
	parsed, err := jwt.ParseWithClaims(tokenStr, &OnboardingClaims{}, func(t *jwt.Token) (interface{}, error) {
		return secret, nil
	}, jwt.WithValidMethods([]string{jwtSigningAlg}))
	if err != nil {
		return nil, &ErrJWTVerify{Cause: err}
	}
	return parsed.Claims.(*OnboardingClaims), nil
}
