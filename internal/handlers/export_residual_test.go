package handlers

// export_residual_test.go — re-exports of unexported symbols for the
// residual-coverage slice (the files below 95% after the prior slice). Kept
// separate from export_test.go / export_rbw_test.go / export_billing_test.go
// so it never collides with concurrent slices. A duplicate re-export is a
// compile error, so every symbol here was confirmed absent from the three
// pre-existing export files before being added.

import (
	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt/v4"
)

// ── billing.go pure-helper export ──
//
// BuildPaymentMethodForTest re-exports buildPaymentMethod so the nil-input arm
// (returns nil) can be asserted directly without a live Razorpay subscription.
func BuildPaymentMethodForTest() fiber.Map {
	return buildPaymentMethod(nil)
}

// ── admin_impersonate.go seam ──
//
// SetSignImpersonationTokenForTest swaps the package-level JWT signer used by
// AdminImpersonateHandler.Impersonate so a test can drive the sign_failed
// (503) branch. Returns a restore func the caller defers.
func SetSignImpersonationTokenForTest(fn func(*jwt.Token, []byte) (string, error)) (restore func()) {
	prev := signImpersonationToken
	signImpersonationToken = fn
	return func() { signImpersonationToken = prev }
}

// ── webhook.go crypto seam ──
//
// SetWebhookCryptoEncryptForTest swaps the package-level crypto.Encrypt
// indirection used by WebhookHandler.storeEncryptedURL so a test can drive the
// encrypt-failed branch. Returns a restore func.
func SetWebhookCryptoEncryptForTest(fn func(key []byte, plaintext string) (string, error)) (restore func()) {
	prev := cryptoEncrypt
	cryptoEncrypt = fn
	return func() { cryptoEncrypt = prev }
}
