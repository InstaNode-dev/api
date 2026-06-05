package handlers

// internal_e2e_account_export_test.go — white-box seams for the external
// internal_e2e_account_*_test.go coverage suite (package handlers_test).

import (
	"time"

	"github.com/google/uuid"
)

// SetE2ESignSessionJWTForTest overrides the e2eSignSessionJWT seam so a test
// can force the token_issue_failed (503) arm of CreateAccount. Returns a
// restore func. HS256-over-[]byte never errors in practice, so this seam is
// the only way to deterministically exercise that defensive branch.
func SetE2ESignSessionJWTForTest(fn func(jwtSecret string, userID, teamID uuid.UUID, email string, expiresAt time.Time) (string, error)) (restore func()) {
	prev := e2eSignSessionJWT
	e2eSignSessionJWT = fn
	return func() { e2eSignSessionJWT = prev }
}
