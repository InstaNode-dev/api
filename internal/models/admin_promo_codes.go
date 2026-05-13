package models

// admin_promo_codes.go — single-use promo codes issued by a platform admin
// via POST /api/v1/admin/customers/:team_id/promo. Promotes / first-month-free /
// fixed-amount discounts the customer can redeem at checkout time.
//
// Storage shape: dedicated `admin_promo_codes` table (migration 021). We
// considered extending plans.Registry's in-memory promotion definitions but
// those are static, server-config-level discounts ("everyone gets 10% in
// November"), not single-use admin-issued codes scoped to one team. Two
// distinct concepts → two distinct storage layers. The plans-config side
// stays in code/yaml; this admin-issued side lives in Postgres so it can
// be audited, expired, and redemption-marked at runtime.

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
)

// Promo code kind constants — keep in one place so handlers and DB CHECK
// constraint stay in sync. The DB column is TEXT + CHECK so the constant
// values must match what the migration's CHECK enforces.
const (
	PromoKindPercentOff      = "percent_off"
	PromoKindFirstMonthFree  = "first_month_free"
	PromoKindAmountOff       = "amount_off"
)

// ValidPromoKinds returns the set of valid promo-code kinds. Used by handlers
// to validate request input before hitting the DB (so we surface a clean
// 400 instead of a CHECK-constraint violation 503).
func ValidPromoKinds() []string {
	return []string{PromoKindPercentOff, PromoKindFirstMonthFree, PromoKindAmountOff}
}

// IsValidPromoKind reports whether kind is one of the accepted values.
func IsValidPromoKind(kind string) bool {
	switch kind {
	case PromoKindPercentOff, PromoKindFirstMonthFree, PromoKindAmountOff:
		return true
	}
	return false
}

// AdminPromoCode mirrors one row of the admin_promo_codes table.
type AdminPromoCode struct {
	ID            uuid.UUID
	Code          string
	TeamID        uuid.NullUUID
	IssuedByEmail string
	Kind          string
	Value         int
	AppliesTo     sql.NullInt64
	UsedAt        sql.NullTime
	ExpiresAt     time.Time
	CreatedAt     time.Time
}

// promoCodeLength is the number of hex characters in a generated code. 8 hex
// chars = 32 bits of entropy — adequate for single-use codes issued by hand
// (collision probability over the lifetime of the table is negligible) and
// short enough to read aloud or paste into a checkout form. The DB has
// UNIQUE(code), so on the astronomically unlikely collision the INSERT
// retries.
const promoCodeLength = 8

// generatePromoCode returns an uppercase hex string of length promoCodeLength.
// Exposed as a package-level var so tests can override it deterministically.
var generatePromoCode = func() (string, error) {
	b := make([]byte, promoCodeLength/2)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("models.generatePromoCode: %w", err)
	}
	return strings.ToUpper(hex.EncodeToString(b)), nil
}

// CreateAdminPromoCodeParams collects the inputs for IssueAdminPromoCode so
// callers (handlers) don't pass a long positional argument list. ValidForDays
// is converted into an absolute ExpiresAt server-side so the DB row carries a
// concrete deadline rather than a relative duration the redemption path
// would have to re-compute.
type CreateAdminPromoCodeParams struct {
	TeamID        uuid.UUID
	IssuedByEmail string
	Kind          string
	Value         int
	AppliesTo     int // 0 → NULL in DB
	ValidForDays  int
}

// IssueAdminPromoCode inserts a new single-use promo code for the given team.
// Returns the persisted row (with the generated code + expires_at).
//
// Validation policy:
//   - kind must be in ValidPromoKinds(); otherwise returns ErrInvalidPromoKind.
//   - valid_for_days must be > 0; otherwise returns ErrInvalidPromoDuration.
//   - value must be >= 0. value > 100 is allowed for percent_off (handler
//     surface caps that) — we don't enforce business limits here, only
//     storage-shape constraints.
//
// Code generation is in-loop with a small retry on collisions: pgcrypto-gen'd
// IDs are unique by definition but the UNIQUE(code) index is what makes the
// code itself collision-safe. In practice the loop should fire once.
func IssueAdminPromoCode(ctx context.Context, db *sql.DB, p CreateAdminPromoCodeParams) (*AdminPromoCode, error) {
	if !IsValidPromoKind(p.Kind) {
		return nil, ErrInvalidPromoKind
	}
	if p.ValidForDays <= 0 {
		return nil, ErrInvalidPromoDuration
	}
	if p.Value < 0 {
		return nil, ErrInvalidPromoValue
	}
	if strings.TrimSpace(p.IssuedByEmail) == "" {
		return nil, fmt.Errorf("models.IssueAdminPromoCode: issued_by_email is required")
	}

	expiresAt := time.Now().UTC().Add(time.Duration(p.ValidForDays) * 24 * time.Hour)

	var appliesTo interface{}
	if p.AppliesTo > 0 {
		appliesTo = p.AppliesTo
	}

	// Retry on UNIQUE(code) collisions. Bounded at 5 to avoid spinning on a
	// pathological RNG failure mode.
	var lastErr error
	for attempt := 0; attempt < 5; attempt++ {
		code, genErr := generatePromoCode()
		if genErr != nil {
			return nil, genErr
		}

		row := &AdminPromoCode{}
		err := db.QueryRowContext(ctx, `
			INSERT INTO admin_promo_codes (code, team_id, issued_by_email, kind, value, applies_to, expires_at)
			VALUES ($1, $2, $3, $4, $5, $6, $7)
			RETURNING id, code, team_id, issued_by_email, kind, value, applies_to, used_at, expires_at, created_at
		`, code, p.TeamID, p.IssuedByEmail, p.Kind, p.Value, appliesTo, expiresAt).Scan(
			&row.ID, &row.Code, &row.TeamID, &row.IssuedByEmail, &row.Kind,
			&row.Value, &row.AppliesTo, &row.UsedAt, &row.ExpiresAt, &row.CreatedAt,
		)
		if err == nil {
			return row, nil
		}
		// Heuristic check for unique-violation on code. We could probe pq.Error
		// codes, but the surface area is small enough that string-matching the
		// constraint name is fine — and avoids depending on the pq error type
		// here.
		if !strings.Contains(strings.ToLower(err.Error()), "admin_promo_codes_code_key") &&
			!strings.Contains(strings.ToLower(err.Error()), "unique") {
			return nil, fmt.Errorf("models.IssueAdminPromoCode: %w", err)
		}
		lastErr = err
	}
	return nil, fmt.Errorf("models.IssueAdminPromoCode: code collision after retries: %w", lastErr)
}

// Sentinel errors for validation failures so handlers can return clean 400s.
var (
	ErrInvalidPromoKind     = errors.New("invalid promo kind")
	ErrInvalidPromoDuration = errors.New("valid_for_days must be > 0")
	ErrInvalidPromoValue    = errors.New("value must be >= 0")
)
