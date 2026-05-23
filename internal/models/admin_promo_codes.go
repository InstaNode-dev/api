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

// ErrAdminPromoCodeNotFound is returned by GetAdminPromoCodeByCode when no row
// matches the (code, team_id) tuple. Wrapped as a sentinel so handlers can
// distinguish "no such code for this team" (caller error → 200+ok:false)
// from a transient DB failure (→ 503).
var ErrAdminPromoCodeNotFound = errors.New("admin promo code not found")

// ErrAdminPromoCodeAlreadyUsed is returned by MarkAdminPromoCodeUsed when the
// UPDATE matched zero rows because used_at was already set (or the row no
// longer exists). Lets the caller fall through cleanly without re-querying.
var ErrAdminPromoCodeAlreadyUsed = errors.New("admin promo code already redeemed")

// GetAdminPromoCodeByCode looks up an admin-issued promo code by its public
// `code` string, scoped to the supplied teamID. Returns the row even if
// used_at is set or expires_at is in the past — the caller (validate
// handler) inspects those fields to surface the right error code.
//
// Scoping by team_id is the whole point of the row's existence: admin codes
// are single-team — leaking the existence of a code that belongs to another
// team would be a cross-team information disclosure. The query is therefore
// (code, team_id) and `not found` covers both "no such code" and "code
// exists but belongs to a different team."
//
// Returns ErrAdminPromoCodeNotFound when no row matches. Any other error is
// a transient DB failure.
func GetAdminPromoCodeByCode(ctx context.Context, db *sql.DB, code string, teamID uuid.UUID) (*AdminPromoCode, error) {
	row := &AdminPromoCode{}
	err := db.QueryRowContext(ctx, `
		SELECT id, code, team_id, issued_by_email, kind, value, applies_to, used_at, expires_at, created_at
		FROM admin_promo_codes
		WHERE code = $1 AND team_id = $2
	`, strings.ToUpper(strings.TrimSpace(code)), teamID).Scan(
		&row.ID, &row.Code, &row.TeamID, &row.IssuedByEmail, &row.Kind,
		&row.Value, &row.AppliesTo, &row.UsedAt, &row.ExpiresAt, &row.CreatedAt,
	)
	if err == sql.ErrNoRows {
		return nil, ErrAdminPromoCodeNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("models.GetAdminPromoCodeByCode: %w", err)
	}
	return row, nil
}

// MarkAdminPromoCodeUsed atomically transitions a row from used_at IS NULL to
// used_at = now(). Uses `WHERE used_at IS NULL` in the predicate so two
// concurrent webhook callers racing on the same code can't both succeed:
// the second UPDATE matches zero rows and returns ErrAdminPromoCodeAlreadyUsed.
//
// The caller is expected to treat ErrAdminPromoCodeAlreadyUsed as a no-op
// (the code was successfully redeemed by the racing caller — there is nothing
// to do).
func MarkAdminPromoCodeUsed(ctx context.Context, db *sql.DB, id uuid.UUID) error {
	res, err := db.ExecContext(ctx, `
		UPDATE admin_promo_codes
		   SET used_at = now()
		 WHERE id = $1 AND used_at IS NULL
	`, id)
	if err != nil {
		return fmt.Errorf("models.MarkAdminPromoCodeUsed: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("models.MarkAdminPromoCodeUsed: rows_affected: %w", err)
	}
	if n == 0 {
		return ErrAdminPromoCodeAlreadyUsed
	}
	return nil
}

// ─────────────────────────────────────────────────────────────────────────────
// Audit feed — see internal/handlers/admin_promos_audit.go
//
// The agent-API admin surface needs a consolidated view of who issued which
// codes to whom and how many got redeemed. Today the data is scattered:
//
//   - issued_by_email + created_at live in admin_promo_codes
//   - team_id → email requires a join through users
//   - redemption timestamp lives in admin_promo_codes.used_at
//   - expiration is admin_promo_codes.expires_at < now() AND used_at IS NULL
//
// We surface each promo's full lifecycle (issued / redeemed / expired) as a
// flat event stream via ListPromoAuditEvents below. Filtering by issuer
// email + since + event_type happens in-query so we don't pull the full
// table into Go just to drop rows.
// ─────────────────────────────────────────────────────────────────────────────

// Event-type constants for the promo audit feed. The query emits one of
// these in the event_type column of each row. Strings (not iota) so the
// JSON response is self-describing and a downstream consumer can filter by
// literal value without an enum mapping.
const (
	PromoAuditEventIssued   = "issued"
	PromoAuditEventRedeemed = "redeemed"
	PromoAuditEventExpired  = "expired"
)

// IsValidPromoAuditEvent reports whether v is a known event_type filter
// value. Used by the handler to validate ?event_type=... before it reaches
// the SQL — the query whitelists the type internally too, so this is the
// "clean 400 vs surprising empty list" surface.
func IsValidPromoAuditEvent(v string) bool {
	switch v {
	case PromoAuditEventIssued, PromoAuditEventRedeemed, PromoAuditEventExpired:
		return true
	}
	return false
}

// PromoAuditEvent is one row in the consolidated lifecycle feed.
//
// Field semantics:
//   - EventType: one of PromoAuditEventIssued / Redeemed / Expired.
//   - EventAt:   the timestamp this row's event happened (created_at for
//                issued, used_at for redeemed, expires_at for expired).
//                Single column so the handler can ORDER BY uniformly and
//                the JSON consumer doesn't have to pick which of three
//                nullable timestamps "this" event referred to.
//   - TeamEmail: the primary owner's email. Empty string when the team
//                has no owner row (data-consistency edge case — the
//                LEFT JOIN keeps the promo visible rather than dropping it).
//
// All other fields are passed through from admin_promo_codes; AppliesTo is
// 0 when the DB stored NULL.
type PromoAuditEvent struct {
	EventType     string
	Code          string
	TeamID        uuid.NullUUID
	TeamEmail     string
	IssuedByEmail string
	Kind          string
	Value         int
	AppliesTo     int
	IssuedAt      time.Time
	RedeemedAt    sql.NullTime
	ExpiredAt     sql.NullTime
	EventAt       time.Time
}

// ListPromoAuditEventsParams collects the filter knobs for the audit feed.
//
//   - Since:           drop events whose event_at < Since. Zero value → no filter.
//   - Limit / Offset:  paging; Limit is capped by the handler.
//   - IssuedByEmail:   case-insensitive exact match on the issuer column.
//                      Empty string → no filter.
//   - EventType:       restrict to a single lifecycle phase. Empty → all three.
type ListPromoAuditEventsParams struct {
	Since          time.Time
	Limit          int
	Offset         int
	IssuedByEmail  string
	EventType      string
}

// ListPromoAuditEvents returns the consolidated lifecycle feed. The query
// is a single CTE: one branch per event_type, unioned and ordered by the
// canonical event_at DESC.
//
// We always-LEFT-JOIN users (not INNER) so a promo whose team has been
// pruned still shows up in the audit log — admins want to see the issuance
// happened even if the recipient team is gone. Team email is "" in that case.
//
// The Expired branch evaluates `expires_at < now()` server-side so the
// query is self-consistent within a single statement (no clock-skew window
// between two Go-side now() calls).
func ListPromoAuditEvents(ctx context.Context, db *sql.DB, p ListPromoAuditEventsParams) ([]*PromoAuditEvent, error) {
	args := []interface{}{}
	// $1, $2... are positional in the generated SQL. We append in a strict
	// order: since, issued_by_email, event_type, limit, offset. The CTE
	// branches reference all of these; the outer WHERE clause filters the
	// unioned result.

	args = append(args, p.Since)            // $1
	args = append(args, p.IssuedByEmail)    // $2 (lowercased)
	args = append(args, p.EventType)        // $3
	args = append(args, p.Limit)            // $4
	args = append(args, p.Offset)           // $5

	// Note on $1 ('epoch' sentinel): when Since is zero, p.Since is the Go
	// zero time which marshals as 0001-01-01. Postgres accepts that and the
	// `>= $1` filter degenerates to "everything" — exactly what we want.
	query := `
		WITH promo_events AS (
			SELECT 'issued'::text AS event_type,
			       p.code, p.team_id,
			       COALESCE(u.email, '') AS team_email,
			       p.issued_by_email, p.kind, p.value,
			       COALESCE(p.applies_to, 0) AS applies_to,
			       p.created_at AS issued_at,
			       p.used_at    AS redeemed_at,
			       CASE WHEN p.expires_at < now() AND p.used_at IS NULL
			            THEN p.expires_at ELSE NULL END AS expired_at,
			       p.created_at AS event_at
			FROM admin_promo_codes p
			LEFT JOIN users u ON u.team_id = p.team_id AND u.role = 'owner'
			UNION ALL
			SELECT 'redeemed'::text,
			       p.code, p.team_id,
			       COALESCE(u.email, ''),
			       p.issued_by_email, p.kind, p.value,
			       COALESCE(p.applies_to, 0),
			       p.created_at, p.used_at,
			       CASE WHEN p.expires_at < now() AND p.used_at IS NULL
			            THEN p.expires_at ELSE NULL END,
			       p.used_at
			FROM admin_promo_codes p
			LEFT JOIN users u ON u.team_id = p.team_id AND u.role = 'owner'
			WHERE p.used_at IS NOT NULL
			UNION ALL
			SELECT 'expired'::text,
			       p.code, p.team_id,
			       COALESCE(u.email, ''),
			       p.issued_by_email, p.kind, p.value,
			       COALESCE(p.applies_to, 0),
			       p.created_at, p.used_at, p.expires_at,
			       p.expires_at
			FROM admin_promo_codes p
			LEFT JOIN users u ON u.team_id = p.team_id AND u.role = 'owner'
			WHERE p.expires_at < now() AND p.used_at IS NULL
		)
		SELECT event_type, code, team_id, team_email,
		       issued_by_email, kind, value, applies_to,
		       issued_at, redeemed_at, expired_at, event_at
		FROM promo_events
		WHERE event_at >= $1
		  AND ($2 = '' OR lower(issued_by_email) = $2)
		  AND ($3 = '' OR event_type = $3)
		ORDER BY event_at DESC
		LIMIT $4 OFFSET $5
	`

	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("models.ListPromoAuditEvents: %w", err)
	}
	defer func() { _ = rows.Close() }()

	out := make([]*PromoAuditEvent, 0)
	for rows.Next() {
		ev := &PromoAuditEvent{}
		if scanErr := rows.Scan(
			&ev.EventType, &ev.Code, &ev.TeamID, &ev.TeamEmail,
			&ev.IssuedByEmail, &ev.Kind, &ev.Value, &ev.AppliesTo,
			&ev.IssuedAt, &ev.RedeemedAt, &ev.ExpiredAt, &ev.EventAt,
		); scanErr != nil {
			return nil, fmt.Errorf("models.ListPromoAuditEvents scan: %w", scanErr)
		}
		out = append(out, ev)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("models.ListPromoAuditEvents rows: %w", err)
	}
	return out, nil
}

// PromoStatsTopIssuer is one row of the "who issued the most codes" leaderboard.
type PromoStatsTopIssuer struct {
	Email string `json:"email"`
	Count int    `json:"count"`
}

// PromoStatsTopCode is one row of the "most-redeemed codes" leaderboard.
// (Single-use codes max at count=1 today, but the column lives in the
// response shape so a future multi-use code variant doesn't break the JSON
// contract.)
type PromoStatsTopCode struct {
	Code  string `json:"code"`
	Count int    `json:"count"`
}

// PromoStats is the response shape of GET /admin/promos/stats. Cached
// 5 min in Redis at the handler layer — DO NOT call ComputePromoStats on
// every request, it walks every row of admin_promo_codes twice.
type PromoStats struct {
	IssuedTotal          int                   `json:"issued_total"`
	RedeemedTotal        int                   `json:"redeemed_total"`
	ExpiredTotal         int                   `json:"expired_total"`
	RedemptionRate       float64               `json:"redemption_rate"`
	TopIssuers           []PromoStatsTopIssuer `json:"top_issuers"`
	TopCodesByRedemption []PromoStatsTopCode   `json:"top_codes_by_redemption"`
}

// promoStatsTopLeaderboardSize caps the top_issuers / top_codes_by_redemption
// arrays. Five is the same cardinality the dashboard renders today; bumping
// it later is a one-line change.
const promoStatsTopLeaderboardSize = 5

// ComputePromoStats walks admin_promo_codes once via aggregate SQL +
// fetches two leaderboards. Three round-trips total — kept simple rather
// than a single mega-CTE because the resulting payload is cached for 5 min
// upstream so the per-call cost matters less than the readability.
//
// Redemption rate = redeemed_total / issued_total, rounded to four decimal
// places (so the dashboard can render "12.34 %"). Zero issued → 0.0 (not
// NaN) so the JSON doesn't break.
func ComputePromoStats(ctx context.Context, db *sql.DB) (PromoStats, error) {
	var s PromoStats

	// Single roundtrip for the three totals — uses FILTER so the planner
	// scans admin_promo_codes once.
	err := db.QueryRowContext(ctx, `
		SELECT
		  COUNT(*) AS issued_total,
		  COUNT(*) FILTER (WHERE used_at IS NOT NULL) AS redeemed_total,
		  COUNT(*) FILTER (WHERE expires_at < now() AND used_at IS NULL) AS expired_total
		FROM admin_promo_codes
	`).Scan(&s.IssuedTotal, &s.RedeemedTotal, &s.ExpiredTotal)
	if err != nil {
		return s, fmt.Errorf("models.ComputePromoStats totals: %w", err)
	}

	if s.IssuedTotal > 0 {
		// Round to 4 dp by integer-rounding the *10000 product.
		rate := float64(s.RedeemedTotal) / float64(s.IssuedTotal)
		s.RedemptionRate = float64(int(rate*10000+0.5)) / 10000.0
	}

	// Top issuers — case-folded so "A@x.com" and "a@x.com" merge.
	issuerRows, err := db.QueryContext(ctx, `
		SELECT lower(issued_by_email) AS email, COUNT(*) AS n
		FROM admin_promo_codes
		GROUP BY lower(issued_by_email)
		ORDER BY n DESC, email ASC
		LIMIT $1
	`, promoStatsTopLeaderboardSize)
	if err != nil {
		return s, fmt.Errorf("models.ComputePromoStats issuers: %w", err)
	}
	s.TopIssuers = make([]PromoStatsTopIssuer, 0, promoStatsTopLeaderboardSize)
	for issuerRows.Next() {
		var row PromoStatsTopIssuer
		if scanErr := issuerRows.Scan(&row.Email, &row.Count); scanErr != nil {
			_ = issuerRows.Close() // result set fully consumed; close error irrelevant
			return s, fmt.Errorf("models.ComputePromoStats issuers scan: %w", scanErr)
		}
		s.TopIssuers = append(s.TopIssuers, row)
	}
	_ = issuerRows.Close() // result set fully consumed; close error irrelevant

	// Top redeemed codes. Single-use today, but the GROUP BY + COUNT shape
	// stays correct if redeemability becomes multi-use later.
	codeRows, err := db.QueryContext(ctx, `
		SELECT code, COUNT(*) AS n
		FROM admin_promo_codes
		WHERE used_at IS NOT NULL
		GROUP BY code
		ORDER BY n DESC, code ASC
		LIMIT $1
	`, promoStatsTopLeaderboardSize)
	if err != nil {
		return s, fmt.Errorf("models.ComputePromoStats codes: %w", err)
	}
	s.TopCodesByRedemption = make([]PromoStatsTopCode, 0, promoStatsTopLeaderboardSize)
	for codeRows.Next() {
		var row PromoStatsTopCode
		if scanErr := codeRows.Scan(&row.Code, &row.Count); scanErr != nil {
			_ = codeRows.Close() // result set fully consumed; close error irrelevant
			return s, fmt.Errorf("models.ComputePromoStats codes scan: %w", scanErr)
		}
		s.TopCodesByRedemption = append(s.TopCodesByRedemption, row)
	}
	_ = codeRows.Close() // result set fully consumed; close error irrelevant

	return s, nil
}
