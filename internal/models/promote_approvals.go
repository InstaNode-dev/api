package models

// promote_approvals.go — email-link approval workflow for env promotions
// targeting non-development environments. See migration 026 for the table
// shape + rationale.
//
// The model layer enforces three contracts:
//
//   1. CRYPTOGRAPHIC TOKENS. GeneratePromoteApprovalToken returns
//      base64-URL-encoded crypto/rand bytes — never math/rand. The token
//      space is 32 bytes (≥ 2^256 possibilities); brute-force at the
//      handler-level 10 req/sec rate limit takes longer than the heat
//      death of the universe.
//
//   2. SINGLE-USE APPROVAL. ApprovePromoteApproval is implemented as an
//      atomic UPDATE ... WHERE status='pending' AND expires_at > now().
//      Returns (false, nil) if zero rows were affected — caller treats
//      that as "already used / expired / never existed" without leaking
//      which branch triggered. Two concurrent clicks on the same link
//      result in exactly one approval.
//
//   3. EXPLICIT EXPIRY FLIP. MarkPromoteApprovalExpired transitions a
//      row from pending → expired so the GET /approve handler can report
//      "this link expired" the second time a user clicks an old link
//      (instead of "this link never existed"). The first click after
//      expiry is the one that flips the row; this is best-effort and
//      idempotent.
//
// The audit_log emission (kind=promote.approval_requested / .approved /
// .rejected / .executed) is the handler's job — this file only owns the
// rows on disk.

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
)

// Promote approval status values. Hard-coded constants (vs free-form
// strings) so the audit_log forwarder + admin reject endpoint never
// have to typo-match a literal.
const (
	PromoteApprovalStatusPending  = "pending"
	PromoteApprovalStatusApproved = "approved"
	PromoteApprovalStatusRejected = "rejected"
	PromoteApprovalStatusExpired  = "expired"
	PromoteApprovalStatusExecuted = "executed"
)

// PromoteApprovalKind discriminates which downstream handler the worker
// (or manual re-call path) will dispatch to once status flips to
// 'approved'. Stack and resource_twin are the two callers today; future
// promote-style endpoints add a new kind here.
const (
	PromoteApprovalKindStack        = "stack"
	PromoteApprovalKindResourceTwin = "resource_twin"
)

// PromoteApprovalTokenTTL is the lifetime applied to a fresh pending row.
// Held as a package-level constant so the handler, audit metadata, and
// the operator-facing copy ("links are valid for 24h") never drift.
const PromoteApprovalTokenTTL = 24 * time.Hour

// PromoteApproval is one row in the promote_approvals table.
type PromoteApproval struct {
	ID                 uuid.UUID
	Token              string
	TeamID             uuid.UUID
	RequestedByEmail   string
	PromoteKind        string
	PromotePayload     []byte // raw JSONB
	FromEnv            string
	ToEnv              string
	Status             string
	CreatedAt          time.Time
	ExpiresAt          time.Time
	ApprovedAt         sql.NullTime
	ExecutedAt         sql.NullTime
	RejectedAt         sql.NullTime
}

// ErrPromoteApprovalNotFound is returned when a token / id lookup yields
// no rows OR the lookup is restricted to pending rows and the row is no
// longer pending. Callers MUST NOT distinguish "never existed" from
// "expired/used/rejected" in the user-facing response — both render as
// "this link is invalid."
var ErrPromoteApprovalNotFound = errors.New("promote approval not found, expired, or already used")

// GeneratePromoteApprovalToken returns a fresh URL-safe random token. 32
// bytes → ~43 base64 chars. Uses crypto/rand only — math/rand would let
// an attacker who saw any single token predict every other token (Go's
// math/rand is a deterministic Mersenne Twister).
func GeneratePromoteApprovalToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("models.GeneratePromoteApprovalToken: rand.Read: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// CreatePromoteApprovalParams is the input shape for CreatePromoteApproval.
// Keeping a struct (vs positional args) so adding "approver_email" or
// "diff_summary" later is a single source-level change.
type CreatePromoteApprovalParams struct {
	Token            string
	TeamID           uuid.UUID
	RequestedByEmail string
	PromoteKind      string
	PromotePayload   []byte // raw JSON bytes
	FromEnv          string
	ToEnv            string
	TTL              time.Duration // 0 → PromoteApprovalTokenTTL
}

// CreatePromoteApproval inserts a fresh pending row. The caller generates
// the plaintext token via GeneratePromoteApprovalToken and persists it
// here in plaintext (single-use, expires fast, only valuable in a 24h
// window — no need for the SHA-256 hashing magic-links use, which guard
// against database-leak replay over weeks).
func CreatePromoteApproval(ctx context.Context, db *sql.DB, p CreatePromoteApprovalParams) (*PromoteApproval, error) {
	ttl := p.TTL
	if ttl <= 0 {
		ttl = PromoteApprovalTokenTTL
	}
	expiresAt := time.Now().UTC().Add(ttl)

	row := &PromoteApproval{}
	err := db.QueryRowContext(ctx, `
		INSERT INTO promote_approvals
			(token, team_id, requested_by_email, promote_kind, promote_payload, from_env, to_env, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		RETURNING id, token, team_id, requested_by_email, promote_kind, promote_payload,
		          from_env, to_env, status, created_at, expires_at, approved_at, executed_at, rejected_at
	`, p.Token, p.TeamID, p.RequestedByEmail, p.PromoteKind, p.PromotePayload, p.FromEnv, p.ToEnv, expiresAt).Scan(
		&row.ID, &row.Token, &row.TeamID, &row.RequestedByEmail, &row.PromoteKind, &row.PromotePayload,
		&row.FromEnv, &row.ToEnv, &row.Status, &row.CreatedAt, &row.ExpiresAt,
		&row.ApprovedAt, &row.ExecutedAt, &row.RejectedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("models.CreatePromoteApproval: %w", err)
	}
	return row, nil
}

// GetPromoteApprovalByToken looks up a row by its token regardless of
// status. The GET /approve/:token handler uses this to distinguish
// "pending" (valid click) from "expired" / "approved" / "rejected" so it
// can render the right copy.
//
// Returns ErrPromoteApprovalNotFound when the token doesn't exist at all
// (so an attacker probing the token space gets the same response as
// someone clicking a typo'd link).
func GetPromoteApprovalByToken(ctx context.Context, db *sql.DB, token string) (*PromoteApproval, error) {
	row := &PromoteApproval{}
	err := db.QueryRowContext(ctx, `
		SELECT id, token, team_id, requested_by_email, promote_kind, promote_payload,
		       from_env, to_env, status, created_at, expires_at, approved_at, executed_at, rejected_at
		FROM promote_approvals
		WHERE token = $1
	`, token).Scan(
		&row.ID, &row.Token, &row.TeamID, &row.RequestedByEmail, &row.PromoteKind, &row.PromotePayload,
		&row.FromEnv, &row.ToEnv, &row.Status, &row.CreatedAt, &row.ExpiresAt,
		&row.ApprovedAt, &row.ExecutedAt, &row.RejectedAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrPromoteApprovalNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("models.GetPromoteApprovalByToken: %w", err)
	}
	return row, nil
}

// GetPromoteApprovalByID looks up a row by primary key. Used by the
// admin reject endpoint and the dashboard's per-approval detail view
// (GET /api/v1/promotions/:id when that lands).
func GetPromoteApprovalByID(ctx context.Context, db *sql.DB, id uuid.UUID) (*PromoteApproval, error) {
	row := &PromoteApproval{}
	err := db.QueryRowContext(ctx, `
		SELECT id, token, team_id, requested_by_email, promote_kind, promote_payload,
		       from_env, to_env, status, created_at, expires_at, approved_at, executed_at, rejected_at
		FROM promote_approvals
		WHERE id = $1
	`, id).Scan(
		&row.ID, &row.Token, &row.TeamID, &row.RequestedByEmail, &row.PromoteKind, &row.PromotePayload,
		&row.FromEnv, &row.ToEnv, &row.Status, &row.CreatedAt, &row.ExpiresAt,
		&row.ApprovedAt, &row.ExecutedAt, &row.RejectedAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrPromoteApprovalNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("models.GetPromoteApprovalByID: %w", err)
	}
	return row, nil
}

// ApprovePromoteApproval atomically flips a pending row to approved.
// Returns (true, nil) on the first call against an unexpired pending row,
// (false, nil) on every other case (already approved, rejected, expired,
// or expires_at in the past). The single-use guarantee comes from the
// WHERE clause: two simultaneous clicks resolve to exactly one row update.
func ApprovePromoteApproval(ctx context.Context, db *sql.DB, id uuid.UUID) (bool, error) {
	res, err := db.ExecContext(ctx, `
		UPDATE promote_approvals
		SET status = 'approved', approved_at = now()
		WHERE id = $1 AND status = 'pending' AND expires_at > now()
	`, id)
	if err != nil {
		return false, fmt.Errorf("models.ApprovePromoteApproval: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("models.ApprovePromoteApproval rows: %w", err)
	}
	return n == 1, nil
}

// MarkPromoteApprovalExpired flips a row's status to 'expired' when its
// expires_at is in the past and it's still pending. Best-effort — used by
// the GET /approve handler to make the second click on an old link
// surface a "link expired" message instead of "link invalid". The first
// click that touches the row after expiry does the flip; further reads
// see status='expired' and can branch on that.
func MarkPromoteApprovalExpired(ctx context.Context, db *sql.DB, id uuid.UUID) error {
	_, err := db.ExecContext(ctx, `
		UPDATE promote_approvals
		SET status = 'expired'
		WHERE id = $1 AND status = 'pending' AND expires_at <= now()
	`, id)
	if err != nil {
		return fmt.Errorf("models.MarkPromoteApprovalExpired: %w", err)
	}
	return nil
}

// RejectPromoteApproval flips a pending row to rejected. Admin-only —
// the handler enforces ADMIN_EMAILS gating before calling this. Returns
// (true, nil) on success, (false, nil) when the row is no longer
// pending (already approved, expired, rejected). The atomic guard is
// the WHERE clause: admin clicks "reject" the same instant a user
// clicks the email link → exactly one of the two transitions wins.
func RejectPromoteApproval(ctx context.Context, db *sql.DB, id uuid.UUID) (bool, error) {
	res, err := db.ExecContext(ctx, `
		UPDATE promote_approvals
		SET status = 'rejected', rejected_at = now()
		WHERE id = $1 AND status = 'pending'
	`, id)
	if err != nil {
		return false, fmt.Errorf("models.RejectPromoteApproval: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("models.RejectPromoteApproval rows: %w", err)
	}
	return n == 1, nil
}

// MarkPromoteApprovalExecuted flips an approved row to executed once the
// worker (out of scope for this PR) has actually run the cached promote.
// Provided here so the model layer owns every legal state transition —
// the worker repo will call this once its polling job lands.
func MarkPromoteApprovalExecuted(ctx context.Context, db *sql.DB, id uuid.UUID) (bool, error) {
	res, err := db.ExecContext(ctx, `
		UPDATE promote_approvals
		SET status = 'executed', executed_at = now()
		WHERE id = $1 AND status = 'approved' AND executed_at IS NULL
	`, id)
	if err != nil {
		return false, fmt.Errorf("models.MarkPromoteApprovalExecuted: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("models.MarkPromoteApprovalExecuted rows: %w", err)
	}
	return n == 1, nil
}

// ListPromoteApprovalsParams is the filter shape for ListPromoteApprovals.
// status == "" means "all statuses" so callers don't have to specialise
// the list call for the "everything" view. Limit is clamped server-side.
type ListPromoteApprovalsParams struct {
	Status string
	Limit  int
}

// promoteApprovalsMaxLimit caps the result set so an unbounded list
// request can't sweep the table. Mirrors auditMaxLimit (audit_log.go).
const promoteApprovalsMaxLimit = 200

// ListPromoteApprovals returns the most recent rows matching the filter,
// newest first. Used by the admin dashboard's "what's awaiting approval"
// view. Filters by status when set, returns everything otherwise.
func ListPromoteApprovals(ctx context.Context, db *sql.DB, p ListPromoteApprovalsParams) ([]*PromoteApproval, error) {
	limit := p.Limit
	if limit <= 0 {
		limit = 50
	}
	if limit > promoteApprovalsMaxLimit {
		limit = promoteApprovalsMaxLimit
	}

	var rows *sql.Rows
	var err error
	if p.Status == "" {
		rows, err = db.QueryContext(ctx, `
			SELECT id, token, team_id, requested_by_email, promote_kind, promote_payload,
			       from_env, to_env, status, created_at, expires_at, approved_at, executed_at, rejected_at
			FROM promote_approvals
			ORDER BY created_at DESC
			LIMIT $1
		`, limit)
	} else {
		rows, err = db.QueryContext(ctx, `
			SELECT id, token, team_id, requested_by_email, promote_kind, promote_payload,
			       from_env, to_env, status, created_at, expires_at, approved_at, executed_at, rejected_at
			FROM promote_approvals
			WHERE status = $1
			ORDER BY created_at DESC
			LIMIT $2
		`, p.Status, limit)
	}
	if err != nil {
		return nil, fmt.Errorf("models.ListPromoteApprovals: %w", err)
	}
	defer rows.Close()

	out := make([]*PromoteApproval, 0)
	for rows.Next() {
		row := &PromoteApproval{}
		if err := rows.Scan(
			&row.ID, &row.Token, &row.TeamID, &row.RequestedByEmail, &row.PromoteKind, &row.PromotePayload,
			&row.FromEnv, &row.ToEnv, &row.Status, &row.CreatedAt, &row.ExpiresAt,
			&row.ApprovedAt, &row.ExecutedAt, &row.RejectedAt,
		); err != nil {
			return nil, fmt.Errorf("models.ListPromoteApprovals scan: %w", err)
		}
		out = append(out, row)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("models.ListPromoteApprovals rows: %w", err)
	}
	return out, nil
}
