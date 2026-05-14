package models

// pending_deletion.go — model layer for migration 044's pending_deletions
// table. Wave FIX-I. Drives the email-confirmed two-step deletion flow
// for paid-tier deploys and stacks.
//
// All public functions are concurrency-safe through atomic state
// transitions: the CAS-style UPDATEs gate every write on the current
// status, so a double-confirm or confirm-after-cancel race resolves to
// exactly one winner. The handler interprets a 0-row UPDATE as "already
// resolved" and returns 410 Gone with an honest agent_action.

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
)

// PendingDeletionTokenPrefix is the visible prefix on every emitted
// plaintext confirmation token. Picked to be unmistakable in logs/emails
// (vs. magic-link "mlnk_" or PAT "ink_") so a leaked grep result reads
// "this is a deletion-confirm token".
const PendingDeletionTokenPrefix = "del_"

// PendingDeletionResourceTypes — the two values currently allowed by the
// migration 044 CHECK constraint. Adding a third (e.g. "resource" for
// db/cache/nosql/queue/storage/webhook) requires migration 045 + a model
// + handler refresh. Keep this list aligned with the SQL CHECK.
const (
	PendingDeletionResourceDeploy = "deploy"
	PendingDeletionResourceStack  = "stack"
)

// PendingDeletionStatus values mirror the migration 044 CHECK enum. The
// handler writes pending/confirmed/cancelled; the worker is the only
// writer of 'expired' (separate write path keeps the TTL policy in one
// place — the worker — not split across handler + worker).
const (
	PendingDeletionStatusPending   = "pending"
	PendingDeletionStatusConfirmed = "confirmed"
	PendingDeletionStatusCancelled = "cancelled"
	PendingDeletionStatusExpired   = "expired"
)

// PendingDeletion is the in-memory projection of one pending_deletions
// row. Tokens themselves never live in this struct — the table stores
// only the hash, and the plaintext is returned exactly once at create
// time as a separate return value.
type PendingDeletion struct {
	ID                    uuid.UUID
	ResourceID            uuid.UUID
	ResourceType          string
	TeamID                uuid.UUID
	RequestedByUserID     uuid.UUID
	RequestedAt           time.Time
	ExpiresAt             time.Time
	ConfirmationTokenHash string
	Status                string
	ConfirmedAt           sql.NullTime
	CancelledAt           sql.NullTime
	EmailSentTo           string
}

// ErrPendingDeletionNotFound is returned by the lookup helpers when no
// row matches OR the row is in a terminal state. Callers MUST NOT
// distinguish "wrong token" from "expired token" in their response — a
// token-bearing attacker should learn nothing about token validity.
var ErrPendingDeletionNotFound = errors.New("pending deletion not found, expired, or already resolved")

// ErrPendingDeletionAlreadyExists is returned by CreatePendingDeletion
// when the resource already has a row in 'pending' status. The handler
// converts this to a 409 envelope with an agent_action that explains the
// existing email is still in flight.
var ErrPendingDeletionAlreadyExists = errors.New("a pending deletion already exists for this resource")

// GeneratePendingDeletionPlaintext returns a fresh url-safe token in the
// canonical "del_<base64url>" form. 32 random bytes → ~43 base64 chars
// → tokens ~47 chars total. The plaintext is returned EXACTLY ONCE; the
// caller embeds it in the email link and discards. The DB stores only
// sha256(plaintext) so a snapshot of the platform DB never leaks live
// tokens.
func GeneratePendingDeletionPlaintext() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("rand.Read: %w", err)
	}
	return PendingDeletionTokenPrefix + base64.RawURLEncoding.EncodeToString(b), nil
}

// HashPendingDeletionToken returns the storage form of a plaintext
// token. SHA-256 is constant-time on fixed-length input, which is the
// shape we have (random bytes always produce same-length base64). Same
// pattern as HashMagicLink — kept as a sibling function for symmetry.
func HashPendingDeletionToken(plaintext string) string {
	h := sha256.Sum256([]byte(plaintext))
	return hex.EncodeToString(h[:])
}

// CreatePendingDeletion inserts a fresh row + returns the (id,
// plaintextToken, expiresAt) triple. The PLAINTEXT is returned once and
// is the caller's responsibility to embed in the email link; only the
// hash is persisted.
//
// Atomicity / dedupe: enforced by a pre-INSERT existence query inside a
// transaction so a second concurrent DELETE on the same resource gets
// ErrPendingDeletionAlreadyExists rather than racing two rows into the
// pending state. We rely on idx_pending_deletions_resource_pending for
// the lookup. The unique constraint on confirmation_token_hash provides
// a backstop against accidental token collisions (effectively 2^-256).
//
// ttl is added to now() to derive expires_at. Pass 15*time.Minute for
// the operator-default; tests pass shorter ttls to exercise the worker's
// expirer path.
func CreatePendingDeletion(
	ctx context.Context,
	db *sql.DB,
	resourceID uuid.UUID,
	resourceType string,
	teamID, requestedByUserID uuid.UUID,
	emailSentTo string,
	ttl time.Duration,
) (*PendingDeletion, string, error) {
	if resourceType != PendingDeletionResourceDeploy && resourceType != PendingDeletionResourceStack {
		return nil, "", fmt.Errorf("CreatePendingDeletion: invalid resource_type %q", resourceType)
	}

	plaintext, err := GeneratePendingDeletionPlaintext()
	if err != nil {
		return nil, "", fmt.Errorf("CreatePendingDeletion: %w", err)
	}
	hash := HashPendingDeletionToken(plaintext)
	expiresAt := time.Now().UTC().Add(ttl)

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return nil, "", fmt.Errorf("CreatePendingDeletion.begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }() //nolint:errcheck // rollback after commit is a no-op

	// Existence check — partial index idx_pending_deletions_resource_pending
	// keeps this cheap. Any existing pending row blocks a second create.
	var existingID uuid.UUID
	err = tx.QueryRowContext(ctx, `
		SELECT id FROM pending_deletions
		WHERE resource_id = $1 AND resource_type = $2 AND status = 'pending'
		LIMIT 1
	`, resourceID, resourceType).Scan(&existingID)
	if err == nil {
		return nil, "", ErrPendingDeletionAlreadyExists
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return nil, "", fmt.Errorf("CreatePendingDeletion.dedup: %w", err)
	}

	p := &PendingDeletion{}
	err = tx.QueryRowContext(ctx, `
		INSERT INTO pending_deletions (
			resource_id, resource_type, team_id, requested_by_user_id,
			expires_at, confirmation_token_hash, status, email_sent_to
		) VALUES ($1, $2, $3, $4, $5, $6, 'pending', $7)
		RETURNING id, resource_id, resource_type, team_id, requested_by_user_id,
		          requested_at, expires_at, confirmation_token_hash, status,
		          confirmed_at, cancelled_at, email_sent_to
	`, resourceID, resourceType, teamID, requestedByUserID, expiresAt, hash, emailSentTo).Scan(
		&p.ID, &p.ResourceID, &p.ResourceType, &p.TeamID, &p.RequestedByUserID,
		&p.RequestedAt, &p.ExpiresAt, &p.ConfirmationTokenHash, &p.Status,
		&p.ConfirmedAt, &p.CancelledAt, &p.EmailSentTo,
	)
	if err != nil {
		return nil, "", fmt.Errorf("CreatePendingDeletion.insert: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return nil, "", fmt.Errorf("CreatePendingDeletion.commit: %w", err)
	}

	return p, plaintext, nil
}

// GetPendingDeletionByTokenHash looks up a row by its hashed token and
// gates on status='pending' AND expires_at > now(). A row that's
// already confirmed/cancelled/expired returns ErrPendingDeletionNotFound
// — callers MUST NOT distinguish those cases in the response (any
// distinction leaks token validity to an attacker).
func GetPendingDeletionByTokenHash(ctx context.Context, db *sql.DB, hash string) (*PendingDeletion, error) {
	p := &PendingDeletion{}
	err := db.QueryRowContext(ctx, `
		SELECT id, resource_id, resource_type, team_id, requested_by_user_id,
		       requested_at, expires_at, confirmation_token_hash, status,
		       confirmed_at, cancelled_at, email_sent_to
		FROM pending_deletions
		WHERE confirmation_token_hash = $1
		  AND status = 'pending'
		  AND expires_at > now()
	`, hash).Scan(
		&p.ID, &p.ResourceID, &p.ResourceType, &p.TeamID, &p.RequestedByUserID,
		&p.RequestedAt, &p.ExpiresAt, &p.ConfirmationTokenHash, &p.Status,
		&p.ConfirmedAt, &p.CancelledAt, &p.EmailSentTo,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrPendingDeletionNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("GetPendingDeletionByTokenHash: %w", err)
	}
	return p, nil
}

// GetPendingDeletionByResource returns the active pending row for the
// (resource_id, resource_type) pair, or ErrPendingDeletionNotFound if
// none is active. Drives the dashboard banner ("deletion pending, sent
// to m***@…, expires in N min") and the per-resource lookup on the
// cancel endpoint when called without a token.
func GetPendingDeletionByResource(
	ctx context.Context,
	db *sql.DB,
	resourceID uuid.UUID,
	resourceType string,
) (*PendingDeletion, error) {
	p := &PendingDeletion{}
	err := db.QueryRowContext(ctx, `
		SELECT id, resource_id, resource_type, team_id, requested_by_user_id,
		       requested_at, expires_at, confirmation_token_hash, status,
		       confirmed_at, cancelled_at, email_sent_to
		FROM pending_deletions
		WHERE resource_id = $1 AND resource_type = $2 AND status = 'pending'
		LIMIT 1
	`, resourceID, resourceType).Scan(
		&p.ID, &p.ResourceID, &p.ResourceType, &p.TeamID, &p.RequestedByUserID,
		&p.RequestedAt, &p.ExpiresAt, &p.ConfirmationTokenHash, &p.Status,
		&p.ConfirmedAt, &p.CancelledAt, &p.EmailSentTo,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrPendingDeletionNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("GetPendingDeletionByResource: %w", err)
	}
	return p, nil
}

// MarkPendingDeletionConfirmed atomically flips a row to 'confirmed'.
// The WHERE clause gates on status='pending' so a double-click on the
// email link resolves to "first one wins, second is 0-row noop". Returns
// (true, nil) on the winning path; (false, nil) on the noop path;
// (false, err) on a real DB error. The handler reads false as "already
// resolved" and responds 410 Gone.
func MarkPendingDeletionConfirmed(ctx context.Context, db *sql.DB, id uuid.UUID) (bool, error) {
	res, err := db.ExecContext(ctx, `
		UPDATE pending_deletions
		SET status = 'confirmed', confirmed_at = now()
		WHERE id = $1 AND status = 'pending'
	`, id)
	if err != nil {
		return false, fmt.Errorf("MarkPendingDeletionConfirmed: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("MarkPendingDeletionConfirmed.rows: %w", err)
	}
	return n == 1, nil
}

// MarkPendingDeletionCancelled atomically flips a row to 'cancelled'.
// Same single-winner semantics as MarkPendingDeletionConfirmed — the
// handler reads false as "already resolved" (could be confirmed,
// cancelled, or expired) and responds 410 Gone.
func MarkPendingDeletionCancelled(ctx context.Context, db *sql.DB, id uuid.UUID) (bool, error) {
	res, err := db.ExecContext(ctx, `
		UPDATE pending_deletions
		SET status = 'cancelled', cancelled_at = now()
		WHERE id = $1 AND status = 'pending'
	`, id)
	if err != nil {
		return false, fmt.Errorf("MarkPendingDeletionCancelled: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("MarkPendingDeletionCancelled.rows: %w", err)
	}
	return n == 1, nil
}

// ExpireOldPendingDeletions flips every row past its expires_at to
// status='expired' and returns the count flipped. Idempotent: rows
// already in a terminal state are filtered out by the status='pending'
// gate. Called by the worker's pending_deletion_expirer every 60s.
// Returns the list of (id, resource_id, resource_type, team_id) tuples
// flipped so the caller can emit one audit row per expiry.
type ExpiredPendingDeletion struct {
	ID           uuid.UUID
	ResourceID   uuid.UUID
	ResourceType string
	TeamID       uuid.UUID
	RequestedAt  time.Time
}

func ExpireOldPendingDeletions(ctx context.Context, db *sql.DB) ([]ExpiredPendingDeletion, error) {
	rows, err := db.QueryContext(ctx, `
		UPDATE pending_deletions
		SET status = 'expired'
		WHERE status = 'pending' AND expires_at < now()
		RETURNING id, resource_id, resource_type, team_id, requested_at
	`)
	if err != nil {
		return nil, fmt.Errorf("ExpireOldPendingDeletions: %w", err)
	}
	defer rows.Close()

	var out []ExpiredPendingDeletion
	for rows.Next() {
		var e ExpiredPendingDeletion
		if err := rows.Scan(&e.ID, &e.ResourceID, &e.ResourceType, &e.TeamID, &e.RequestedAt); err != nil {
			return nil, fmt.Errorf("ExpireOldPendingDeletions.scan: %w", err)
		}
		out = append(out, e)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("ExpireOldPendingDeletions.iter: %w", err)
	}
	return out, nil
}

// MaskEmail returns a privacy-preserving rendering of an email address
// for use in API envelopes and audit metadata. "alice@example.com"
// becomes "a***@example.com"; a one-char local part stays as-is
// ("a@example.com" → "a@example.com") to avoid emitting "@example.com"
// which leaks the full domain with zero local-part signal. An invalid
// address (no '@') is returned unchanged.
//
// The mask is reversible only with knowledge of the original — it leaks
// the domain (necessary signal for the user: "is this email going to the
// right place?") and the first char of the local part. Considered safe
// for inclusion in API responses returned to authenticated owners.
func MaskEmail(addr string) string {
	at := strings.LastIndex(addr, "@")
	if at <= 0 {
		return addr
	}
	local := addr[:at]
	domain := addr[at:]
	if len(local) == 1 {
		return local + domain
	}
	return local[:1] + strings.Repeat("*", 3) + domain
}
