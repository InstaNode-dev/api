package models

// resource_family.go — env-twin family helpers introduced by migration 018
// (slice 2 of env-aware deployments). A "family" is a set of resources that
// represent the same logical resource across envs (e.g. prod-db / staging-db
// / dev-db). The root row has parent_resource_id IS NULL and its id is the
// family id. Children point at the root via parent_resource_id.
//
// Caching note: ListResourceFamiliesByTeam aggregates across every active
// resource for a team. Family membership only changes on provisioning + soft
// delete, so the handler is free to cache the response per team for short
// windows (the handler picks Cache-Control: private, max-age=30 — same
// freshness window as ListResourcesByTeam, since the family view is a
// strictly-narrower aggregation of the same row set). Quota / billing gates
// must NOT rely on this aggregate.

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"instant.dev/common/resourcestatus"
)

// FamilyMember is one row in a family payload — the subset of Resource fields
// dashboards and the families list endpoint care about. Keeping the type tight
// avoids accidentally surfacing fields like connection_url across the wire.
type FamilyMember struct {
	ID           uuid.UUID
	Token        uuid.UUID
	Env          string
	ResourceType string
	Name         sql.NullString
	Tier         string
	Status       string
	IsRoot       bool
}

// FamilySummary is one entry in ListResourceFamiliesByTeam. The root id is
// the stable family identifier. MembersPerEnv groups by env so the dashboard
// renders an env-grid (prod / staging / dev) without client-side bucketing.
type FamilySummary struct {
	FamilyRootID uuid.UUID
	ResourceType string
	MembersByEnv map[string]FamilyMember
}

// GetResourceFamily returns the root + all members of the family that `id`
// belongs to. If `id` is itself an orphan (no parent and no children) the
// result is a single-element slice containing just that resource. Empty
// slice means the id wasn't found at all (caller should already have
// authorised + verified ownership before calling).
//
// The root walk uses WITH RECURSIVE so any chain depth is supported, though
// in practice provisioning only ever creates direct children of the root.
func GetResourceFamily(ctx context.Context, db *sql.DB, id uuid.UUID) ([]*Resource, error) {
	// Step 1: resolve the family root. If the row itself has parent IS NULL
	// it IS the root; otherwise walk up.
	var rootID uuid.UUID
	err := db.QueryRowContext(ctx, `
		WITH RECURSIVE chain(id, parent_resource_id) AS (
			SELECT id, parent_resource_id FROM resources WHERE id = $1
			UNION ALL
			SELECT r.id, r.parent_resource_id
			  FROM resources r
			  JOIN chain c ON c.parent_resource_id = r.id
		)
		SELECT id FROM chain WHERE parent_resource_id IS NULL LIMIT 1
	`, id).Scan(&rootID)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("models.GetResourceFamily: walk root: %w", err)
	}

	// Step 2: fetch root + all direct children (skip soft-deleted rows).
	rows, err := db.QueryContext(ctx, `
		SELECT `+resourceColumns+`
		FROM resources
		WHERE (id = $1 OR parent_resource_id = $1)
		  AND status != 'deleted'
		ORDER BY (id = $1) DESC, env ASC, created_at ASC
	`, rootID)
	if err != nil {
		return nil, fmt.Errorf("models.GetResourceFamily: fetch: %w", err)
	}
	defer rows.Close()

	var results []*Resource
	for rows.Next() {
		r, err := scanResource(rows)
		if err != nil {
			return nil, fmt.Errorf("models.GetResourceFamily: scan: %w", err)
		}
		results = append(results, r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("models.GetResourceFamily: rows: %w", err)
	}
	return results, nil
}

// FindFamilyMemberByEnv returns the family member at a specific env, or nil
// (no error) if none exists yet. Used by the family-binding path before
// 409-ing on a duplicate twin.
func FindFamilyMemberByEnv(ctx context.Context, db *sql.DB, rootID uuid.UUID, env string) (*Resource, error) {
	row := db.QueryRowContext(ctx, `
		SELECT `+resourceColumns+`
		FROM resources
		WHERE (id = $1 OR parent_resource_id = $1)
		  AND env = $2
		  AND status != 'deleted'
		LIMIT 1
	`, rootID, env)
	r, err := scanResource(row)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("models.FindFamilyMemberByEnv: %w", err)
	}
	return r, nil
}

// ListResourceFamiliesByTeam returns one FamilySummary per family root the
// team owns. A resource without children or parent renders as a single-
// member family (its own root). Soft-deleted rows are excluded.
//
// Implementation note: a single SELECT pulls every active team resource,
// then we group in-memory by (parent_resource_id ?? id). The team's total
// resource count is bounded by tier limits — at most a few hundred rows
// per call even on the team tier — so the in-Go grouping stays cheaper
// than a multi-CTE Postgres aggregation.
func ListResourceFamiliesByTeam(ctx context.Context, db *sql.DB, teamID uuid.UUID) ([]FamilySummary, error) {
	rows, err := db.QueryContext(ctx, `
		SELECT `+resourceColumns+`
		FROM resources
		WHERE team_id = $1 AND status != 'deleted'
		ORDER BY created_at ASC
	`, teamID)
	if err != nil {
		return nil, fmt.Errorf("models.ListResourceFamiliesByTeam: %w", err)
	}
	defer rows.Close()

	// Group by family root id. root_id = parent_resource_id when set,
	// else the row's own id.
	type group struct {
		rootID       uuid.UUID
		resourceType string
		members      map[string]FamilyMember
	}
	groups := make(map[uuid.UUID]*group)
	order := make([]uuid.UUID, 0)

	for rows.Next() {
		r, scanErr := scanResource(rows)
		if scanErr != nil {
			return nil, fmt.Errorf("models.ListResourceFamiliesByTeam: scan: %w", scanErr)
		}
		var rootID uuid.UUID
		if r.ParentResourceID != nil {
			rootID = *r.ParentResourceID
		} else {
			rootID = r.ID
		}
		g, ok := groups[rootID]
		if !ok {
			g = &group{
				rootID:       rootID,
				resourceType: r.ResourceType,
				members:      make(map[string]FamilyMember),
			}
			groups[rootID] = g
			order = append(order, rootID)
		}
		g.members[r.Env] = FamilyMember{
			ID:           r.ID,
			Token:        r.Token,
			Env:          r.Env,
			ResourceType: r.ResourceType,
			Name:         r.Name,
			Tier:         r.Tier,
			Status:       r.Status,
			IsRoot:       r.ParentResourceID == nil,
		}
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("models.ListResourceFamiliesByTeam: rows: %w", err)
	}

	// A child whose root is not in the result set (e.g. root was hard-
	// deleted or owned by a different team — defensive) still appears
	// as its own family. The map already keyed it under the child id
	// when the root wasn't seen; nothing extra to do.

	summaries := make([]FamilySummary, 0, len(order))
	for _, rid := range order {
		g := groups[rid]
		summaries = append(summaries, FamilySummary{
			FamilyRootID: g.rootID,
			ResourceType: g.resourceType,
			MembersByEnv: g.members,
		})
	}
	return summaries, nil
}

// GetResourceByID fetches a single resource by its internal id (not token).
// Returns ErrResourceNotFound when the row doesn't exist. Used by the
// family-link validation path so we don't expose the token of someone
// else's resource via the parent_resource_id check.
func GetResourceByID(ctx context.Context, db *sql.DB, id uuid.UUID) (*Resource, error) {
	row := db.QueryRowContext(ctx, `SELECT `+resourceColumns+` FROM resources WHERE id = $1`, id)
	r, err := scanResource(row)
	if err == sql.ErrNoRows {
		return nil, &ErrResourceNotFound{Token: id.String()}
	}
	if err != nil {
		return nil, fmt.Errorf("models.GetResourceByID: %w", err)
	}
	return r, nil
}

// FamilyLinkError differentiates the three "can't link" cases so the
// handler can map each to the right HTTP status (403 cross-team, 400
// cross-type, 409 duplicate twin).
type FamilyLinkError struct {
	Reason string // "cross_team" | "cross_type" | "duplicate_twin" | "deleted_parent"
	Detail string
}

func (e *FamilyLinkError) Error() string { return e.Detail }

// ValidateFamilyParent checks that linking `child` (a not-yet-created
// resource of resourceType in env) to the family containing `parentID`
// is legal:
//   - parent must exist + be active (else deleted_parent)
//   - parent must belong to the same team (else cross_team)
//   - parent must be the same resource_type (else cross_type)
//   - no existing member of the family must already occupy `env`
//     (else duplicate_twin)
//
// Returns the family ROOT id (which is what callers store in the new
// row's parent_resource_id) and no error on success.
func ValidateFamilyParent(
	ctx context.Context, db *sql.DB,
	parentID uuid.UUID, teamID uuid.UUID, resourceType, env string,
) (uuid.UUID, error) {
	parent, err := GetResourceByID(ctx, db, parentID)
	if err != nil {
		var nf *ErrResourceNotFound
		if errors.As(err, &nf) {
			return uuid.Nil, &FamilyLinkError{
				Reason: "deleted_parent",
				Detail: "parent_resource_id does not refer to an existing resource",
			}
		}
		return uuid.Nil, err
	}
	if parentStatus, _ := resourcestatus.Parse(parent.Status); parentStatus.IsDeleted() {
		return uuid.Nil, &FamilyLinkError{
			Reason: "deleted_parent",
			Detail: "parent resource has been deleted",
		}
	}
	if !parent.TeamID.Valid || parent.TeamID.UUID != teamID {
		return uuid.Nil, &FamilyLinkError{
			Reason: "cross_team",
			Detail: "parent resource belongs to a different team",
		}
	}
	if parent.ResourceType != resourceType {
		return uuid.Nil, &FamilyLinkError{
			Reason: "cross_type",
			Detail: fmt.Sprintf("parent resource is %s; cannot link a %s child", parent.ResourceType, resourceType),
		}
	}

	// Resolve the family root so the new row joins at the root, not at
	// a child (keeps the chain depth ≤1).
	rootID := parent.ID
	if parent.ParentResourceID != nil {
		rootID = *parent.ParentResourceID
	}

	// Reject duplicates at the model layer for a friendly 409 — the
	// partial unique index in migration 018 is the schema-level guard,
	// but doing the lookup here avoids leaking a Postgres constraint
	// error string to the API caller.
	existing, err := FindFamilyMemberByEnv(ctx, db, rootID, env)
	if err != nil {
		return uuid.Nil, err
	}
	if existing != nil {
		return uuid.Nil, &FamilyLinkError{
			Reason: "duplicate_twin",
			Detail: fmt.Sprintf("family already has a %s resource in env=%s", resourceType, env),
		}
	}

	return rootID, nil
}
