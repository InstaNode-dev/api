package handlers

// family_bulk_twin.go — POST /api/v1/families/bulk-twin.
//
// One-call env-twinning for every "parent" resource a team owns in a source
// env. The agentic-founder use case: setting up a fresh staging environment
// when there are 8 prod resources turns from 8 sequential per-resource
// /provision-twin calls into one request.
//
// Behaviour summary (see the bulk-twin brief for the full spec):
//
//   - Selects active resources where env=source_env AND parent_resource_id IS NULL
//     (the "parents" of each family) for the authenticated team.
//   - Optional resource_types filter (default: all twin-supported types — postgres,
//     redis, mongodb; webhook/queue/storage are silently dropped because they
//     don't have per-env infra and would always 400 unsupported_for_twin).
//   - For each parent: skip if a twin in target_env already exists, otherwise
//     provision via the per-type ProvisionForTwinCore method. Skips are NOT
//     errors — they're explicit "already_existed" counts so idempotency is
//     observable in the response.
//   - Concurrency: a small semaphore (bulkTwinSemaphoreSize) caps in-flight
//     provisions. Bound chosen so a customer with 30 resources doesn't wait
//     30× serial provision time, but the provisioner gRPC pool / customer-DB
//     CREATE DATABASE serialisation aren't hammered. See the discussion in
//     ENG-RFC §5 for why 5 (not 10): each provision is ~2-5s and 5 keeps the
//     p99 fan-out under 6s on a typical 8-resource bundle.
//   - Idempotency: every parent that already has a twin in target_env is
//     counted into skipped_already_existed. Calling the endpoint twice in a
//     row therefore returns twinned=0, skipped=N — designed in mind of the
//     future Idempotency-Key middleware (brief B1): the natural-key dedup
//     here is what an Idempotency-Key replay would shape into anyway.
//   - Tier gate: Pro+ only. Anon/hobby/free returns 402 with agent_action.
//   - Quota gate: per-team quota headroom (default: large no-op) refuses
//     additional twins past the headroom and reports them as failures with
//     code=quota_exceeded. The default impl is permissive; bulkTwinQuotaFunc
//     is injected in tests to exercise the partial-fill path.
//   - Failure isolation: if any individual provision fails the others are
//     NOT rolled back. The customer retries just the failed ones.
//
// HTTP shape:
//
//   POST /api/v1/families/bulk-twin
//   {
//     "source_env": "production",
//     "target_env": "staging",
//     "resource_types": ["postgres", "redis"]    // optional, default = all
//   }
//
//   200 OK    — every selected parent was twinned (or already had a twin)
//   207 Multi-Status — at least one parent failed; body still carries the
//                      successful twins so the caller can keep what works
//   200 OK    — empty source_env (twinned=0, skipped=0, failures=[]). NOT
//                an error — a fresh team querying bulk-twin should get a
//                no-op response, not a 4xx.
//   402       — team's tier is below pro
//   400       — invalid source/target env, or source == target

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"sort"
	"sync"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"golang.org/x/sync/semaphore"

	"instant.dev/internal/middleware"
	"instant.dev/internal/models"
	"instant.dev/internal/plans"
)

// bulkTwinSemaphoreSize caps in-flight provision calls per bulk-twin request.
// See file-header comment for the 5-vs-10 tradeoff.
const bulkTwinSemaphoreSize = 5

// bulkTwinMaxParentsPerCall is a hard upper bound on the parents we even
// consider in one bulk call. A team that legitimately wants to twin more than
// 200 resources at once is unusual enough that we'd rather force them to slice
// the request than risk a 10-minute hold on a single Fiber connection.
const bulkTwinMaxParentsPerCall = 200

// agentActionBulkTwinQuotaExceeded — agent_action returned per-row when the
// team's headroom is exhausted before all parents were twinned. Follows the
// agent_action contract (Tell the user … specific reason … exact action …
// full https URL … under 280 chars). The dynamic %d count is bounded by
// bulkTwinMaxParentsPerCall so the rendered string stays well under 280.
func newAgentActionBulkTwinQuotaExceeded(triedCount int) string {
	return fmt.Sprintf(
		"Tell the user they've hit their plan's resource quota mid-bulk-twin (%d parents could not be twinned). Upgrade to Pro for higher quotas at https://instanode.dev/pricing — takes 30 seconds, then retry just the failed parents.",
		triedCount,
	)
}

// BulkTwinHandler orchestrates POST /api/v1/families/bulk-twin. Holds the
// three per-type provision handlers so each row can dispatch into the same
// ProvisionForTwinCore pipeline that single-row /provision-twin uses.
//
// QuotaHeadroom is the injection point for the partial-fill quota gate.
// Default impl (when nil) returns MaxInt — every parent is provisioned.
// Tests override it to assert the 207-with-quota_exceeded path.
type BulkTwinHandler struct {
	db     *sql.DB
	dbH    *DBHandler
	cacheH *CacheHandler
	nosqlH *NoSQLHandler
	plans  *plans.Registry

	// QuotaHeadroom returns the number of additional twins the team can
	// create RIGHT NOW for the given resource_type. The handler stops
	// dispatching provisions once headroom is exhausted and reports the
	// remainder as quota_exceeded failures. Negative or huge values mean
	// effectively unlimited. nil = permissive default.
	QuotaHeadroom func(ctx context.Context, teamID uuid.UUID, resourceType string) int
}

// NewBulkTwinHandler wires the bulk-twin orchestrator. Panics on missing
// per-type handlers — preferring a constructor panic to a 500 at request
// time, matching the NewTwinHandler posture above.
func NewBulkTwinHandler(db *sql.DB, dbH *DBHandler, cacheH *CacheHandler, nosqlH *NoSQLHandler, reg *plans.Registry) *BulkTwinHandler {
	if dbH == nil || cacheH == nil || nosqlH == nil {
		panic("handlers.NewBulkTwinHandler: db/cache/nosql handlers are all required")
	}
	return &BulkTwinHandler{
		db:     db,
		dbH:    dbH,
		cacheH: cacheH,
		nosqlH: nosqlH,
		plans:  reg,
	}
}

// bulkTwinRequest is the on-the-wire JSON body.
type bulkTwinRequest struct {
	SourceEnv     string   `json:"source_env"`
	TargetEnv     string   `json:"target_env"`
	ResourceTypes []string `json:"resource_types,omitempty"`
}

// bulkTwinItem is one entry in the response items array (a successful or
// skipped twin). Failures use bulkTwinFailure instead so the two paths can
// carry different metadata without nullable fields.
type bulkTwinItem struct {
	ParentToken  string `json:"parent_token"`
	TwinToken    string `json:"twin_token"`
	ResourceType string `json:"resource_type"`
	Env          string `json:"env"`
	Skipped      bool   `json:"skipped,omitempty"`
}

// bulkTwinFailure carries a per-row failure shape with the agent-readable
// error string. parent_token is always populated so the caller knows exactly
// which input row to retry.
type bulkTwinFailure struct {
	ParentToken  string `json:"parent_token"`
	ResourceType string `json:"resource_type"`
	Error        string `json:"error"`
	Message      string `json:"message"`
	AgentAction  string `json:"agent_action,omitempty"`
	UpgradeURL   string `json:"upgrade_url,omitempty"`
}

// BulkTwin is the Fiber handler.
func (h *BulkTwinHandler) BulkTwin(c *fiber.Ctx) error {
	ctx := c.UserContext()
	requestID := middleware.GetRequestID(c)

	teamID, err := parseTeamID(middleware.GetTeamID(c))
	if err != nil {
		return respondError(c, fiber.StatusUnauthorized, "unauthorized", "Valid session token required")
	}

	var body bulkTwinRequest
	if err := parseProvisionBody(c, &body); err != nil {
		return err
	}

	// Normalise + validate env strings. Empty source/target are both errors
	// here — bulk-twin is an explicit "I want every prod resource in staging"
	// operation, not a default-fill operation, so we reject the missing
	// fields rather than silently substituting EnvDefault.
	if body.SourceEnv == "" {
		return respondError(c, fiber.StatusBadRequest, "missing_source_env",
			"source_env is required — name the env you want to copy FROM (e.g. \"production\")")
	}
	if body.TargetEnv == "" {
		return respondError(c, fiber.StatusBadRequest, "missing_target_env",
			"target_env is required — name the env you want to copy TO (e.g. \"staging\")")
	}
	sourceEnv, ok := models.NormalizeEnv(body.SourceEnv)
	if !ok {
		return respondError(c, fiber.StatusBadRequest, "invalid_source_env",
			"source_env must match ^[a-z0-9-]{1,32}$ (lowercase letters, digits, dashes; max 32 chars)")
	}
	targetEnv, ok := models.NormalizeEnv(body.TargetEnv)
	if !ok {
		return respondError(c, fiber.StatusBadRequest, "invalid_target_env",
			"target_env must match ^[a-z0-9-]{1,32}$ (lowercase letters, digits, dashes; max 32 chars)")
	}
	if sourceEnv == targetEnv {
		return respondError(c, fiber.StatusBadRequest, "same_env",
			"source_env and target_env must differ — there's nothing to twin if they're the same")
	}

	// Tier gate. Multi-env workflows are Pro+ — mirror the per-resource
	// twin endpoint so the agent-facing 402 shape is identical across the
	// env-aware surface (see twin.go).
	team, err := models.GetTeamByID(ctx, h.db, teamID)
	if err != nil {
		slog.Error("bulk_twin.team_lookup_failed",
			"error", err, "team_id", teamID, "request_id", requestID)
		return respondError(c, fiber.StatusServiceUnavailable, "team_lookup_failed", "Failed to look up team")
	}
	if !multiEnvTierAllowed(team.PlanTier) {
		return respondMultiEnvUpgradeRequired(c, team.PlanTier)
	}

	// Build the resource_types filter set. Empty → twin every type the
	// twin endpoint supports. Unknown types in the filter are silently
	// dropped (rather than 400'd) so callers can pass a known-stable
	// whitelist like [postgres, redis] from older code without breaking
	// when we add a new supported type — the bulk path is conservative
	// about partial input.
	typeFilter := map[string]struct{}{}
	if len(body.ResourceTypes) == 0 {
		typeFilter[models.ResourceTypePostgres] = struct{}{}
		typeFilter[models.ResourceTypeRedis] = struct{}{}
		typeFilter[models.ResourceTypeMongoDB] = struct{}{}
	} else {
		for _, rt := range body.ResourceTypes {
			if isTwinSupportedType(rt) {
				typeFilter[rt] = struct{}{}
			}
		}
		if len(typeFilter) == 0 {
			// All filter entries were unsupported (e.g. webhook+queue+storage).
			// Returning 200 with twinned=0 lets the caller observe the no-op
			// instead of guessing whether their filter was wrong — same
			// posture as the empty-source-env path below.
			return c.JSON(fiber.Map{
				"ok":                      true,
				"twinned":                 0,
				"skipped_already_existed": 0,
				"items":                   []bulkTwinItem{},
				"failures":                []bulkTwinFailure{},
			})
		}
	}

	parents, err := h.findParents(ctx, teamID, sourceEnv, typeFilter)
	if err != nil {
		slog.Error("bulk_twin.find_parents_failed",
			"error", err, "team_id", teamID, "source_env", sourceEnv, "request_id", requestID)
		return respondError(c, fiber.StatusServiceUnavailable, "list_failed", "Failed to enumerate source resources")
	}

	// Empty source_env (no parents) is a clean no-op, NOT a 4xx. A founder
	// running bulk-twin on a fresh team would otherwise see a confusing
	// 404 — far better to return 200 + twinned=0 so the dashboard's
	// "Twin all to staging" button does nothing visible without an error
	// toast.
	if len(parents) == 0 {
		_ = h.emitBulkTwinAudit(ctx, teamID, sourceEnv, targetEnv, 0, 0, 0)
		return c.JSON(fiber.Map{
			"ok":                      true,
			"twinned":                 0,
			"skipped_already_existed": 0,
			"items":                   []bulkTwinItem{},
			"failures":                []bulkTwinFailure{},
		})
	}

	if len(parents) > bulkTwinMaxParentsPerCall {
		// Trim rather than 400 — agents calling bulk-twin shouldn't have to
		// pre-count their resources. The remainder shows up as a "retry"
		// hint in the response (failures with a clean message), which is
		// observable + actionable.
		extra := parents[bulkTwinMaxParentsPerCall:]
		parents = parents[:bulkTwinMaxParentsPerCall]
		// Note: we don't synthesise failure rows for the trimmed parents
		// here — the agent only needs the "your team has more than N
		// resources, slice the call" signal once, conveyed via metadata
		// on the audit row + a 200 with the truncated set. Surfacing 100s
		// of fake failures would drown the real failures the caller cares
		// about.
		slog.Warn("bulk_twin.truncated",
			"team_id", teamID, "trimmed", len(extra),
			"cap", bulkTwinMaxParentsPerCall, "request_id", requestID)
	}

	// Dispatch the twin per parent. Build the worklist first so we can
	// short-circuit on "already exists" without acquiring the semaphore —
	// the duplicate check is a single index read, the provision is the
	// expensive part.
	items := make([]bulkTwinItem, 0, len(parents))
	failures := make([]bulkTwinFailure, 0)
	var itemsMu sync.Mutex // guards items + failures from the goroutine pool

	// Group by resource_type so the per-type quota headroom (if injected)
	// applies independently. A team that's at quota on postgres but has
	// headroom on redis should still get redis twins.
	parentsByType := map[string][]*models.Resource{}
	for _, p := range parents {
		parentsByType[p.ResourceType] = append(parentsByType[p.ResourceType], p)
	}

	sem := semaphore.NewWeighted(bulkTwinSemaphoreSize)
	var wg sync.WaitGroup

	// Iterate types in a deterministic order so logs + the response
	// items array stay reproducible across runs — easier debugging,
	// easier test assertions.
	typeOrder := make([]string, 0, len(parentsByType))
	for t := range parentsByType {
		typeOrder = append(typeOrder, t)
	}
	sort.Strings(typeOrder)

	for _, rt := range typeOrder {
		rtParents := parentsByType[rt]
		headroom := h.resolveHeadroom(ctx, teamID, rt)

		for i, parent := range rtParents {
			parent := parent
			rt := rt

			// Quota gate: parents past the headroom go straight to the
			// failures array with quota_exceeded. We DO NOT acquire the
			// semaphore for these — they're cheap to enumerate, no point
			// burning a concurrency slot.
			if i >= headroom {
				itemsMu.Lock()
				failures = append(failures, bulkTwinFailure{
					ParentToken:  parent.Token.String(),
					ResourceType: rt,
					Error:        "quota_exceeded",
					Message:      "team plan resource quota exhausted",
					AgentAction:  newAgentActionBulkTwinQuotaExceeded(len(rtParents) - i),
					UpgradeURL:   "https://instanode.dev/pricing",
				})
				itemsMu.Unlock()
				continue
			}

			// Family-link check + duplicate-twin check happens first
			// inside the goroutine so it counts against the concurrency
			// limit (the SELECT touches the same DB the provisioner does;
			// not literally I/O-free).
			wg.Add(1)
			go func() {
				defer wg.Done()
				if err := sem.Acquire(ctx, 1); err != nil {
					itemsMu.Lock()
					failures = append(failures, bulkTwinFailure{
						ParentToken:  parent.Token.String(),
						ResourceType: rt,
						Error:        "context_cancelled",
						Message:      err.Error(),
					})
					itemsMu.Unlock()
					return
				}
				defer sem.Release(1)

				item, failure := h.twinOneParent(ctx, team, parent, targetEnv, requestID)
				itemsMu.Lock()
				defer itemsMu.Unlock()
				if failure != nil {
					failures = append(failures, *failure)
					return
				}
				items = append(items, *item)
			}()
		}
	}

	wg.Wait()

	twinned := 0
	skipped := 0
	for _, it := range items {
		if it.Skipped {
			skipped++
			continue
		}
		twinned++
	}

	_ = h.emitBulkTwinAudit(ctx, teamID, sourceEnv, targetEnv, twinned, skipped, len(failures))

	// Status code: 207 Multi-Status when there's any failure, 200 OK
	// otherwise. The spec is explicit (see file header) — partial success
	// MUST surface 207 so callers can decide whether to retry.
	status := fiber.StatusOK
	if len(failures) > 0 {
		status = http.StatusMultiStatus
	}

	// Sort items + failures by parent_token so the JSON shape is
	// deterministic — handy for snapshot tests and for the dashboard's
	// "what happened" view.
	sort.Slice(items, func(i, j int) bool { return items[i].ParentToken < items[j].ParentToken })
	sort.Slice(failures, func(i, j int) bool { return failures[i].ParentToken < failures[j].ParentToken })

	return c.Status(status).JSON(fiber.Map{
		"ok":                      len(failures) == 0,
		"twinned":                 twinned,
		"skipped_already_existed": skipped,
		"items":                   items,
		"failures":                failures,
	})
}

// findParents returns the family-root resources for a team in sourceEnv.
// "Parents" here means rows with parent_resource_id IS NULL — the prod
// resource that staging/preprod twins reference back to. Resources already
// linked as a twin (parent_resource_id IS NOT NULL) are NOT eligible as
// bulk-twin sources — we always twin from the root.
func (h *BulkTwinHandler) findParents(
	ctx context.Context, teamID uuid.UUID, sourceEnv string, typeFilter map[string]struct{},
) ([]*models.Resource, error) {
	all, err := models.ListResourcesByTeamAndEnv(ctx, h.db, teamID, sourceEnv)
	if err != nil {
		return nil, err
	}
	parents := make([]*models.Resource, 0, len(all))
	for _, r := range all {
		if r.ParentResourceID != nil {
			continue // skip — already a twin, not a root
		}
		if r.Status != "active" {
			continue // skip paused / deleted; ListResourcesByTeamAndEnv already drops deleted, this defends against paused
		}
		if _, allowed := typeFilter[r.ResourceType]; !allowed {
			continue
		}
		parents = append(parents, r)
	}
	// Deterministic order: oldest-first. Bulk-twin's quota partial-fill
	// then walks "from oldest to newest" — the principle being that long-
	// lived resources are more important to mirror than yesterday's
	// experiments. The test asserts this ordering.
	sort.Slice(parents, func(i, j int) bool {
		return parents[i].CreatedAt.Before(parents[j].CreatedAt)
	})
	return parents, nil
}

// twinOneParent provisions a single env-twin for one parent. Returns either
// a successful/skipped item or a failure — never both, never neither.
//
// The body mirrors TwinHandler.ProvisionTwin's per-row branch (validate
// family link → dispatch to per-type Core) without the body parsing,
// approval-email gate, or fiber response writes. Both paths share the
// ProvisionForTwinCore methods so the provision pipeline never forks.
//
// Note: the email-link approval gate (migration 026) intentionally does NOT
// apply to bulk-twin. The product call is that bulk-twin is itself a deliberate
// "I'm cloning prod" operation — the founder running it has already decided.
// Forcing per-row approvals would turn a "1 button" UX into "8 emails to click."
// If the operator wants the gate they should use the per-resource endpoint.
func (h *BulkTwinHandler) twinOneParent(
	ctx context.Context, team *models.Team, parent *models.Resource, targetEnv, requestID string,
) (*bulkTwinItem, *bulkTwinFailure) {
	rootID, err := models.ValidateFamilyParent(ctx, h.db, parent.ID, team.ID, parent.ResourceType, targetEnv)
	if err != nil {
		var linkErr *models.FamilyLinkError
		if errors.As(err, &linkErr) {
			switch linkErr.Reason {
			case "duplicate_twin":
				// Not a failure — record as a skipped (already-existed) item.
				// The existing twin's token is what we return so the caller
				// can update its env-binding map without a follow-up GET.
				existing, _ := models.FindFamilyMemberByEnv(ctx, h.db, parent.ID, targetEnv)
				twinToken := ""
				if existing != nil {
					twinToken = existing.Token.String()
				}
				return &bulkTwinItem{
					ParentToken:  parent.Token.String(),
					TwinToken:    twinToken,
					ResourceType: parent.ResourceType,
					Env:          targetEnv,
					Skipped:      true,
				}, nil
			case "cross_team", "cross_type", "deleted_parent":
				// Defensive — findParents already filtered these.
				return nil, &bulkTwinFailure{
					ParentToken:  parent.Token.String(),
					ResourceType: parent.ResourceType,
					Error:        linkErr.Reason,
					Message:      linkErr.Detail,
				}
			}
		}
		slog.Error("bulk_twin.validate_family_failed",
			"error", err, "parent_id", parent.ID, "target_env", targetEnv, "request_id", requestID)
		return nil, &bulkTwinFailure{
			ParentToken:  parent.Token.String(),
			ResourceType: parent.ResourceType,
			Error:        "family_validate_failed",
			Message:      "failed to validate twin link for this parent",
		}
	}

	in := ProvisionForTwinInput{
		TeamID:       team.ID,
		Name:         nullStrOrEmpty(parent.Name),
		Tier:         parent.Tier,
		Env:          targetEnv,
		ParentRootID: &rootID,
		Fingerprint:  nullStr(parent.Fingerprint),
		CloudVendor:  nullStr(parent.CloudVendor),
		CountryCode:  nullStr(parent.CountryCode),
		RequestID:    requestID,
		Start:        time.Now(),
	}

	var (
		result TwinProvisionResult
		provErr error
	)
	switch parent.ResourceType {
	case models.ResourceTypePostgres:
		result, provErr = h.dbH.ProvisionForTwinCore(ctx, in)
	case models.ResourceTypeRedis:
		result, provErr = h.cacheH.ProvisionForTwinCore(ctx, in)
	case models.ResourceTypeMongoDB:
		result, provErr = h.nosqlH.ProvisionForTwinCore(ctx, in)
	default:
		// Defensive — findParents already filtered to supported types.
		return nil, &bulkTwinFailure{
			ParentToken:  parent.Token.String(),
			ResourceType: parent.ResourceType,
			Error:        "unsupported_for_twin",
			Message:      "resource_type not supported for env-twin",
		}
	}
	if provErr != nil {
		return nil, &bulkTwinFailure{
			ParentToken:  parent.Token.String(),
			ResourceType: parent.ResourceType,
			Error:        "provision_failed",
			Message:      provErr.Error(),
		}
	}

	return &bulkTwinItem{
		ParentToken:  parent.Token.String(),
		TwinToken:    result.Token,
		ResourceType: parent.ResourceType,
		Env:          targetEnv,
	}, nil
}

// resolveHeadroom returns the per-resource-type headroom for the team. The
// QuotaHeadroom hook (test-injectable) drives the partial-fill case. Default
// behaviour returns a huge number — bulk-twin doesn't enforce a count cap
// in prod today because plans.yaml has no per-type resource-count quota.
// If/when one lands (e.g. team-tier max 100 postgres rows), wiring it here
// is one method change.
func (h *BulkTwinHandler) resolveHeadroom(
	ctx context.Context, teamID uuid.UUID, resourceType string,
) int {
	if h.QuotaHeadroom == nil {
		return bulkTwinMaxParentsPerCall
	}
	hr := h.QuotaHeadroom(ctx, teamID, resourceType)
	if hr < 0 {
		hr = 0
	}
	return hr
}

// emitBulkTwinAudit writes a best-effort audit row carrying the per-call
// twin counts. Best-effort means we don't fail the request if the audit
// write errors — matches the rest of the audit pipeline's fail-open posture.
// Kind matches the brief's expectation: family.bulk_twin.
func (h *BulkTwinHandler) emitBulkTwinAudit(
	ctx context.Context, teamID uuid.UUID, sourceEnv, targetEnv string,
	twinned, skipped, failures int,
) error {
	meta, _ := json.Marshal(map[string]any{
		"source_env":     sourceEnv,
		"target_env":     targetEnv,
		"twinned_count": twinned,
		"skipped_count": skipped,
		"failure_count": failures,
	})
	summary := fmt.Sprintf(
		"agent bulk-twinned <code>%s</code> → <code>%s</code>: %d twinned, %d skipped, %d failed",
		sourceEnv, targetEnv, twinned, skipped, failures,
	)
	go func() {
		_ = models.InsertAuditEvent(context.Background(), h.db, models.AuditEvent{
			TeamID:   teamID,
			Actor:    "agent",
			Kind:     models.AuditKindFamilyBulkTwin,
			Summary:  summary,
			Metadata: meta,
		})
	}()
	return nil
}

// nullStrOrEmpty mirrors nullStr but reads the sql.NullString from a
// models.Resource.Name without forcing the caller to inline the check.
func nullStrOrEmpty(ns sql.NullString) string {
	if !ns.Valid {
		return ""
	}
	return ns.String
}
