package models

// deployment_event.go — model for the deployment_events table.
//
// Autopsy rows are written by the worker (deploy_status_reconcile + build
// failure path) and read by the api's GET /deploy/:id handler via
// GetLatestDeploymentAutopsy. The api then serialises the result into the
// optional "failure" field of the deployment response per the contract:
//
//   "failure": {
//     "reason":      "<FailureReason constant>",
//     "exit_code":   <int|null>,
//     "event":       "<k8s event message or build error>",
//     "last_lines":  ["<log line>", ...],  // up to 200, oldest-first
//     "hint":        "<plain-language likely cause + remedy>",
//     "occurred_at": "<RFC3339>"
//   }
//
// The "failure" object is present only when the deployment is in a failure
// state AND an autopsy row exists. Absent when the deployment is healthy /
// building / deploying / stopped (stopped = namespace torn down, not a
// failure).

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
)

// ── Failure reason constants ──────────────────────────────────────────────────
//
// Named constants so no handler or worker ever hard-codes a string literal.
// If a new reason is added, grep for FailureReasonUnknown to find the
// exhaustive switch statements that need updating.
const (
	// FailureReasonOOMKilled means the container was killed by the kernel
	// because it exceeded its memory limit.
	FailureReasonOOMKilled = "OOMKilled"

	// FailureReasonEvicted means the pod was evicted from the node (disk
	// pressure, memory pressure, or node-level resource starvation).
	FailureReasonEvicted = "Evicted"

	// FailureReasonImagePullBackOff means k8s could not pull the container
	// image — bad image name, registry auth failure, or image not pushed yet.
	FailureReasonImagePullBackOff = "ImagePullBackOff"

	// FailureReasonCrashLoopBackOff means the container crashed repeatedly
	// and k8s backed off retrying. The application exited non-zero.
	FailureReasonCrashLoopBackOff = "CrashLoopBackOff"

	// FailureReasonBuildFailed means the Kaniko image build job failed before
	// any k8s Deployment was created. The event field holds the build error.
	FailureReasonBuildFailed = "BuildFailed"

	// FailureReasonDeadlineExceeded means the build or rollout timed out
	// (10-minute deadline in runDeploy / waitForJobComplete).
	FailureReasonDeadlineExceeded = "DeadlineExceeded"

	// FailureReasonError covers transient k8s API errors and generic
	// "ReplicaFailure" conditions that don't map to a more specific reason.
	FailureReasonError = "Error"

	// FailureReasonUnknown is the catch-all for states the platform cannot
	// classify. Dashboard should prompt the user to check logs.
	FailureReasonUnknown = "Unknown"
)

// DeploymentEventKindFailureAutopsy is the kind stored for failure post-mortems.
// The only kind used today — extensible for future row types.
const DeploymentEventKindFailureAutopsy = "failure_autopsy"

// DeploymentEvent mirrors one row of the deployment_events table.
// Only failure_autopsy kind rows are exposed via the public API today.
type DeploymentEvent struct {
	ID           uuid.UUID
	DeploymentID uuid.UUID
	Kind         string
	Reason       string
	ExitCode     sql.NullInt32 // NULL when no exit code is available
	Event        string        // k8s event message or build error text
	LastLines    []string      // up to 200 lines, oldest-first
	Hint         string
	CreatedAt    time.Time
}

// DeploymentAutopsyRow is the minimal projection used by deploymentToMap to
// populate the "failure" response field. It does NOT embed the full
// DeploymentEvent so the query can be a lean SELECT without scanning all
// columns of a wide join.
type DeploymentAutopsyRow struct {
	Reason    string
	ExitCode  sql.NullInt32
	Event     string
	LastLines []string
	Hint      string
	CreatedAt time.Time
}

// GetLatestDeploymentAutopsy returns the most recent failure_autopsy row for
// the given deployment, or (nil, nil) when no autopsy exists. The api's
// deploymentToMap calls this when serialising a failed deployment.
//
// The query uses the deployment_events_autopsy_uniq partial unique index
// (deployment_id, kind) WHERE kind='failure_autopsy', so at most one row is
// ever returned.
func GetLatestDeploymentAutopsy(ctx context.Context, db *sql.DB, deploymentID uuid.UUID) (*DeploymentAutopsyRow, error) {
	var row DeploymentAutopsyRow
	var lastLinesRaw []byte

	err := db.QueryRowContext(ctx, `
		SELECT reason, exit_code, event, last_lines, hint, created_at
		FROM deployment_events
		WHERE deployment_id = $1
		  AND kind = $2
		ORDER BY created_at DESC
		LIMIT 1
	`, deploymentID, DeploymentEventKindFailureAutopsy).Scan(
		&row.Reason,
		&row.ExitCode,
		&row.Event,
		&lastLinesRaw,
		&row.Hint,
		&row.CreatedAt,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("models.GetLatestDeploymentAutopsy: %w", err)
	}

	if len(lastLinesRaw) > 0 {
		if err := json.Unmarshal(lastLinesRaw, &row.LastLines); err != nil {
			// Defensive: return what we can rather than surfacing a parse
			// error to the caller. An empty slice is preferable to a 500.
			row.LastLines = nil
		}
	}
	if row.LastLines == nil {
		row.LastLines = []string{}
	}

	return &row, nil
}

// UpsertDeploymentAutopsy writes or updates the single failure_autopsy row for
// a deployment. The partial unique index on (deployment_id, kind) WHERE
// kind='failure_autopsy' ensures at most one row exists per deployment;
// ON CONFLICT DO UPDATE makes successive calls from the reconcile loop
// idempotent — a repeated tick with the same data is a silent no-op at the
// DB level (updated_at is not stored; created_at stays the original timestamp
// of the first failure capture).
//
// Parameters are passed as a struct to keep the call-site readable across the
// two write paths (worker reconcile + api build failure).
type UpsertAutopsyParams struct {
	DeploymentID uuid.UUID
	Reason       string
	ExitCode     sql.NullInt32
	Event        string
	LastLines    []string
	Hint         string
}

// UpsertDeploymentAutopsy inserts or updates the failure autopsy row.
func UpsertDeploymentAutopsy(ctx context.Context, db *sql.DB, p UpsertAutopsyParams) error {
	lastLines := p.LastLines
	if lastLines == nil {
		lastLines = []string{}
	}
	lastLinesJSON, err := json.Marshal(lastLines)
	if err != nil {
		return fmt.Errorf("models.UpsertDeploymentAutopsy: marshal last_lines: %w", err)
	}

	var exitCode interface{}
	if p.ExitCode.Valid {
		exitCode = p.ExitCode.Int32
	}

	_, err = db.ExecContext(ctx, `
		INSERT INTO deployment_events
			(deployment_id, kind, reason, exit_code, event, last_lines, hint)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
		ON CONFLICT (deployment_id, kind) WHERE kind = 'failure_autopsy'
		DO UPDATE SET
			reason     = EXCLUDED.reason,
			exit_code  = EXCLUDED.exit_code,
			event      = EXCLUDED.event,
			last_lines = EXCLUDED.last_lines,
			hint       = EXCLUDED.hint
	`,
		p.DeploymentID,
		DeploymentEventKindFailureAutopsy,
		p.Reason,
		exitCode,
		p.Event,
		lastLinesJSON,
		p.Hint,
	)
	if err != nil {
		return fmt.Errorf("models.UpsertDeploymentAutopsy: %w", err)
	}
	return nil
}
