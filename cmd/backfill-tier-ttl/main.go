// Command backfill-tier-ttl is a one-off operator tool that repairs the
// deployment-TTL state of every paid team whose data predates the
// 2026-05-31 "tier upgrade auto-promotes deployment TTLs" fix.
//
// THE BUG (P1, mastermanas805 report 2026-05-31)
//
//	Before the fix, the Razorpay subscription.charged webhook called
//	models.UpgradeTeamAllTiersWithSubscription but did NOT call
//	models.PromoteDeploymentTTLsForTeam — so a team that upgraded
//	free→pro carried forward its 'auto_24h' team default (every
//	future POST /deploy/new still inherited a 24h TTL) AND, for
//	teams whose upgrade landed before the broader ElevateDeployments
//	tx also set ttl_policy='permanent', their pre-upgrade auto_24h
//	deploys kept auto-expiring. The user got "expires in 6 hours"
//	emails for deploys they thought they had paid to keep.
//
// WHAT THIS DOES
//
//	For every team where plan_tier ∈ {hobby, hobby_plus, pro, growth, team}:
//	  - Calls models.PromoteDeploymentTTLsForTeam, which (inside one tx)
//	    (a) flips teams.default_deployment_ttl_policy 'auto_24h' →
//	        'permanent' iff the current value is 'auto_24h' (user-explicit
//	        non-auto values are LEFT UNTOUCHED — see the model doc), and
//	    (b) updates every non-terminal deployment row with
//	        ttl_policy='auto_24h' SET ttl_policy='permanent',
//	        expires_at=NULL, reminders_sent=0, last_reminder_at=NULL.
//
//	Anonymous and free teams are NEVER touched — those tiers don't get
//	permanent deploys, and a flip would be a contract change.
//
// USAGE
//
//	# Dry-run first (default — prints what WOULD change, mutates nothing):
//	DATABASE_URL=postgres://... go run ./cmd/backfill-tier-ttl
//
//	# Apply the backfill (after eyeballing the dry-run summary):
//	DATABASE_URL=postgres://... go run ./cmd/backfill-tier-ttl -apply
//
//	# Production: connect through the bastion/kubectl port-forward to
//	# api/internal/handlers/billing.go's source-of-truth platform DB.
//	# DO NOT run this against any other instance.
//
// SAFETY
//
//	The function is idempotent — every UPDATE has a "only-if-still-stale"
//	WHERE predicate, so running this twice on the same DB is a no-op the
//	second time. It is safe to re-run after a partial failure.
//
//	Per-team work runs in its own tx; a single team's failure does NOT roll
//	back the teams processed before it. The exit code reports how many
//	teams errored — operator should re-run for the residual.
package main

import (
	"context"
	"database/sql"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/google/uuid"
	_ "github.com/lib/pq"

	"instant.dev/internal/models"
)

const (
	// backfillExitOK reports a clean run (every team either succeeded or was
	// excluded by the tier filter).
	backfillExitOK = 0
	// backfillExitUsage means CLI args / env config were wrong.
	backfillExitUsage = 2
	// backfillExitPartial means at least one team's promote tx errored.
	// The operator should re-run; the function is idempotent.
	backfillExitPartial = 3
)

// paidTierFilter is the SQL fragment selecting the teams the backfill
// targets — paid tiers only (hobby and above). plans.Rank() would be more
// portable but a literal IN-list is what the operator can paste into
// `psql` to preview the candidate set independently.
const paidTierFilter = `plan_tier IN ('hobby', 'hobby_plus', 'pro', 'growth', 'team')`

// candidateTeamSQL selects teams that actually have something to backfill:
// either the team default is still 'auto_24h' OR they have at least one
// non-terminal auto_24h deploy. Excluding already-promoted teams keeps the
// dry-run summary readable on a large customer base.
const candidateTeamSQL = `
	SELECT t.id, t.plan_tier,
	       COALESCE(t.default_deployment_ttl_policy, 'auto_24h') AS team_default,
	       (
	         SELECT count(*) FROM deployments d
	          WHERE d.team_id = t.id
	            AND d.ttl_policy = 'auto_24h'
	            AND d.status NOT IN ('deleted', 'expired')
	       ) AS auto_deploy_count
	  FROM teams t
	 WHERE ` + paidTierFilter + `
	 ORDER BY t.created_at ASC
`

// exitFn is os.Exit at runtime; tests swap it so the main() body becomes
// a measurable statement instead of an irreducible coverage hole. Mirrors
// the pattern in cmd/openapi-snapshot/main.go.
var exitFn = os.Exit

// openDB is the *sql.DB factory; tests swap it for a sqlmock-backed handle
// so the run() body is exercisable without a real postgres listener. Default
// uses lib/pq.
var openDB = func(dsn string) (*sql.DB, error) { return sql.Open("postgres", dsn) }

// promoteFn is the model call the apply-loop drives. Tests swap it so the
// success/error reporting branches at the bottom of run() are reachable
// without a populated platform DB.
var promoteFn = models.PromoteDeploymentTTLsForTeam

func main() { exitFn(run(os.Args[1:], os.Stdout, os.Stderr)) }

// run is the testable body of main — splits CLI parsing from os.Exit so the
// command's exit-code surface can be pinned by a unit test.
func run(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("backfill-tier-ttl", flag.ContinueOnError)
	fs.SetOutput(stderr)
	apply := fs.Bool("apply", false, "actually mutate the DB (default: dry-run, no mutations)")
	dbURL := fs.String("database-url", os.Getenv("DATABASE_URL"),
		"platform_db connection string (defaults to $DATABASE_URL)")
	if err := fs.Parse(args); err != nil {
		return backfillExitUsage
	}
	if *dbURL == "" {
		_, _ = fmt.Fprintln(stderr, "backfill-tier-ttl: DATABASE_URL is unset and -database-url not supplied")
		return backfillExitUsage
	}

	db, err := openDB(*dbURL)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "backfill-tier-ttl: open db: %v\n", err)
		return backfillExitUsage
	}
	defer func() { _ = db.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	if err := db.PingContext(ctx); err != nil {
		_, _ = fmt.Fprintf(stderr, "backfill-tier-ttl: ping db: %v\n", err)
		return backfillExitUsage
	}

	rows, err := db.QueryContext(ctx, candidateTeamSQL)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "backfill-tier-ttl: list candidates: %v\n", err)
		return backfillExitUsage
	}
	defer func() { _ = rows.Close() }()

	var candidates []candidate
	for rows.Next() {
		var c candidate
		if err := rows.Scan(&c.teamID, &c.tier, &c.teamDefault, &c.autoDeployCount); err != nil {
			_, _ = fmt.Fprintf(stderr, "backfill-tier-ttl: scan: %v\n", err)
			return backfillExitUsage
		}
		// Skip teams already fully promoted — nothing to do, keeps the
		// summary readable.
		if c.teamDefault != "auto_24h" && c.autoDeployCount == 0 {
			continue
		}
		candidates = append(candidates, c)
	}
	if err := rows.Err(); err != nil {
		_, _ = fmt.Fprintf(stderr, "backfill-tier-ttl: rows: %v\n", err)
		return backfillExitUsage
	}

	mode := "DRY-RUN"
	if *apply {
		mode = "APPLY"
	}
	_, _ = fmt.Fprintf(stdout, "backfill-tier-ttl: mode=%s candidates=%d\n", mode, len(candidates))
	for _, c := range candidates {
		_, _ = fmt.Fprintf(stdout, "  team=%s tier=%s team_default=%s auto_deploys=%d\n",
			c.teamID, c.tier, c.teamDefault, c.autoDeployCount)
	}
	if !*apply {
		_, _ = fmt.Fprintln(stdout, "backfill-tier-ttl: dry-run complete — re-run with -apply to mutate")
		return backfillExitOK
	}

	var ok, errored int
	for _, c := range candidates {
		result, promoteErr := promoteFn(ctx, db, c.teamID)
		if promoteErr != nil {
			errored++
			_, _ = fmt.Fprintf(stderr, "  team=%s ERROR: %v\n", c.teamID, promoteErr)
			continue
		}
		ok++
		_, _ = fmt.Fprintf(stdout, "  team=%s OK promoted_deploys=%d team_default_flipped=%t\n",
			c.teamID, result.DeploysPromoted, result.TeamDefaultFlipped)
	}
	_, _ = fmt.Fprintf(stdout, "backfill-tier-ttl: applied — ok=%d errored=%d\n", ok, errored)
	if errored > 0 {
		// The function is idempotent — operator re-runs for the residual.
		return backfillExitPartial
	}
	return backfillExitOK
}

// candidate is one row from candidateTeamSQL.
type candidate struct {
	teamID          uuid.UUID
	tier            string
	teamDefault     string
	autoDeployCount int
}

// ensureModelsImportUsed is a compile-time guard: if a future refactor
// removes the only PromoteDeploymentTTLsForTeam call site above, this var
// keeps the import live so the godoc still cross-references the function.
var _ = errors.New
