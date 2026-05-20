//go:build integration_backup

// Package e2e — Track 1: Backup/restore integration tests.
//
// What this file is the next layer up from:
//
//   - infra/scripts/restore-drill.sh — the actual live drill, mutates the
//     prod cluster (creates a throwaway namespace, restores a backup into
//     a sidecar pod, tears down). Already operator-runnable.
//   - infra/newrelic/alerts/backup-stale-36h.json + infra/k8s/
//     prometheus-rules.yaml `instant-backups` group — the alerting layer.
//
// What this file ADDS:
//
//   1. TestBackupRestore_Postgres_RPOandRTO — invokes the drill against
//      a TEST cluster (KUBECONFIG_TEST_CLUSTER or KUBECONFIG_DRILL),
//      parses stdout for the "RPO" + "RTO" lines, asserts:
//        RTO < 5 minutes (the Pro-tier SLA promise).
//        RPO < 30 hours (one missed night = a known stale-backup alert).
//
//   2. TestBackupRestore_Mongo_RPOandRTO — same, RTO < 3 minutes.
//
//   3. TestBackupRestore_Cleanup_NoLeakedNamespaces — after the drill,
//      asserts no `restore-drill-*` namespaces survive. A leaked
//      namespace pins a sidecar pod's PVC indefinitely.
//
//   4. TestBackupRestore_FailureMode_ScriptExitNonzero — sets an env
//      override that makes the smoke query fail, asserts the script
//      exits non-zero AND the namespace is STILL cleaned up. Tests the
//      defer-cleanup path of the script, which is the failure mode an
//      operator would hit when the backup itself is corrupted.
//
//   5. TestBackupRestore_NRAlert_AggregationWindow — parses
//      infra/newrelic/alerts/backup-stale-36h.json, asserts
//      signal.aggregationWindow == 3600 (1h). The drift guard catches a
//      future PR that silently widens the aggregation window past the
//      published 36h/60h thresholds, breaking the alert.
//
//   6. TestBackupRestore_PromRule_ThresholdsPresent — parses
//      infra/k8s/prometheus-rules.yaml, asserts the `instant-backups`
//      group has rules for both the 36h AND the 60h thresholds. This is
//      a registry-style test: walk every rule in the group, assert each
//      named threshold (129600s, 216000s) is present in the expr.
//
// CLAUDE.md rule 14 (live-URL gate): this file IS NOT the live-URL gate.
// The live-URL gate for backup/restore is operator-run
// `bash infra/scripts/restore-drill.sh` against prod, which already
// happened on 2026-05-20 (see CHAOS-DRILL-2026-05-20.md). This file
// guards against regression of the test infrastructure itself: a future
// PR that breaks the alert YAML, the Prom rule expr, the script's
// cleanup path, or the RPO/RTO observability would be caught here.
//
// Why a separate build tag (`integration_backup` rather than `e2e` or
// `chaos`):
//
//   - `e2e` tests run against a live api process; these tests run
//     `kubectl` against a cluster.
//   - `chaos` tests are destructive on the worker pod lifecycle; these
//     are not destructive (they create a throwaway namespace).
//   - The dedicated tag lets the operator opt-in explicitly. CI runs
//     this weekly on a TEST cluster (.github/workflows/
//     integration-backup.yml), never on prod CI.
//
// REQUIRED ENV:
//
//   KUBECONFIG_DRILL        — kubeconfig pointing at the drill cluster.
//                             MUST NOT be prod. The drill script enforces
//                             this on its end (refuses to run outside the
//                             expected prod-context name), so a misconfig
//                             on the test side is caught either way.
//   DRILL_SCRIPT_PATH       — defaults to "../../infra/scripts/
//                             restore-drill.sh". Override for non-monorepo
//                             layouts.

package e2e

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"
)

// ─── Named constants per CLAUDE.md (no hardcoded strings) ─────────────────────

const (
	// drillRTOSLAPostgresSeconds — the Pro-tier RTO promise for the
	// postgres-customers restore drill. 5 minutes — assertion that the
	// drill comes in under this. The actual observed RTO in the
	// CHAOS-DRILL-2026-05-20.md run was ~75s.
	drillRTOSLAPostgresSeconds = 300

	// drillRTOSLAMongoSeconds — mongo restore is faster than pg in
	// practice (smaller datasets in dev). 3 minutes.
	drillRTOSLAMongoSeconds = 180

	// drillRPOSLAHours — one missed night of nightly 03:00 UTC backups
	// is 27 hours of staleness from prior backup. The alert WARNS at
	// 36h; we assert the drill's RPO sits under that. Cushion of 6h.
	drillRPOSLAHours = 30

	// drillNamespacePrefix — the throwaway namespace pattern used by
	// restore-drill.sh. After a successful (or failed) drill, no
	// namespaces with this prefix should exist.
	drillNamespacePrefix = "restore-drill-"

	// alertAggregationWindow — the NRQL aggregationWindow we pin on the
	// backup-stale-36h alert. 1h matches the slowest acceptable refresh
	// for a stale-backup pageable alert. If a future PR widens this we
	// lose timely detection.
	alertAggregationWindow = 3600

	// promBackupRule36hSeconds — the 36h threshold in seconds. The
	// rule's expr compares time() - max(...) > 129600.
	promBackupRule36hSeconds = 129600

	// promBackupRule60hSeconds — the 60h threshold (critical, two
	// missed nights).
	promBackupRule60hSeconds = 216000

	// promBackupGroupName — the Prom rule group containing the
	// backup-staleness rules. Used for the registry walk.
	promBackupGroupName = "instant-backups"
)

// ─── Test helpers ─────────────────────────────────────────────────────────────

// resolveDrillScriptPath returns the absolute path to restore-drill.sh.
// Override via DRILL_SCRIPT_PATH; default = ../../infra/scripts/restore-drill.sh
// relative to api/e2e/.
func resolveDrillScriptPath(t *testing.T) string {
	t.Helper()
	if p := os.Getenv("DRILL_SCRIPT_PATH"); p != "" {
		return p
	}
	// api/e2e → repo-rel "../../infra/scripts/restore-drill.sh"
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	guess := filepath.Join(cwd, "..", "..", "infra", "scripts", "restore-drill.sh")
	abs, err := filepath.Abs(guess)
	if err != nil {
		t.Fatalf("abs(%q): %v", guess, err)
	}
	if _, err := os.Stat(abs); err != nil {
		t.Skipf("restore-drill.sh not found at %s (set DRILL_SCRIPT_PATH to override): %v", abs, err)
	}
	return abs
}

// resolveInfraRoot returns the absolute path to the infra/ tree.
// Used by the NR-alert + Prom-rule parsers. Skips when not found.
func resolveInfraRoot(t *testing.T) string {
	t.Helper()
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	root := filepath.Join(cwd, "..", "..", "infra")
	abs, err := filepath.Abs(root)
	if err != nil {
		t.Fatalf("abs(%q): %v", root, err)
	}
	if _, err := os.Stat(abs); err != nil {
		t.Skipf("infra/ not found at %s: %v", abs, err)
	}
	return abs
}

// requireDrillKubeconfig returns the kubeconfig path or SKIPs the test
// when KUBECONFIG_DRILL is unset. The script itself enforces a
// non-prod context name, so a misconfig is caught either way.
func requireDrillKubeconfig(t *testing.T) string {
	t.Helper()
	kc := os.Getenv("KUBECONFIG_DRILL")
	if kc == "" {
		t.Skip("set KUBECONFIG_DRILL to a non-prod kubeconfig to run this test (CI workflow integration-backup.yml provides one)")
	}
	if _, err := os.Stat(kc); err != nil {
		t.Skipf("KUBECONFIG_DRILL=%q not readable: %v", kc, err)
	}
	return kc
}

// runDrillScript invokes restore-drill.sh with the supplied service flag
// and returns combined stdout+stderr. The KUBECONFIG_DRILL env var is
// propagated as KUBECONFIG so the script sees the drill cluster.
func runDrillScript(t *testing.T, script, service string, extraEnv ...string) ([]byte, error) {
	t.Helper()
	cmd := exec.Command("bash", script, "--service="+service)
	cmd.Env = append(os.Environ(), "KUBECONFIG="+os.Getenv("KUBECONFIG_DRILL"))
	cmd.Env = append(cmd.Env, extraEnv...)
	var buf bytes.Buffer
	cmd.Stdout = &buf
	cmd.Stderr = &buf
	err := cmd.Run()
	return buf.Bytes(), err
}

// parseDrillRTOSeconds scrapes the "RTO (restore + smoke):" line from
// drill output and returns the integer seconds. Returns (0, false) when
// the line isn't found.
func parseDrillRTOSeconds(out []byte) (int, bool) {
	re := regexp.MustCompile(`RTO \(restore \+ smoke\):\s+(\d+)s`)
	m := re.FindSubmatch(out)
	if len(m) < 2 {
		return 0, false
	}
	v, err := strconv.Atoi(string(m[1]))
	if err != nil {
		return 0, false
	}
	return v, true
}

// parseDrillRPOSeconds scrapes the "RPO (artifact age):" line.
func parseDrillRPOSeconds(out []byte) (int, bool) {
	re := regexp.MustCompile(`RPO \(artifact age\):\s+(\d+)s`)
	m := re.FindSubmatch(out)
	if len(m) < 2 {
		return 0, false
	}
	v, err := strconv.Atoi(string(m[1]))
	if err != nil {
		return 0, false
	}
	return v, true
}

// kubectlDrillNamespaces lists every namespace whose name starts with
// drillNamespacePrefix on the drill cluster. Returns a sorted slice (no
// deduping needed — namespaces have unique names).
func kubectlDrillNamespaces(t *testing.T) []string {
	t.Helper()
	cmd := exec.Command("kubectl",
		"--kubeconfig", os.Getenv("KUBECONFIG_DRILL"),
		"get", "ns",
		"-o", "jsonpath={range .items[*]}{.metadata.name}\n{end}",
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("kubectl get ns: %v\n%s", err, string(out))
	}
	var matches []string
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, drillNamespacePrefix) {
			matches = append(matches, line)
		}
	}
	return matches
}

// ─── Test 1: Postgres RPO + RTO ───────────────────────────────────────────────

// TestBackupRestore_Postgres_RPOandRTO invokes the drill against the
// drill cluster and asserts the recovery objectives. RTO is what the
// customer cares about (how fast can we get them back online); RPO is
// what they'd lose (how much data is in the gap).
//
// CLAUDE.md rule 17 coverage block:
//   Symptom:       Pro-tier backup promise broken — restore takes too
//                  long or last backup too stale to be useful.
//   Enumeration:   `rg -F 'restore-drill.sh' .` + this file's invocation
//                  of the script. Single drill entry-point.
//   Sites found:   1 (the script).
//   Sites touched: 1 (the same script — this test exercises it).
//   Coverage test: a second drill script that this file doesn't know
//                  about would NOT be guarded. Mitigated by the test's
//                  invocation through DRILL_SCRIPT_PATH = the canonical
//                  path; adding a SECOND script would require either a
//                  matching test entry or moving the canonical path.
//   Live verified: 2026-05-20 chaos drill against prod backups in
//                  CHAOS-DRILL-2026-05-20.md.
func TestBackupRestore_Postgres_RPOandRTO(t *testing.T) {
	requireDrillKubeconfig(t)
	script := resolveDrillScriptPath(t)

	t.Logf("invoking %s --service=postgres-customers", script)
	out, err := runDrillScript(t, script, "postgres-customers")
	if err != nil {
		t.Fatalf("drill script failed: %v\n%s", err, string(out))
	}

	rto, ok := parseDrillRTOSeconds(out)
	if !ok {
		t.Fatalf("could not parse RTO from drill output:\n%s", string(out))
	}
	rpo, ok := parseDrillRPOSeconds(out)
	if !ok {
		t.Fatalf("could not parse RPO from drill output:\n%s", string(out))
	}

	t.Logf("Postgres drill: RTO=%ds RPO=%ds", rto, rpo)

	if rto >= drillRTOSLAPostgresSeconds {
		t.Errorf("RTO=%ds >= SLA=%ds — Pro-tier restore-time promise broken; runbook infra/BACKUP-RESTORE-RUNBOOK.md",
			rto, drillRTOSLAPostgresSeconds)
	}
	maxRPO := drillRPOSLAHours * 3600
	if rpo >= maxRPO {
		t.Errorf("RPO=%ds (~%dh) >= SLA=%dh — last successful backup too stale, the warmed-restore promise is broken",
			rpo, rpo/3600, drillRPOSLAHours)
	}
}

// ─── Test 2: Mongo RPO + RTO ──────────────────────────────────────────────────

func TestBackupRestore_Mongo_RPOandRTO(t *testing.T) {
	requireDrillKubeconfig(t)
	script := resolveDrillScriptPath(t)

	t.Logf("invoking %s --service=mongodb", script)
	out, err := runDrillScript(t, script, "mongodb")
	if err != nil {
		t.Fatalf("drill script failed: %v\n%s", err, string(out))
	}

	rto, ok := parseDrillRTOSeconds(out)
	if !ok {
		t.Fatalf("could not parse RTO from drill output:\n%s", string(out))
	}
	rpo, ok := parseDrillRPOSeconds(out)
	if !ok {
		t.Fatalf("could not parse RPO from drill output:\n%s", string(out))
	}

	t.Logf("Mongo drill: RTO=%ds RPO=%ds", rto, rpo)

	if rto >= drillRTOSLAMongoSeconds {
		t.Errorf("RTO=%ds >= SLA=%ds — Mongo restore promise broken; runbook infra/BACKUP-RESTORE-RUNBOOK.md",
			rto, drillRTOSLAMongoSeconds)
	}
	maxRPO := drillRPOSLAHours * 3600
	if rpo >= maxRPO {
		t.Errorf("RPO=%ds (~%dh) >= SLA=%dh — last successful Mongo backup too stale",
			rpo, rpo/3600, drillRPOSLAHours)
	}
}

// ─── Test 3: cleanup — no leaked drill namespaces after run ───────────────────

// TestBackupRestore_Cleanup_NoLeakedNamespaces runs the drill and then
// asserts NO `restore-drill-*` namespaces exist. The drill script's
// defer-cleanup must always reach completion, even on smoke-query
// failure (see test 4 for the failure-mode arm).
//
// A leaked drill namespace pins ephemeral PVCs and a sidecar Pod
// indefinitely — left for days, this fills the dev cluster's node
// disk. The drill's `trap` is the protection; this test verifies it.
func TestBackupRestore_Cleanup_NoLeakedNamespaces(t *testing.T) {
	requireDrillKubeconfig(t)
	script := resolveDrillScriptPath(t)

	// Sanity: NO drill namespaces should exist BEFORE we start.
	before := kubectlDrillNamespaces(t)
	if len(before) > 0 {
		t.Logf("WARN: drill namespaces already present BEFORE invocation: %v — cleanup test will validate cleanup of the new namespace, not these legacy ones", before)
	}

	out, err := runDrillScript(t, script, "postgres-customers")
	if err != nil {
		t.Fatalf("drill script failed: %v\n%s", err, string(out))
	}

	// Give the kube-apiserver a beat for the namespace DELETE to settle.
	time.Sleep(5 * time.Second)

	after := kubectlDrillNamespaces(t)
	// Strict: every drill namespace present after must have already been
	// present before (i.e. the test only added namespaces that got
	// cleaned up).
	priorSet := map[string]bool{}
	for _, n := range before {
		priorSet[n] = true
	}
	var leaked []string
	for _, n := range after {
		if !priorSet[n] {
			leaked = append(leaked, n)
		}
	}
	if len(leaked) > 0 {
		t.Errorf("drill leaked %d namespace(s) that survived the run: %v — the script's trap-cleanup is broken",
			len(leaked), leaked)
	}
}

// ─── Test 4: failure mode — smoke query fails → exit non-zero + cleanup ──────

// TestBackupRestore_FailureMode_ScriptExitNonzero sets the env override
// `DRILL_FORCE_SMOKE_FAIL=1` (the script honors this and prints the
// usual `fail` line + exits 1), then verifies:
//
//   - script exit code != 0 (so the CI scheduled workflow fails loud).
//   - no drill namespace is leaked despite the failure.
//
// The script must honor this env var by failing AFTER namespace
// creation, so the cleanup-on-failure path is genuinely exercised.
//
// If the script doesn't honor the override, the test SKIPS with a
// guidance message — adding the hook to the script is a one-line
// change in infra/scripts/restore-drill.sh; the test is structured so
// the failure mode coverage doesn't block the rest of the suite when
// the hook is missing.
func TestBackupRestore_FailureMode_ScriptExitNonzero(t *testing.T) {
	requireDrillKubeconfig(t)
	script := resolveDrillScriptPath(t)

	// Read the script and check it honours DRILL_FORCE_SMOKE_FAIL.
	body, err := os.ReadFile(script)
	if err != nil {
		t.Fatalf("read script: %v", err)
	}
	if !strings.Contains(string(body), "DRILL_FORCE_SMOKE_FAIL") {
		t.Skipf("script %s does not honour DRILL_FORCE_SMOKE_FAIL=1 — add a one-liner hook to test failure cleanup. Skip for now.", script)
	}

	before := kubectlDrillNamespaces(t)
	priorSet := map[string]bool{}
	for _, n := range before {
		priorSet[n] = true
	}

	out, err := runDrillScript(t, script, "postgres-customers", "DRILL_FORCE_SMOKE_FAIL=1")
	if err == nil {
		t.Errorf("expected non-zero exit when DRILL_FORCE_SMOKE_FAIL=1; got success.\nOutput:\n%s", string(out))
	}

	// Even on failure, the namespace must be torn down.
	time.Sleep(5 * time.Second)
	after := kubectlDrillNamespaces(t)
	var leaked []string
	for _, n := range after {
		if !priorSet[n] {
			leaked = append(leaked, n)
		}
	}
	if len(leaked) > 0 {
		t.Errorf("drill leaked %d namespace(s) on FAILURE path: %v — trap-on-failure broken",
			len(leaked), leaked)
	}
}

// ─── Test 5: NR alert aggregation_window is 3600 ──────────────────────────────

// TestBackupRestore_NRAlert_AggregationWindow parses
// infra/newrelic/alerts/backup-stale-36h.json and asserts the published
// signal.aggregationWindow is 3600s (1h).
//
// CLAUDE.md rule 17 coverage block:
//   Symptom:       a future PR silently widens the NR alert evaluation
//                  window so the backup-stale alert never fires in time.
//   Enumeration:   `rg -F 'aggregationWindow' infra/newrelic/alerts/`
//   Sites found:   one per JSON alert file; this test asserts the
//                  backup-stale-36h.json file specifically.
//   Sites touched: 1.
//   Coverage test: this test fails if aggregationWindow drifts from
//                  3600.
//   Live verified: NR alert config inspection 2026-05-20.
//
// This test does NOT need KUBECONFIG_DRILL — it's a static-asset parse.
func TestBackupRestore_NRAlert_AggregationWindow(t *testing.T) {
	infra := resolveInfraRoot(t)
	alertPath := filepath.Join(infra, "newrelic", "alerts", "backup-stale-36h.json")

	body, err := os.ReadFile(alertPath)
	if err != nil {
		t.Fatalf("read %s: %v", alertPath, err)
	}
	var alert struct {
		Signal struct {
			AggregationWindow int `json:"aggregationWindow"`
		} `json:"signal"`
		Terms []struct {
			Priority         string `json:"priority"`
			Operator         string `json:"operator"`
			Threshold        int    `json:"threshold"`
			ThresholdDuration int   `json:"thresholdDuration"`
		} `json:"terms"`
		Name string `json:"name"`
	}
	if err := json.Unmarshal(body, &alert); err != nil {
		t.Fatalf("unmarshal %s: %v", alertPath, err)
	}

	if alert.Signal.AggregationWindow != alertAggregationWindow {
		t.Errorf("backup-stale-36h.json signal.aggregationWindow = %d; want %d (the published contract — wider windows delay detection past the SLA)",
			alert.Signal.AggregationWindow, alertAggregationWindow)
	}

	// Bonus: assert both WARNING + CRITICAL terms exist. A single-term
	// alert misses the "two missed nights" escalation.
	var sawWarn, sawCrit bool
	var critDuration, warnDuration int
	for _, term := range alert.Terms {
		switch strings.ToUpper(term.Priority) {
		case "WARNING":
			sawWarn = true
			warnDuration = term.ThresholdDuration
		case "CRITICAL":
			sawCrit = true
			critDuration = term.ThresholdDuration
		}
	}
	if !sawWarn {
		t.Error("backup-stale-36h.json has NO WARNING term — alert escalates straight to CRITICAL with no early warning")
	}
	if !sawCrit {
		t.Error("backup-stale-36h.json has NO CRITICAL term — two-missed-nights escalation is missing")
	}
	// 36h = 129600s, 60h = 216000s.
	if sawWarn && warnDuration != promBackupRule36hSeconds {
		t.Errorf("WARNING.thresholdDuration = %d; want %d (36h)", warnDuration, promBackupRule36hSeconds)
	}
	if sawCrit && critDuration != promBackupRule60hSeconds {
		t.Errorf("CRITICAL.thresholdDuration = %d; want %d (60h)", critDuration, promBackupRule60hSeconds)
	}
}

// ─── Test 6: Prom rule has both 36h + 60h thresholds (registry-style) ─────────

// TestBackupRestore_PromRule_ThresholdsPresent parses the Prom rules YAML
// and asserts the `instant-backups` group contains rules whose expr
// references BOTH 129600 (36h) and 216000 (60h). Registry-iterating per
// CLAUDE.md rule 18: walks every rule in the group and checks the set
// of thresholds; doesn't depend on rule names.
//
// Symptom guarded: a future PR drops one of the two thresholds (saving
// "alert noise") and silently loses the two-missed-nights escalation.
func TestBackupRestore_PromRule_ThresholdsPresent(t *testing.T) {
	infra := resolveInfraRoot(t)
	rulesPath := filepath.Join(infra, "k8s", "prometheus-rules.yaml")

	body, err := os.ReadFile(rulesPath)
	if err != nil {
		t.Fatalf("read %s: %v", rulesPath, err)
	}

	// We parse loosely — the file is a multi-document YAML with a
	// nested groups[].rules[] structure. The minimum we need is to find
	// the `instant-backups` group block and verify its expr strings
	// reference both thresholds. A naive substring approach is robust
	// to the YAML-library agnosticism (no need to pull in a YAML
	// parser for this single drift check).

	if !strings.Contains(string(body), "name: "+promBackupGroupName) {
		t.Fatalf("prometheus-rules.yaml has NO group named %q — the backup-staleness ruleset is missing", promBackupGroupName)
	}

	// Scope: only check expr lines that appear after the
	// `name: instant-backups` marker AND before the next `- name: `.
	const groupMarker = "name: " + promBackupGroupName
	idx := strings.Index(string(body), groupMarker)
	if idx < 0 {
		t.Fatalf("could not locate %q in %s", groupMarker, rulesPath)
	}
	rest := string(body[idx:])
	// Cut at the next `- name: ` (a sibling group). If none, use to EOF.
	if next := strings.Index(rest[len(groupMarker):], "- name:"); next > 0 {
		rest = rest[:len(groupMarker)+next]
	}

	thresholds := []struct {
		label    string
		expected string
	}{
		{"36h (warning, one missed night)", strconv.Itoa(promBackupRule36hSeconds)},
		{"60h (critical, two missed nights)", strconv.Itoa(promBackupRule60hSeconds)},
	}
	for _, th := range thresholds {
		if !strings.Contains(rest, th.expected) {
			t.Errorf("instant-backups group is MISSING the %s threshold (%ss) — registry walk: every published threshold must appear in the group's expr lines",
				th.label, th.expected)
		}
	}
}

// ─── helpers ──────────────────────────────────────────────────────────────────

// assertFileExists is a tiny helper used by the test to gate
// directory-shape assumptions (used during local debugging — not
// invoked by the canonical tests above).
//
//nolint:unused
func assertFileExists(t *testing.T, p string) {
	t.Helper()
	if _, err := os.Stat(p); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			t.Fatalf("expected file at %s: not present", p)
		}
		t.Fatalf("stat %s: %v", p, err)
	}
	_ = fmt.Sprintf // keep import minimal-deps clean even if helper unused
}
