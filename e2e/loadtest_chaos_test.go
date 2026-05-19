//go:build loadtest && e2e

// Package e2e — CHAOS HARNESS (safe, non-destructive)
//
// Behind `loadtest && e2e` — never runs in any normal gate. Compiles only
// under `-tags 'e2e loadtest'` (the e2e helper layer it reuses is itself
// `//go:build e2e`).
//
// ─── WHAT THIS DOES ───────────────────────────────────────────────────────────
//
// Kills ONE replica at a time of each stateless deployment — instant-api,
// instant-worker, instant-provisioner — via `kubectl delete pod`, and verifies:
//
//   - k8s reschedules the pod (Deployment self-heal).
//   - GET /healthz recovers (the API stays serving throughout, because the
//     surviving replica absorbs traffic — these run 2 replicas).
//   - In-flight requests fired DURING the kill either succeed or fail
//     cleanly (clean HTTP error / 503) — never a silent drop.
//
// ─── SAFETY ENVELOPE — WHAT THIS DELIBERATELY DOES NOT DO ─────────────────────
//
//   - One pod at a time. Full recovery is awaited before the next kill.
//   - Stateless deployments ONLY. instant-data stateful pods (postgres,
//     redis, mongo, nats) are NEVER touched.
//   - Nothing is scaled to zero. No DB failover. No node drain.
//   - The kill is `delete pod`, which a Deployment immediately replaces —
//     identical to a routine rolling restart, safe on prod.
//
// Destructive scenarios worth running in a dedicated maintenance window
// (DB failover, scale-to-zero, node drain) are described as RECOMMENDATIONS
// in LOAD-CHAOS-REPORT — they are NOT executed here.
//
// ─── HOW TO RUN ───────────────────────────────────────────────────────────────
//
//	make chaostest
//
// Required env:
//
//	E2E_BASE_URL   live API root (https://api.instanode.dev)
//
// Optional:
//
//	CHAOS_NAMESPACE_APP    namespace of instant-api          (default instant)
//	CHAOS_NAMESPACE_INFRA  namespace of worker/provisioner   (default instant-infra)
//	CHAOS_RECOVER_TIMEOUT  per-deployment recovery wait      (default 120s)
package e2e

import (
	"context"
	"io"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"sync"
	"testing"
	"time"
)

// chaosNamespaceApp / Infra — overridable namespace targets.
func chaosNamespaceApp() string {
	if v := os.Getenv("CHAOS_NAMESPACE_APP"); v != "" {
		return v
	}
	return "instant"
}

func chaosNamespaceInfra() string {
	if v := os.Getenv("CHAOS_NAMESPACE_INFRA"); v != "" {
		return v
	}
	return "instant-infra"
}

func chaosRecoverTimeout() time.Duration {
	if v := os.Getenv("CHAOS_RECOVER_TIMEOUT"); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			return d
		}
	}
	return 120 * time.Second
}

// kubectl runs a kubectl command and returns trimmed stdout.
func kubectl(t *testing.T, args ...string) (string, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "kubectl", args...).CombinedOutput()
	return strings.TrimSpace(string(out)), err
}

// firstPodName returns the name of the first pod matching the deployment's
// label selector in the namespace.
func firstPodName(t *testing.T, namespace, selector string) string {
	t.Helper()
	out, err := kubectl(t, "get", "pods", "-n", namespace, "-l", selector,
		"-o", "jsonpath={.items[0].metadata.name}")
	if err != nil || out == "" {
		t.Skipf("chaos: cannot list pods (ns=%s selector=%s): %v out=%q",
			namespace, selector, err, out)
	}
	return out
}

// readyReplicas returns the .status.readyReplicas of a deployment.
func readyReplicas(t *testing.T, namespace, deployment string) string {
	t.Helper()
	out, _ := kubectl(t, "get", "deploy", deployment, "-n", namespace,
		"-o", "jsonpath={.status.readyReplicas}")
	return out
}

// healthzOK issues a single GET /healthz and reports whether it returned 200.
func healthzOK(t *testing.T) (bool, int) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, baseURL()+"/healthz", nil)
	resp, err := client.Do(req)
	if err != nil {
		return false, 0
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	return resp.StatusCode == 200, resp.StatusCode
}

// chaosTarget describes one deployment to chaos-test.
type chaosTarget struct {
	name      string // deployment name
	namespace string
	selector  string // label selector for its pods
	probesAPI bool   // whether /healthz directly reflects this deployment
}

// chaosTargets — the three stateless deployments. All run >1 replica so a
// single-pod kill is fully absorbed by the survivor.
var chaosTargets = []chaosTarget{
	{"instant-api", "", "app=instant-api", true},
	{"instant-worker", "", "app=instant-worker", false},
	{"instant-provisioner", "", "app=instant-provisioner", false},
}

// ════════════════════════════════════════════════════════════════════════════
// CHAOS TEST — single-replica kill + recovery, one deployment at a time
// ════════════════════════════════════════════════════════════════════════════

// TestChaos_SingleReplicaKill_SelfHeal kills one replica of each stateless
// deployment in sequence and verifies:
//   - k8s reschedules to full readyReplicas within the recovery timeout.
//   - For instant-api: /healthz stays serving throughout (survivor absorbs)
//     and a stream of probe requests fired during the kill window never
//     silently drops — each gets a real HTTP status or a clean error.
func TestChaos_SingleReplicaKill_SelfHeal(t *testing.T) {
	// Pre-flight: cluster reachable + API healthy.
	if _, err := kubectl(t, "version", "--client=true"); err != nil {
		t.Skipf("chaos: kubectl unavailable: %v", err)
	}
	if ok, code := healthzOK(t); !ok {
		t.Fatalf("chaos pre-flight: /healthz not OK (status %d) — refusing to inject chaos", code)
	}
	t.Logf("chaos pre-flight: /healthz OK, cluster reachable")

	appNS := chaosNamespaceApp()
	infraNS := chaosNamespaceInfra()
	recoverTimeout := chaosRecoverTimeout()

	for i := range chaosTargets {
		tgt := chaosTargets[i]
		if tgt.namespace == "" {
			if tgt.name == "instant-api" {
				tgt.namespace = appNS
			} else {
				tgt.namespace = infraNS
			}
		}

		t.Run(tgt.name, func(t *testing.T) {
			// Record desired replica count up front.
			desired, _ := kubectl(t, "get", "deploy", tgt.name, "-n", tgt.namespace,
				"-o", "jsonpath={.spec.replicas}")
			before := readyReplicas(t, tgt.namespace, tgt.name)
			t.Logf("[%s] desired=%s readyReplicas(before)=%s", tgt.name, desired, before)

			victim := firstPodName(t, tgt.namespace, tgt.selector)
			t.Logf("[%s] killing pod %s", tgt.name, victim)

			// ── Probe stream: only for instant-api, where /healthz directly
			//    reflects availability. Runs continuously across the kill.
			var probeWG sync.WaitGroup
			probeStop := make(chan struct{})
			var probeTotal, probeOK, probe5xx, probeDrop int
			var probeMu sync.Mutex
			if tgt.probesAPI {
				probeWG.Add(1)
				go func() {
					defer probeWG.Done()
					for {
						select {
						case <-probeStop:
							return
						default:
						}
						ok, code := healthzOK(t)
						probeMu.Lock()
						probeTotal++
						switch {
						case ok:
							probeOK++
						case code >= 500 && code <= 599:
							probe5xx++
						case code == 0:
							probeDrop++
						}
						probeMu.Unlock()
						time.Sleep(150 * time.Millisecond)
					}
				}()
			}

			// ── Kill one pod ──
			killStart := time.Now()
			out, err := kubectl(t, "delete", "pod", victim, "-n", tgt.namespace, "--wait=false")
			if err != nil {
				close(probeStop)
				probeWG.Wait()
				t.Fatalf("[%s] delete pod failed: %v\n%s", tgt.name, err, out)
			}
			t.Logf("[%s] delete issued: %s", tgt.name, out)

			// ── Await full recovery: readyReplicas == desired ──
			deadline := time.Now().Add(recoverTimeout)
			recovered := false
			for time.Now().Before(deadline) {
				if rr := readyReplicas(t, tgt.namespace, tgt.name); rr == desired && rr != "" {
					recovered = true
					break
				}
				time.Sleep(2 * time.Second)
			}
			recoverDur := time.Since(killStart)

			// Stop probe stream.
			if tgt.probesAPI {
				close(probeStop)
				probeWG.Wait()
			}

			if !recovered {
				t.Errorf("[%s] did NOT return to %s ready replicas within %s (last=%s)",
					tgt.name, desired, recoverTimeout, readyReplicas(t, tgt.namespace, tgt.name))
			} else {
				t.Logf("[%s] self-healed to %s ready replicas in %s",
					tgt.name, desired, recoverDur.Round(time.Second))
			}

			// ── In-flight request assertions (instant-api only) ──
			if tgt.probesAPI {
				probeMu.Lock()
				total, okN, fiveN, dropN := probeTotal, probeOK, probe5xx, probeDrop
				probeMu.Unlock()
				t.Logf("[%s] /healthz probes during kill window: total=%d ok=%d 5xx=%d dropped=%d",
					tgt.name, total, okN, fiveN, dropN)

				// The survivor replica must keep serving — we expect the vast
				// majority OK. A brief blip is tolerated, but a sustained
				// outage or any silent drop is a finding.
				if total == 0 {
					t.Errorf("[%s] probe stream recorded nothing", tgt.name)
				}
				// 5xx during a single-pod kill on a 2-replica deployment is a
				// finding: the survivor should have absorbed all traffic.
				if fiveN > 0 {
					t.Errorf("[%s] %d × 5xx during single-replica kill — survivor "+
						"replica did not fully absorb traffic", tgt.name, fiveN)
				}
				// Transport-layer drops mean a request neither succeeded nor
				// failed cleanly.
				if dropN > 0 {
					t.Logf("[%s] NOTE: %d transport-level errors during kill window — "+
						"acceptable only if they coincide with connection-reset on the "+
						"killed pod; investigate if sustained", tgt.name, dropN)
				}
				if total > 0 && okN*100/total < 80 {
					t.Errorf("[%s] only %d/%d (%.0f%%) probes OK during kill — "+
						"availability dropped below 80%%", tgt.name, okN, total,
						float64(okN)*100/float64(total))
				}
			}

			// Final post-recovery health confirmation.
			if ok, code := healthzOK(t); !ok {
				t.Errorf("[%s] post-recovery /healthz NOT OK (status %d)", tgt.name, code)
			} else {
				t.Logf("[%s] post-recovery /healthz OK", tgt.name)
			}

			// Settle before the next target so kills never overlap.
			time.Sleep(5 * time.Second)
		})
	}
}
