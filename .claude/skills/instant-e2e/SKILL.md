---
name: instant-e2e
version: 1.0.0
description: |
  Run instanode.dev E2E tests against the live server and report results.
  Auto-detects whether the server is running on k8s (NodePort) or docker-compose.
allowed-tools:
  - Bash
  - Read
---

# /instant-e2e — Run E2E Tests

You are running the instanode.dev E2E test suite against the live server.

---

## Step 1: Detect target server

Check for the live k8s NodePort first, then fall back to docker-compose:

```bash
# Try k8s
NODE_PORT=$(kubectl get svc instant-api -n instant -o jsonpath='{.spec.ports[0].nodePort}' 2>/dev/null)
if [ -n "$NODE_PORT" ]; then
  curl -sf http://localhost:${NODE_PORT}/healthz > /dev/null 2>&1 && echo "k8s:${NODE_PORT}" || echo "k8s-unhealthy"
else
  # Try docker-compose
  curl -sf http://localhost:8080/healthz > /dev/null 2>&1 && echo "docker:8080" || echo "none"
fi
```

- If `k8s:<port>`: set `E2E_BASE_URL=http://localhost:<port>`
- If `docker:8080`: set `E2E_BASE_URL=http://localhost:8080`
- If `k8s-unhealthy`: report "k8s pod found but health check failed" and **STOP**
- If `none`: report "No live server found. Run `make docker-up && make run` or `make k8s-deploy`" and **STOP**

---

## Step 2: Run E2E suite

```bash
E2E_BASE_URL=http://localhost:<port> go test ./e2e/... -v -tags e2e -timeout 60s 2>&1
```

If the user passed a specific test name (e.g., `/instant-e2e TestE2E_FullUserJourney`), add `-run <name>` to the command.

---

## Step 3: Parse and report results

Count PASS/FAIL from the output. Format the report:

```
E2E Results — http://localhost:<port>

PASS  TestE2E_Healthz_ReturnsOK                         (12ms)
PASS  TestE2E_ProvisionMonitor_Returns201WithRequiredFields (8ms)
...
FAIL  TestE2E_Claim_DoubleClaim_Returns409              (5ms)
      e2e_test.go:394: second POST /claim: want 409, got 503

──────────────────────────────
Total: N passed, M failed (Xs)
```

If all tests pass:
```
✓ All N E2E tests passed (Xs)
Server: http://localhost:<port>
```

If any tests fail:
- List each failure with the file:line and error message
- Group failures by category (Provisioning, Onboarding, Concurrency, etc.)
- Suggest the most likely root cause for each group

---

## Rules

- Never modify any code. This is read-only.
- Never mock anything. E2E tests hit the real server.
- If tests fail due to stale DB state (e.g., unique constraint on email), note that `make k8s-delete && make k8s-deploy` resets all data.
