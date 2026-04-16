---
name: instant-ship
version: 1.0.0
description: |
  instant.dev deploy pipeline: build → vet → unit tests → docker build → k8s rollout → E2E tests → health check.
  Run this after any code change to ship to the local k8s cluster.
allowed-tools:
  - Bash
  - Read
  - AskUserQuestion
---

# /instant-ship — Deploy to Local Kubernetes

You are running the instant.dev ship pipeline. This is **fully automated** — run straight through without asking for confirmation. Stop only on failures.

The working directory is the instant.dev project root (`~/Documents/learningProjects/instant/api`).

---

## Step 1: Build gate

```bash
go build ./... 2>&1
go vet ./... 2>&1
```

**If either fails:** Show the errors. **STOP.** Do not proceed until the build is clean.

---

## Step 2: Unit + integration tests

```bash
go test ./... -race -count=1 2>&1
```

Skip this step only if the user passed `--skip-unit` as an argument to the skill.

**If any test fails:** Show the failures. **STOP.**

**If all pass:** Note the count briefly ("N packages, N tests passed") and continue.

---

## Step 3: Docker image build

```bash
docker build -t instant-api:local . 2>&1
```

**If the build fails:** Show the error. **STOP.**

**If successful:** Note the image digest and continue.

---

## Step 4: Regenerate migrations ConfigMap (if SQL changed)

Check if any migration file changed since the last git commit:

```bash
git diff HEAD --name-only 2>/dev/null | grep -q 'migrations/' && echo "changed" || echo "unchanged"
```

If changed:
```bash
kubectl create configmap instant-migrations \
  --from-file=001_initial.sql=internal/db/migrations/001_initial.sql \
  -n instant --dry-run=client -o yaml > k8s/migrations-configmap.yaml
kubectl apply -f k8s/migrations-configmap.yaml
```

If unchanged: skip silently.

---

## Step 5: Kubernetes rollout

```bash
kubectl rollout restart deployment/instant-api -n instant
kubectl rollout status deployment/instant-api -n instant --timeout=120s
```

**If the rollout fails or times out:** Show pod events:
```bash
kubectl describe pod -l app=instant-api -n instant | tail -20
kubectl logs -l app=instant-api -n instant --previous 2>/dev/null | tail -30
```
**STOP.** Show the logs and wait for the user to investigate.

---

## Step 6: Health check

Get the NodePort and verify the service responds:

```bash
NODE_PORT=$(kubectl get svc instant-api -n instant -o jsonpath='{.spec.ports[0].nodePort}')
curl -sf http://localhost:${NODE_PORT}/healthz
```

**If the health check fails:** **STOP.** The rollout completed but the app is unhealthy.

---

## Step 7: E2E tests

```bash
NODE_PORT=$(kubectl get svc instant-api -n instant -o jsonpath='{.spec.ports[0].nodePort}')
E2E_BASE_URL=http://localhost:${NODE_PORT} go test ./e2e/... -v -tags e2e -timeout 60s 2>&1
```

Skip this step if the user passed `--skip-e2e` as an argument.

**If any E2E test fails:** Show the failures. **STOP.** The deployment is live but broken — the user needs to decide whether to rollback.

**If all pass:** Output a summary.

---

## Final output

```
✓ Build clean
✓ N unit tests passed
✓ Docker image built (sha256:...)
✓ k8s rollout complete
✓ Health check OK
✓ N E2E tests passed
API is live at http://localhost:<NodePort>
```

---

## Rules

- Never skip Step 1 (build gate). A broken binary deployed silently is worse than a failed deploy.
- Never force-restart pods that haven't finished terminating.
- If the user passes `--skip-unit`: skip Step 2 only. All other steps are mandatory.
- If the user passes `--skip-e2e`: skip Step 7 only. All other steps are mandatory.
- Never `kubectl delete` anything — only `rollout restart`.
