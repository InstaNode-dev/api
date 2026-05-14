# Runbook — Rotating shared secrets (PROVISIONER_SECRET, AES_KEY, JWT_SECRET, …)

## Why this runbook exists

On 2026-05-13 the platform served 503 on every `POST /db/new` for ~2 hours.
The platform `/healthz` reported green throughout. Root cause: `PROVISIONER_SECRET`
in `instant-infra-secrets` had been rotated, but the running provisioner pods
captured the old value at startup (the gRPC auth interceptor closes over
`secret` at `grpc.NewServer` time and never re-reads it). The api pod, which
mounts the secret via `valueFrom`, restarted naturally on a separate deploy
and picked up the new value. The provisioner did not. Result: api presented
the new token, provisioner compared it against the old captured token, every
RPC came back `code = Unauthenticated desc = invalid provisioner token`.

This runbook prevents that incident class.

## When to use

Use whenever you change any of these k8s secret keys:

- `instant-infra-secrets/PROVISIONER_SECRET` → consumed by api + provisioner + worker
- `instant-infra-secrets/AES_KEY` → consumed by api + provisioner + worker (vault decrypt)
- `instant-secrets/JWT_SECRET` → consumed by api (and worker for internal HS256)
- `instant-secrets/RAZORPAY_WEBHOOK_SECRET` → consumed by api
- `instant-infra-secrets/PROVISIONER_DATABASE_URL` → consumed by provisioner
- Anything else mounted via `valueFrom.secretKeyRef`

## Procedure

1. **Stage the new value** (do not yet apply):

   ```bash
   NEW=$(openssl rand -hex 32)
   echo "NEW_SECRET=$NEW"  # capture for re-use, do NOT commit
   ```

2. **Patch the Secret** in BOTH consuming namespaces if it lives in both
   (`instant` and `instant-infra` historically duplicate `PROVISIONER_SECRET`):

   ```bash
   kubectl create secret generic instant-infra-secrets -n instant-infra \
     --from-literal=PROVISIONER_SECRET="$NEW" \
     --dry-run=client -o yaml | kubectl apply -f -
   # (repeat for instant namespace if the secret is mirrored)
   ```

3. **MANDATORY — restart every Deployment that consumes this secret.**
   k8s does NOT auto-restart pods on `valueFrom.secretKeyRef` updates.

   ```bash
   kubectl rollout restart deployment/instant-api          -n instant
   kubectl rollout restart deployment/instant-provisioner  -n instant-infra
   kubectl rollout restart deployment/instant-worker       -n instant-infra
   ```

   Wait for each rollout to converge:

   ```bash
   kubectl rollout status deployment/instant-api         -n instant       --timeout=180s
   kubectl rollout status deployment/instant-provisioner -n instant-infra --timeout=180s
   kubectl rollout status deployment/instant-worker      -n instant-infra --timeout=180s
   ```

4. **Verify** via the post-deploy smoke script:

   ```bash
   bash scripts/post-deploy-smoke.sh https://api.instanode.dev
   ```

   Exit 0 means the api↔provisioner gRPC auth path is healthy. Exit 3 means
   one of the consumer pods didn't actually restart (or the new secret wasn't
   propagated to all namespaces). Repeat step 3 for any deployment that lags.

## What NOT to do

- **Don't kubectl patch the Secret in place and assume pods pick it up.**
  They don't, for `valueFrom` env mounts. (Volume-mounted secrets DO refresh
  on disk after ~60s but env vars are captured at process start.)
- **Don't rotate during peak hours unless you've practiced the rollout cadence.**
  The api and provisioner share the secret — restarting in the wrong order
  briefly fails-closed (api with new secret, provisioner still with old)
  until both converge. Typical window: ~30 seconds per service.
- **Don't skip step 4.** A green `/healthz` after rotation is necessary but
  not sufficient — only a successful `POST /db/new` proves the auth path.

## Future-proofing (open RFCs)

- Consider rewriting the provisioner's `UnaryAuthInterceptor` to take a
  `func() string` provider rather than a captured string, with the provider
  re-reading from a file-mounted secret. This requires switching the env-var
  mount to a file mount on the provisioner Deployment, but it gives us
  zero-downtime rotation.
- Add a Kyverno policy that flags any `kubectl edit secret` not followed
  within 5 minutes by `kubectl rollout restart` of the consumer Deployments.
