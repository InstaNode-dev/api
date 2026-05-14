#!/usr/bin/env bash
# post-deploy-smoke.sh — verify a fresh rollout actually serves traffic.
#
# Runs after `kubectl set image` + `kubectl rollout status`. Catches the
# 2026-05-13 outage class: deploy reports success, /healthz reports green,
# but POST /db/new returns 503 because the api↔provisioner gRPC auth path
# is broken.
#
# Usage:
#   ./scripts/post-deploy-smoke.sh [base-url] [expected-commit-prefix]
#
# Defaults: base=https://api.instanode.dev, no commit assertion.
#
# Exit codes:
#   0 — healthy
#   1 — /healthz responded but commit_id mismatch (old image still serving)
#   2 — /healthz responded but migration_status != ok
#   3 — POST /db/new returned 503 with provisioner failure (REGRESSION class)
#   4 — POST /db/new returned an unexpected non-201/202/429/402 status
#   5 — network failure (couldn't reach base url)

set -euo pipefail

BASE="${1:-https://api.instanode.dev}"
EXPECTED="${2:-}"

red() { printf '\033[31m%s\033[0m\n' "$*"; }
green() { printf '\033[32m%s\033[0m\n' "$*"; }
yellow() { printf '\033[33m%s\033[0m\n' "$*"; }

echo "==> Smoking $BASE"

# --- Step 1: /healthz ------------------------------------------------------
hz="$(curl -fsS -m 10 "$BASE/healthz" 2>/dev/null)" || { red "FAIL: /healthz unreachable"; exit 5; }
commit="$(echo "$hz" | jq -r .commit_id)"
mstatus="$(echo "$hz" | jq -r .migration_status)"
version="$(echo "$hz" | jq -r .version)"

echo "    commit=$commit version=$version migration_status=$mstatus"

if [[ -n "$EXPECTED" && "$commit" != "$EXPECTED"* ]]; then
  red "FAIL: /healthz commit_id=$commit does not start with expected $EXPECTED"
  red "      pods are likely still serving the old image — rollout did not converge"
  exit 1
fi

if [[ "$mstatus" != "ok" ]]; then
  red "FAIL: migration_status=$mstatus (want 'ok') — deploy ran but migrations did not complete"
  exit 2
fi

green "    /healthz: OK"

# --- Step 2: POST /db/new --------------------------------------------------
# Single call. Burning the anonymous fingerprint cap for smoke purposes is fine
# in dev, but in prod the smoke caller's IP should be in a static allow-list or
# this should run from a synthetic-monitor source IP.

body_file="$(mktemp)"
trap 'rm -f "$body_file"' EXIT

# Retry strategy: 3 attempts with 5s backoff to absorb ingress flap and the
# brief window where pods are Running but cert-manager / ingress hasn't
# resolved the new endpoint slice. A regression (5xx with provisioner error in
# the body) propagates immediately — we only retry on EMPTY 503 bodies which
# are an ingress signature, NOT an api-layer signature.
attempt=0
max_attempts=3
while :; do
  attempt=$((attempt + 1))
  http_code="$(curl -sS -m 60 -o "$body_file" -w '%{http_code}' \
                -H 'Content-Type: application/json' \
                -H 'User-Agent: instant-post-deploy-smoke/1.0' \
                -X POST "$BASE/db/new" -d '{}' || echo 000)"
  body="$(cat "$body_file")"
  echo "    /db/new attempt=$attempt status=$http_code body=$(echo "$body" | head -c 200)"
  if [[ "$http_code" != "503" || -n "$body" ]]; then break; fi
  if (( attempt >= max_attempts )); then
    red "FAIL: 503 with empty body after $max_attempts attempts — ingress/edge flap or upstream pod refused connection"
    exit 4
  fi
  yellow "    transient 503 with empty body, retrying in 5s..."
  sleep 5
done

case "$http_code" in
  200|201|202)
    green "    /db/new: provisioned successfully"
    ;;
  402|429)
    yellow "    /db/new: $http_code (tier-block / rate-limit) — not a regression of the provisioner-auth class; counts as smoke-OK"
    ;;
  503)
    err="$(echo "$body" | jq -r '.error // ""')"
    msg="$(echo "$body" | jq -r '.message // ""' | tr '[:upper:]' '[:lower:]')"
    if [[ "$err" == "provision_failed" || "$msg" == *"provisioner"* ]]; then
      red "FAIL: REGRESSION — provisioner unreachable from api (2026-05-13 outage class)"
      red "      body: $body"
      red "      Triage:"
      red "        kubectl logs -n instant -l app=instant-api --tail=20 | grep provision_failed"
      red "        kubectl rollout restart deployment/instant-provisioner -n instant-infra"
      exit 3
    fi
    red "FAIL: 503 with non-provisioner cause: $body"
    exit 4
    ;;
  *)
    red "FAIL: unexpected status $http_code: $body"
    exit 4
    ;;
esac

green "==> Smoke OK"
