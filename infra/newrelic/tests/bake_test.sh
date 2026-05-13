#!/usr/bin/env bash
#
# bake_test.sh — verify that the dashboards/*.json, alerts/*.json, and
# policies/*.json source files have F's three jq adapter fixes baked in:
#
#   1. Dashboards: accountIds use the "${NEW_RELIC_ACCOUNT_ID}" token,
#      not the literal [0] placeholder.
#   2. Alerts: no top-level "type": "NRQL" discriminator — NerdGraph
#      rejects it on the NrqlConditionStaticInput mutation.
#   3. Alert policy: policies/instant-api.json exists with the expected
#      fields, and every alert in alerts/ links to it via "policyName".
#
# Run from anywhere — the script discovers its own infra/newrelic root.
#
# Exit codes:
#   0  all assertions pass
#   1  one or more assertions failed

set -uo pipefail

SCRIPT_DIR="$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
ROOT="$( cd -- "$SCRIPT_DIR/.." &> /dev/null && pwd )"
DASHBOARDS_DIR="$ROOT/dashboards"
ALERTS_DIR="$ROOT/alerts"
POLICIES_DIR="$ROOT/policies"
POLICY_FILE="$POLICIES_DIR/instant-api.json"

PASS=0
FAIL=0

ok()   { PASS=$((PASS + 1)); printf '  ok  %s\n' "$1"; }
fail() { FAIL=$((FAIL + 1)); printf '  FAIL  %s\n' "$1" >&2; }

command -v jq >/dev/null 2>&1 || { echo "missing dep: jq" >&2; exit 2; }

DASHBOARDS=(api-overview billing-dunning deploy provisioning worker)
ALERTS=(dunning-recovery-rate-low error-rate-high nats-down p95-latency-high payment-failure-spike worker-stalled)

echo "==> Dashboards parse + no accountIds:[0] residue"
for name in "${DASHBOARDS[@]}"; do
  f="$DASHBOARDS_DIR/$name.json"
  if [ ! -f "$f" ]; then fail "$name.json missing"; continue; fi
  if jq empty "$f" >/dev/null 2>&1; then
    ok "$name.json parses"
  else
    fail "$name.json does not parse"
    continue
  fi
  # Must not contain the literal [0] placeholder anywhere.
  if grep -q '"accountIds": *\[ *0 *\]' "$f"; then
    fail "$name.json still contains accountIds:[0] (bake not applied)"
  else
    ok "$name.json has no accountIds:[0] residue"
  fi
  # Must contain the substitution token for every nrqlQueries entry.
  expected=$(jq '[.. | objects | select(has("nrqlQueries")) | .nrqlQueries | length] | add // 0' "$f")
  actual=$(grep -c '"accountIds": *\["\${NEW_RELIC_ACCOUNT_ID}"\]' "$f" || true)
  if [ "$expected" = "$actual" ] && [ "$actual" -gt 0 ]; then
    ok "$name.json has $actual accountIds tokens (matches nrqlQueries count)"
  else
    fail "$name.json token count mismatch: expected=$expected actual=$actual"
  fi
done

echo
echo "==> Alerts parse + no type:NRQL + policyName link"
for name in "${ALERTS[@]}"; do
  f="$ALERTS_DIR/$name.json"
  if [ ! -f "$f" ]; then fail "$name.json missing"; continue; fi
  if jq empty "$f" >/dev/null 2>&1; then
    ok "$name.json parses"
  else
    fail "$name.json does not parse"
    continue
  fi
  has_type=$(jq -r 'has("type")' "$f")
  if [ "$has_type" = "false" ]; then
    ok "$name.json has no \"type\" field (NRQL discriminator removed)"
  else
    fail "$name.json still has \"type\" field"
  fi
  policyName=$(jq -r '.policyName // ""' "$f")
  if [ "$policyName" = "instant-api alerts" ]; then
    ok "$name.json has policyName=\"instant-api alerts\""
  else
    fail "$name.json missing/wrong policyName (got: \"$policyName\")"
  fi
done

echo
echo "==> Policy file"
if [ ! -f "$POLICY_FILE" ]; then
  fail "policies/instant-api.json missing"
else
  if jq empty "$POLICY_FILE" >/dev/null 2>&1; then
    ok "policies/instant-api.json parses"
  else
    fail "policies/instant-api.json does not parse"
  fi
  policy_name=$(jq -r '.name // ""' "$POLICY_FILE")
  if [ "$policy_name" = "instant-api alerts" ]; then
    ok "policies/instant-api.json name = \"instant-api alerts\""
  else
    fail "policies/instant-api.json name wrong (got: \"$policy_name\")"
  fi
  pref=$(jq -r '.incidentPreference // ""' "$POLICY_FILE")
  if [ "$pref" = "PER_CONDITION_AND_TARGET" ]; then
    ok "policies/instant-api.json incidentPreference = \"PER_CONDITION_AND_TARGET\""
  else
    fail "policies/instant-api.json incidentPreference wrong (got: \"$pref\")"
  fi
fi

echo
echo "==> Cross-reference: every alert's policyName matches policy file's name"
policy_name=$(jq -r '.name // ""' "$POLICY_FILE" 2>/dev/null || echo "")
for name in "${ALERTS[@]}"; do
  f="$ALERTS_DIR/$name.json"
  [ -f "$f" ] || continue
  alert_policy=$(jq -r '.policyName // ""' "$f")
  if [ "$alert_policy" = "$policy_name" ] && [ -n "$policy_name" ]; then
    ok "$name.json policyName links to policy file"
  else
    fail "$name.json policyName=\"$alert_policy\" does not match policy file name=\"$policy_name\""
  fi
done

echo
echo "==> Summary: $PASS passed, $FAIL failed"
if [ "$FAIL" -gt 0 ]; then
  exit 1
fi
exit 0
