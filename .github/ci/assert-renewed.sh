#!/usr/bin/env bash
# Proves issuance, then renewal: run CoreDNS to issue a cert, stop it, run it
# again against the same storage. The Corefile sets renewBeforeDays above the
# issued cert's lifetime, so the second boot renews it -> the cert serial changes.
# Set UPGRADE_BIN to run the second boot with a different binary (upgrade test).
# Usage: assert-renewed.sh <coredns-bin> <corefile> <cert-pem-path> [timeout-per-phase]
set -euo pipefail

BIN="${1:?coredns binary}"
COREFILE="${2:?corefile}"
PEM="${3:?cert .pem path}"
TIMEOUT="${4:-90}"

serial() { openssl x509 -in "$PEM" -noout -serial 2>/dev/null | cut -d= -f2; }

# run_coredns_until <predicate-cmd> : start CoreDNS, poll predicate, then stop it.
# Leaves the CoreDNS log in $log.
run_coredns_until() {
  local pred="$1" pid i
  log="$(mktemp)"
  "$BIN" -conf "$COREFILE" >"$log" 2>&1 &
  pid=$!
  for ((i = 0; i < TIMEOUT; i++)); do
    if eval "$pred"; then
      kill "$pid" 2>/dev/null || true
      wait "$pid" 2>/dev/null || true
      return 0
    fi
    sleep 1
  done
  echo "TIMEOUT after ${TIMEOUT}s waiting for: $pred" >&2
  echo "----- coredns log -----" >&2
  cat "$log" >&2
  kill "$pid" 2>/dev/null || true
  wait "$pid" 2>/dev/null || true
  return 1
}

# Phase 1: issue.
run_coredns_until 'test -s "$PEM"'
S1="$(serial)"
echo "issued: serial=$S1"

# Phase 2: renew (serial must change).
BIN="${UPGRADE_BIN:-$BIN}"
run_coredns_until '[ -n "$(serial)" ] && [ "$(serial)" != "'"$S1"'" ]'
# Phase 2 must reuse what phase 1 left: a failed renew falls back to a fresh order (which changes
# the serial too), and a new account key is only written when the stored one wasn't found.
if grep -E 'Error renewing certificate|registered new Let.s Encrypt account' "$log" >&2; then
  echo "phase 2 did not reuse the stored cert/account, log:" >&2
  cat "$log" >&2
  exit 1
fi
echo "renewed: serial=$(serial)"
