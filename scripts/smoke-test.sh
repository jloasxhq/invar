#!/usr/bin/env bash
# End-to-end smoke test: starts a throwaway forge-backend and exercises every
# endpoint, link, and interconnection (domain <-> crypto <-> ledger over HTTP, the
# Go CLI <-> backend link, capability-auth enforcement, and the PQC multisig flow).
#
# Usage: bash scripts/smoke-test.sh
# Exits non-zero if any check fails.
set -uo pipefail
cd "$(dirname "$0")/.."

command -v go >/dev/null 2>&1 || export PATH="/c/Program Files/Go/bin:$PATH"

PORT="${SMOKE_PORT:-8137}"
CAPS_PORT="${SMOKE_CAPS_PORT:-8138}"
BASE="http://127.0.0.1:${PORT}"
CAPS_BASE="http://127.0.0.1:${CAPS_PORT}"
BODYFILE="$(mktemp)"
PASS=0; FAIL=0
GREEN='\033[32m'; RED='\033[31m'; DIM='\033[2m'; NC='\033[0m'

req() { # METHOD PATH [BODY] [TOKEN] ; sets HTTP + reads body into BODYFILE
  local method="$1" url="$2" body="${3:-}" token="${4:-}"
  local args=(-s -o "$BODYFILE" -w "%{http_code}" -X "$method" "$url")
  [ -n "$body" ] && args+=(-H "content-type: application/json" -d "$body")
  [ -n "$token" ] && args+=(-H "x-forge-capability: $token")
  HTTP="$(curl "${args[@]}")"
}
check() { # DESC EXPECTED
  if [ "$HTTP" = "$2" ]; then
    PASS=$((PASS+1)); printf "  ${GREEN}PASS${NC} %-52s [%s]\n" "$1" "$HTTP"
  else
    FAIL=$((FAIL+1)); printf "  ${RED}FAIL${NC} %-52s [got %s want %s] %s\n" "$1" "$HTTP" "$2" "$(cat "$BODYFILE")"
  fi
}
jfield() { node -e 'let fs=require("fs");let o={};try{o=JSON.parse(fs.readFileSync(0,"utf8"))}catch(e){}process.stdout.write(String(o[process.argv[1]]??""))' "$1" < "$BODYFILE"; }
assert_eq() { if [ "$2" = "$3" ]; then PASS=$((PASS+1)); printf "  ${GREEN}PASS${NC} %-52s [%s]\n" "$1" "$2"; else FAIL=$((FAIL+1)); printf "  ${RED}FAIL${NC} %-52s [got %s want %s]\n" "$1" "$2" "$3"; fi; }

echo "==> Building forge-backend + Go CLI"
cargo build --release -p forge-backend >/dev/null 2>&1 || { echo "cargo build failed"; exit 1; }
BIN="target/release/forge-backend"; [ -f "${BIN}.exe" ] && BIN="${BIN}.exe"

PIDS=()
cleanup() { for p in "${PIDS[@]:-}"; do kill "$p" 2>/dev/null || true; done; rm -f "$BODYFILE"; }
trap cleanup EXIT

echo "==> Starting backend (dev mode) on :${PORT}"
FORGE_BIND="127.0.0.1:${PORT}" FORGE_ADMIN="issuer" "./$BIN" >/dev/null 2>&1 &
PIDS+=($!)
curl --retry-connrefused --retry 30 --retry-delay 1 -sf "$BASE/health" >/dev/null || { echo "backend did not become healthy"; exit 1; }

echo ""
echo "== Health & token =="
req GET "$BASE/health";                                              check "GET /health" 200
req GET "$BASE/token";                                               check "GET /token" 200
assert_eq "token symbol == gUSD" "$(jfield symbol)" "gUSD"

echo "== Capability issuance (auth link) =="
req POST "$BASE/auth/token" '{"subject":"issuer","scopes":["*"],"ttl_secs":300}'; check "POST /auth/token" 200
TOKEN="$(jfield token)"; [ -n "$TOKEN" ] && PASS=$((PASS+1)) && printf "  ${GREEN}PASS${NC} %-52s [%s..]\n" "capability token issued" "${TOKEN:0:8}" || { FAIL=$((FAIL+1)); echo "  FAIL token empty"; }

echo "== Onboarding & KYC (compliance link) =="
for id in acme globex carol; do
  req POST "$BASE/accounts" "{\"id\":\"$id\"}";                      check "POST /accounts ($id)" 201
  req POST "$BASE/accounts/$id/kyc" '{"verified":true}';            check "POST /accounts/$id/kyc" 204
done

echo "== Reserve (oracle + attest, crypto link) =="
req POST "$BASE/reserve/oracle" '{"reserve":1000000}';              check "POST /reserve/oracle" 204
req POST "$BASE/reserve/sync";                                      check "POST /reserve/sync" 200
assert_eq "attested_reserve synced" "$(jfield attested_reserve)" "1000000"
req POST "$BASE/attest" '{"reserve":1000000,"custodian_ref":"bank:1"}'; check "POST /attest" 200
assert_eq "attestation algorithm ML-DSA-65" "$(jfield algorithm)" "ML-DSA-65"

echo "== Mint + peg invariant =="
req POST "$BASE/mint" '{"to":"acme","amount":400000}';             check "POST /mint (within reserve)" 200
req GET  "$BASE/accounts/acme";                                     check "GET /accounts/acme" 200
assert_eq "acme balance == 400000" "$(jfield balance)" "400000"
req POST "$BASE/mint" '{"to":"acme","amount":9000000}';            check "POST /mint (breaks peg -> 422)" 422

echo "== Roles & supply allowances =="
req POST "$BASE/accounts/carol/roles/grant" '{"role":"minter"}';   check "POST roles/grant" 204
req POST "$BASE/accounts/carol/allowance" '{"amount":100}';        check "POST allowance" 204
req POST "$BASE/accounts/carol/roles/revoke" '{"role":"minter"}';  check "POST roles/revoke" 204

echo "== Transfer & holds (escrow link) =="
req POST "$BASE/transfer" '{"from":"acme","to":"globex","amount":150000}'; check "POST /transfer" 200
req GET  "$BASE/accounts/globex"; assert_eq "globex balance 150000" "$(jfield balance)" "150000"
req POST "$BASE/holds" '{"from":"acme","amount":50000,"beneficiary":"globex"}'; check "POST /holds" 200
HOLD_ID="$(jfield id)"
req GET  "$BASE/accounts/acme"; assert_eq "acme locked (balance 200000)" "$(jfield balance)" "200000"
req POST "$BASE/holds/$HOLD_ID/execute" '{}';                      check "POST /holds/:id/execute" 200
req GET  "$BASE/accounts/globex"; assert_eq "globex received hold (200000)" "$(jfield balance)" "200000"
req POST "$BASE/holds" '{"from":"globex","amount":10000}';         check "POST /holds (no beneficiary)" 200
HOLD2="$(jfield id)"
req POST "$BASE/holds/$HOLD2/release";                             check "POST /holds/:id/release" 200
req GET  "$BASE/holds";                                            check "GET /holds" 200

echo "== Burn & redeem =="
req POST "$BASE/burn" '{"from":"acme","amount":20000}';            check "POST /burn" 200
req POST "$BASE/redeem" '{"from":"globex","amount":30000}';        check "POST /redeem" 200

echo "== Freeze / unfreeze =="
req POST "$BASE/accounts/acme/freeze" '{"frozen":true}';           check "POST freeze" 204
req POST "$BASE/transfer" '{"from":"acme","to":"globex","amount":1}'; check "transfer blocked when frozen" 409
req POST "$BASE/accounts/acme/freeze" '{"frozen":false}';          check "POST unfreeze" 204

echo "== Rescue (treasury recovery) =="
req POST "$BASE/transfer" '{"from":"globex","to":"__treasury__","amount":5000}'; check "misdirect to treasury" 200
req POST "$BASE/rescue" '{"to":"carol","amount":5000}';            check "POST /rescue" 200
req GET  "$BASE/accounts/carol"; assert_eq "carol rescued 5000" "$(jfield balance)" "5000"

echo "== Pause / unpause =="
req POST "$BASE/pause" '{"paused":true}';                          check "POST pause" 204
req POST "$BASE/mint" '{"to":"acme","amount":1}';                  check "mint blocked when paused" 409
req POST "$BASE/pause" '{"paused":false}';                         check "POST unpause" 204

echo "== PQC multisig (M-of-N ML-DSA-65) =="
req GET  "$BASE/multisig/policy";                                  check "GET /multisig/policy" 200
assert_eq "multisig threshold 2" "$(jfield threshold)" "2"
req POST "$BASE/multisig" '{"mint":{"to":"acme","amount":100000}}'; check "POST /multisig (propose)" 200
MSID="$(jfield id)"
req POST "$BASE/multisig/$MSID/execute";                           check "execute before quorum -> 409" 409
req POST "$BASE/multisig/$MSID/approve" '{"signer_index":0}';      check "approve #1" 204
req POST "$BASE/multisig/$MSID/execute";                           check "execute at 1/2 -> 409" 409
req POST "$BASE/multisig/$MSID/approve" '{"signer_index":1}';      check "approve #2" 204
req POST "$BASE/multisig/$MSID/execute";                           check "execute at quorum -> 200" 200
req GET  "$BASE/multisig";                                         check "GET /multisig (list)" 200

echo "== Metadata & entries =="
req POST "$BASE/token/metadata" '{"metadata":"ipfs://terms"}';     check "POST /token/metadata" 204
req GET  "$BASE/entries";                                          check "GET /entries" 200

echo "== Go CLI <-> backend interconnection =="
if command -v go >/dev/null 2>&1; then
  EXT=""; case "$(uname -s)" in MINGW*|MSYS*|CYGWIN*) EXT=".exe";; esac
  CLIBIN="forge-cli${EXT}"
  # Build to the project dir (go run's cache exe can be blocked by host policy).
  if (cd go && go build -o "$CLIBIN" ./cli 2>/dev/null); then
    if (cd go && "./$CLIBIN" -url "$BASE" token 2>/dev/null | grep -q "gUSD"); then
      PASS=$((PASS+1)); printf "  ${GREEN}PASS${NC} %-52s\n" "CLI 'token' returns gUSD"
    else FAIL=$((FAIL+1)); printf "  ${RED}FAIL${NC} %-52s\n" "CLI 'token'"; fi
    if (cd go && "./$CLIBIN" -url "$BASE" account acme >/dev/null 2>&1); then
      PASS=$((PASS+1)); printf "  ${GREEN}PASS${NC} %-52s\n" "CLI 'account acme' ok"
    else FAIL=$((FAIL+1)); printf "  ${RED}FAIL${NC} %-52s\n" "CLI 'account acme'"; fi
    rm -f "go/$CLIBIN"
  else
    FAIL=$((FAIL+1)); printf "  ${RED}FAIL${NC} %-52s\n" "CLI build"
  fi
else
  printf "  ${DIM}SKIP CLI checks (go not found)${NC}\n"
fi

echo "== Token lifecycle (delete last) =="
req POST "$BASE/token/delete";                                     check "POST /token/delete" 200
req POST "$BASE/mint" '{"to":"acme","amount":1}';                  check "mint blocked after delete -> 409" 409

echo ""
echo "== Capability ENFORCEMENT (second instance, FORGE_REQUIRE_CAPS=true) on :${CAPS_PORT} =="
FORGE_BIND="127.0.0.1:${CAPS_PORT}" FORGE_ADMIN="issuer" FORGE_REQUIRE_CAPS=true "./$BIN" >/dev/null 2>&1 &
PIDS+=($!)
curl --retry-connrefused --retry 30 --retry-delay 1 -sf "$CAPS_BASE/health" >/dev/null || { echo "caps backend unhealthy"; }
req POST "$CAPS_BASE/mint" '{"to":"acme","amount":1}';             check "mint WITHOUT token -> 403" 403
req POST "$CAPS_BASE/auth/token" '{"subject":"issuer","scopes":["*"],"ttl_secs":300}'; check "issue admin token" 200
CT="$(jfield token)"
req POST "$CAPS_BASE/accounts" '{"id":"acme"}' "$CT";              check "onboard WITH token -> 201" 201
req POST "$CAPS_BASE/accounts/acme/kyc" '{"verified":true}' "$CT"; check "kyc WITH token -> 204" 204
req POST "$CAPS_BASE/reserve/oracle" '{"reserve":1000000}' "$CT"; check "oracle WITH token" 204
req POST "$CAPS_BASE/reserve/sync" '' "$CT";                       check "sync WITH token" 200
req POST "$CAPS_BASE/mint" '{"to":"acme","amount":1000}' "$CT";    check "mint WITH valid token -> 200" 200
req POST "$CAPS_BASE/auth/token" '{"subject":"issuer","scopes":["burn"],"ttl_secs":300}'; BT="$(jfield token)"
req POST "$CAPS_BASE/mint" '{"to":"acme","amount":1}' "$BT";       check "mint with wrong-scope token -> 403" 403

echo ""
echo "=================================================="
printf "  RESULT: ${GREEN}%d passed${NC}, ${RED}%d failed${NC}\n" "$PASS" "$FAIL"
echo "=================================================="
[ "$FAIL" -eq 0 ]
