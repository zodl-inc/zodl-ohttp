#!/bin/bash
# End-to-end check through a real relay: key config → HPKE → BHTTP gRPC → relay → gateway → lightwalletd.
#
#   NETWORK=testnet|mainnet GATEWAY_HOST=ohttp-gateway.example RELAY_URL=https://relay.example/relay \
#     ./scripts/test-e2e.sh [trace_id]
#
# GATEWAY_HOST (the gateway's inner authority) and RELAY_URL are required; there are no built-in
# endpoints. NETWORK defaults to testnet. Exits non-zero if GetLatestBlock does not come back
# with inner status 200 / grpc-status 0, or if an unknown :authority is not rejected with inner 403.
# The key configuration is read as the unsigned document (OHTTP_E2E_KEY_CONFIG_SOURCE=plain,
# the default here). With CONFIGS_URL pointing at a signed configuration, set
# OHTTP_E2E_KEY_CONFIG_SOURCE=signed and the network's OHTTP configuration, OHTTP_E2E_*_<NET>
# (e2e-client/README.md). A relay simulator is reached over plain HTTP, which the script allows
# for it (OHTTP_E2E_PLAIN_HTTP_RELAY=1); any other http:// RELAY_URL needs the caller to set it.
# RELAY_SIMULATOR=1 says RELAY_URL is a relay simulator (key configuration fetched through it,
# plain HTTP allowed), RELAY_SIMULATOR=0 that it is not; unset, empty or "auto", RELAY_URL is
# taken for a simulator when it contains the text "relay-simulator" (the simulator's host or
# service name).
# Every run of the e2e client that exits non-zero prints a FAIL: line and fails the script.
# A simulator's RELAY_URL must end in /relay unless CONFIGS_URL is set. The script prints
# neither RELAY_URL, CONFIGS_URL nor the trace id.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
# Exported: the e2e client reads NETWORK too (the network a signed configuration is verified
# for), and would otherwise fall back to mainnet when the caller did not export it.
export NETWORK="${NETWORK:-testnet}"
TRACE="${1:-e2e-$(date -u +%Y%m%d-%H%M%S)}"

case "$NETWORK" in
  mainnet|testnet) ;;
  *) echo "NETWORK must be mainnet or testnet" >&2; exit 2 ;;
esac
GW="${GATEWAY_HOST:?set GATEWAY_HOST to the gateway host name}"
RELAY_URL="${RELAY_URL:?set RELAY_URL to the relay URL}"
# The key-configuration source is always explicit, never the e2e client's guess from the URL.
export OHTTP_E2E_KEY_CONFIG_SOURCE="${OHTTP_E2E_KEY_CONFIG_SOURCE:-plain}"

# Derive CONFIGS_URL: if relay-simulator, fetch config via relay; otherwise direct from gateway
case "${RELAY_SIMULATOR:-auto}" in
  1) SIMULATOR=1 ;;
  0) SIMULATOR=0 ;;
  auto) if [[ "$RELAY_URL" == *"relay-simulator"* ]]; then SIMULATOR=1; else SIMULATOR=0; fi ;;
  *) echo "RELAY_SIMULATOR must be 1, 0, auto or unset (empty)" >&2; exit 2 ;;
esac
if [ "$SIMULATOR" = 1 ]; then
  # The simulator serves the key configuration next to its /relay endpoint; from any other
  # path that location cannot be derived.
  if [ -z "${CONFIGS_URL:-}" ] && [[ "$RELAY_URL" != */relay ]]; then
    echo "a relay simulator's RELAY_URL must end in /relay (or set CONFIGS_URL)" >&2; exit 2
  fi
  RELAY_BASE="${RELAY_URL%/relay}"
  # The simulator listens on plain HTTP; the e2e client refuses http:// relay URLs without this.
  export OHTTP_E2E_PLAIN_HTTP_RELAY="${OHTTP_E2E_PLAIN_HTTP_RELAY:-1}"
  CONFIGS_URL="${CONFIGS_URL:-$RELAY_BASE/ohttp-configs}"
else
  CONFIGS_URL="${CONFIGS_URL:-https://$GW/ohttp-configs}"
fi

BIN="$REPO_ROOT/e2e-client/target/release/ohttp-e2e"
[ -x "$BIN" ] || (cd "$REPO_ROOT/e2e-client" && cargo build --release --quiet)

# Neither URL nor the trace id is printed: the output may be kept where those must not be.
echo "== $NETWORK: GetLatestBlock through the relay"
# `if !` keeps set -e from ending the script silently when the e2e client exits non-zero.
if ! OUT=$("$BIN" "$CONFIGS_URL" "$RELAY_URL" "$GW" POST /cash.z.wallet.sdk.rpc.CompactTxStreamer/GetLatestBlock "$TRACE"); then
  echo "$OUT"; echo "FAIL: GetLatestBlock (the e2e client exited non-zero)"; exit 1
fi
echo "$OUT"
grep -q 'inner response status=200' <<<"$OUT" && grep -q 'grpc-status: 0' <<<"$OUT" || { echo "FAIL: GetLatestBlock"; exit 1; }

echo "== $NETWORK: unknown authority must be rejected"
# OHTTP_E2E_EXPECT_OK is emptied for this run: with a caller's =1 the e2e client would exit
# non-zero on the inner 403 that is expected here.
if ! OUT=$(OHTTP_E2E_EXPECT_OK= "$BIN" "$CONFIGS_URL" "$RELAY_URL" evil.example POST /cash.z.wallet.sdk.rpc.CompactTxStreamer/GetLatestBlock "$TRACE-neg"); then
  echo "$OUT"; echo "FAIL: unknown authority (the e2e client exited non-zero)"; exit 1
fi
grep -q 'inner response status=403' <<<"$OUT" || { echo "$OUT"; echo "FAIL: unknown authority not rejected"; exit 1; }
echo "PASS"
