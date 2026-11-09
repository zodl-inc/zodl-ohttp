#!/bin/bash
# End-to-end check through a real relay: key config → HPKE → BHTTP gRPC → relay → gateway → lightwalletd.
#
#   NETWORK=testnet|mainnet GATEWAY_HOST=ohttp-gateway.example RELAY_URL=https://relay.example/relay \
#     ./scripts/test-e2e.sh [trace_id]
#
# GATEWAY_HOST (the gateway's inner authority) and RELAY_URL are required; there are no built-in
# endpoints. NETWORK defaults to testnet. Exits non-zero if GetLatestBlock does not come back
# with inner status 200 / grpc-status 0, or if an unknown :authority is not rejected with inner 403.
# With CONFIGS_URL pointing at a signed configuration (.../ohttp-configs/signed) the e2e client
# also needs the network's OHTTP configuration, OHTTP_E2E_*_<NET> (e2e-client/README.md).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
NETWORK="${NETWORK:-testnet}"
TRACE="${1:-e2e-$(date -u +%Y%m%d-%H%M%S)}"

case "$NETWORK" in
  mainnet|testnet) ;;
  *) echo "NETWORK must be mainnet or testnet" >&2; exit 2 ;;
esac
GW="${GATEWAY_HOST:?set GATEWAY_HOST to the gateway host name}"
RELAY_URL="${RELAY_URL:?set RELAY_URL to the relay URL}"

# Derive CONFIGS_URL: if relay-simulator, fetch config via relay; otherwise direct from gateway
if [[ "$RELAY_URL" == *"relay-simulator"* ]]; then
  RELAY_BASE="${RELAY_URL%/relay}"
  CONFIGS_URL="${CONFIGS_URL:-$RELAY_BASE/ohttp-configs}"
else
  CONFIGS_URL="${CONFIGS_URL:-https://$GW/ohttp-configs}"
fi

BIN="$REPO_ROOT/e2e-client/target/release/ohttp-e2e"
[ -x "$BIN" ] || (cd "$REPO_ROOT/e2e-client" && cargo build --release --quiet)

echo "== $NETWORK: GetLatestBlock via $RELAY_URL (configs from $CONFIGS_URL, trace $TRACE)"
OUT=$("$BIN" "$CONFIGS_URL" "$RELAY_URL" "$GW" POST /cash.z.wallet.sdk.rpc.CompactTxStreamer/GetLatestBlock "$TRACE")
echo "$OUT"
grep -q 'inner response status=200' <<<"$OUT" && grep -q 'grpc-status: 0' <<<"$OUT" || { echo "FAIL: GetLatestBlock"; exit 1; }

echo "== $NETWORK: unknown authority must be rejected"
OUT=$("$BIN" "$CONFIGS_URL" "$RELAY_URL" evil.example POST /cash.z.wallet.sdk.rpc.CompactTxStreamer/GetLatestBlock "$TRACE-neg")
grep -q 'inner response status=403' <<<"$OUT" || { echo "$OUT"; echo "FAIL: unknown authority not rejected"; exit 1; }
echo "PASS"
