#!/usr/bin/env bash
# Strict Bitcoin Core 31.1 replay for hashlock+timeout and pointlock+timeout
# Disprove spends. The node is isolated and rejects non-standard transactions.

set -Eeuo pipefail
IFS=$'\n\t'

[[ $# -eq 1 ]] || { printf 'Usage: %s FIRST_PASS_FIXTURE_DIR\n' "${0##*/}" >&2; exit 2; }
readonly FIRST_PASS_DIR="$(cd "$1" && pwd -P)"
readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
readonly REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd -P)"

BITCOIND="${BITCOIND:-bitcoind}"
BITCOIN_CLI="${BITCOIN_CLI:-bitcoin-cli}"
BITCOIN_TX="${BITCOIN_TX:-bitcoin-tx}"
CARGO="${CARGO:-cargo}"
RPC_PORT="${DISPROVE_RPC_PORT:-$((30000 + ($$ % 10000)))}"
WORK_DIR="${DISPROVE_REGTEST_WORKDIR:-$(mktemp -d "${TMPDIR:-/tmp}/disprove-pointlock-core31.XXXXXX")}"
readonly BITCOIND BITCOIN_CLI BITCOIN_TX CARGO RPC_PORT WORK_DIR
readonly DATADIR="$WORK_DIR/node"
readonly ARTIFACT_DIR="$WORK_DIR/artifacts"
readonly BOUND_DIR="$WORK_DIR/bound-fixture"
readonly WALLET_NAME="disprove-pointlock-policy-harness"
mkdir -p "$DATADIR" "$ARTIFACT_DIR" "$BOUND_DIR"

die() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }
note() { printf '[disprove-pointlock-core31] %s\n' "$*"; }
for command in "$BITCOIND" "$BITCOIN_CLI" "$BITCOIN_TX" "$CARGO" jq awk cmp tr; do
    command -v "$command" >/dev/null 2>&1 || die "required command not found: $command"
done
for file in hashlock-address.txt pointlock-address.txt hashlock-script.hex pointlock-script.hex; do
    [[ -s "$FIRST_PASS_DIR/$file" ]] || die "missing first-pass $file"
done
core_version="$("$BITCOIND" --version | awk 'NR == 1 { print; exit }')"
[[ "$core_version" == *"v31.1"* ]] || die "Bitcoin Core 31.1 required: $core_version"

node_started=0
btc() { "$BITCOIN_CLI" -regtest -datadir="$DATADIR" -rpcport="$RPC_PORT" "$@"; }
wallet_rpc() { btc -rpcwallet="$WALLET_NAME" "$@"; }
stop_node() {
    local status=$?
    if [[ $node_started -eq 1 ]]; then btc stop >/dev/null 2>&1 || true; fi
    if [[ $status -ne 0 ]]; then printf 'FAILED; preserved work directory: %s\n' "$WORK_DIR" >&2; fi
    return "$status"
}
trap stop_node EXIT INT TERM
test_accept_file() {
    jq -Rsc 'split("\n") | map(select(length > 0))' "$1" | btc -stdin testmempoolaccept
}

note "work directory: $WORK_DIR"
"$BITCOIND" -regtest -datadir="$DATADIR" -rpcport="$RPC_PORT" \
    -rpcbind=127.0.0.1 -rpcallowip=127.0.0.1 -server=1 -daemonwait \
    -listen=0 -dnsseed=0 -discover=0 -persistmempool=0 \
    -acceptnonstdtxn=0 -fallbackfee=0.00001000 -maxmempool=300 >/dev/null
node_started=1
btc -rpcwait -rpcwaittimeout=60 getblockchaininfo >/dev/null
btc createwallet "$WALLET_NAME" >/dev/null
miner_address="$(wallet_rpc getnewaddress '' bech32m)"
wallet_rpc generatetoaddress 101 "$miner_address" >/dev/null

hash_address="$(tr -d '\r\n' < "$FIRST_PASS_DIR/hashlock-address.txt")"
point_address="$(tr -d '\r\n' < "$FIRST_PASS_DIR/pointlock-address.txt")"
"$BITCOIN_TX" -chain=regtest -create \
    "outaddr=0.00001000:$hash_address" \
    "outaddr=0.00001000:$point_address" > "$ARTIFACT_DIR/funding-unsigned.hex"
{
    tr -d '\r\n' < "$ARTIFACT_DIR/funding-unsigned.hex"
    printf '\n{"changePosition":2,"change_type":"bech32m","fee_rate":1,"replaceable":true}\n'
} | wallet_rpc -stdin fundrawtransaction > "$ARTIFACT_DIR/funding-funded.json"
jq -r '.hex' "$ARTIFACT_DIR/funding-funded.json" > "$ARTIFACT_DIR/funding-funded.hex"
wallet_rpc -stdin signrawtransactionwithwallet < "$ARTIFACT_DIR/funding-funded.hex" \
    > "$ARTIFACT_DIR/funding-signed.json"
jq -e '.complete == true' "$ARTIFACT_DIR/funding-signed.json" >/dev/null || die "funding signing incomplete"
jq -r '.hex' "$ARTIFACT_DIR/funding-signed.json" > "$ARTIFACT_DIR/funding-signed.hex"
btc -stdin decoderawtransaction < "$ARTIFACT_DIR/funding-signed.hex" > "$ARTIFACT_DIR/funding-decoded.json"
hash_script="$(tr -d '\r\n' < "$FIRST_PASS_DIR/hashlock-script.hex")"
point_script="$(tr -d '\r\n' < "$FIRST_PASS_DIR/pointlock-script.hex")"
jq -e --arg h "$hash_script" --arg p "$point_script" '
    (.vin | length) == 1 and (.vout | length) == 3 and
    .vout[0].value == 0.00001 and .vout[0].scriptPubKey.hex == $h and
    .vout[1].value == 0.00001 and .vout[1].scriptPubKey.hex == $p
' "$ARTIFACT_DIR/funding-decoded.json" >/dev/null || die "funding output order changed"
test_accept_file "$ARTIFACT_DIR/funding-signed.hex" > "$ARTIFACT_DIR/funding-accept.json"
jq -e 'length == 1 and .[0].allowed == true' "$ARTIFACT_DIR/funding-accept.json" >/dev/null ||
    die "strict policy rejected funding"
funding_txid="$(btc -stdin sendrawtransaction < "$ARTIFACT_DIR/funding-signed.hex")"
funding_txid="${funding_txid//[[:space:]\"]/}"

(
    cd "$REPO_ROOT"
    DISPROVE_FUNDING_TXID="$funding_txid" DISPROVE_EXPORT_DIR="$BOUND_DIR" \
        "$CARGO" test --locked --release -p whir-gc --test disprove_pointlock_cost \
        disprove_hashlock_vs_pointlock_exact_serialization -- --exact --nocapture
) 2>&1 | tee "$ARTIFACT_DIR/bound-export.log"
cmp -s "$FIRST_PASS_DIR/hashlock-script.hex" "$BOUND_DIR/hashlock-script.hex" || die "hashlock changed"
cmp -s "$FIRST_PASS_DIR/pointlock-script.hex" "$BOUND_DIR/pointlock-script.hex" || die "pointlock changed"

btc -stdin decoderawtransaction < "$BOUND_DIR/hashlock-spend.hex" > "$ARTIFACT_DIR/hashlock-decoded.json"
btc -stdin decoderawtransaction < "$BOUND_DIR/pointlock-spend.hex" > "$ARTIFACT_DIR/pointlock-decoded.json"
jq -e --arg txid "$funding_txid" '
    .size == 188 and .weight == 386 and .vsize == 97 and
    .vin[0].txid == $txid and .vin[0].vout == 0 and
    (.vin[0].txinwitness | length) == 3
' "$ARTIFACT_DIR/hashlock-decoded.json" >/dev/null || die "hashlock spend changed"
jq -e --arg txid "$funding_txid" '
    .size == 134 and .weight == 332 and .vsize == 83 and
    .vin[0].txid == $txid and .vin[0].vout == 1 and
    (.vin[0].txinwitness | length) == 1 and
    (.vin[0].txinwitness[0] | length) == 128
' "$ARTIFACT_DIR/pointlock-decoded.json" >/dev/null || die "pointlock spend changed"

test_accept_file "$BOUND_DIR/hashlock-spend.hex" > "$ARTIFACT_DIR/hashlock-accept.json"
test_accept_file "$BOUND_DIR/pointlock-spend.hex" > "$ARTIFACT_DIR/pointlock-accept.json"
jq -e 'length == 1 and .[0].allowed == true and .[0].vsize == 97' \
    "$ARTIFACT_DIR/hashlock-accept.json" >/dev/null || die "strict policy rejected hashlock"
jq -e 'length == 1 and .[0].allowed == true and .[0].vsize == 83' \
    "$ARTIFACT_DIR/pointlock-accept.json" >/dev/null || die "strict policy rejected pointlock"
hashlock_txid="$(btc -stdin sendrawtransaction < "$BOUND_DIR/hashlock-spend.hex")"
pointlock_txid="$(btc -stdin sendrawtransaction < "$BOUND_DIR/pointlock-spend.hex")"
wallet_rpc generatetoaddress 1 "$miner_address" >/dev/null
[[ "$(btc getrawmempool | jq 'length')" -eq 0 ]] || die "spends did not confirm"

funding_vsize="$(jq -r '.[0].vsize' "$ARTIFACT_DIR/funding-accept.json")"
jq -n --arg core_version "$core_version" --arg work_dir "$WORK_DIR" \
    --arg funding_txid "$funding_txid" --arg hashlock_txid "$hashlock_txid" \
    --arg pointlock_txid "$pointlock_txid" --argjson funding_vsize "$funding_vsize" '
    {
        scheme: "disprove-hashlock-vs-pointlock",
        core_version: $core_version,
        strict_standard_policy: true,
        work_dir: $work_dir,
        funding: {txid: $funding_txid, vsize: $funding_vsize},
        false_label_bytes: 16,
        hashlock_with_timeout: {txid: $hashlock_txid, weight: 386, vsize: 97},
        pointlock_with_timeout: {txid: $pointlock_txid, weight: 332, vsize: 83},
        pointlock_saving: {weight: 54, vsize: 14},
        all_confirmed: true
    }
' | tee "$ARTIFACT_DIR/report.json"
note "PASS: strict Core accepted both Disprove variants; pointlock saves 14 vB with timeout"
note "preserved evidence: $WORK_DIR"
btc stop >/dev/null
node_started=0
