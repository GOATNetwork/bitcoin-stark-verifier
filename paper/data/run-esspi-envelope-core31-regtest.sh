#!/usr/bin/env bash
# Strict Bitcoin Core 31.1 replay for the ESSPI-style P2TR envelope fixture.
# The node is isolated regtest with non-standard transactions disabled.

set -Eeuo pipefail
IFS=$'\n\t'

[[ $# -eq 1 ]] || {
    printf 'Usage: %s FIRST_PASS_FIXTURE_DIR\n' "${0##*/}" >&2
    exit 2
}

readonly FIRST_PASS_DIR="$(cd "$1" && pwd -P)"
readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
readonly REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd -P)"
readonly FIRST_ADDRESS="$FIRST_PASS_DIR/commit-address.txt"
readonly FIRST_SCRIPT="$FIRST_PASS_DIR/commit-script.hex"

BITCOIND="${BITCOIND:-bitcoind}"
BITCOIN_CLI="${BITCOIN_CLI:-bitcoin-cli}"
BITCOIN_TX="${BITCOIN_TX:-bitcoin-tx}"
CARGO="${CARGO:-cargo}"
RPC_PORT="${ESSPI_RPC_PORT:-$((28000 + ($$ % 12000)))}"
WORK_DIR="${ESSPI_REGTEST_WORKDIR:-$(mktemp -d "${TMPDIR:-/tmp}/esspi-envelope-core31.XXXXXX")}"
readonly BITCOIND BITCOIN_CLI BITCOIN_TX CARGO RPC_PORT WORK_DIR
readonly DATADIR="$WORK_DIR/node"
readonly ARTIFACT_DIR="$WORK_DIR/artifacts"
readonly BOUND_DIR="$WORK_DIR/bound-fixture"
readonly WALLET_NAME="esspi-envelope-policy-harness"
mkdir -p "$DATADIR" "$ARTIFACT_DIR" "$BOUND_DIR"

die() {
    printf 'ERROR: %s\n' "$*" >&2
    exit 1
}

note() {
    printf '[esspi-envelope-core31] %s\n' "$*"
}

for command in "$BITCOIND" "$BITCOIN_CLI" "$BITCOIN_TX" "$CARGO" jq awk cmp tr; do
    command -v "$command" >/dev/null 2>&1 || die "required command not found: $command"
done
[[ -s "$FIRST_ADDRESS" && -s "$FIRST_SCRIPT" ]] || die "incomplete first-pass fixture"
core_version="$("$BITCOIND" --version | awk 'NR == 1 { print; exit }')"
[[ "$core_version" == *"v31.1"* ]] || die "Bitcoin Core 31.1 required: $core_version"

node_started=0
btc() {
    "$BITCOIN_CLI" -regtest -datadir="$DATADIR" -rpcport="$RPC_PORT" "$@"
}
wallet_rpc() {
    btc -rpcwallet="$WALLET_NAME" "$@"
}
stop_node() {
    local status=$?
    if [[ $node_started -eq 1 ]]; then
        btc stop >/dev/null 2>&1 || true
    fi
    if [[ $status -ne 0 ]]; then
        printf 'FAILED; preserved work directory: %s\n' "$WORK_DIR" >&2
    fi
    return "$status"
}
trap stop_node EXIT INT TERM

test_accept_file() {
    jq -Rsc 'split("\n") | map(select(length > 0))' "$1" |
        btc -stdin testmempoolaccept
}

note "work directory: $WORK_DIR"
"$BITCOIND" \
    -regtest \
    -datadir="$DATADIR" \
    -rpcport="$RPC_PORT" \
    -rpcbind=127.0.0.1 \
    -rpcallowip=127.0.0.1 \
    -server=1 \
    -daemonwait \
    -listen=0 \
    -dnsseed=0 \
    -discover=0 \
    -persistmempool=0 \
    -acceptnonstdtxn=0 \
    -fallbackfee=0.00001000 \
    -maxmempool=300 >/dev/null
node_started=1
btc -rpcwait -rpcwaittimeout=60 getblockchaininfo >/dev/null
btc createwallet "$WALLET_NAME" >/dev/null
miner_address="$(wallet_rpc getnewaddress '' bech32m)"
wallet_rpc generatetoaddress 101 "$miner_address" >/dev/null

commit_address="$(tr -d '\r\n' < "$FIRST_ADDRESS")"
readonly COMMIT_UNSIGNED="$ARTIFACT_DIR/commit-unsigned.hex"
readonly COMMIT_FUNDED_JSON="$ARTIFACT_DIR/commit-funded.json"
readonly COMMIT_FUNDED_HEX="$ARTIFACT_DIR/commit-funded.hex"
readonly COMMIT_SIGNED_JSON="$ARTIFACT_DIR/commit-signed.json"
readonly COMMIT_SIGNED_HEX="$ARTIFACT_DIR/commit-signed.hex"
readonly COMMIT_DECODED="$ARTIFACT_DIR/commit-decoded.json"

"$BITCOIN_TX" -chain=regtest -create "outaddr=0.00100000:$commit_address" \
    > "$COMMIT_UNSIGNED"
{
    tr -d '\r\n' < "$COMMIT_UNSIGNED"
    printf '\n{"changePosition":1,"change_type":"bech32m","fee_rate":1,"replaceable":true}\n'
} | wallet_rpc -stdin fundrawtransaction > "$COMMIT_FUNDED_JSON"
jq -e '.changepos == 1' "$COMMIT_FUNDED_JSON" >/dev/null || die "commit change position changed"
jq -r '.hex' "$COMMIT_FUNDED_JSON" > "$COMMIT_FUNDED_HEX"
wallet_rpc -stdin signrawtransactionwithwallet < "$COMMIT_FUNDED_HEX" > "$COMMIT_SIGNED_JSON"
jq -e '.complete == true' "$COMMIT_SIGNED_JSON" >/dev/null || die "commit signing incomplete"
jq -r '.hex' "$COMMIT_SIGNED_JSON" > "$COMMIT_SIGNED_HEX"
btc -stdin decoderawtransaction < "$COMMIT_SIGNED_HEX" > "$COMMIT_DECODED"

expected_script="$(tr -d '\r\n' < "$FIRST_SCRIPT")"
jq -e --arg script "$expected_script" '
    (.vin | length) == 1 and (.vout | length) == 2 and
    .vout[0].n == 0 and .vout[0].value == 0.001 and
    .vout[0].scriptPubKey.hex == $script and
    .vout[0].scriptPubKey.type == "witness_v1_taproot"
' "$COMMIT_DECODED" >/dev/null || die "commit output does not match envelope commitment"
test_accept_file "$COMMIT_SIGNED_HEX" > "$ARTIFACT_DIR/commit-accept.json"
jq -e 'length == 1 and .[0].allowed == true' "$ARTIFACT_DIR/commit-accept.json" >/dev/null ||
    die "strict policy rejected commit"
commit_txid="$(btc -stdin sendrawtransaction < "$COMMIT_SIGNED_HEX")"
commit_txid="${commit_txid//[[:space:]\"]/}"
note "unconfirmed commit txid: $commit_txid"

(
    cd "$REPO_ROOT"
    ESSPI_COMMIT_TXID="$commit_txid" \
    ESSPI_COMMIT_VOUT=0 \
    ESSPI_EXPORT_DIR="$BOUND_DIR" \
        "$CARGO" test --locked --release -p whir-gc \
        --test esspi_envelope_cost esspi_p2tr_envelope_exact_serialization \
        -- --exact --nocapture
) 2>&1 | tee "$ARTIFACT_DIR/bound-export.log"
cmp -s "$FIRST_SCRIPT" "$BOUND_DIR/commit-script.hex" || die "bound taproot commitment changed"

readonly REVEAL_HEX="$BOUND_DIR/reveal.hex"
readonly REVEAL_DECODED="$ARTIFACT_DIR/reveal-decoded.json"
btc -stdin decoderawtransaction < "$REVEAL_HEX" > "$REVEAL_DECODED"
jq -e --arg commit_txid "$commit_txid" '
    .version == 2 and .locktime == 0 and
    .size == 131118 and .weight == 131400 and .vsize == 32850 and
    (.vin | length) == 1 and .vin[0].txid == $commit_txid and .vin[0].vout == 0 and
    (.vin[0].txinwitness | length) == 3 and
    (.vin[0].txinwitness[0] | length) == 128 and
    (.vin[0].txinwitness[1] | length) == 261834 and
    (.vin[0].txinwitness[2] | length) == 66 and
    (.vout | length) == 1 and .vout[0].scriptPubKey.type == "witness_v1_taproot"
' "$REVEAL_DECODED" >/dev/null || die "reveal serialization changed"

test_accept_file "$REVEAL_HEX" > "$ARTIFACT_DIR/reveal-unconfirmed-parent-accept.json"
jq -e 'length == 1 and .[0].allowed == true' \
    "$ARTIFACT_DIR/reveal-unconfirmed-parent-accept.json" >/dev/null || {
    jq . "$ARTIFACT_DIR/reveal-unconfirmed-parent-accept.json" >&2
    die "strict policy rejected reveal with unconfirmed commit"
}
reveal_txid="$(btc -stdin sendrawtransaction < "$REVEAL_HEX")"
reveal_txid="${reveal_txid//[[:space:]\"]/}"
wallet_rpc generatetoaddress 1 "$miner_address" >/dev/null
[[ "$(btc getrawmempool | jq 'length')" -eq 0 ]] || die "commit/reveal did not confirm"

commit_vsize="$(jq -r '.[0].vsize' "$ARTIFACT_DIR/commit-accept.json")"
reveal_vsize="$(jq -r '.[0].vsize' "$ARTIFACT_DIR/reveal-unconfirmed-parent-accept.json")"
total_vsize="$((commit_vsize + reveal_vsize))"
jq -n \
    --arg core_version "$core_version" \
    --arg work_dir "$WORK_DIR" \
    --arg commit_txid "$commit_txid" \
    --arg reveal_txid "$reveal_txid" \
    --argjson commit_vsize "$commit_vsize" \
    --argjson reveal_vsize "$reveal_vsize" \
    --argjson total_vsize "$total_vsize" '
    {
        scheme: "esspi-p2tr-envelope-transport",
        core_version: $core_version,
        strict_standard_policy: true,
        work_dir: $work_dir,
        commit: {txid: $commit_txid, vsize: $commit_vsize},
        reveal: {
            txid: $reveal_txid,
            payload_bytes: 130128,
            tapscript_bytes: 130917,
            weight: 131400,
            vsize: $reveal_vsize,
            accepted_with_unconfirmed_parent: true
        },
        commit_plus_reveal_vsize: $total_vsize,
        transactions: 2,
        confirmation_blocks: 1
    }
' | tee "$ARTIFACT_DIR/report.json"

note "PASS: strict Core accepted commit and authenticated envelope reveal"
note "PASS: commit + reveal = $total_vsize vB in two transactions"
note "preserved evidence: $WORK_DIR"
btc stop >/dev/null
node_started=0
