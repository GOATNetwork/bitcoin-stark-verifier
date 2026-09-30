#!/usr/bin/env bash
# Reproduce Bitcoin Core policy and relay checks for the exported Lamport
# Assert transactions.  This script creates a private regtest node and never
# connects to Bitcoin mainnet, testnet, signet, or another peer.

set -Eeuo pipefail
IFS=$'\n\t'

readonly SCRIPT_NAME="${0##*/}"
readonly EXPECTED_INPUTS=1044
readonly EXPECTED_REVEALS=174
readonly MAX_STANDARD_WEIGHT=400000
readonly CLUSTER_LIMIT_VB=101000
readonly EXPECTED_FULL_SIZE=396349
readonly EXPECTED_FULL_WEIGHT=397246
readonly EXPECTED_FULL_VSIZE=99312
readonly EXPECTED_TAIL_SIZE=337739
readonly EXPECTED_TAIL_WEIGHT=338636
readonly EXPECTED_TAIL_VSIZE=84659
readonly EXPECTED_REVEAL_TOTAL_VSIZE=17265635
readonly EXPECTED_FINAL_SIZE=30679
readonly EXPECTED_FINAL_WEIGHT=52240
readonly EXPECTED_FINAL_VSIZE=13060

usage() {
    cat <<EOF
Usage: $SCRIPT_NAME FIRST_PASS_FIXTURE_DIR

FIRST_PASS_FIXTURE_DIR must contain the output of:

  WHIR_GC_EXPORT_DIR=DIR cargo test --locked -p whir-gc --release \\
    --test lamport_tx_cost serialized_lamport_assert_component_for_measured_verifier \\
    -- --nocapture

The first-pass reveal hex files use the exporter's placeholder funding txid.
This harness uses funding_outputs.json to create and confirm an ordered funding
transaction, then runs the exporter a second time with WHIR_GC_FUNDING_TXID set
to the real txid.  Only the second-pass reveals are submitted to Bitcoin Core.

Environment:
  BITCOIND                  Bitcoin Core 31.1 bitcoind (default: bitcoind)
  BITCOIN_CLI               Matching bitcoin-cli (default: bitcoin-cli)
  CARGO                     Cargo executable (default: cargo)
  WHIR_GC_REGTEST_WORKDIR   Empty/new directory; default is a new /tmp directory
  WHIR_GC_RPC_PORT          Isolated RPC port; default is derived from the PID
  WHIR_GC_BATCH_SIZE        Progress/check batch size (default: 10)
  WHIR_GC_FUNDING_FEERATE   Funding fee rate in sat/vB (default: 1)

The work directory and node log are deliberately preserved after the run.
All large raw-transaction RPC arguments are passed through bitcoin-cli -stdin.
EOF
}

die() {
    printf 'ERROR: %s\n' "$*" >&2
    exit 1
}

note() {
    printf '[lamport-core31] %s\n' "$*"
}

need_command() {
    command -v "$1" >/dev/null 2>&1 || die "required command not found: $1"
}

one_line_file() {
    tr -d '\r\n' < "$1"
    printf '\n'
}

validate_hex_file() {
    local path="$1"
    [[ -s "$path" ]] || die "missing or empty hex file: $path"
    awk '
        NR != 1 { exit 1 }
        $0 !~ /^[[:xdigit:]]+$/ { exit 1 }
        length($0) % 2 != 0 { exit 1 }
        END { if (NR != 1) exit 1 }
    ' "$path" || die "not a single-line, even-length hex file: $path"
}

[[ $# -eq 1 ]] || {
    usage >&2
    exit 2
}

FIRST_PASS_DIR="$(cd "$1" 2>/dev/null && pwd -P)" ||
    die "fixture directory does not exist: $1"
readonly FIRST_PASS_DIR
readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
readonly REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd -P)"
readonly FIRST_OUTPUTS="$FIRST_PASS_DIR/funding_outputs.json"
readonly FIRST_MANIFEST="$FIRST_PASS_DIR/funding_scripts.tsv"

BITCOIND="${BITCOIND:-bitcoind}"
BITCOIN_CLI="${BITCOIN_CLI:-bitcoin-cli}"
CARGO="${CARGO:-cargo}"
BATCH_SIZE="${WHIR_GC_BATCH_SIZE:-10}"
FUNDING_FEERATE="${WHIR_GC_FUNDING_FEERATE:-1}"
RPC_PORT="${WHIR_GC_RPC_PORT:-$((24000 + ($$ % 16000)))}"

[[ "$BATCH_SIZE" =~ ^[1-9][0-9]*$ ]] || die "WHIR_GC_BATCH_SIZE must be positive"
[[ "$FUNDING_FEERATE" =~ ^[0-9]+([.][0-9]+)?$ ]] ||
    die "WHIR_GC_FUNDING_FEERATE must be a non-negative JSON number"
[[ "$RPC_PORT" =~ ^[1-9][0-9]*$ ]] || die "WHIR_GC_RPC_PORT must be a TCP port"
(( RPC_PORT <= 65535 )) || die "WHIR_GC_RPC_PORT must be at most 65535"

need_command "$BITCOIND"
need_command "$BITCOIN_CLI"
need_command "$CARGO"
need_command jq
need_command awk
need_command cmp
need_command sort
need_command tr

core_version="$("$BITCOIND" --version | awk 'NR == 1 { print; exit }')"
[[ "$core_version" == *"v31.1"* ]] ||
    die "Bitcoin Core 31.1 is required, found: $core_version"

[[ -s "$FIRST_OUTPUTS" ]] || die "missing $FIRST_OUTPUTS"
[[ -s "$FIRST_MANIFEST" ]] || die "missing $FIRST_MANIFEST"
jq -e --argjson count "$EXPECTED_INPUTS" '
    type == "array" and
    length == $count and
    all(.[]; type == "object" and length == 1)
' "$FIRST_OUTPUTS" >/dev/null || die "unexpected funding_outputs.json schema/count"

awk -F '\t' -v count="$EXPECTED_INPUTS" '
    NF != 3 { exit 1 }
    $1 != NR - 1 { exit 1 }
    $2 !~ /^bcrt1/ { exit 1 }
    $3 !~ /^[[:xdigit:]]+$/ { exit 1 }
    END { if (NR != count) exit 1 }
' "$FIRST_MANIFEST" || die "unexpected funding_scripts.tsv schema/count/order"

shopt -s nullglob
first_reveals=("$FIRST_PASS_DIR"/reveal-*.hex)
shopt -u nullglob
[[ ${#first_reveals[@]} -eq $EXPECTED_REVEALS ]] ||
    die "expected $EXPECTED_REVEALS first-pass reveal files, found ${#first_reveals[@]}"
[[ -s "$FIRST_PASS_DIR/finalization.hex" ]] || die "missing first-pass finalization.hex"

if [[ -n "${WHIR_GC_REGTEST_WORKDIR:-}" ]]; then
    WORK_DIR="$WHIR_GC_REGTEST_WORKDIR"
    mkdir -p "$WORK_DIR"
    [[ -z "$(find "$WORK_DIR" -mindepth 1 -maxdepth 1 -print -quit)" ]] ||
        die "WHIR_GC_REGTEST_WORKDIR must be empty: $WORK_DIR"
    WORK_DIR="$(cd "$WORK_DIR" && pwd -P)"
else
    WORK_DIR="$(mktemp -d "${TMPDIR:-/tmp}/lamport-core31-regtest.XXXXXX")"
fi

readonly WORK_DIR
readonly DATADIR="$WORK_DIR/node"
readonly BOUND_DIR="$WORK_DIR/bound-fixtures"
readonly ARTIFACT_DIR="$WORK_DIR/artifacts"
readonly WALLET_NAME="lamport-policy-harness"
mkdir -p "$DATADIR" "$BOUND_DIR" "$ARTIFACT_DIR"

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
        node_started=0
    fi
    if [[ $status -ne 0 ]]; then
        printf 'FAILED; preserved work directory: %s\n' "$WORK_DIR" >&2
    fi
    return "$status"
}
trap stop_node EXIT INT TERM

test_accept_file() {
    local path="$1"
    # -c keeps the JSON array on one line: bitcoin-cli -stdin treats each line
    # as one RPC argument.  The raw transaction never appears in argv.
    jq -Rsc 'split("\n") | map(select(length > 0))' "$path" |
        btc -stdin testmempoolaccept
}

assert_allowed() {
    local result_file="$1"
    local label="$2"
    jq -e 'length == 1 and .[0].allowed == true' "$result_file" >/dev/null || {
        jq . "$result_file" >&2
        die "$label was not accepted"
    }
}

assert_cluster_rejection() {
    local result_file="$1"
    local label="$2"
    jq -e '
        length == 1 and
        .[0].allowed == false and
        .[0]["reject-reason"] == "too-large-cluster"
    ' "$result_file" >/dev/null || {
        jq . "$result_file" >&2
        die "$label did not fail specifically with too-large-cluster"
    }
}

note "work directory: $WORK_DIR"
note "starting isolated $core_version regtest node on RPC port $RPC_PORT"
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
    -maxmempool=300 \
    -debug=mempool \
    -debug=validation >/dev/null
node_started=1
btc -rpcwait -rpcwaittimeout=60 getblockchaininfo >/dev/null
btc createwallet "$WALLET_NAME" >/dev/null

miner_address="$(wallet_rpc getnewaddress)"
note "mining 101 blocks to mature a private regtest coinbase"
wallet_rpc generatetoaddress 101 "$miner_address" >/dev/null

readonly FUNDING_UNSIGNED="$ARTIFACT_DIR/funding-unsigned.hex"
readonly FUNDING_FUNDED_JSON="$ARTIFACT_DIR/funding-funded.json"
readonly FUNDING_FUNDED_HEX="$ARTIFACT_DIR/funding-funded.hex"
readonly FUNDING_SIGNED_JSON="$ARTIFACT_DIR/funding-signed.json"
readonly FUNDING_SIGNED_HEX="$ARTIFACT_DIR/funding-signed.hex"
readonly FUNDING_DECODED="$ARTIFACT_DIR/funding-decoded.json"

note "constructing ordered $EXPECTED_INPUTS-output funding transaction"
{
    printf '[]\n'
    one_line_file "$FIRST_OUTPUTS"
} | wallet_rpc -stdin createrawtransaction > "$FUNDING_UNSIGNED"
validate_hex_file "$FUNDING_UNSIGNED"

{
    one_line_file "$FUNDING_UNSIGNED"
    printf '{"changePosition":%d,"fee_rate":%s,"replaceable":true}\n' \
        "$EXPECTED_INPUTS" "$FUNDING_FEERATE"
} | wallet_rpc -stdin fundrawtransaction > "$FUNDING_FUNDED_JSON"
jq -e --argjson pos "$EXPECTED_INPUTS" '.changepos == $pos' \
    "$FUNDING_FUNDED_JSON" >/dev/null || {
    jq . "$FUNDING_FUNDED_JSON" >&2
    die "wallet did not append change at vout $EXPECTED_INPUTS"
}
jq -r '.hex' "$FUNDING_FUNDED_JSON" > "$FUNDING_FUNDED_HEX"
validate_hex_file "$FUNDING_FUNDED_HEX"

wallet_rpc -stdin signrawtransactionwithwallet < "$FUNDING_FUNDED_HEX" \
    > "$FUNDING_SIGNED_JSON"
jq -e '.complete == true' "$FUNDING_SIGNED_JSON" >/dev/null || {
    jq . "$FUNDING_SIGNED_JSON" >&2
    die "funding transaction was not completely signed"
}
jq -r '.hex' "$FUNDING_SIGNED_JSON" > "$FUNDING_SIGNED_HEX"
validate_hex_file "$FUNDING_SIGNED_HEX"
btc -stdin decoderawtransaction < "$FUNDING_SIGNED_HEX" > "$FUNDING_DECODED"

jq -r --argjson count "$EXPECTED_INPUTS" '
    .vout[0:$count][] | "\(.n)\t\(.scriptPubKey.hex)"
' "$FUNDING_DECODED" > "$ARTIFACT_DIR/funding-actual-order.tsv"
awk -F '\t' '{ print $1 "\t" $3 }' "$FIRST_MANIFEST" \
    > "$ARTIFACT_DIR/funding-expected-order.tsv"
cmp -s "$ARTIFACT_DIR/funding-expected-order.tsv" \
    "$ARTIFACT_DIR/funding-actual-order.tsv" ||
    die "fundrawtransaction changed the committed vout order"
jq -e --argjson count "$EXPECTED_INPUTS" '
    (.vout | length) == ($count + 1) and
    .vout[$count].n == $count and
    all(.vout[0:$count][]; .value == 0.00017000)
' "$FUNDING_DECODED" >/dev/null || die "unexpected funding output/change count"

test_accept_file "$FUNDING_SIGNED_HEX" > "$ARTIFACT_DIR/funding-accept.json"
assert_allowed "$ARTIFACT_DIR/funding-accept.json" "funding transaction"
funding_txid="$(btc -stdin sendrawtransaction < "$FUNDING_SIGNED_HEX")"
funding_txid="${funding_txid//[[:space:]\"]/}"
decoded_funding_txid="$(jq -r '.txid' "$FUNDING_DECODED")"
[[ "$funding_txid" == "$decoded_funding_txid" ]] ||
    die "broadcast and decoded funding txids disagree"
btc getmempoolentry "$funding_txid" > "$ARTIFACT_DIR/funding-mempool-entry.json"
note "unconfirmed funding txid: $funding_txid"

note "regenerating signed reveals against the real funding txid"
(
    cd "$REPO_ROOT"
    WHIR_GC_FUNDING_TXID="$funding_txid" \
    WHIR_GC_EXPORT_DIR="$BOUND_DIR" \
    RUST_TEST_THREADS=1 \
        "$CARGO" test --locked -p whir-gc --release \
        --test lamport_tx_cost \
        serialized_lamport_assert_component_for_measured_verifier -- \
        --nocapture
) 2>&1 | tee "$ARTIFACT_DIR/second-pass-export.log"

cmp -s "$FIRST_OUTPUTS" "$BOUND_DIR/funding_outputs.json" ||
    die "second-pass funding outputs differ from first pass"
cmp -s "$FIRST_MANIFEST" "$BOUND_DIR/funding_scripts.tsv" ||
    die "second-pass funding scripts differ from first pass"

shopt -s nullglob
reveals=("$BOUND_DIR"/reveal-*.hex)
shopt -u nullglob
mapfile -t reveals < <(printf '%s\n' "${reveals[@]}" | sort)
[[ ${#reveals[@]} -eq $EXPECTED_REVEALS ]] ||
    die "second pass exported ${#reveals[@]} reveals, expected $EXPECTED_REVEALS"
for ((i = 0; i < EXPECTED_REVEALS; i++)); do
    printf -v expected_name 'reveal-%03d.hex' "$i"
    [[ "${reveals[$i]##*/}" == "$expected_name" ]] ||
        die "missing or misordered reveal fixture: $expected_name"
done
validate_hex_file "${reveals[0]}"
validate_hex_file "${reveals[$((EXPECTED_REVEALS - 1))]}"
validate_hex_file "$BOUND_DIR/finalization.hex"

# Decode the large hex through stdin and retain only a compact structural
# summary.  These assertions make explicit that Core sees the Schnorr
# signatures, every Lamport preimage, the complete tapscript and control block;
# the measurements are not payload-only estimates.
btc -stdin decoderawtransaction < "${reveals[0]}" | tee \
    "$ARTIFACT_DIR/reveal-full-decoded.json" | jq -e \
    --argjson size "$EXPECTED_FULL_SIZE" \
    --argjson weight "$EXPECTED_FULL_WEIGHT" \
    --argjson vsize "$EXPECTED_FULL_VSIZE" '
        .size == $size and .weight == $weight and .vsize == $vsize and
        (.vin | length) == 6 and (.vout | length) == 1 and
        all(.vin[];
            (.txinwitness | length) == 1001 and
            all(.txinwitness[0:998][]; length == 32) and
            (.txinwitness[998] | length) == 128 and
            (.txinwitness[999] | length) == 97874 and
            (.txinwitness[1000] | length) == 66)
    ' >/dev/null || die "full reveal serialization/witness layout changed"
jq '{
        txid, size, weight, vsize,
        inputs: (.vin | length), outputs: (.vout | length),
        witness_items_per_input: [.vin[].txinwitness | length],
        preimages_per_input: 998,
        preimage_bytes: (.vin[0].txinwitness[0] | length / 2),
        signature_bytes: (.vin[0].txinwitness[998] | length / 2),
        tapscript_bytes: (.vin[0].txinwitness[999] | length / 2),
        control_block_bytes: (.vin[0].txinwitness[1000] | length / 2),
        initial_stack_items: 999,
        measured_transient_peak: 1000
    }' "$ARTIFACT_DIR/reveal-full-decoded.json" \
    > "$ARTIFACT_DIR/reveal-full-summary.json"

btc -stdin decoderawtransaction < "${reveals[$((EXPECTED_REVEALS - 1))]}" \
    | tee "$ARTIFACT_DIR/reveal-tail-decoded.json" | jq -e \
    --argjson size "$EXPECTED_TAIL_SIZE" \
    --argjson weight "$EXPECTED_TAIL_WEIGHT" \
    --argjson vsize "$EXPECTED_TAIL_VSIZE" '
        .size == $size and .weight == $weight and .vsize == $vsize and
        (.vin | length) == 6 and (.vout | length) == 1 and
        all(.vin[0:5][]; (.txinwitness | length) == 1001) and
        (.vin[5].txinwitness | length) == 113 and
        (.vin[5].txinwitness[110] | length) == 128 and
        (.vin[5].txinwitness[111] | length) == 10850 and
        (.vin[5].txinwitness[112] | length) == 66
    ' >/dev/null || die "tail reveal serialization/witness layout changed"
jq '{txid, size, weight, vsize, inputs: (.vin | length), outputs: (.vout | length),
     witness_items_per_input: [.vin[].txinwitness | length]}' \
    "$ARTIFACT_DIR/reveal-tail-decoded.json" \
    > "$ARTIFACT_DIR/reveal-tail-summary.json"

btc -stdin decoderawtransaction < "$BOUND_DIR/finalization.hex" | tee \
    "$ARTIFACT_DIR/finalization-decoded.json" | jq -e \
    --argjson size "$EXPECTED_FINAL_SIZE" \
    --argjson weight "$EXPECTED_FINAL_WEIGHT" \
    --argjson vsize "$EXPECTED_FINAL_VSIZE" '
        .size == $size and .weight == $weight and .vsize == $vsize and
        (.vin | length) == 174 and (.vout | length) == 1 and
        all(.vin[];
            (.txinwitness | length) == 3 and
            (.txinwitness[0] | length) == 128 and
            (.txinwitness[1] | length) == 68 and
            (.txinwitness[2] | length) == 66)
    ' >/dev/null || die "finalization serialization/witness layout changed"
jq '{
        txid, size, weight, vsize,
        inputs: (.vin | length), outputs: (.vout | length),
        witness_items_per_input: 3,
        signature_bytes: (.vin[0].txinwitness[0] | length / 2),
        tapscript_bytes: (.vin[0].txinwitness[1] | length / 2),
        control_block_bytes: (.vin[0].txinwitness[2] | length / 2)
    }' "$ARTIFACT_DIR/finalization-decoded.json" \
    > "$ARTIFACT_DIR/finalization-summary.json"

note "checking rejection while the 44.9-kvB funding parent is unconfirmed"
test_accept_file "${reveals[0]}" \
    > "$ARTIFACT_DIR/reveal-unconfirmed-funding-rejection.json"
assert_cluster_rejection \
    "$ARTIFACT_DIR/reveal-unconfirmed-funding-rejection.json" \
    "reveal with unconfirmed funding parent"

note "confirming funding transaction"
wallet_rpc generatetoaddress 1 "$miner_address" >/dev/null
funding_confirmations="$(wallet_rpc gettransaction "$funding_txid" |
    jq -r '.confirmations')"
[[ "$funding_confirmations" -ge 1 ]] || die "funding transaction did not confirm"
[[ "$(btc getrawmempool | jq 'length')" -eq 0 ]] ||
    die "mempool was not empty after confirming funding"

note "checking the full-sized and tail reveals against confirmed prevouts"
test_accept_file "${reveals[0]}" > "$ARTIFACT_DIR/reveal-full-accept.json"
assert_allowed "$ARTIFACT_DIR/reveal-full-accept.json" "full reveal"
test_accept_file "${reveals[$((EXPECTED_REVEALS - 1))]}" \
    > "$ARTIFACT_DIR/reveal-tail-accept.json"
assert_allowed "$ARTIFACT_DIR/reveal-tail-accept.json" "tail reveal"
full_vsize="$(jq -r '.[0].vsize' "$ARTIFACT_DIR/reveal-full-accept.json")"
tail_vsize="$(jq -r '.[0].vsize' "$ARTIFACT_DIR/reveal-tail-accept.json")"
[[ "$full_vsize" -le $((MAX_STANDARD_WEIGHT / 4)) ]] ||
    die "full reveal exceeds 100,000 vB"
note "Core accepted full=$full_vsize vB and tail=$tail_vsize vB"

note "broadcasting $EXPECTED_REVEALS independent singleton clusters"
: > "$ARTIFACT_DIR/reveal-txids.tsv"
sent=0
for reveal in "${reveals[@]}"; do
    reveal_txid="$(btc -stdin sendrawtransaction < "$reveal")"
    reveal_txid="${reveal_txid//[[:space:]\"]/}"
    printf '%s\t%s\n' "${reveal##*/}" "$reveal_txid" \
        >> "$ARTIFACT_DIR/reveal-txids.tsv"
    sent=$((sent + 1))
    if (( sent % BATCH_SIZE == 0 || sent == EXPECTED_REVEALS )); then
        mempool_count="$(btc getrawmempool | jq 'length')"
        [[ "$mempool_count" -eq "$sent" ]] ||
            die "after $sent reveals, mempool contains $mempool_count transactions"
        note "relay-safe progress batch: $sent/$EXPECTED_REVEALS in mempool"
    fi
done

reveal_total_vsize="$(btc getmempoolinfo | jq -r '.bytes')"
[[ "$reveal_total_vsize" -eq "$EXPECTED_REVEAL_TOTAL_VSIZE" ]] ||
    die "Core reports $reveal_total_vsize reveal vB, expected $EXPECTED_REVEAL_TOTAL_VSIZE"

note "checking that finalization cannot merge 174 unconfirmed parent clusters"
test_accept_file "$BOUND_DIR/finalization.hex" \
    > "$ARTIFACT_DIR/finalization-unconfirmed-rejection.json"
assert_cluster_rejection \
    "$ARTIFACT_DIR/finalization-unconfirmed-rejection.json" \
    "finalization with unconfirmed reveal parents"

note "mining reveal transactions until their mempool is empty"
reveal_blocks=0
previous_count="$EXPECTED_REVEALS"
while (( previous_count > 0 )); do
    wallet_rpc generatetoaddress 1 "$miner_address" >/dev/null
    reveal_blocks=$((reveal_blocks + 1))
    mempool_count="$(btc getrawmempool | jq 'length')"
    (( mempool_count < previous_count )) ||
        die "block $reveal_blocks did not reduce the reveal mempool"
    previous_count="$mempool_count"
    note "reveal mining: block $reveal_blocks, $mempool_count remain"
    (( reveal_blocks <= 30 )) || die "reveals did not clear within 30 blocks"
done
(( reveal_blocks >= 18 )) ||
    die "unexpectedly mined the 17.27-MvB reveal set in fewer than 18 blocks"

note "checking finalization after every reveal parent is confirmed"
test_accept_file "$BOUND_DIR/finalization.hex" \
    > "$ARTIFACT_DIR/finalization-confirmed-accept.json"
assert_allowed "$ARTIFACT_DIR/finalization-confirmed-accept.json" \
    "finalization after reveal confirmation"
final_vsize="$(jq -r '.[0].vsize' \
    "$ARTIFACT_DIR/finalization-confirmed-accept.json")"
final_txid="$(btc -stdin sendrawtransaction < "$BOUND_DIR/finalization.hex")"
final_txid="${final_txid//[[:space:]\"]/}"
wallet_rpc generatetoaddress 1 "$miner_address" >/dev/null
btc gettxout "$final_txid" 0 > "$ARTIFACT_DIR/finalization-utxo.json"
jq -e '.confirmations >= 1' "$ARTIFACT_DIR/finalization-utxo.json" >/dev/null ||
    die "finalization output was not confirmed"

funding_vsize="$(jq -r '.[0].vsize' "$ARTIFACT_DIR/funding-accept.json")"
unconfirmed_reject="$(jq -r '.[0]["reject-reason"]' \
    "$ARTIFACT_DIR/reveal-unconfirmed-funding-rejection.json")"
final_reject="$(jq -r '.[0]["reject-reason"]' \
    "$ARTIFACT_DIR/finalization-unconfirmed-rejection.json")"

jq -n \
    --arg core_version "$core_version" \
    --arg work_dir "$WORK_DIR" \
    --arg funding_txid "$funding_txid" \
    --arg finalization_txid "$final_txid" \
    --arg funding_parent_rejection "$unconfirmed_reject" \
    --arg finalization_rejection "$final_reject" \
    --argjson funding_vsize "$funding_vsize" \
    --argjson full_reveal_vsize "$full_vsize" \
    --argjson tail_reveal_vsize "$tail_vsize" \
    --argjson reveal_total_vsize "$reveal_total_vsize" \
    --argjson reveal_count "$EXPECTED_REVEALS" \
    --argjson reveal_blocks "$reveal_blocks" \
    --argjson finalization_vsize "$final_vsize" \
    --argjson cluster_limit_vb "$CLUSTER_LIMIT_VB" \
    '{
        core_version: $core_version,
        work_dir: $work_dir,
        funding: {txid: $funding_txid, vsize: $funding_vsize},
        unconfirmed_funding_reveal_rejection: $funding_parent_rejection,
        reveals: {
            count: $reveal_count,
            full_vsize: $full_reveal_vsize,
            tail_vsize: $tail_reveal_vsize,
            total_vsize: $reveal_total_vsize,
            confirmation_blocks: $reveal_blocks
        },
        cluster_limit_vb: $cluster_limit_vb,
        unconfirmed_finalization_rejection: $finalization_rejection,
        finalization: {txid: $finalization_txid, vsize: $finalization_vsize, confirmed: true}
    }' | tee "$ARTIFACT_DIR/report.json"

note "PASS: Core accepted every reveal only after funding confirmation"
note "PASS: Core rejected unconfirmed graph joins and accepted finalization after mining"
note "preserved evidence: $WORK_DIR"

btc stop >/dev/null
node_started=0
