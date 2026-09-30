#!/usr/bin/env bash
# Reproduce Bitcoin Core 31.1 strict-policy checks for the exported adaptor-
# signature and Antichain-Winternitz input-publication fixtures.  The harness
# creates a private regtest node and never connects to any external network.

set -Eeuo pipefail
IFS=$'\n\t'

readonly SCRIPT_NAME="${0##*/}"
readonly MAX_STANDARD_WEIGHT=400000
readonly CLUSTER_LIMIT_VB=101000
readonly FUNDING_AMOUNT_BTC=0.00100000

usage() {
    cat <<EOF
Usage: $SCRIPT_NAME SCHEME FIRST_PASS_FIXTURE_DIR

SCHEME is one of:
  adaptor    adaptor_tx_cost / globally optimized reveal packing
  adaptor16  adaptor_tx_cost / 16-bit digit reveal packing
  antichain  antichain_tx_cost / safe ACW(2,16) packing

FIRST_PASS_FIXTURE_DIR must contain funding_outputs.json,
funding_scripts.tsv, and reveal-NNN.hex files exported with the placeholder
all-zero funding txid.  For example:

  WHIR_GC_EXPORT_DIR=DIR cargo test --locked --release -p whir-gc \\
    --test adaptor_tx_cost \\
    adaptor_globally_optimized_reveal_is_2_222_213_vbytes -- --nocapture

The harness creates an ordered funding transaction, checks its exact script
order, and reruns the selected Rust test with WHIR_GC_FUNDING_TXID and
WHIR_GC_EXPORT_DIR to bind every reveal to the real funding transaction.

Environment:
  BITCOIND                  Bitcoin Core 31.1 bitcoind (default: bitcoind)
  BITCOIN_CLI               Matching bitcoin-cli (default: bitcoin-cli)
  BITCOIN_TX                Matching bitcoin-tx (default: bitcoin-tx)
  CARGO                     Cargo executable (default: cargo)
  WHIR_GC_REGTEST_WORKDIR   Empty/new directory; default: new /tmp directory
  WHIR_GC_RPC_PORT          Isolated RPC port; default: derived from the PID
  WHIR_GC_BATCH_SIZE        Progress/check batch size (default: 10)
  WHIR_GC_FUNDING_FEERATE   Funding fee rate in sat/vB (default: 1)

The work directory, bound fixtures, decoded transactions, RPC responses,
node log, and report.json are preserved after both successful and failed runs.
All large raw-transaction RPC arguments pass through bitcoin-cli -stdin.
EOF
}

die() {
    printf 'ERROR: %s\n' "$*" >&2
    exit 1
}

note() {
    printf '[input-fixture-core31:%s] %s\n' "$SCHEME" "$*"
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

[[ $# -eq 2 ]] || {
    usage >&2
    exit 2
}

SCHEME="$1"
case "$SCHEME" in
    adaptor)
        EXPECTED_INPUTS=133
        EXPECTED_REVEALS=23
        EXPECTED_REVEAL_TOTAL_VSIZE=2222213
        EXPECTED_FULL_WEIGHT=399936
        EXPECTED_FULL_VSIZE=99984
        EXPECTED_FULL_INPUTS=6
        EXPECTED_FULL_DIGITS='[998,998,998,998,998,865]'
        EXPECTED_TAIL_WEIGHT=340881
        EXPECTED_TAIL_VSIZE=85221
        EXPECTED_TAIL_INPUTS=5
        EXPECTED_TAIL_DIGITS='[998,998,998,998,998]'
        TEST_TARGET=adaptor_tx_cost
        TEST_NAME=adaptor_globally_optimized_reveal_is_2_222_213_vbytes
        ;;
    adaptor16)
        EXPECTED_INPUTS=66
        EXPECTED_REVEALS=12
        EXPECTED_REVEAL_TOTAL_VSIZE=1111128
        EXPECTED_FULL_WEIGHT=399936
        EXPECTED_FULL_VSIZE=99984
        EXPECTED_FULL_INPUTS=6
        EXPECTED_FULL_DIGITS='[998,998,998,998,998,865]'
        EXPECTED_TAIL_WEIGHT=340881
        EXPECTED_TAIL_VSIZE=85221
        EXPECTED_TAIL_INPUTS=5
        EXPECTED_TAIL_DIGITS='[998,998,998,998,998]'
        TEST_TARGET=adaptor_tx_cost
        TEST_NAME=adaptor_16bit_globally_optimized_reveal_is_1_111_128_vbytes
        ;;
    antichain)
        EXPECTED_INPUTS=784
        EXPECTED_REVEALS=131
        EXPECTED_REVEAL_TOTAL_VSIZE=11848875
        EXPECTED_FULL_WEIGHT=362762
        EXPECTED_FULL_VSIZE=90691
        EXPECTED_FULL_INPUTS=6
        EXPECTED_FULL_DIGITS='[332,332,332,332,332,332]'
        EXPECTED_TAIL_WEIGHT=236178
        EXPECTED_TAIL_VSIZE=59045
        EXPECTED_TAIL_INPUTS=4
        EXPECTED_TAIL_DIGITS='[332,332,332,300]'
        TEST_TARGET=antichain_tx_cost
        TEST_NAME=signed_acw_d332_capacity_and_full_input_packing
        ;;
    *)
        usage >&2
        die "SCHEME must be adaptor, adaptor16, or antichain"
        ;;
esac

readonly SCHEME EXPECTED_INPUTS EXPECTED_REVEALS
readonly EXPECTED_REVEAL_TOTAL_VSIZE
readonly EXPECTED_FULL_WEIGHT EXPECTED_FULL_VSIZE EXPECTED_FULL_INPUTS
readonly EXPECTED_FULL_DIGITS
readonly EXPECTED_TAIL_WEIGHT EXPECTED_TAIL_VSIZE EXPECTED_TAIL_INPUTS
readonly EXPECTED_TAIL_DIGITS TEST_TARGET TEST_NAME

FIRST_PASS_DIR="$(cd "$2" 2>/dev/null && pwd -P)" ||
    die "fixture directory does not exist: $2"
readonly FIRST_PASS_DIR
readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
readonly REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd -P)"
readonly FIRST_OUTPUTS="$FIRST_PASS_DIR/funding_outputs.json"
readonly FIRST_MANIFEST="$FIRST_PASS_DIR/funding_scripts.tsv"

BITCOIND="${BITCOIND:-bitcoind}"
BITCOIN_CLI="${BITCOIN_CLI:-bitcoin-cli}"
BITCOIN_TX="${BITCOIN_TX:-bitcoin-tx}"
CARGO="${CARGO:-cargo}"
BATCH_SIZE="${WHIR_GC_BATCH_SIZE:-10}"
FUNDING_FEERATE="${WHIR_GC_FUNDING_FEERATE:-1}"
RPC_PORT="${WHIR_GC_RPC_PORT:-$((24000 + ($$ % 16000)))}"

[[ "$BATCH_SIZE" =~ ^[1-9][0-9]*$ ]] ||
    die "WHIR_GC_BATCH_SIZE must be positive"
[[ "$FUNDING_FEERATE" =~ ^[0-9]+([.][0-9]+)?$ ]] ||
    die "WHIR_GC_FUNDING_FEERATE must be a non-negative JSON number"
[[ "$RPC_PORT" =~ ^[1-9][0-9]*$ ]] ||
    die "WHIR_GC_RPC_PORT must be a TCP port"
(( RPC_PORT <= 65535 )) || die "WHIR_GC_RPC_PORT must be at most 65535"

need_command "$BITCOIND"
need_command "$BITCOIN_CLI"
need_command "$BITCOIN_TX"
need_command "$CARGO"
need_command jq
need_command awk
need_command cmp
need_command find
need_command sort
need_command tr

core_version="$("$BITCOIND" --version | awk 'NR == 1 { print; exit }')"
[[ "$core_version" == *"v31.1"* ]] ||
    die "Bitcoin Core 31.1 is required, found: $core_version"
tx_tool_version="$("$BITCOIN_TX" --version | awk 'NR == 1 { print; exit }')"
[[ "$tx_tool_version" == *"v31.1"* ]] ||
    die "Bitcoin Core 31.1 bitcoin-tx is required, found: $tx_tool_version"

[[ -s "$FIRST_OUTPUTS" ]] || die "missing $FIRST_OUTPUTS"
[[ -s "$FIRST_MANIFEST" ]] || die "missing $FIRST_MANIFEST"
jq -e \
    --argjson count "$EXPECTED_INPUTS" \
    --argjson amount "$FUNDING_AMOUNT_BTC" '
        type == "array" and
        length == $count and
        all(.[];
            type == "object" and length == 1 and
            all(.[]; . == $amount))
    ' "$FIRST_OUTPUTS" >/dev/null ||
    die "unexpected funding_outputs.json schema/count/value"

awk -F '\t' -v count="$EXPECTED_INPUTS" '
    NF != 3 { exit 1 }
    $1 != NR - 1 { exit 1 }
    $2 !~ /^bcrt1p/ { exit 1 }
    $3 !~ /^[[:xdigit:]]+$/ { exit 1 }
    length($3) != 68 || substr($3, 1, 4) != "5120" { exit 1 }
    END { if (NR != count) exit 1 }
' "$FIRST_MANIFEST" || die "unexpected funding_scripts.tsv schema/count/order"

shopt -s nullglob
first_reveals=("$FIRST_PASS_DIR"/reveal-*.hex)
shopt -u nullglob
[[ ${#first_reveals[@]} -eq $EXPECTED_REVEALS ]] ||
    die "expected $EXPECTED_REVEALS first-pass reveals, found ${#first_reveals[@]}"

if [[ -n "${WHIR_GC_REGTEST_WORKDIR:-}" ]]; then
    WORK_DIR="$WHIR_GC_REGTEST_WORKDIR"
    mkdir -p "$WORK_DIR"
    [[ -z "$(find "$WORK_DIR" -mindepth 1 -maxdepth 1 -print -quit)" ]] ||
        die "WHIR_GC_REGTEST_WORKDIR must be empty: $WORK_DIR"
    WORK_DIR="$(cd "$WORK_DIR" && pwd -P)"
else
    WORK_DIR="$(mktemp -d "${TMPDIR:-/tmp}/input-${SCHEME}-core31-regtest.XXXXXX")"
fi

readonly WORK_DIR
readonly DATADIR="$WORK_DIR/node"
readonly BOUND_DIR="$WORK_DIR/bound-fixtures"
readonly ARTIFACT_DIR="$WORK_DIR/artifacts"
readonly WALLET_NAME="input-${SCHEME}-policy-harness"
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

decode_and_validate_reveal() {
    local path="$1"
    local label="$2"
    local expected_weight="$3"
    local expected_vsize="$4"
    local expected_inputs="$5"
    local expected_digits="$6"
    local first_vout="$7"
    local decoded="$ARTIFACT_DIR/reveal-${label}-decoded.json"
    local summary="$ARTIFACT_DIR/reveal-${label}-summary.json"

    btc -stdin decoderawtransaction < "$path" > "$decoded"
    jq -e \
        --arg scheme "$SCHEME" \
        --arg funding_txid "$funding_txid" \
        --argjson weight "$expected_weight" \
        --argjson vsize "$expected_vsize" \
        --argjson input_count "$expected_inputs" \
        --argjson digits "$expected_digits" \
        --argjson first_vout "$first_vout" '
        def valid_witness($w; $d):
            if ($scheme | startswith("adaptor")) then
                ($w | length) == ($d + 2) and
                all($w[0:$d][]; type == "string" and length == 128) and
                ($w[$d] | length) == (2 * (3 * $d + 31)) and
                ($w[$d + 1] | length) == 66
            else
                ($w | length) == (3 * $d + 3) and
                all(range(0; $d);
                    . as $j |
                    ($w[3 * $j] | length) == 40 and
                    ($w[3 * $j + 1] | length) == 40 and
                    ($w[3 * $j + 2] | length) == 2) and
                ($w[3 * $d] | length) == 128 and
                ($w[3 * $d + 1] | length) == (2 * (137 * $d + 35)) and
                ($w[3 * $d + 2] | length) == 66
            end;
        . as $tx |
        .version == 2 and .locktime == 0 and
        .weight == $weight and .vsize == $vsize and
        (.vin | length) == $input_count and
        ($digits | length) == $input_count and
        (.vout | length) == 2 and
        all(.vout[];
            .value == 0.00001000 and
            .scriptPubKey.type == "witness_v1_taproot" and
            (.scriptPubKey.hex | length) == 68) and
        all(range(0; $input_count);
            . as $i |
            $tx.vin[$i].txid == $funding_txid and
            $tx.vin[$i].vout == ($first_vout + $i) and
            $tx.vin[$i].scriptSig.hex == "" and
            $tx.vin[$i].sequence == 4294967295 and
            valid_witness($tx.vin[$i].txinwitness; $digits[$i]))
    ' "$decoded" >/dev/null ||
        die "$label reveal serialization/witness structure changed"

    jq --arg scheme "$SCHEME" --argjson digits "$expected_digits" '{
        scheme: $scheme,
        txid,
        size,
        weight,
        vsize,
        inputs: (.vin | length),
        outputs: (.vout | length),
        funding_vouts: [.vin[].vout],
        digits_per_input: $digits,
        witness_items_per_input: [.vin[].txinwitness | length],
        tapscript_bytes_per_input: [
            range(0; (.vin | length)) as $i |
            if ($scheme | startswith("adaptor")) then
                (.vin[$i].txinwitness[$digits[$i]] | length / 2)
            else
                (.vin[$i].txinwitness[3 * $digits[$i] + 1] | length / 2)
            end
        ],
        control_block_bytes_per_input: [.vin[].txinwitness[-1] | length / 2]
    }' "$decoded" > "$summary"
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
note "mining 101 blocks to mature private regtest coinbase outputs"
wallet_rpc generatetoaddress 101 "$miner_address" >/dev/null

readonly FUNDING_UNSIGNED="$ARTIFACT_DIR/funding-unsigned.hex"
readonly FUNDING_FUNDED_JSON="$ARTIFACT_DIR/funding-funded.json"
readonly FUNDING_FUNDED_HEX="$ARTIFACT_DIR/funding-funded.hex"
readonly FUNDING_SIGNED_JSON="$ARTIFACT_DIR/funding-signed.json"
readonly FUNDING_SIGNED_HEX="$ARTIFACT_DIR/funding-signed.hex"
readonly FUNDING_DECODED="$ARTIFACT_DIR/funding-decoded.json"

note "constructing ordered $EXPECTED_INPUTS-output funding transaction"
# createrawtransaction rejects duplicate address keys even in its ordered-array
# form.  Both schemes legitimately reuse identical leaves, especially the
# adaptor fixture, so use Core's bitcoin-tx constructor.  Repeated outaddr
# commands preserve every duplicate and the manifest order exactly.
funding_commands=(-chain=regtest -create)
while IFS=$'\t' read -r output_index output_address output_script; do
    funding_commands+=("outaddr=${FUNDING_AMOUNT_BTC}:${output_address}")
done < "$FIRST_MANIFEST"
[[ ${#funding_commands[@]} -eq $((EXPECTED_INPUTS + 2)) ]] ||
    die "failed to construct one bitcoin-tx output command per manifest row"
"$BITCOIN_TX" "${funding_commands[@]}" > "$FUNDING_UNSIGNED"
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
jq -e \
    --argjson count "$EXPECTED_INPUTS" \
    --argjson amount "$FUNDING_AMOUNT_BTC" '
        (.vout | length) == ($count + 1) and
        .vout[$count].n == $count and
        all(.vout[0:$count][];
            .value == $amount and
            .scriptPubKey.type == "witness_v1_taproot" and
            (.scriptPubKey.hex | length) == 68)
    ' "$FUNDING_DECODED" >/dev/null ||
    die "unexpected funding output value/type/change count"

test_accept_file "$FUNDING_SIGNED_HEX" > "$ARTIFACT_DIR/funding-accept.json"
assert_allowed "$ARTIFACT_DIR/funding-accept.json" "funding transaction"
funding_txid="$(btc -stdin sendrawtransaction < "$FUNDING_SIGNED_HEX")"
funding_txid="${funding_txid//[[:space:]\"]/}"
decoded_funding_txid="$(jq -r '.txid' "$FUNDING_DECODED")"
[[ "$funding_txid" == "$decoded_funding_txid" ]] ||
    die "submitted and decoded funding txids disagree"
btc getmempoolentry "$funding_txid" > "$ARTIFACT_DIR/funding-mempool-entry.json"
note "unconfirmed funding txid: $funding_txid"

note "regenerating signed $SCHEME reveals against the real funding txid"
(
    cd "$REPO_ROOT"
    WHIR_GC_FUNDING_TXID="$funding_txid" \
    WHIR_GC_EXPORT_DIR="$BOUND_DIR" \
    RUST_TEST_THREADS=1 \
        "$CARGO" test --locked -p whir-gc --release \
        --test "$TEST_TARGET" "$TEST_NAME" -- --exact --nocapture
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
    validate_hex_file "${reveals[$i]}"
done

decode_and_validate_reveal \
    "${reveals[0]}" full \
    "$EXPECTED_FULL_WEIGHT" "$EXPECTED_FULL_VSIZE" \
    "$EXPECTED_FULL_INPUTS" "$EXPECTED_FULL_DIGITS" 0
decode_and_validate_reveal \
    "${reveals[$((EXPECTED_REVEALS - 1))]}" tail \
    "$EXPECTED_TAIL_WEIGHT" "$EXPECTED_TAIL_VSIZE" \
    "$EXPECTED_TAIL_INPUTS" "$EXPECTED_TAIL_DIGITS" \
    "$((EXPECTED_INPUTS - EXPECTED_TAIL_INPUTS))"

note "checking rejection while the funding parent is unconfirmed"
test_accept_file "${reveals[0]}" \
    > "$ARTIFACT_DIR/reveal-unconfirmed-funding-rejection.json"
assert_cluster_rejection \
    "$ARTIFACT_DIR/reveal-unconfirmed-funding-rejection.json" \
    "reveal with unconfirmed funding parent"

note "confirming funding transaction"
wallet_rpc generatetoaddress 1 "$miner_address" >/dev/null
funding_confirmations="$(wallet_rpc gettransaction "$funding_txid" |
    jq -r '.confirmations')"
[[ "$funding_confirmations" -ge 1 ]] ||
    die "funding transaction did not confirm"
[[ "$(btc getrawmempool | jq 'length')" -eq 0 ]] ||
    die "mempool was not empty after confirming funding"

note "checking representative full and tail reveals against confirmed prevouts"
test_accept_file "${reveals[0]}" > "$ARTIFACT_DIR/reveal-full-accept.json"
assert_allowed "$ARTIFACT_DIR/reveal-full-accept.json" "full reveal"
test_accept_file "${reveals[$((EXPECTED_REVEALS - 1))]}" \
    > "$ARTIFACT_DIR/reveal-tail-accept.json"
assert_allowed "$ARTIFACT_DIR/reveal-tail-accept.json" "tail reveal"
full_vsize="$(jq -r '.[0].vsize' "$ARTIFACT_DIR/reveal-full-accept.json")"
tail_vsize="$(jq -r '.[0].vsize' "$ARTIFACT_DIR/reveal-tail-accept.json")"
[[ "$full_vsize" -eq "$EXPECTED_FULL_VSIZE" ]] ||
    die "Core reports full reveal $full_vsize vB, expected $EXPECTED_FULL_VSIZE"
[[ "$tail_vsize" -eq "$EXPECTED_TAIL_VSIZE" ]] ||
    die "Core reports tail reveal $tail_vsize vB, expected $EXPECTED_TAIL_VSIZE"
[[ "$EXPECTED_FULL_WEIGHT" -le "$MAX_STANDARD_WEIGHT" ]] ||
    die "configured full reveal exceeds standard transaction weight"
note "Core accepted full=$full_vsize vB and tail=$tail_vsize vB"

note "submitting $EXPECTED_REVEALS independent singleton clusters"
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
        note "mempool-admission progress batch: $sent/$EXPECTED_REVEALS"
    fi
done

reveal_total_vsize="$(btc getmempoolinfo | jq -r '.bytes')"
[[ "$reveal_total_vsize" -eq "$EXPECTED_REVEAL_TOTAL_VSIZE" ]] ||
    die "Core reports $reveal_total_vsize reveal vB, expected $EXPECTED_REVEAL_TOTAL_VSIZE"

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

funding_vsize="$(jq -r '.[0].vsize' "$ARTIFACT_DIR/funding-accept.json")"
funding_serialized_outputs="$(jq -r '.vout | length' "$FUNDING_DECODED")"
unconfirmed_reject="$(jq -r '.[0]["reject-reason"]' \
    "$ARTIFACT_DIR/reveal-unconfirmed-funding-rejection.json")"
full_size="$(jq -r '.size' "$ARTIFACT_DIR/reveal-full-decoded.json")"
tail_size="$(jq -r '.size' "$ARTIFACT_DIR/reveal-tail-decoded.json")"

jq -n \
    --arg scheme "$SCHEME" \
    --arg test_target "$TEST_TARGET" \
    --arg test_name "$TEST_NAME" \
    --arg core_version "$core_version" \
    --arg work_dir "$WORK_DIR" \
    --arg funding_txid "$funding_txid" \
    --arg funding_parent_rejection "$unconfirmed_reject" \
    --argjson funding_vsize "$funding_vsize" \
    --argjson funding_protocol_outputs "$EXPECTED_INPUTS" \
    --argjson funding_serialized_outputs "$funding_serialized_outputs" \
    --argjson funding_amount_btc "$FUNDING_AMOUNT_BTC" \
    --argjson full_size "$full_size" \
    --argjson full_weight "$EXPECTED_FULL_WEIGHT" \
    --argjson full_vsize "$full_vsize" \
    --argjson full_inputs "$EXPECTED_FULL_INPUTS" \
    --argjson tail_size "$tail_size" \
    --argjson tail_weight "$EXPECTED_TAIL_WEIGHT" \
    --argjson tail_vsize "$tail_vsize" \
    --argjson tail_inputs "$EXPECTED_TAIL_INPUTS" \
    --argjson reveal_total_vsize "$reveal_total_vsize" \
    --argjson reveal_count "$EXPECTED_REVEALS" \
    --argjson reveal_blocks "$reveal_blocks" \
    --argjson cluster_limit_vb "$CLUSTER_LIMIT_VB" '
    {
        scheme: $scheme,
        fixture_test: {target: $test_target, name: $test_name},
        core_version: $core_version,
        strict_standard_policy: true,
        work_dir: $work_dir,
        funding: {
            txid: $funding_txid,
            protocol_outputs: $funding_protocol_outputs,
            serialized_outputs: $funding_serialized_outputs,
            wallet_change_outputs: ($funding_serialized_outputs - $funding_protocol_outputs),
            amount_btc_per_protocol_output: $funding_amount_btc,
            vsize: $funding_vsize,
            confirmed_before_reveals: true
        },
        unconfirmed_funding_reveal_rejection: $funding_parent_rejection,
        cluster_limit_vb: $cluster_limit_vb,
        reveals: {
            count: $reveal_count,
            full: {
                inputs: $full_inputs,
                size: $full_size,
                weight: $full_weight,
                vsize: $full_vsize
            },
            tail: {
                inputs: $tail_inputs,
                size: $tail_size,
                weight: $tail_weight,
                vsize: $tail_vsize
            },
            total_mempool_vsize: $reveal_total_vsize,
            confirmation_blocks: $reveal_blocks,
            all_confirmed: true
        }
    }' | tee "$ARTIFACT_DIR/report.json"

note "PASS: decoded full/tail structures and exact weight/vsize match"
note "PASS: unconfirmed funding-to-reveal edge was rejected as too-large-cluster"
note "PASS: all $EXPECTED_REVEALS reveals entered strict-policy mempool after funding confirmation"
note "PASS: aggregate mempool vsize is exactly $EXPECTED_REVEAL_TOTAL_VSIZE"
note "preserved evidence: $WORK_DIR"

btc stop >/dev/null
node_started=0
