# Measurement archive

This directory contains the raw outputs and helper source used for the paper's
measurements. It is tracked so that the numeric claims can be audited separately
from the prose. `Cargo.lock` pins the Rust dependencies used by the current
reproduction commands.

The paper studies a measured hash-based verifier and a conditional Bitcoin
integration. The logs do not constitute an implementation of multi-copy
hash-key soldering or of the complete pre-signed transaction graph.

## Integrity

`SHA256SUMS` covers every archived log, helper source file and historical
snapshot in this directory. It intentionally excludes `README.md` and
`SHA256SUMS` itself. Verify it from the repository root with:

```sh
cd paper/data
sha256sum -c SHA256SUMS
```

When replacing a log, record the exact command and environment here, then
recompute its entry in `SHA256SUMS`. Do not silently edit benchmark output.

## Running the heavy tests

Commands below are written relative to the repository root and show the Cargo
test that produces the substantive output. The full-verifier tests should be
run under the memory and CPU cap documented in `whir-gc/README.md`. Add
`/usr/bin/time -v` when peak RSS and wall-clock output are required. Runtime
depends strongly on proof-of-work grinding and machine load.

Several files combine output from multiple invocations. Redirect both stdout
and stderr when capturing a replacement log because Rust tests print the
measurement lines on stderr.

## Artifact map

### Full-verifier scale and profile

- `run-2_18-full-verifier.txt` supports the 2^18 row in `tab:main`, the
  phase breakdown in `tab:profile`, the abstract's 94.1M-gate result and the
  whole-process peak-RSS statement. Reproduce the circuit run with:

  ```sh
  WHIR_GC_LOG_HEIGHT=18 RAYON_NUM_THREADS=8 cargo test --locked -p whir-gc --release \
    --test keccak_stark full_verifier_circuit_on_the_2_18_schedule -- \
    --ignored --nocapture
  ```

- `run-2_20-full-verifier.txt` supports the 2^20 row in `tab:main`. Use the
  same command with `WHIR_GC_LOG_HEIGHT=20`. The archived run used the larger
  machine described in the paper.

- `run-table4-rerun.txt` contains the 2^5, 2^8, 2^12 and 2^16 rows now
  reported in `tab:main`; the historical filename is retained for checksum
  stability. Run the full-verifier command above once for each
  `WHIR_GC_LOG_HEIGHT` in `5`, `8`, `12` and `16`.

### Ablation and comparison

- `run-ablation.txt` supports `tab:ablation`. The stored and streamed 2^5
  rows can be reproduced with:

  ```sh
  WHIR_GC_LOG_HEIGHT=5 cargo test --locked -p whir-gc --release --test keccak_stark \
    stored_build_of_the_full_verifier -- --ignored --nocapture
  WHIR_GC_LOG_HEIGHT=5 cargo test --locked -p whir-gc --release --test keccak_stark \
    full_verifier_circuit_on_the_2_18_schedule -- --ignored --nocapture
  ```

  The old two-AND Blake3-adder rows are historical ablation output. That
  implementation is not selectable in the current tree, so those rows cannot
  be regenerated without restoring the old adder. The archive preserves the
  evidence rather than claiming a nonexistent current command.

- `run-bitvm-gc-streamed.txt` supports the measured DV-Pari comparison row in
  `tab:compare` (481,628,790 non-free gates, 1,919,770,238 wires and
  15,578,968 live wires). It was captured from streaming tests in GOAT's
  `bitvm-gc`, which this workspace pins at commit
  `10083d4a63eb08a344dc40ee84bc11394b218a89`. Dependency-crate tests are not
  exposed as targets of this workspace; reproduce them in a checkout of that
  commit. The log preserves the upstream test names and the original temporary
  log paths. The exact wrapper command was not retained.

### Input-size studies

- `run-input-bits-sweep.txt` supports `tab:inputs`: the measured input counts,
  the component split and the 845,952-bit tuned configuration. Reproduce with:

  ```sh
  cargo test --locked -p whir-gc --release --test keccak_stark \
    input_bits_of_whir_configurations -- --ignored --nocapture
  ```

- `run-input-bits-candidates.txt` is the broader width, trace-height, security
  target and digest-width sweep used for the narrow-AIR and recursion
  discussion. It is not a second measurement of `tab:inputs`. Reproduce with:

  ```sh
  cargo test --locked -p whir-gc --release --test keccak_stark \
    input_bits_of_candidate_statements -- --ignored --nocapture
  ```

- `run-equal-area-input.txt` supports the equal-committed-cell narrow-statement
  models. It retains at least the $1{,}625\times2^{18}$ source cell count and
  makes explicit that these are schedule counts, not generated proofs:

  ```sh
  cargo test --locked -p whir-gc --release --test keccak_stark \
    input_bits_of_equal_area_narrow_statements -- --ignored --nocapture
  ```

- `run-merkle-frontier-sim.txt` supports the expected 0.4498% data-only saving
  from retaining Plonky3's pruned frontier. It uses one million deterministic
  trials and the repository's actual stratified-query assembly routine:

  ```sh
  cargo test --locked -p whir-gc --release --test merkle_frontier_sim -- \
    --ignored --nocapture
  ```

### Garble/evaluate and executed dispute components

- `run-garble-then-evaluate.txt` supports the claim that a circuit garbled
  before a proof exists evaluates to the accept label for the real proof and
  the reject label for a changed proof. Run the following once with
  `WHIR_GC_LOG_HEIGHT=5` and once with `WHIR_GC_LOG_HEIGHT=8`:

  ```sh
  WHIR_GC_LOG_HEIGHT=5 cargo test --locked -p whir-gc --release --test keccak_stark \
    garbled_before_the_proof_evaluates_real_proofs -- --ignored --nocapture
  ```

- `run-stark-dispute.txt` supports the executed 2^5 Lamport Assert/evaluation/
  Disprove component test. It does not include transaction signatures,
  timelocks, cut-and-choose, multi-copy soldering or a serialized transaction
  graph. Reproduce with:

  ```sh
  WHIR_GC_LOG_HEIGHT=5 cargo test --locked -p whir-gc --release --test keccak_stark \
    dispute_over_the_stark_verifier_in_script -- --ignored --nocapture
  ```

### Input-authentication costs

All current transaction-bound rows use the following on-chain accounting
boundary.  Signatures, complete tapscripts, Taproot control blocks, input
shells, witness framing and serialized outputs are included; the headline
aggregate remains the reveal set, while funding and any available
finalization are reported separately.

| Scheme | Published/authentication witness per input | Tapscript and control | Reveal transaction shell |
|---|---|---|---|
| Schnorr adaptor | One 64-byte completed `SIGHASH_DEFAULT` signature per eight-bit digit; it both carries the digit and binds the transaction | `3d+31`-byte script for `d` digits; 33-byte depth-zero control block | Full version-2 inputs and two P2TR outputs |
| Wider adaptor encoding experiment | The same one completed signature per chosen digit, swept at 10/11/12/16 bits | Same per-digit script shape; the exponentially larger off-chain choice table and digit-to-binary-label mapping are not implemented | Exact serialized shapes for all widths; the 16-bit row also has real signatures and Core replay |
| Safe ACW `(2,16)` | Per four-bit digit: two 20-byte chain values plus one one-byte nonzero coordinate; one additional 64-byte transaction signature per input | `137d+35`-byte script; 33-byte depth-zero control block | Full version-2 inputs and two P2TR outputs |
| Signed Lamport | One 16-byte preimage per bit; one additional 64-byte transaction signature per input | `49d+35`-byte script; 33-byte depth-zero control block | Full version-2 inputs and one P2TR output; a separate signed finalization is also measured |

- `run-adaptor-tx-cost.txt` records the repaired transaction-bound
  Schnorr-adaptor fixture. Bitcoin Core exposed an earlier false positive: the
  fixture and pinned `bitvm_scriptexec` both used byte offsets for
  `OP_CODESEPARATOR`, whereas BIP342 requires opcode positions. The current
  fixture uses `0xffffffff` for the first check and `3*i` thereafter, verifies
  every completed signature directly, and is independently executed by Core
  through the harness below. The log covers the 128-digit golden, exact
  998-signature stack boundary, negative signature/order/transaction/control
  tests and both eight-bit packings. It predates the wider-digit tests and does
  not contain their output. Reproduce the current full target remotely with:

  ```sh
  cargo test --locked --release -p whir-gc --test adaptor_tx_cost -- --nocapture
  ```

- `run-adaptor-wider-tx-cost.txt` records the current-source targeted rerun of
  the exact 8/10/11/12/16-bit serialized sweep for all 1,041,024 bits and the
  full 16-bit fixture with real signatures. The wider experiment does not
  construct the exponential choice tables or a digit-to-binary-label selector;
  its separate strict-policy Core replay is summarized below.

- `run-antichain-tx-cost.txt` records the transaction-bound safe
  Antichain-Winternitz `(2,16)` fixture at the pinned upstream revision. It
  executes genuine openings and forgery negatives, adds a real transaction
  signature, checks the D=332/333 stack boundary, and serializes the full
  all-nonzero packing. Reproduce with:

  ```sh
  cargo test --locked --release -p whir-gc --test antichain_tx_cost -- --nocapture
  ```

- `run-pq-selector-cost.txt` records the serialization-only hash-based
  replacement for the per-digit Schnorr adaptor: a pair-complement WOTS
  selector over 4-bit digits, batched per transaction under a draft BIP360
  P2MR output, a 0xC2 leaf, one SHRINCS-shaped authorization per transaction
  and a hypothetical `OP_CHECKBATCHPAIRSELECT`. The n=16 fixture is
  2,133,778 vB (2,122,693 vB with canonical 11-record blobs) over 23
  transactions; the n=24 fixture is 3,172,934 vB over 33 transactions. The
  payload bytes of the n=16 variant equal the adaptor's 130,128 x 65 B
  exactly. Nothing in it is executable by Bitcoin Core, n=16 is not a
  post-quantum parameter set, and the digit-to-label delivery layer is not
  constructed. Reproduce with:

  ```sh
  cargo test --locked --release -p whir-gc --test pq_selector_cost --test pq_selector_n24_cost -- --nocapture
  ```

- `run-input-fixtures-core31-regtest.txt` records strict Bitcoin Core 31.1
  validation of the repaired adaptor and safe ACW fixtures. The generic
  `run-input-fixture-core31-regtest.sh` harness accepts `adaptor`, `adaptor16`
  or `antichain` plus a first-pass export directory. It preserves repeated
  funding scripts in exact order, regenerates signatures against the real
  funding txid, decodes and checks full/tail witness structures, requires the
  unconfirmed funding edge to fail with `too-large-cluster`, and then confirms
  funding before submitting and mining every reveal.

  The repaired adaptor run measured a 5,841-vB funding transaction and 23
  reveals totaling exactly 2,222,213 vB; its full/tail reveals were
  399,936/340,881 WU and all reveals mined in three blocks. The ACW run
  measured 33,836-vB funding and 131 reveals totaling exactly 11,848,875 vB;
  its full/tail reveals were 362,762/236,178 WU and all reveals mined in 12
  blocks. Preserved remote evidence paths and the pre-fix adaptor rejection are
  listed in the archived log.

  `run-adaptor16-core31-regtest.json` is the machine-readable strict-policy
  report for the wider encoding experiment. Its funding transaction has 66
  protocol P2TR outputs plus one wallet-change output, is 2,960 vB, and its
  twelve signed reveals total 1,111,128 vB, for a bounded
  total of 1,114,088 vB in thirteen transactions. A 99,984-vB full reveal plus
  the unconfirmed funding parent exceeded Core's 101-kvB cluster limit; after
  funding confirmation all reveals were accepted and mined in two blocks.

  Start with a placeholder-txid export, then let the harness create and bind
  the real funding transaction:

  ```sh
  fixture_dir="$(mktemp -d)"
  WHIR_GC_EXPORT_DIR="$fixture_dir" \
    cargo test --locked --release -p whir-gc --test adaptor_tx_cost \
      adaptor_globally_optimized_reveal_is_2_222_213_vbytes -- --exact --nocapture

  BITCOIND=/path/to/bitcoin-core-31.1/bin/bitcoind \
  BITCOIN_CLI=/path/to/bitcoin-core-31.1/bin/bitcoin-cli \
  BITCOIN_TX=/path/to/bitcoin-core-31.1/bin/bitcoin-tx \
    paper/data/run-input-fixture-core31-regtest.sh adaptor "$fixture_dir"
  ```

  For the remotely verified 16-bit transaction shape, replace the test name
  and harness scheme as follows:

  ```sh
  fixture_dir="$(mktemp -d)"
  WHIR_GC_EXPORT_DIR="$fixture_dir" \
    cargo test --locked --release -p whir-gc --test adaptor_tx_cost \
      adaptor_16bit_globally_optimized_reveal_is_1_111_128_vbytes \
      -- --exact --nocapture

  BITCOIND=/path/to/bitcoin-core-31.1/bin/bitcoind \
  BITCOIN_CLI=/path/to/bitcoin-core-31.1/bin/bitcoin-cli \
  BITCOIN_TX=/path/to/bitcoin-core-31.1/bin/bitcoin-tx \
    paper/data/run-input-fixture-core31-regtest.sh adaptor16 "$fixture_dir"
  ```

- `whir-gc/tests/esspi_envelope_cost.rs` and
  `run-esspi-envelope-core31-regtest.sh` measure authenticated bulk-data
  transport through an ESSPI-style P2TR envelope. The 130,128-byte payload is
  committed by a 130,917-byte tapscript and authorized by a real 64-byte
  `SIGHASH_DEFAULT` signature. `run-esspi-envelope-core31-regtest.json` records
  strict Core 31.1 acceptance of the 154-vB wallet-signed commit and
  32,850-vB reveal, totaling 33,004 vB in two transactions confirmed together
  in one block. This is not a complete ESSPI or GC Assert: it omits the DA-DAG,
  secondary BitVMX instance, fraud/timeout/settlement branches and any mapping
  from raw proof bytes to selected garbled input labels.

  ```sh
  fixture_dir="$(mktemp -d)"
  ESSPI_EXPORT_DIR="$fixture_dir" \
    cargo test --locked --release -p whir-gc --test esspi_envelope_cost \
      esspi_p2tr_envelope_exact_serialization -- --exact --nocapture

  BITCOIND=/path/to/bitcoin-core-31.1/bin/bitcoind \
  BITCOIN_CLI=/path/to/bitcoin-core-31.1/bin/bitcoin-cli \
  BITCOIN_TX=/path/to/bitcoin-core-31.1/bin/bitcoin-tx \
    bash paper/data/run-esspi-envelope-core31-regtest.sh "$fixture_dir"
  ```

- `whir-gc/tests/disprove_pointlock_cost.rs` compares the actual 16-byte
  false-label hashlock with a false-label-derived Taproot key-path pointlock;
  both outputs retain the same timeout sibling. The strict-policy report
  `run-disprove-pointlock-core31-regtest.json` records 386 WU / 97 vB for the
  hashlock spend and 332 WU / 83 vB for the pointlock, a 54-WU / 14-vB saving.
  The shared 197-vB comparison funding transaction is not a per-Disprove cost,
  and the timeout spend itself is not executed by this fixture.

  ```sh
  fixture_dir="$(mktemp -d)"
  DISPROVE_EXPORT_DIR="$fixture_dir" \
    cargo test --locked --release -p whir-gc --test disprove_pointlock_cost \
      disprove_hashlock_vs_pointlock_exact_serialization -- --exact --nocapture

  BITCOIND=/path/to/bitcoin-core-31.1/bin/bitcoind \
  BITCOIN_CLI=/path/to/bitcoin-core-31.1/bin/bitcoin-cli \
  BITCOIN_TX=/path/to/bitcoin-core-31.1/bin/bitcoin-tx \
    bash paper/data/run-disprove-pointlock-core31-regtest.sh "$fixture_dir"
  ```

- `run-raw-input-cost.txt` supports the 33,299-vB unauthenticated transport
  baseline. The test serializes the two-input transaction, verifies both
  Taproot control-block commitments, and executes both leaf scripts. It uses
  synthetic outpoints and does not call Bitcoin Core's `testmempoolaccept`:

  ```sh
  cargo test --locked -p whir-gc --test raw_input_cost -- --nocapture
  ```

- `lamport_cost.rs` is the helper source and `run-lamport-cost.txt` its output.
  They measure the 49-byte-per-bit authentication script and 17-byte-per-bit
  preimage witness. The paper adds a modeled 204-WU depth-0 one-leaf P2TR input
  envelope, giving the historical precursor estimate of 66.2 WU, or 16.55 vB,
  per bit. The current `tab:onchain` Lamport row instead uses the signed full
  transaction fixture below. This helper does not serialize transaction-global
  fields, outputs or a dispute graph. The
  helper uses `poseidon2`'s development dependencies. To
  rerun it without changing a tracked source file, temporarily copy it into
  that crate's integration-test directory:

  ```sh
  cp paper/data/lamport_cost.rs poseidon2/tests/paper_lamport_cost.rs
  cargo test --locked -p poseidon2 --release --test paper_lamport_cost -- --nocapture
  ```

  Remove the temporary `poseidon2/tests/paper_lamport_cost.rs` afterwards.

- `whir-gc/tests/lamport_tx_cost.rs` is the transaction-bound fixture for all
  1,041,024 authenticated input bits. It serializes the 64-byte
  SIGHASH_DEFAULT authorization signature, Lamport preimages, complete
  tapscript, control block, input and output fields for every spend. Its 174
  reveal transactions total 17,265,635 vB; a full six-input reveal is
  397,246 WU (99,312 vB), and the signed 174-input finalization transaction is
  52,240 WU (13,060 vB).

  `run-lamport-core31-regtest.txt` records the completed strict-policy run on
  Bitcoin Core 31.1, including exact funding, reveal and finalization sizes,
  both `too-large-cluster` rejections and the 18-block reveal schedule.

  `run-lamport-core31-regtest.sh` turns that deterministic fixture into an
  end-to-end Bitcoin Core 31.1 regtest check. It explicitly enables standard
  transaction policy on regtest, creates the 1,044 funding outputs in their
  committed order, regenerates the signed fixtures against the real funding
  txid, and passes large transaction hex to RPC through stdin. It checks the
  expected cluster rejection before funding confirmation, standard-policy
  acceptance of the full and tail reveals after confirmation, mempool admission of all
  174 independent reveals, rejection of their unconfirmed 174-parent join,
  and acceptance and mining of the finalization after the reveals confirm.
  Start from a first-pass export; the harness performs the txid-bound second
  pass itself:

  ```sh
  fixture_dir="$(mktemp -d)"
  WHIR_GC_EXPORT_DIR="$fixture_dir" \
    cargo test --locked -p whir-gc --release --test lamport_tx_cost \
      serialized_lamport_assert_component_for_measured_verifier -- --nocapture

  BITCOIND=/path/to/bitcoin-core-31.1/bin/bitcoind \
  BITCOIN_CLI=/path/to/bitcoin-core-31.1/bin/bitcoin-cli \
    paper/data/run-lamport-core31-regtest.sh "$fixture_dir"
  ```

- `run-winternitz-cost.txt` is exploratory output from earlier executable
  Winternitz cost models, including the response-on-demand experiment:

  ```sh
  cargo test --locked -p whir-gc --release --test winternitz_cost -- --nocapture
  ```

  These measurements are not the safe Antichain `(2,16)` row in
  `tab:onchain`. The current row comes from
  `whir-gc/tests/antichain_tx_cost.rs` and includes genuine upstream openings,
  a 64-byte transaction-binding signature per input, every authentication
  script and control block, input shells, and two P2TR outputs per transaction.
  Its all-nonzero full packing measures 11,848,875 vB, or 11.38 vB/bit. The
  cited paper's 11.31-vB/bit number remains useful provenance for the marginal
  script-and-witness construction, but it cancels fixed transaction overhead
  and omits the transaction-binding authorization added by our safe fixture.
  The response-on-demand experiment is not merely incomplete: its 520-byte
  initial witness arguments violate Core's 80-byte standard-policy limit, its
  drop-only script has no transaction authorization, and adding `CHECKSIG`
  would still not bind ordinary witness arguments. It is retained only as a
  historical capacity model and must not be reported as a safe Assert.

### Ziren compressed proof as the statement

- `run-ziren-compressed-proof-prove.txt`, `run-ziren-compressed-proof-census.txt`
  and `run-ziren-compress-machine-census.txt` measure what the garbled verifier
  would have to take if the statement is a Ziren compressed (recursion) proof
  rather than the Keccak AIR. The proof is of `examples/fibonacci` (n = 500) at
  Ziren `da7e1f2c`, CPU prover, 4 core shards and 6 recursion shards, 3:33 wall
  on 8 cores, 20.7 GB peak. Its verifier is Ziren's compress machine: KoalaBear,
  Poseidon2 Merkle trees, LogUp-GKR, zerocheck and a jagged-over-WHIR opening,
  which is a different verifier from this repository's binary-field Blake3 WHIR
  verifier. The census walks the serialized proof: 191,215 base field elements,
  5,927,665 bits at 31 bits each, of which the WHIR query openings are 169,687
  elements (124/88/85 queries at depths 20/17/14 with 256-element leaves). The
  machine census lists the compress machine's eight chips with widths and
  symbolic constraint counts. `ziren_proof_census.rs` and
  `ziren_machine_census.rs` are the two binaries, built as extra
  `[[bin]]` targets of `examples/fibonacci/host` with `serde_json`, `zkm-pcs`,
  `zkm-recursion-core`, `p3-air` and `p3-uni-stark` added as dependencies.
  Reproduce with:

  ```sh
  source ~/.zkm-toolchain/env
  cd Ziren/examples && cargo build --release -p fibonacci-host --bin compressed
  ./target/release/compressed   # writes compressed-proof-with-pis.bin
  ./target/release/census compressed-proof-with-pis.bin
  ./target/release/machine_census
  ```

- `ziren_whir_model.py` and `run-ziren-whir-model.txt` project the size of a
  Ziren-shaped compressed proof under WHIR parameter changes (decoding regime,
  grinding, starting rate, folding, digest width) and without LogUp-GKR. The
  model reproduces the measured WHIR part within 0.1% (169,876 against 169,687
  elements); every other row is a projection, not a measured proof. Run with
  `python3 ziren_whir_model.py`.

- `ziren_dump_shrink.rs` dumps Ziren's `shrink` program (the in-circuit
  verifier of one compressed proof) and its witness for a compressed proof,
  after running it in Ziren's runtime; `run-ziren-dump-shrink.txt` is its
  output (1,024,796 instructions, 141,020 witness words). It was built as a
  temporary `[[bin]]` of `Ziren/examples/fibonacci/host` with `zkm-prover`,
  `zkm-pcs`, `zkm-recursion-core`, `zkm-recursion-circuit`,
  `zkm-recursion-compiler`, `p3-field`, `p3-koala-bear` and `p3-symmetric`
  (Plonky3 `4dd0d47a`) added. `whir-gc/src/ziren.rs` translates the dump into
  a Boolean circuit. `run-ziren-gc-count-full.txt` is the exact count of the
  full-path circuit (37,901,356,001 non-free gates, 606.4 GB garbled, 5,763,458
  input bits); `run-ziren-gc-eval-dedup.txt` builds the Merkle-deduplicated
  circuit with the evaluating backend (38,339,147,832 non-free gates, 613.4 GB,
  5,179,170 input bits), accepts the real proof with every written value equal
  to the native run, and rejects a one-word change. `run-ziren-gc-count-dedup-v1.txt`
  is the earlier deduplicated count with every extension-read witness word
  given four limbs and a double-counted routing profile; it is kept for the
  record, and its total of 41,088,543,889 non-free gates is the builder's own
  count. `run-ziren-gc-garble-prefix.txt` garbles a 220,000-instruction prefix
  with the streaming garbler: 1.95 M non-free gates per second per core.
  Reproduce with the dump at `target/ziren-shrink.bin`:

  ```sh
  cargo test --release -p whir-gc --test ziren_shrink -- --ignored --nocapture
  ```

- `run-ziren-binary-stage.txt` is Ziren's binary stage end to end on
  `feat/binary-whir-blake3` at `3ec37f76` (eigmax): core, compress, a
  Blake3-committed shrink proof, then the program verifying it proven over
  GF(2^128) with Boolean WHIR and Blake3. Run on ant-5090-2 with 64 cores and
  a 300 GB cap; the same code was OOM-killed at 128 GB. Binary program 1,388,441
  instructions; eleven tables, 15,367 columns, 18.9 Gbit of witness; proof
  2,247,101 bytes in 663 s, verified in 4.9 s, peak 285 GB.

- The binary stage's verifier as a garbled circuit (notes §7n), translated
  from Ziren's recorded tape by `whir-gc/src/binary_tape.rs`:
  - `ziren_dump_binary_tape_v1.rs` and `run-ziren-binary-tape-dump.txt`: at
    `f30cd48c`, proves fibonacci to the binary stage (2,246,717-byte proof)
    and dumps its verifier's tape (ZTAP v1: 5,890,991 ops, 702,274 inputs).
    `run-ziren-binary-tape-{count,eval,garble}-v1.txt` translate it:
    3,607,895,750 non-free gates, 57.73 GB, 18,148,352 input bits; accepts
    the real proof with all 9,413,288 values equal to the tape; rejects three
    single-input changes; garbled by the streaming garbler in 3,519 s.
  - `ziren_dump_binary_tape.rs` and `run-ziren-narrow-dump.txt`: at
    `ee5ca380` (local, unpushed), dumps the level-1 tape (ZTAP v2), proves
    its run on the narrow recursion's tape machine (1,468,673-byte proof,
    1,033 s on 64 cores, 446 GiB peak; OOM at 300G and 450G caps first) and
    dumps the tape machine's verifier on it (level 2). Run on ant-5090-2 with
    a 700G cap and a box-wide 95% memory watchdog.
  - `run-ziren-binary-tape-{count,eval}-v2.txt`: level 1 at `ee5ca380`,
    3,371,420,904 non-free gates, 53.94 GB, 18,050,304 input bits; accepts
    with 0 of 4,914,646 values differing; rejects three changes.
  - `run-ziren-narrow-tape-gc.txt`: level 2, 757,969,914 non-free gates,
    12.13 GB, 11,165,056 input bits; accepts with 0 of 1,172,571 values
    differing; rejects three changes; garbled in 541 s (1.40 M/s, one core).
  - `ziren_real_narrow_schedules.rs` and `run-ziren-narrow-schedules.txt`:
    the WHIR schedules of the narrow machine at its real shapes, read off
    the derived configurations without proving (queries, grinding, digests,
    an unpruned byte estimate) for unique decoding and the Johnson regime.
  - `run-ziren-narrow-dump-johnson-3-4.txt`: the narrow proof under the
    Johnson regime at rate 1/8, folding 4 (`ZIREN_B_SCHEDULE=johnson,3,4`):
    727,235 bytes in 5,821 s (4,948 s of it grinding), 356 GiB peak.
    `run-ziren-narrow-tape-gc-johnson-3-4.txt` translates its verifier:
    483,917,940 non-free gates, 7.74 GB, 5,289,344 input bits; accepts with
    0 of 780,062 values differing; rejects three changes; garbled in 259 s.
  - `run-ziren-narrow-dump-cf932a58-johnson-3-4.txt`: the same at Ziren
    `cf932a58` (narrower rewiring rows) with `ADDR_BITS` raised from 24 to
    26 in the box copy, since the committed limit does not fit the real
    tape: 446,677 bytes in 7,930 s, 536 GiB peak.
    `run-ziren-narrow-tape-gc-cf932a58-johnson-3-4.txt` translates its
    verifier: 400,877,039 non-free gates, 6.41 GB, 3,387,648 input bits;
    accepts with 0 of 601,241 values differing; rejects three changes;
    garbled in 201 s.
  - `run-ziren-narrow-dump-b8bfde94-oom.txt`: Ziren `b8bfde94` (narrower
    round and hash rows, one paired WHIR opening) with `ADDR_BITS` and
    `PERMUTATION_ID_BITS` raised to 26: binary proof 2,035,263 bytes, the
    level-1 tape and the narrow machine's shapes (2,688 main values). The
    narrow proof was OOM-killed at 697.5 GiB; its level-2 input is only
    estimated (notes §7n).
  - `run-ziren-narrow-small-memory-b8bfde94.txt`: Ziren's own small
    narrow-recursion test at `b8bfde94`, with the test binary's RSS sampled
    every 0.2 s: 4.2 GiB after setup, rising through proving to an 11.5 GiB
    peak at the end of the narrow proof (the paired opening).
  - `run-ziren-narrow-recursion-small.txt`: Ziren's own `narrow_recursion`
    test on a small synthetic proof: level 1 4.25e7 and level 2 6.14e8 AND
    by Ziren's estimate, the narrow verifier's floor.

  Reproduce a count with the tape at `target/binary-tape.bin` (or
  `BINARY_TAPE_DUMP=target/narrow-tape.bin` for level 2):

  ```sh
  cargo test --release -p whir-gc --test binary_tape -- --ignored --nocapture
  ```

### Historical context

- `whir-gc-README-before-trim.md` is a snapshot of the longer measurement
  notebook before the crate README was shortened. It records earlier WHIR-only
  cap, parameter-sweep and KoalaBear measurements. It is provenance, not a
  command output and not a substitute for the final paper tables.
