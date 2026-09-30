# whir-gc

A binary-field STARK verifier path as a Boolean circuit, to be garbled. The
measured artifact exercises Plonky3's `p3-multi-stark` path for one Keccak-f
AIR over the WHIR polynomial commitment, with every field in the `GF(2^128)`
tower and Blake3 for commitments, transcript and garbling. The implementation
currently has one AIR, no public values, no preprocessed columns and no lookups.

The paper, [*Garbling a Hash-Based STARK Verifier for
Bitcoin*](../paper/garbled-stark-verifier.pdf), covers the design, the security
analysis, a conditional BitVM3-style integration and the measurements. Neither
this crate nor the paper implements hash-key soldering across retained
garblings or a complete serialized transaction graph. Bitcoin transaction
signatures are not post-quantum, so this is not an end-to-end post-quantum
Bitcoin protocol.

Built on the circuit API of GOAT's [`bitvm-gc`](https://github.com/GOATNetwork/bitvm-gc)
(`garbled-snark-verifier`), using:
- its Blake3 gadget (`blake3_ckt`, 10,281 AND per compression);
- its streaming garbler (`stream`);
- its gate garbling and evaluation (`gate_garbled_with_delta`, `gate_evaluate`).

## Results

The trace is Keccak-f with 1,625 columns. The WHIR parameters are rate 1/32,
folding 4 and 110 bits per term. Each circuit accepts its real proof. At 2^5 and
2^8 rows, the test also checks that the circuit rejects the proof with one
opened value changed.

| trace | non-free gates | garbled | bytes per committed cell | garbler memory | input bits | soundness |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| 2^5 rows | 44,573,121 | 713 MB | 13,715 | 0.32 GiB | 586,240 | 106.1 |
| 2^8 rows | 66,459,859 | 1,063 MB | 2,556 | 0.46 GiB | 743,808 | 105.2 |
| 2^12 rows | 77,736,394 | 1,243 MB | 186.9 | 0.54 GiB | 874,240 | 104.7 |
| 2^16 rows | 88,680,747 | 1,418 MB | 13.32 | 0.61 GiB | 997,760 | 104.3 |
| **2^18 rows** | **94,069,548** | **1,505 MB** | **3.53** | 0.65 GiB | 1,041,024 | 104.3 |
| 2^20 rows | 99,613,898 | 1,593 MB | 0.94 | 0.68 GiB | 1,108,992 | 103.95 |

- **Garbled size** is 16 bytes per non-free gate. Garbling takes under a minute
  on one core.
- **Garbler memory** is the plan (one byte per wire) plus 18 bytes per live
  wire.
- **Whole-process peak.** The 2^18 run peaks at 5.82 GiB, almost all of it
  proof generation, which took 87 min on 8 cores.
- **Soundness** is Plonky3's composed bound, in bits.

## Protocol scope and on-chain accounting

At 2^18 rows the circuit consumes 1,041,024 input bits (127.1 KiB), whereas
the serialized Plonky3 proof is 140.0 KiB; these are different encodings. The
following figures account for the dispute-time input-authentication component,
including its signature or opening witness and verification script. They do
not include a complete dispute graph. Each authenticated row now has an
complete signed reveal-transaction fixture, although the output shapes differ.
All three have been tested through strict Bitcoin Core 31.1 policy after
funding confirmation:

| input authentication | one key set | `M = 7` component projection | accounting boundary and caveat |
| --- | ---: | ---: | --- |
| Schnorr adaptors | 2.22 MvB | not multiplied here | Core-tested 133-input/23-reveal-transaction optimum for the measured two-output shell, with completed signatures using BIP342 code-separator positions, scripts and controls; discrete-log based |
| Antichain Winternitz | 11.85 MvB | 82.94 MvB (830 × 100-kvB) | Core-tested all-nonzero worst case: 784 signed inputs/131 two-output transactions using pinned upstream openings; one-set-to-many hash soldering is unimplemented |
| Lamport | 17.27 MvB | 120.86 MvB (1,209 × 100-kvB) | fully serialized 174-reveal fixture with transaction-binding signatures, preimages, scripts, depth-0 controls and tx shells; strict Core 31.1 regtest accepted it after funding confirmation; soldering unimplemented |

Total on-chain footprint means every serialized transaction in the dispute
graph, including ordinary transaction signatures, authentication witnesses,
scripts, control blocks, inputs, outputs, anchors, timeouts and fee-management
transactions. The complete graph has not been built, so the table is a
component study and the total remains unknown. The `100-kvB` figures are
capacity equivalents, not transaction counts.

The Core-tested funding transactions are 5,841 vB (adaptor), 33,836 vB
(Antichain) and 45,016 vB (Lamport). Funding plus reveals therefore totals
2,228,054, 11,882,711 and 17,310,651 vB, respectively. Core rejected each
funding→reveal edge while the parent was unconfirmed as `too-large-cluster`;
after funding confirmation it accepted all reveals and mined the sets in 3, 12
and 18 blocks. The signed 13,060-vB Lamport join brings its tested bounded slice
to 17,323,711 vB; the corresponding adaptor and Antichain joins are not built.
This validates staged bounded components under standard policy, not
public-network propagation, fee robustness or the missing challenge, timeout,
Disprove, anchor and soldering graph.

The hash-key `M = 7` column is deliberately labelled a projection. Publishing
seven independent authentication components does not itself prove that all seven
key sets encode the same proof bits. Conversely, the one-key-set hash figures
are conditional on a soldering construction that has not been built or costed
at this scale.

The measured STARK configuration has about 104 classical bits of soundness and
about 52 bits against generic quantum search. The reported cut-and-choose
parameters are only about 40 classical bits, and the surrounding Bitcoin
signatures are not post-quantum.

An unauthenticated raw-data transport is not the protocol's on-chain cost. The executable
`raw_input_cost` test packs them into 1,627 standard-policy-sized witness items
over two internally committed one-leaf P2TR script-path fixtures and executes
both leaf scripts. The serialized transaction is
132,788 bytes, 133,193 WU and 33,299 vB, below the 400,000-WU
standard-transaction limit. It includes the drop scripts, control blocks and
transaction framing but no signature or bit-to-label authentication. It uses
synthetic outpoints, a public internal key, and no fee or
`testmempoolaccept` call, so it is not an accepted transaction. It is only a
transport reference point; the MvB-scale authenticated reveal is the relevant
dispute-time component.

### Assert/Disprove reduction experiments

Three follow-up fixtures separate an encoding improvement from an architecture
change and a small Disprove optimization:

| experiment | strict Core 31.1 result | boundary |
| --- | ---: | --- |
| 16-bit adaptor encoding | 2,960-vB funding + 1,111,128-vB reveals = **1,114,088 vB, 13 tx** | Real completed signatures and standard transactions; the 277.162-GB/keyset choice-table model, digit-to-binary-label delivery and complete dispute graph are not implemented |
| ESSPI-style signed envelope | 154-vB commit + 32,850-vB reveal = **33,004 vB, 2 tx** | Authenticated transport for 130,128 bytes, not a drop-in GC Assert; excludes the DA-DAG, secondary BitVMX and settlement |
| false-label pointlock | **83-vB** spend versus **97-vB** 16-byte hashlock with the same timeout sibling | Saves 14 vB on Disprove; adds the Schnorr/discrete-log assumption and does not itself constrain outputs |

The adaptor test also serializes exact 10-, 11- and 12-bit transaction shapes,
whose funding-plus-reveal totals are 1,782,498, 1,620,499 and 1,485,410 vB.
Those widths still use placeholder signatures in the sweep and have not been
replayed through Core. Wider digits only become a protocol improvement after a
construction proves that one digit secret releases exactly the selected binary
labels; the current fixture measures the on-chain encoding, not that missing
correlation layer.

The full method comparison and evidence levels are in
[`paper/assert-disprove-reduction-survey.md`](../paper/assert-disprove-reduction-survey.md).

## Input-optimization experiments

The schedule count agrees with the actual fresh-input wire count at all five
constructed heights through 2^18. Additional tests separate three different
optimization claims:

| experiment | result | interpretation |
| --- | ---: | --- |
| pruned Merkle frontier, 1M trials | 1,036,341 expected bits (-0.45%) | queries mostly fall below different cap roots, so path sharing is negligible |
| equal-area width 128, current WHIR profile | 659,840 bits (-36.6%) | layout model only; no narrow Keccak AIR exists |
| equal-area width 32, current WHIR profile | 636,288 bits (-38.9%) | diminishing returns once openings stop dominating |
| equal-area width 128, best 48-bit-grinding frontier | 464,768 bits (-55.4%) | combines an unimplemented AIR with impractical aggressive grinding |
| equal-area width 32, best 48-bit-grinding frontier | 441,216 bits (-57.6%) | model frontier, not a generated proof |

"Equal area" raises the trace height to retain at least as many committed cells
as the measured 1,625-by-2^18 trace. It is a stricter comparison than holding
the height fixed, but still does not prove that a narrow AIR can express the
same computation with that area. Separately, the real 2^18 and 2^20 artifacts
use 99.29 and 26.44 input bits per Keccak-f respectively: batching four times
the work increases total input by only 6.53%.

A committed, challenged segment of at most `B` bits would need at least
`B + 256 * ceil(log2(ceil(1_041_024 / B))) + C_state` authenticated bits. For
`B = 6,656`, this is 8,704 bits plus boundary state. Segmenting only the WHIR
queries does not achieve that bound: the unsegmented remainder is still 530,560
bits. A real construction must also segment openings, sumchecks, the ring switch
and transcript, then bind states and implement bisection and withholding
penalties. None of those protocol mechanisms is present here.

## Raw measurements

The tracked [`paper/data`](../paper/data/README.md) directory maps every
archived log to its command and paper table or claim. It also records provenance
for historical ablations that the current tree cannot reproduce directly.
Verify the archive with `cd paper/data && sha256sum -c SHA256SUMS`.

## Running

```
LIMIT="systemd-run --user --scope -q -p MemoryMax=32G -p MemorySwapMax=0 taskset -c 0-7"
RAYON_NUM_THREADS=8 $LIMIT cargo test --locked -p whir-gc --release --test keccak_stark -- --nocapture
WHIR_GC_LOG_HEIGHT=18 RAYON_NUM_THREADS=8 $LIMIT cargo test --locked -p whir-gc --release --test keccak_stark \
    full_verifier_circuit_on_the_2_18_schedule -- --ignored --nocapture
```

Every test runs in 32 GB of RAM on 8 cores, so a regression kills the test and
not the machine. The default tests do four things:
- check the reference against Plonky3's verifier;
- garble the full circuit at 2^5 and 2^8 rows;
- print Plonky3's soundness report;
- run the dispute on a small circuit (`tests/protocol.rs`): a Blake3
  preimage claim is garbled at setup, its 512 bits are revealed through a
  Lamport Assert script, the challenger evaluates from the labels alone, and
  a Disprove hashlock script opens for a false claim and not for a true one.
- serialize the complete 1,041,024-bit raw payload in a policy-shaped P2TR
  transaction and assert its item, stack and weight limits (`raw_input_cost`).

The ignored tests are:

| test | what it does |
| --- | --- |
| `full_verifier_circuit_on_the_2_18_schedule` | any height from `WHIR_GC_LOG_HEIGHT` |
| `stored_build_of_the_full_verifier` | the memory comparison |
| `whir_schedule_of_the_measured_configurations` | queries and grinding per round |
| `input_bits_of_whir_configurations` | the input-size sweep |
| `input_bits_of_equal_area_narrow_statements` | equal-committed-cell narrow-statement models under the current and best searched WHIR profiles |
| `merkle_frontier_sim::current_whir_pruned_multiproof_savings` | one-million-trial simulation using the real stratified-query routine and cap forest |
| `garbled_before_the_proof_evaluates_real_proofs` | garbles with every input at 0, then evaluates the stored garbling on a real proof (label of 1) and on a changed proof (label of 0) |
| `dispute_over_the_stark_verifier_in_script` | the dispute on the real verifier: garbled with every input at 0, the proof's input bits revealed through Lamport Assert scripts (998 bits each, stack limit on), evaluated from the labels alone; Disprove opens for a changed proof and not for the real one |

## Layout

| module | what |
| --- | --- |
| `tower` | `GF(2^128)` tower arithmetic on wires, checked against `p3-binary-field` |
| `pruned` | expansion of Plonky3's pruned Merkle proofs into per-query paths |
| `reference` | the WHIR verifier on field elements, op for op with Plonky3 |
| `circuit` | the WHIR verifier on wires, with a prefix hook and a gate profile |
| `stark`, `stark_circuit` | the multi-STARK layers (zerocheck, column batching, bit ring switch), as reference and as wires |
| `garble` | garbling and evaluation of a stored gate list |
| `tests/keccak_stark.rs` | real Keccak-f STARK proofs, verified by the reference and garbled |
