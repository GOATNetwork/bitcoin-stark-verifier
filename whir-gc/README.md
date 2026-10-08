# whir-gc

STARK verifiers over the binary tower field `GF(2^128)` with Blake3, built as
Boolean circuits and garbled. Two verifiers are covered:

- **Plonky3's multi-STARK over Boolean WHIR**, exercised by a Keccak-f AIR
  (`stark`, `stark_circuit`, `circuit`). It has one AIR, no public values, no
  preprocessed columns and no lookups.
- **Ziren's binary-stage and narrow-recursion verifiers**, translated from the
  straight-line tapes Ziren records (`binary_tape`).

The paper, [*Garbling a Hash-Based STARK Verifier for
Bitcoin*](../paper/garbled-stark-verifier.pdf), has the design, the security
analysis and all measurements; this README keeps only the headline figures.

Built on the circuit API of GOAT's [`bitvm-gc`](https://github.com/GOATNetwork/bitvm-gc)
(`garbled-snark-verifier`): its Blake3 gadget (10,281 AND per compression), its
streaming garbler, and its gate garbling and evaluation.

## Headline figures

| verifier | non-free gates | garbled | input bits | soundness |
| --- | ---: | ---: | ---: | ---: |
| Keccak-f, 2^18 rows | 94,069,548 | 1.51 GB | 1,041,024 | 104.3 bits |
| Keccak-f, 2^20 rows | 99,613,898 | 1.59 GB | 1,108,992 | 103.95 bits |
| narrow recursion, level 4 | 218,022,788 | 3.49 GB | 564,552 | 100 bits per proof |

- **Garbled size:** 16 bytes per non-free gate. One core garbles the Keccak
  verifier in under a minute.
- **Correctness:** every circuit accepts its real proof. Rejection of changed
  inputs is tested at 2^5 and 2^8 rows and at level 4.
- **Narrow recursion:** its figures depend on the unreviewed Plonky3 and Ziren
  changes in [`../patches/`](../patches/README.md).
- **On-chain cost:** publishing the 564,552 input bits at dispute time costs
  1.21 MvB with Schnorr adaptor signatures, 6.43 MvB with Antichain Winternitz
  and 9.36 MvB with Lamport. The paper gives the accounting boundaries and
  what is still unbuilt.

## Running

Every test runs under a 32 GB, 8-core cap, so a regression kills the test and
not the machine:

```
LIMIT="systemd-run --user --scope -q -p MemoryMax=32G -p MemorySwapMax=0 taskset -c 0-7"
RAYON_NUM_THREADS=8 $LIMIT cargo test --locked -p whir-gc --release
```

The default suite includes:
- checking the reference verifier against Plonky3's;
- garbling the Keccak verifier at 2^5 and 2^8 rows;
- a small dispute run end to end (`tests/protocol.rs`);
- the on-chain fixtures, serialized at the Keccak input size.

The heavy tests are ignored; run them by name with `-- --ignored --nocapture`:

| test | what it does |
| --- | --- |
| `keccak_stark::full_verifier_circuit_on_the_2_18_schedule` | the Keccak verifier at `WHIR_GC_LOG_HEIGHT` rows (default 2^18) |
| `keccak_stark::dispute_over_the_stark_verifier_in_script` | the dispute on the real verifier: garbled before the proof, its inputs revealed through Lamport scripts, Disprove checked |
| `keccak_stark::garbled_before_the_proof_evaluates_real_proofs` | garbles with every input at 0, then evaluates on a real and a changed proof |
| `keccak_stark::input_bits_*`, `merkle_frontier_sim` | the input-size studies |
| `binary_tape::*` | Ziren's tape verifiers. `BINARY_TAPE_DUMP` points at a tape written by Ziren's `dump_binary_tape` test, which the Ziren patch adds |
| `ziren_shrink::*` | Ziren's compressed-proof verifier, from `ZIREN_SHRINK_DUMP` |

The on-chain fixtures (`adaptor_tx_cost`, `antichain_tx_cost`,
`lamport_tx_cost`, `winternitz_cost`) take `WHIR_GC_INPUT_BITS`. The default is
the Keccak verifier's 1,041,024 bits, where their exact totals are asserted.

## Layout

| module | what |
| --- | --- |
| `tower` | `GF(2^128)` tower arithmetic on wires, checked against `p3-binary-field` |
| `reference`, `circuit` | the WHIR verifier on field elements, op for op with Plonky3, and on wires |
| `pruned` | expansion of Plonky3's pruned Merkle proofs into per-query paths |
| `stark`, `stark_circuit` | the multi-STARK layers (zerocheck, column batching, bit ring switch), as reference and on wires |
| `binary_tape` | Ziren's recorded verifier tapes as circuits |
| `ziren`, `ziren_constants`, `koala` | Ziren's KoalaBear/Poseidon2 compressed-proof verifier as a circuit |
| `garble` | garbling and label-level evaluation of a stored gate list |
