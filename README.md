# bitcoin-stark-verifier

This repository studies two ways to verify a STARK using Bitcoin's currently
available opcodes, with **no `OP_CAT`**:

- **in Bitcoin Script**, with Poseidon2 over KoalaBear and WHIR;
- **as a garbled circuit**, with the Plonky3 Boolean-WHIR verifier path
  exercised by a Keccak-f AIR, garbled off-chain and evaluated in a dispute.

| Crate | What it is |
| --- | --- |
| [`poseidon2`](poseidon2/) | Poseidon2 over KoalaBear in Script: the permutation, the degree-4 extension field, row hashing and Merkle path verification |
| [`whir`](whir/) | The WHIR verifier in Script on top of it, run end to end against Plonky3's prover |
| [`whir-gc`](whir-gc/) | The measured Keccak/Boolean-WHIR verifier path over `GF(2^128)` and Blake3 as a Boolean circuit, garbled by streaming on GOAT's [`bitvm-gc`](https://github.com/GOATNetwork/bitvm-gc) |

📄 **[Paper: Garbling a Hash-Based STARK Verifier for Bitcoin](paper/garbled-stark-verifier.pdf)**:
the measured garbled verifier, its classical and quantum security analysis,
and a conditional BitVM3-style integration and cost study.

The artifact does not yet bind public values, implement hash-key soldering
across the kept garblings, or validate the complete pre-signed transaction
graph. Bitcoin's transaction signatures are also not post-quantum. It is
therefore a hash-based verifier and cost study, not a complete post-quantum
Bitcoin protocol.

```
cargo test --locked                     # default workspace suite; heavy tests are ignored
```

Run the tests under a memory cap; [`whir-gc/README.md`](whir-gc/README.md)
gives the command.

## The Script verifier

Script has no byte concatenation, so a SHA256 Merkle step needs `OP_CAT`. A
Poseidon2 digest is field elements, which Script can pass to an arithmetic
routine with nothing to concatenate. On that basis [`whir`](whir/) verifies a
real Plonky3 WHIR proof entirely in Script.

The cost is the obstacle:
- **Total size:** the 2^20 example configuration is 2,162 Poseidon2
  permutations, 1.24 GB of script, or 309 blocks.
- **One permutation doesn't fit a transaction:** a standard transaction holds
  0.70 of one permutation.
- **So it runs as a dispute:** the verifier executes as a dispute over
  committed sub-query chunks, about 2,000 of them for the 80-bit, 20-variable
  configuration.

Details, measurements and the soundness regimes are in
[`whir/README.md`](whir/README.md) and [`poseidon2/README.md`](poseidon2/README.md).

## The garbled verifier

The measured verifier for a 2^18-row, 1,625-column Keccak-f trace at 104 bits of
soundness is a circuit of 94.1M non-free gates. It garbles to 1.5 GB in under a
minute on one core and needs under 0.7 GiB of memory. That is about 30× fewer
non-free gates than the Boolean-garbled Groth16 verifier, with no pairing and no
trusted setup. The circuit is garbled before any proof exists. A challenger
evaluates the stored garbling on the operator's proof: a valid proof yields the
accept label, and a changed one yields the reject label that disproves it.

The largest measured on-chain component is dispute-time input
authentication. The circuit consumes 1,041,024 input bits (127.1 KiB), whereas
the serialized Plonky3 proof is 140.0 KiB; these are different encodings. A
policy-shaped Taproot fixture carries the unauthenticated raw bitstream in
33,299 vB, but it has no signature or bit-to-label authentication and is not a
protocol cost. Including the adaptor or one-time-signature witness and its
verification script, the executed one-key-set fixtures measure 2.22 MvB with
Schnorr adaptors, 11.85 MvB with safe Antichain Winternitz, and 17.27 MvB with
Lamport. Every row includes transaction-binding signatures, authentication
scripts, control blocks and full reveal transaction shells. Strict Bitcoin
Core 31.1 regtest policy accepted all three reveal sets after funding
confirmation. Their signed funding transactions are 5,841, 33,836 and 45,016
vB, so funding plus reveals totals 2,228,054, 11,882,711 and 17,310,651 vB.
The adaptor fixture uses BIP342 opcode positions for every code separator. A
signed 13,060-vB Lamport join raises its tested staged slice to 17,323,711 vB.
The mechanisms still use different accounting
boundaries, and the complete dispute graph has not been constructed, so these
figures cannot substitute for a measured total on-chain cost. The Schnorr path
is not post-quantum. The two hash-key
figures are also conditional on an unimplemented mechanism that solders one
key set to all kept garblings.

Reproduced optimization bounds are deliberately separated from implementations:
WHIR tuning reaches 845,952 bits (-18.74%); a one-million-trial Merkle-frontier
simulation saves only 0.45%; the reported 128- and 32-column equal-area
narrow-AIR models span 659,840--441,216 bits (-36.6% to -57.6%), but no such
AIR has been built. The
real 2^20 artifact amortizes input per Keccak-f by 3.76x relative to 2^18 while
increasing the absolute input by 6.53%.

With `M = 7` kept garblings, simply multiplying the hash-authentication
component gives arithmetic projections of 82.94 MvB (830 × 100-kvB) for
Antichain and 120.86 MvB (1,209 × 100-kvB) for Lamport, before
transaction-graph overhead. These are capacity equivalents, not transaction
counts or complete on-chain costs. The construction still needs a mechanism
that enforces the same bit choice across all seven
key sets. Tuning the proof removes about 19% of the one-set input component.

Narrow recursion shrinks the input further with real proofs. Ziren's binary
stage proves a zkVM proof's verifier over GF(2^128) with Boolean WHIR and Blake3,
and its five-table tape machine proves recorded verifier tapes. The garbled
verifier of the third narrow-recursion proof of a Fibonacci program takes
603,112 input bits in 216.5M non-free gates (3.46 GB), 0.58x the Keccak
verifier's input; it accepts the real proof and rejects changed inputs. The
reduction rests on experimental, unreviewed changes to Plonky3 and Ziren
(shared ring-switch tensors, 200-bit digests, linear-form openings,
eq-factored bus rounds), kept as patches in [`patches/`](patches/README.md).
At the adaptor baseline's 2.13 vB per bit that would be about 1.28 MvB, a
scaling rather than a fixture.

Details are in [`whir-gc/README.md`](whir-gc/README.md) and the paper. The
tracked raw logs, test-command map and checksums are in
[`paper/data/`](paper/data/README.md).

## Credits

[Plonky3](https://github.com/Plonky3/Plonky3) for the specification and the
prover, [BitVM](https://github.com/bitvm/bitvm) and
[`rust-bitcoin-m31`](https://github.com/Bitcoin-Wildlife-Sanctuary/rust-bitcoin-m31)
for the Bitcoin Script field-arithmetic technique, and GOAT's
[`bitvm-gc`](https://github.com/GOATNetwork/bitvm-gc) for the garbling code.
