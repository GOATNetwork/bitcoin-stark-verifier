# bitcoin-stark-verifier

Two ways to verify a STARK on Bitcoin with today's opcodes, without
`OP_CAT`:

- **in Bitcoin Script**: Poseidon2 over KoalaBear and a WHIR verifier;
- **as a garbled circuit**: a binary-field WHIR verifier, garbled off-chain
  and evaluated in a dispute.

| Crate | What it is |
| --- | --- |
| [`poseidon2`](poseidon2/) | Poseidon2 over KoalaBear in Script: the permutation, the degree-4 extension field, row hashing and Merkle paths |
| [`whir`](whir/) | The WHIR verifier in Script, run end to end against Plonky3's prover |
| [`whir-gc`](whir-gc/) | STARK verifiers over `GF(2^128)` and Blake3 as Boolean circuits, garbled by streaming on GOAT's [`bitvm-gc`](https://github.com/GOATNetwork/bitvm-gc) |

📄 **[Paper: Garbling a Hash-Based STARK Verifier for Bitcoin](paper/garbled-stark-verifier.pdf)**
has the design, the security analysis, the protocol integration and every
measurement.

## Headline numbers

- **Script verifier.** The 2^20 example is 2,162 Poseidon2 permutations, about
  1.24 GB of script. A standard transaction holds 0.70 of one permutation, so
  the verifier can only run as a dispute over committed sub-query chunks.
- **Garbled verifier, Keccak-f trace.** At 2^18 rows and 104 bits of soundness
  it is 94.1M non-free gates and 1.5 GB garbled, in under a minute on one core.
  It reads 1,041,024 input bits.
- **Garbled verifier, narrow recursion.** Ziren's binary stage and narrow
  recursion bring the statement to a level-4 proof of a zkVM run. Its verifier
  is 218.0M non-free gates and 3.49 GB garbled, and reads 564,552 input bits.
  The proofs meet 100 bits in the Johnson regime. The reduction rests on
  unreviewed Plonky3 and Ziren changes, kept in [`patches/`](patches/README.md).
- **Dispute-time input publication at 564,552 bits.** Schnorr adaptor
  signatures take 1.21 MvB, Antichain Winternitz 6.43 MvB and Lamport 9.36 MvB.
  Disprove is a 97-vB hashlock spend.

## Scope

This is a measured verifier and a cost study, not a complete protocol:
- it does not solder one hash-key set to the kept garblings;
- it does not build the full pre-signed transaction graph;
- cut-and-choose at (181, 7) is about 40 bits;
- Bitcoin's transaction signatures are not post-quantum.

## Running

```
cargo test --locked    # the default suite; the heavy tests are ignored
```

Run tests under a memory cap; [`whir-gc/README.md`](whir-gc/README.md) gives
the command and lists the ignored tests. The Script verifier's details are in
[`whir/README.md`](whir/README.md) and [`poseidon2/README.md`](poseidon2/README.md).

## Credits

[Plonky3](https://github.com/Plonky3/Plonky3) for the specification and the
prover, [BitVM](https://github.com/bitvm/bitvm) and
[`rust-bitcoin-m31`](https://github.com/Bitcoin-Wildlife-Sanctuary/rust-bitcoin-m31)
for the Script field-arithmetic technique, GOAT's
[`bitvm-gc`](https://github.com/GOATNetwork/bitvm-gc) for the garbling code,
and [Ziren](https://github.com/ProjectZKM/Ziren) for the recursion stages.
