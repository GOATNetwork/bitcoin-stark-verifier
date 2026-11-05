# bitcoin-stark-verifier

A hash-based STARK verifier for Bitcoin with today's opcodes, without
`OP_CAT`: a binary-field WHIR verifier as a garbled circuit, garbled off-chain
and evaluated in a dispute.

| Crate | What it is |
| --- | --- |
| [`whir-gc`](whir-gc/) | STARK verifiers over `GF(2^128)` and Blake3 as Boolean circuits, garbled by streaming on GOAT's [`bitvm-gc`](https://github.com/GOATNetwork/bitvm-gc) |

The earlier verifier in Bitcoin Script (Poseidon2 over KoalaBear and WHIR, the
`poseidon2` and `whir` crates) is at commit
[`d45e453`](https://github.com/GOATNetwork/bitcoin-stark-verifier/tree/d45e45386315c4ce927e099c97f51eed48bdc877).

📄 **[Paper: Garbling a Hash-Based STARK Verifier for Bitcoin](paper/garbled-stark-verifier.pdf)**
has the design, the security analysis, the protocol integration and every
measurement.

## Headline numbers

- **Garbled verifier, Keccak-f trace.** At 2^18 rows and 104 bits of soundness
  it is 94.1M non-free gates and 1.5 GB garbled, in under a minute on one core.
  It reads 1,041,024 input bits.
- **Garbled verifier, narrow recursion.** Ziren's binary stage and narrow
  recursion bring the statement to a level-4 proof of a zkVM run. Its verifier
  is 218.0M non-free gates and 3.49 GB garbled, and reads 564,552 input bits.
  The proofs meet 100 bits in the Johnson regime. The reduction rests on
  unreviewed Plonky3 and Ziren changes, on Ziren `feat/binary-whir-blake3`
  `80af2779` and Plonky3 `zkm/binary-whir` `be1c6f92` ([`patches/`](patches/README.md)).
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
the command and lists the ignored tests.

## Credits

[Plonky3](https://github.com/Plonky3/Plonky3) for the specification and the
prover, [BitVM](https://github.com/bitvm/bitvm) for the Script tooling, GOAT's
[`bitvm-gc`](https://github.com/GOATNetwork/bitvm-gc) for the garbling code,
and [Ziren](https://github.com/ProjectZKM/Ziren) for the recursion stages.
