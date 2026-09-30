# Paper: Garbling a Hash-Based STARK Verifier for Bitcoin

This is a draft, not yet released.

The measured artifact is the verifier path exercised by the Keccak-f AIR in
this repository. It has no public values and is not a complete post-quantum
Bitcoin protocol. The paper separately identifies the unimplemented
multi-copy hash-key soldering, the unvalidated transaction graph and Bitcoin's
non-post-quantum transaction signatures.

| file | what |
| --- | --- |
| `garbled-stark-verifier.tex` | the paper (built: `garbled-stark-verifier.pdf`) |
| `assert-disprove-reduction-survey.md` | evidence-tiered study of current-consensus and soft-fork methods to shrink Assert/Disprove |
| `refs.bib` | bibliography used by the paper |
| `notes.md` | per-paper notes with section, table and figure references, plus our measurements and a list of things to fix before release |
| `data/` | tracked raw measurement records, reproduction commands, provenance notes and SHA-256 checksums |
| `refs/` | PDFs of the papers read (git-ignored) |

Build:

```
pdflatex garbled-stark-verifier && bibtex garbled-stark-verifier && pdflatex garbled-stark-verifier && pdflatex garbled-stark-verifier
```

## Measurements

[`data/README.md`](data/README.md) maps each archived log to its test command
and to the paper table or claim it supports. From the repository root, verify
the archived artifacts with:

```sh
cd paper/data
sha256sum -c SHA256SUMS
```

The circuit consumes 1,041,024 input bits (127.1 KiB), whereas the serialized
Plonky3 proof is 140.0 KiB; these are different encodings. A policy-shaped,
script-executed Taproot fixture transports the raw input in 33,299 vB, but its
synthetic outpoints have not passed `testmempoolaccept` and it provides no
signature or garbled-label authentication, so it is not a protocol on-chain
cost. The accounted dispute-time authentication component includes the
signature or opening witness and its verification script. For one key set it
measures 2.22 MvB with Schnorr adaptors, 11.85 MvB with safe Antichain
Winternitz and 17.27 MvB with Lamport. All three are complete signed
reveal-transaction fixtures accepted under strict Bitcoin Core 31.1 regtest
policy after funding confirmation; their output shapes differ. The signed
funding transactions are 5,841, 33,836 and 45,016 vB, making the staged
funding-plus-reveal slices 2,228,054, 11,882,711 and 17,310,651 vB. A signed
13,060-vB Lamport join brings its tested slice to 17,323,711 vB.
The three mechanisms still have different transaction-shell boundaries; the
complete challenge, timeout, Disprove, anchor and fee-management graph has not
been constructed, so these figures cannot substitute for a measured total
on-chain cost. Schnorr is not post-quantum. The two
hash-key figures assume an unimplemented one-set-to-many soldering mechanism.
Merely multiplying the hash component by the seven retained garblings gives
arithmetic component projections of 82.94 MvB
(830 × 100-kvB) and 120.86 MvB (1,209 × 100-kvB), respectively. This
multiplication does not by itself prove that all seven sets encode the same
bits, and the capacity equivalents are not transaction counts.

The follow-up reduction study adds three strict-Core fixtures. A 16-bit
adaptor transaction encoding cuts the bounded funding-plus-reveal slice to
1,114,088 vB in 13 transactions, but requires a modeled 277.162-GB choice
table per independent keyset and still lacks the digit-to-binary-label
construction. An ESSPI-style P2TR envelope authenticates the 130,128-byte
payload in 33,004 vB over a commit and reveal, but is only a transport
component and cannot replace selected GC labels. For the actual 16-byte output
label, a pointlock reduces a Disprove spend with the same timeout sibling from
97 to 83 vB. See [`assert-disprove-reduction-survey.md`](assert-disprove-reduction-survey.md)
for evidence levels, protocol boundaries and the soft-fork comparison.

The input experiments also show that Merkle-frontier compression saves only
0.45% on average, WHIR parameter tuning saves 18.74%, and equal-area narrow-AIR
layout models save 36.6%--57.6% but have no implemented AIR. Real 2^18 and
2^20 artifacts reduce input per Keccak-f from 99.29 to 26.44 bits by batching;
the absolute proof input still grows by 6.53%.

Still to do before release: the author list
and the open points in `notes.md` §8.
