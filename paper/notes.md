# Literature notes for the whir-gc paper

These are working notes, one section per source, kept alongside `garbled-stark-verifier.tex`. Each
number is quoted from the source, with its section, table or figure. Anything
marked **[ours]** is our own reading or measurement and not a claim the source
makes. PDFs are in `refs/`, which is git-ignored.

The last section lists errors and open points to fix before release.

---

## 1. BABE: *Verifying Proofs on Bitcoin Made 1000x Cheaper* — ePrint 2026/065

Garg, Kolonelos (UC Berkeley), Sergeevitch (Babylon Labs), Sridhar (Byzantine
Research), Tse (Byzantine Research, Stanford). 61 pp.

- **Problem.** Verify Groth16 proofs on Bitcoin in the BitVM setting (Prover and
  Verifier, hashlocks and timelocks only). BitVM2's unhappy path costs over
  $14,000 on-chain. BitVM3's garbled Groth16 verifier costs little on-chain but
  is 42 GiB per garbled circuit (Abstract, Sec. 1.2).
- **BitVM3 baseline, as they report it.** They cite BitVM/garbled-snark-verifier
  [Bit25b]: about 10B gates and 3B non-free, with free-XOR and privacy-free half
  gates, giving a 42 GiB garbled circuit and 6 minutes to garble one circuit on
  one core (Sec. 1.2.2). The storage figure in Fig. 2 is 2.7B non-free gates at
  16 B each, about 41,200 MiB (Sec. 9.1). Cut-and-choose setup at
  (N_CC, M_CC) = (181, 7) is 3:24:24, estimated as twice the garbling time
  (Tab. 3).
- **Alternatives they mention.**
  - Eagen's Glock [Eag25] uses a designated-verifier SNARK on a binary curve,
    giving a 12 MB garbled circuit. BABE says that "the security of binary curves
    is not widely accepted", so the approach "is not currently pursued in
    practice".
  - [FBFL25] garbles the verifier with arithmetic circuits: "still expected to be
    100 million ciphertexts (a few GBs)" (Sec. 1.2.2).
- **Idea.** Witness encryption for *linear* pairing relations
  [BC16, GKPW24]. For `e(w1,x1)+e(x2,w2)=x3` the ciphertext is
  `(r x1, r x2, r x3 + msg)` (Sec. 1.3.2). Groth16 is quadratic because of
  `e(π1, π2)`, so they treat π1 as a public input:
  `e(x0,π2)+e(π3,x1)=x2`, with `x0 := π1`. The ciphertext needs `r·π1`, which is
  unknown at setup. A maliciously secure 2PC gives it: the Verifier garbles a
  circuit computing `r·π1` with `r` hard-coded, and the Prover's input labels
  are the Lamport signature on π1 (Sec. 1.3.2, Fig. 4).
- **Roles are reversed relative to BitVM3.** In BitVM3 the garbled circuit
  releases the secret on an *invalid* proof (the Verifier wins). In BABE's WE
  view, the Prover decrypts with a *valid* proof and opens the hashlock
  (Figs. 1 and 3).
- **Garbling r·π1.** Builds on Argo MAC [EL26]. Decomposable randomized
  encodings (DRE, [IK00, Ish13]) reduce the BN254 scalar multiplication to a
  254-dimensional vector homomorphic MAC. Each component is linearised by
  feeding in the monomials `(x, y, x², y², xy)`, making it an inner product. A
  small Boolean Yao circuit computes the monomials and checks the point
  (Sec. 1.3.3, Sec. 5).
- **Sizes (Sec. 9.1).**
  - Per-instance artifact: **22.16 MiB**. That is 6.35 MiB of Boolean Yao gadgets
    (π1 validation and the feature vector), plus 15.77 MiB of DRE selection
    tables (n(8n+3) = 516,890 field elements of 32 B), plus 480 B of WE
    ciphertext.
  - Setup: 174.9 ms. Decryption: 126.5 ms, single-threaded on a Ryzen 7 7840U.
- **On-chain (Tab. 1, mainnet experiment).** Assert 9,240 vB, ChallengeAssert
  17,400 vB, WronglyChallenged 149 vB. That is **$56.90** at 2.2 sat/vB and
  BTC = $95,500. BitVM3 is $37.65 and BitVM2 $14,211 (Fig. 2).
- **Malicious setup (Sec. 9.2–9.4).**
  - Cut-and-choose with soundness error at most 2^-40. Setup time by
    (N_CC, M_CC): 0:06 at (78, 10), 0:09 at (181, 7), 1:37 at (2,268, 4). Peak
    RAM stays around 1–2 GB.
  - zk-SNARK soldering (an SP1 zkVM prototype) reduces the on-chain input-label
    sets from M_CC to one. It takes 745.5 s at M_CC = 4 for BABE (508 labels),
    and 1,529–1,977 s for BitVM3 (1,019 labels) (Tabs. 4–6).
  - Verifiable Shamir secret sharing (the Glock-inspired alternative) adds
    33–333 s (Tab. 7). Its on-chain integration isn't done yet.
- **Security.**
  - The BitVM-core primitive (Sec. 3) has two properties. u-Robustness: an
    honest Prover with a valid witness wins. Knowledge soundness: a Prover wins
    only if the witness can be extracted.
  - Honest-setup security: Thms. 6–8, assuming a ledger with safety, liveness
    and chain growth. The WE part uses the generic bilinear group model and a
    random oracle (Sec. 2.2.1, Sec. 4).
  - Groth16 knowledge soundness is Thm. 2.
- **[ours] Relevance.**
  - Post-quantum: no. It uses BN254 pairings and Groth16, with a trusted setup
    per circuit.
  - The statement must be Groth16, so any other proof system has to be wrapped
    in Groth16.
  - On-chain cost is the same order as garbled-circuit BitVM3.
  - Its 22 MiB beats our 1.5 GB of garbled circuit by about 70×. We verify a
    STARK directly, post-quantum, with no wrapping and no trusted setup.

## 2. Partial-binding WE over Groth16 — bitvm-gc `docs/partial_binding_we.tex`

Stephen Duan, 2026-04-19. Internal note, built on BABE.

- **Problem.** BABE's `Enc` needs the *whole* public-input vector at encryption
  time, which is peg-in for a bridge. Some inputs (the chain tip, a watchtower
  bitmap) are only known at dispute time.
- **Construction.** Split the public inputs into a static part `x_S`, fixed at
  encryption, and a dynamic part `x_D`, fixed at dispute time.
  - Encrypt under `Y_S = e(α,β)·e(P_S,γ)`, blinded by `e(B,γ)^{-1}`.
  - A **Dual-Scalar Garbled Circuit** outputs `r·π1` and `r·P_D + r·B`, with
    `r·L_j` and `r·B` baked in as constants.
  - The `x_D` input wires are Lamport-soldered, so only the on-chain-committed
    `x_D` can be fed in.
  - The construction relies on Groth16's *linear* public-input aggregation
    `vk_x = Σ x_j L_j`.
- **Security.** `Adv ≤ Adv_BABE + Adv_DLog(G1)`, plus garbling security and
  Lamport one-wayness. There is a sketch of a UC proof (App. A).
- **Cost.** Each dynamic slot adds about 1.5·10^8 gates to the garbled circuit.
  The note gives BABE's base garbled circuit as about 4.7·10^8 gates. For the
  BitVM2 bridge with |D| = 4, the circuit is about 1.1·10^9 gates. Lamport
  witness: +|D|·254 bits.
- **In code.** `verifiable-circuit-babe`: `gc/circuit.rs` has "Circuit 1 / FGC"
  computing ū(π) and "SGC Part 1" computing `Q = x_d·L_2 + B`. `dre/` holds the
  DRE, and `babe-programs/soldering` is a Ziren (zkm) guest for soldering.
  `N_CC = 181` and `M_CC = 7` are the production values in the comments; the
  code sets 4 and 2 for tests.
- **[ours] Inconsistency to resolve.** The note's 4.7·10^8-gate figure for the
  basic BABE garbled circuit doesn't match BABE's own 22 MiB artifact, which is
  6.35 MiB of Yao gadgets plus DRE tables. The note seems to count a Boolean
  scalar-multiplication circuit (GOAT's implementation?), while BABE garbles
  most of the work through DRE. Check which one GOAT deploys before quoting
  either.

## 3. Bitcoin PIPEs v2 — ePrint 2026/186

Abdalla, Carmer, El Gebali, Kilinc-Alper, Komarov, Rebenko, Soukhanov, Tairi,
Tatuzova, Towa (alloc init). 22 pp.

- **Idea.** Witness-encrypt a Schnorr signing key under an NP statement x. A
  valid witness decrypts the key, and the spend is an ordinary Schnorr/P2TR
  signature, so there is no soft fork (Sec. 1, Fig. 1).
- **Witness Signature (WS) primitive** (Sec. 3): Setup, OutVerify, WSign.
  Properties: correctness, WS-EUF-CMA and verifiability.
  - The construction (Sec. 4) is `ct = WE.Enc(x, sk)` plus a NIZK that `ct`
    encrypts the `sk` for `pk`.
  - Security (Thms. 1–3) rests on Schnorr EUF-CMA, a hard relation, NIZK zero
    knowledge and *extractable* WE.
- **Limits they state.**
  - The key is released once, not per transaction ("binary NP covenant",
    Def. 1.1). There is no template enforcement like `OP_CTV` (footnote 2).
  - In BitVM-PIPE the statement includes `h = Hash(w)`, so the operator must
    know w at setup. GC setup doesn't need w (Sec. 6).
- **WE instantiation.** AADP, the next section. The ciphertext is estimated at
  about **338 TB** for a SNARK verifier (Sec. 5.3.1). Security is heuristic
  (Sec. 5.2).
- **BitVM mapping (Sec. 6).** The relation is `R = (f(w) = 0) ∧ (h = Hash(w))`.
  AssertTx carries one hash and DisproveTx one signature. The signer committee
  is n-of-n, and one honest challenger suffices.
- **[ours]** "Any NP relation" holds in theory. In practice only statements
  proven in their custom small-verifier SNARK qualify, because the ciphertext
  grows cubically. It isn't post-quantum.

## 4. AADP witness encryption — ePrint 2026/175

Soukhanov, Rebenko, El Gebali, Komarov, Kilinc-Alper, Abdalla, Towa (alloc
init). 38 pp.

- **Arithmetic ADPs.** Constraints have the form `(Ax)∘(Bx) = (Cx)∘(Dx)` over a
  large field. Each constraint is a 4×4 block `U_i`, of rank 2 if it holds and
  rank 4 otherwise. The blocks are randomised as `L_i U_i R_i` and summed into a
  `(2m+1)×(2m+1)` matrix, which has rank 2m exactly on solutions (Alg. 1,
  Thm. 1).
  - Encryption adds msg to the bottom-right entry of `M^0`. Decryption solves
    `det(E − t e eᵀ) = 0` for t (Algs. 2–3).
- **Projective safety** (Def. 3): every variable needs a certificate
  `x_i² = a(x_0..x_{i−1})·b(x)`, which rules out solutions at infinity.
  Otherwise the correlated span attack recovers the randomness (Sec. 3.1–3.2).
- **Cryptanalysis.**
  - A parametric rank-drop attack **broke an earlier version**, the one with
    bit-check matrices (Sec. 3.3).
  - For the linearization attack they estimate at least `k^28` time and call the
    evidence "inconclusive" (Sec. 3.4).
  - Assumption 1 is extractable WE, which they acknowledge is non-falsifiable.
    It needs `g(x) > m^ε`, i.e. gates repeated.
  - Assumption 2 claims 100-bit concrete security, capped by BN254.
- **Gadgets** (Sec. 4). General multiplication costs `O(log|F|)`
  certification. Instead they build everything from "multiply and square root"
  steps `c² = ab` in the odd-order subgroup: exponentiation, the Miller loop with
  fixed G2 points, and Poseidon with an x^5 S-box.
  - "20,000 witness, 20,000 constraint system yield ciphertext sizes ≈ 1 PB";
    one 256-bit scalar multiplication would be "several exabytes" (Sec. 4.2).
- **SNARK** (Sec. 4.3). A modified squaring QAP with batched KZG and one pairing
  equation. The G2 points are fixed, rewritten from Pari's (Sec. 4.3 opening
  argument). The setup is circuit-specific. It is knowledge-sound in the
  generic group model plus the random oracle model (Thm. 3).
- **Cost** (Sec. 4.10, from a modelling script, github.com/alloc-init/adp-estimates):

  | subroutine | variables | gates |
  | --- | ---: | ---: |
  | extension basis | 11 | 22 |
  | glue | 1,265 | 1,270 |
  | hash | 1,017 | 1,192 |
  | non-native arithmetic | 3,578 | 3,580 |
  | pairing equation | 8,212 | 8,307 |
  | **total** | **14,083** | **14,371** |

  The ciphertext is `v(2g+1)²|F|`, about **338 TB**. That is cubic in circuit
  size since v ≈ g; the paper calls it "cubic scaling". There is no
  implementation.
- **[ours]** The gadgets need odd characteristic (square roots in the
  odd-order subgroup, Fermat certification), so binary-field arithmetic doesn't
  fit. Our 94M-gate verifier is 6,500 times their gate count, so roughly 10^20
  times larger under cubic scaling. It's out of reach.

## 5. Garuda and Pari — ePrint 2024/1245

Dellepere (Provable), Mishra and Shirzad (UPenn). 52 pp.

- **EPC.** Equifficient polynomial commitments enforce that several committed
  polynomials have equal coefficient vectors in bases the setup specifies. The
  commitment then handles the linear checks and the PIOP only the non-linear
  ones (Sec. 2.2–2.3).
- **Pari.** For square R1CS. The proof is **2 G1 + 2 F**, which is 1,280 bits
  (160 B) on BLS12-381. Groth16 is 1,536 bits and Polymath 1,408 (Table 1).
  - The verifier does 3 pairings plus O(|x|) field operations.
  - The prover does O(n log n) field operations and 4 MSMs of size about m.
  - It is proven in the algebraic group model plus the random oracle model
    (interactive version).
  - The setup is circuit-specific. It isn't zero-knowledge as written.
  - Pari is not implemented. The unrolled SNARK is Fig. 6: proof
    `(T, U, v_a, v_b)`, verifier `e(T, δ2H) = e(U, δ1τH − rδ1H)·e(v_aαG + v_bβG + v_qG, H)`.
- **Garuda.** For GR1CS (custom gates) with free linear gates and a linear-time
  prover. Proof and verifier are O(log m). The setup is circuit-specific.
  - It is implemented on arkworks. On Rescue-Prime it proves about 5× faster
    than Groth16 and 2.67× faster than HyperPlonk.
  - Proofs are 29–43× Groth16's size, and the verification key is up to
    14.78 kB (Sec. 2.7).
- **[ours] Connections.**
  - bitvm-gc's DV-SNARK (`circuits/sect233k1`, "ported from
    alpenlabs/dv-pari-circuit", and `dv_bn254`) is **designated-verifier Pari**.
    `ProofRef{commit_p, kzg_k, a0, b0}` corresponds to Pari's `(T, U, v_a, v_b)`,
    and `TrapdoorRef{tau, delta, epsilon}` is the setup trapdoor. The verifier
    replaces the pairings with a G1 relation, checked as the hinted double
    scalar multiplication `x1·G + x2·Q − z·P = 0`.
  - AADP's "Garuda-inspired" SNARK is structurally Pari.

## 6. A Note on the Security of the BitVM3 Garbling Scheme — ePrint 2025/1291

Futoransky and Barbara (Fairgate Labs), Larotonda (UBA/CONICET). 7 pp., with a
proof of concept (BitVM3-garbling-toy).

- They break the **authenticity** of RSA-based garbling:
  1. **BitVM3 [Lin25].** The rules have the form `x0 = a0^e · b0^{e1}`, with
     small public exponents. Fan-out needs adaptors. With exponents e and e2
     coprime, extended Euclid gives `b1 = (b1^e)^{k1} (b1^{e2})^{k2}`. That
     forges an input label from a 2-gate, 3-input circuit, and then the output
     label `x1` (Lemma 2, Cor. 3). "Most non-trivial circuits will suffer from
     many similar exponent collisions", and changing the circuit's topology
     doesn't help (Remark 4).
  2. **Label forward propagation [FDZ25], GOAT's scheme.** Forged through the
     output adaptors (Cor. 5).
  3. **Linear adaptors** (Linus's suggestion). The Franklin–Reiter
     related-message attack recovers `b1` (Thm. 6).
- **[ours]** It applies only to algebraic (RSA-homomorphic) labels. Hash-PRF
  garbling (free-XOR plus one ciphertext per AND, Blake3), which bitvm-gc and
  whir-gc use now, has no such label relations. This is a motivation for staying
  with hash-based garbling.

---

## 7. Our own measurements (whir-gc), for the Evaluation section

Everything was run under a cgroup cap of 32 GB and 8 cores unless noted. Raw
records are in `data/`.

- **2^18-row full STARK verifier** (Keccak-f, 1,625 columns, 22 packed
  variables; rate 1/32, folding 4, terminal security 110; composed 104.3 bits),
  from `data/run-2_18-full-verifier.txt`:
  - 94,069,548 non-free gates (94,041,082 AND and 28,466 OR), 563,964,415 XOR,
    659,074,989 wires, 1,041,024 input bits.
  - Garbled: 1,505 MB in 56.9 s on one core. At most 2,256,536 labels live at
    once. Plan pass: 21.3 s.
  - Proof: 140.0 KiB, of which 52,000 B are opened values, 72,235 B the WHIR
    opening, and 19,176 B the ring switch and zerocheck. Proving takes 5,202.5 s
    on 8 cores (586% CPU). Peak RSS is 6.1 GB, from the prover.
  - Gate profile: ring switch closing 33.6%, Merkle paths 15.5%, column
    combination 12.3%, AIR constraints 11.4%, STARK transcript 11.2%, the rest
    below 4% each.
- **Scaling table** (whir-gc README): 2^5, 2^8, 2^12, 2^16 and 2^18 rows give
  44.6M, 66.5M, 77.7M, 88.7M and 94.1M non-free gates.
- **Gadgets:**
  - `GF(2^128)` tower multiplication: 2,187 AND (3^7).
  - Blake3 compression: 10,281 AND, down from bitvm-gc's 20,657 (measured on
    bc3df6d) by using a one-AND adder. 256 B costs 41,511 and 1,072 B costs
    186,125.
- **Comparison circuits, streamed through the same garbler** (bitvm-gc
  10083d4):
  - bitvm-gc DV-SNARK (designated-verifier Pari, BN254): 481,628,790 non-free
    gates, 1.92B wires, 15.6M live at peak, 2.2 GB, 5m42s. It accepts the valid
    proof and rejects it with one bit flipped. The stored build needs more than
    64 GB.
  - Hinted double scalar multiplication (3 points): 457,933,037 non-free gates.
  - bitvm-gc `GF(2^233)` multiplication (evaluate-multiply-interpolate over
    GF(2^9)): 2,097 AND and 1,524,691 XOR.
- **Before trimming,** the README (`data/whir-gc-README-before-trim.md`) also
  recorded:
  - WHIR-only circuits: 8, 12 and 18 variables, and the effect of a Merkle cap
    (18 variables at a cap of 32 gives 21.2M).
  - Rate/folding sweep.
  - The KoalaBear/Poseidon2 comparison: one Poseidon2 permutation is
    1,240,747 AND, equal to 120 Blake3 compressions.
- **Upstream bugs found along the way,** fixed on bitvm-gc `whir-gc-upstream`:
  - `Cimp` garbling put `b1` in the ciphertext; it should be `b0`.
  - `test_fq_is_qnr_montgomery` misread its output wire.

## 7b. Added after the pre-submission review (abstracts checked on ePrint)

- **Garbling Groth16 with Native Group Operations (2026/2100).** Khambhati,
  Feickert, Lewe, Tiwari. The garbled program is 2.4 MiB including
  projectivization, against 48 GB for Boolean garbling of Groth16. This
  replaces "Boolean-garbled Groth16" as the size baseline for Groth16.
- **BitVM3: Efficient Bitcoin Bridges via Garbled Circuits (2026/933).** Linus
  Woll, Alexopoulos, Aumayr, Avarikioti, Maffei, Tse. Formalises BitVM3-CORE;
  on-chain cost is about $9, with $0.20 for the challenge.
- **Mosaic (2026/812).** Khambhati, Tiwari et al. (Alpen Labs). Maliciously
  secure cut-and-choose using polynomial label correlation; the on-chain
  footprint doesn't depend on the number of copies.
- **Antichain Winternitz (2026/1568).** Tiwari, Feickert. Reveals labels at up to
  52.9% less on-chain cost than Lamport, with 43.8 kB off-chain per bit.
- **Glock (2025/1485), primary source.** Garbled locks, using a
  designated-verifier variant of a modified Pari. The abstract gives no size; the
  "12 MB" figure is BABE's.
- **Argo MAC** is ePrint 2026/049.
- **ZKM blog, "Hash-based is not the same as post-quantum" (2026-09-03).** A
  post-quantum claim needs a stated assumption and a written reduction.

## 7c. Quantum analysis: verified inputs and measurements (2026-09-24)

- **CMS19 (ePrint 2019/834), checked in the text.** BCS applied to public-coin
  IOPs with round-by-round soundness error ε has soundness
  O(t²ε + t³/2^λ) against t-query quantum attackers.
- **WHIR (ePrint 2024/1586, EUROCRYPT 2025), checked.** §5.1 proves round-by-round
  soundness, "which ensures Fiat–Shamir and BCS security". For the sumcheck
  layers, round-by-round soundness is an *assumption* stated in the paper; still
  to be backed by a citation (e.g. CCHLRR18 for sumcheck).
- **WHIR schedule at 2^18** (term_bits 110,
  `whir_schedule_of_the_measured_configurations`):

  | round | queries | pow bits | folding pow bits |
  | --- | ---: | ---: | ---: |
  | 0 | 33 | 30 | 28 |
  | 1 | 20 | 32 | 30 |
  | 2 | 15 | 29 | 32 |
  | terminal | 12 | 27 | — |

  Starting folding pow is 26 bits.
- **Configuration ceiling** (`WHIR_GC_TERM_BITS` env override in
  `keccak_stark.rs`):
  - The profile accepts at most 134 bits per term. Queries stay the same and
    grinding rises to 51–56, its ceiling. At 200 bits it refuses:
    "Grinding { required: 103, ceiling: 56 }".
  - Plonky3's report fully assesses at most 117 bits per term: 108.6 composed,
    bound by constraint batching at 109.0, with WHIR at 111.3.
  - So about 54 quantum bits is the ceiling of the current proof system.
- **"From Cut-and-Choose to Constant-Size Proofs of Garbling Correctness":** not
  found on ePrint or in the zkMesh July recap. It is mentioned only in a search
  snippet, so it is NOT cited.

## 7d. On-chain protocol: sources and measurements (2026-09-24)

The user chose "enforceable protocol + shrink study": the operator garbles, challengers evaluate, the proof is published on-chain, and the reject label unlocks Disprove.

**Primary-source facts (PDFs in `refs/`):**
- **BitVM3 (2026/933).**
  - The operator garbles and the challenger evaluates (§1, §4.1).
  - Inputs are Schnorr adaptor signatures over 8-bit digits (§8.1): "9707 WU, or approximately 2.4 kvB" for a 128-digit (1,024-bit) proof. That is 9.48 WU/bit.
  - The printed arithmetic is inconsistent: its displayed witness formula gives
    8,901 witness bytes and 9,451 WU including SegWit marker/flag, not 9,707 WU.
    The merged 64-byte-SIGHASH_DEFAULT implementation gives 9,323 WU for the
    same one-input/two-output shell. Keep the reported figure distinct from a
    corrected implementation-backed estimate.
  - Disprove is "370 WU, or approximately 93 vB".
  - §8.1 puts Lamport at 74 B of script plus a 20 B preimage per bit, and says Lamport must be chunked because of the 1,000-item stack limit.
  - Soldering across the 7 kept instances is by VSSS (§8.2, citing Glock); it is asserted, not constructed.
  - Table 1 gives the on-chain cost as O(P).
  - Fig. 1: "Operator in 1 week".
- **Mosaic (2026/812).**
  - P garbles and V evaluates (p.8).
  - Kept copies are tied to one revelation by polynomial label correlation, with an adaptor signature revealing the missing share (abstract).
  - "The on-chain footprint is independent of ℓ and |T|" (p.23).
  - Wires are 8 bits wide. Each 8-bit wire costs 65 B of witness plus 3 B of script (Table 1).
- **Antichain Winternitz (2026/1568).**
  - §2.6: plain Winternitz lets the observer "hash forward to a smaller coordinate and recover the labels associated with another digit value".
  - §2.7: with adaptor signatures, the evaluator holding the key can spend without revealing a label.
  - Table 1:

    | (k, L) | vB/bit | table per bit |
    |---|---|---|
    | (2, 16) | 11.31 | 0.256 kB |
    | (4, 16) | 8.36 | 43.776 kB |

  - Their Lamport baseline is 17.75 vB/bit with 20-byte preimages.
- **Glock (2025/1485).** VSS plus adaptor signatures put a single signature on-chain (§3.4.2). Glock is permissioned.
- **BABE.**
  - Lamport soldering is L = KDF(s) for one instance. zk soldering reduces M sets to one (Tabs. 4–6).
  - Fees are at 2.2 sat/vB and $95,500; BitVM2's unhappy path is $14,211.

**Our measurements:**
- **Lamport script** (`data/lamport_cost.rs`, `data/run-lamport-cost.txt`). 49 B of script plus 17 B of witness per bit, with a 16-byte preimage. 998 bits fit per input (the stack limit), and wrong preimages are rejected. A modeled depth-0 one-leaf P2TR input envelope is 204 WU (base input, witness counts and lengths, and the 33-byte control block), giving 66.2 WU = 16.55 vB per bit. Transaction-global fields and outputs are not included.
- **Transaction-bound Lamport fixture** (`whir-gc/tests/lamport_tx_cost.rs`,
  `data/run-lamport-core31-regtest.sh`). Every input adds a real 64-byte
  BIP341 SIGHASH_DEFAULT signature and CHECKSIGVERIFY, uses a NUMS internal key,
  and includes the full script-path witness and transaction shell. The 174
  reveals total 17,265,635 vB (16.585 vB/input bit); full transactions are
  397,246 WU/99,312 vB and the tail is 338,636 WU/84,659 vB.
- **Transaction-bound adaptor fixture**
  (`whir-gc/tests/adaptor_tx_cost.rs`). It reproduces the merged
  implementation's 128-digit result of 9,323 WU, not BitVM3's printed 9,707
  WU. Bitcoin Core exposed a false positive in the old executor: it supplied
  the byte offset of `OP_CODESEPARATOR` as `codesep_pos`, whereas BIP342
  commits to the opcode position. The fixed fixture uses `0xffffffff` before
  the first separator and `3*i` for the separator preceding signature `i`,
  and directly verifies every completed Schnorr signature against that BIP341
  sighash rather than trusting the old interpreter result. N=998 reaches the
  exact 1,000-item peak. The global reveal optimum for
  130,128 eight-bit digits uses 133 inputs in 23 two-output transactions:
  8,888,837 WU / 2,222,213 vB. Minimizing inputs instead uses 131 inputs/26
  transactions and is 184 vB larger.
- **Transaction-bound safe ACW fixture**
  (`whir-gc/tests/antichain_tx_cost.rs`). It pins upstream at `407893d`, adds a
  real transaction-binding signature and two P2TR outputs, and executes honest,
  forged and tampered cases. D=332 is executable with peak stack 999; D=333
  fails at 1,001. The canonical all-nonzero 1,041,024-bit packing is 784 inputs
  in 131 transactions: 47,395,238 WU / 11,848,875 vB. Each zero ScriptNum
  coordinate saves one WU, so the exact data-dependent total can be smaller.
- **Strict Bitcoin Core 31.1 validation for all three fixtures.** Each fixture
  was rebound to a real signed funding transaction and replayed on an isolated
  regtest node with non-standard transactions disabled. Core rejected a reveal
  while its funding parent was unconfirmed as `too-large-cluster`; after the
  funding transaction confirmed, it accepted every reveal under strict policy
  and mined the reveal sets as follows:

  | fixture | signed funding | signed reveals | funding + reveals | reveal blocks |
  |---|---:|---:|---:|---:|
  | adaptor | 5,841 vB | 23 tx / 2,222,213 vB | 2,228,054 vB | 3 |
  | safe ACW (2,16), all-nonzero | 33,836 vB | 131 tx / 11,848,875 vB | 11,882,711 vB | 12 |
  | Lamport | 45,016 vB | 174 tx / 17,265,635 vB | 17,310,651 vB | 18 |

  Only Lamport currently has a constructed completion transaction. Core
  rejected its signed 174-parent join while the reveal parents were
  unconfirmed, then accepted and mined the 13,060-vB join after they confirmed,
  bringing the tested Lamport funding--reveal--join slice to exactly 17,323,711
  vB. The adaptor and Antichain completion transactions remain unconstructed.
  These runs establish staged standard-policy feasibility, not public-P2P
  propagation, robust fee management or the missing
  challenge/timeout/Disprove/anchor and soldering graph.
- **Input bits** (`whir-gc/tests/keccak_stark.rs`: `input_bits_of_whir_configurations`; `data/run-input-bits-sweep.txt`).
  - The analytic count equals the measured inputs at 2^5 through 2^18.
  - At 2^18 the split is: opened values 416,000; zerocheck 9,344; ring switch 54,912; WHIR caps 32,768; leaf rows 163,840; Merkle paths 346,624; WHIR other 17,536.
  - The smallest in the sweep is rate 1/256, folding 4, pow budget 48: queries 16/12/9/8, 845,952 bits, 103.89 bits composed, nothing unassessed.
- **Costs at 2^18** (2.2 sat/vB, $95,500):

  | scheme | accounted component | serialized transactions | fee equivalent |
  |---|---|---|---|
  | adaptor | 2.222213 MvB | 23 | 0.04889 BTC, $4,669 |
  | safe ACW (2,16), all-nonzero | 11.848875 MvB | 131 | 0.26068 BTC, $24,894 |
  | Lamport reveals | 17.265635 MvB | 174 | 0.37984 BTC, $36,275 |

- **Translation ciphertexts.** 32 B per input bit per instance, 33 MB per instance at 2^18. Derived, not measured.
- **Open item.** Hash-based soldering to M kept instances at a million input bits is not built.

## 7e. Garbling efficiency (2026-09-25)

The user asked for garbling efficiency η = |GC| / (rows × committed columns), in bytes per committed cell. |GC| is 16 B per non-free gate, and there are 1,625 columns of one bit each.

| rows | η (bytes per cell) |
|---|---|
| 2^5 | 13,715 |
| 2^8 | 2,556 |
| 2^12 | 186.9 |
| 2^16 | 13.32 |
| 2^18 | 3.53 |
| 2^20 | 0.94 |

At 2^20 that is 7.5 garbled bits per trace bit, or 38 kB per Keccak-f. Smaller is better. It falls roughly as 1/R, because |GC| grows only with log R.

## 7f. Reducing the on-chain input (2026-09-29)

The input-authentication component is not the total on-chain cost. Total
on-chain footprint is the serialized virtual size of every transaction in the
dispute graph, including ordinary signatures, authentication witnesses,
scripts, controls, transaction I/O, anchors, timeouts and fee management. The
signed adaptor, safe-Antichain and Lamport funding--reveal slices have all been
accepted under Bitcoin Core 31.1 strict policy after funding confirmation, but
the complete graph has not. The three principal comparison rows have executable
complete signed reveal-transaction fixtures: adaptor and safe Antichain use two
P2TR outputs per transaction, whereas Lamport uses one. Only Lamport also has a
constructed and Core-tested join. Source rates remain provenance rather than
final results.

**Why the cost is per bit.** A garbled circuit needs a *label* per input bit, and only the garbler (the operator) can release it. So making the proof data available is not enough. ESSPI (arXiv 2503.02772) publishes data 1:1 under a Schnorr signature, but that works for BitVMX, where the dispute needs only the data. It does not give labels.

**Fewer bits** (`input_bits_of_candidate_statements` in `whir-gc/tests/keccak_stark.rs`; log in local `data/run-input-bits-candidates.txt`). The model equals the measured count on the measured statement. Smallest input over rates 1/8–1/256, folding 3–5 and grinding up to 48 bits:

| statement | WHIR term | bits, 256-bit digests | bits, 2λ-bit digests |
|---|---|---|---|
| Keccak AIR, 1,625 columns, 2^18 rows (measured configuration) | 110 | 1,041,024 | – |
| same, tuned | 110 | 845,952 | 797,952 |
| 512 columns, 2^18 rows | 110 | 526,208 | 493,280 |
| 128 columns, 2^18 rows | 110 | 362,496 | 329,664 |
| 128 columns, 2^18 rows | 100 | 332,288 | 298,352 |
| 128 columns, 2^18 rows | 80 | 250,496 | 213,248 |
| 32 columns, 2^16 rows | 110 | 245,888 | 226,112 |

- Opened values cost 256 bits per column. The zerocheck and ring switch are about 62k bits whatever the statement; 49k of that is the three 128×128 tensors.
- The narrow statements stand for a recursion AIR that does not exist yet. Its width and height are assumptions.
- Truncated digests need a Plonky3 change.
- Only the WHIR terms are set to the target here. The composed soundness of a new AIR is not assessed.

**Cheaper bits.**

| scheme | vB per bit | source | assumption | off-chain |
|---|---|---|---|---|
| Lamport | 16.59 | Core-tested complete signed 174-reveal set after funding confirmation | hash plus non-PQ tx authorization | 32 B per bit per instance |
| Antichain Winternitz (2,16) | 11.38 | Core-tested all-nonzero full signed transaction set after funding confirmation | hash plus non-PQ tx authorization | 0.256 kB per bit |
| Antichain Winternitz (4,16) | 8.36 | 2026/1568 Table 1, marginal rate | hash | 43.8 kB per bit |
| Winternitz + translation gadget | 7.38 | 2026/1684: Assert of 508 bits is 3,748 vB | hash | table quadratic per chunk; about 1.9 MiB per 127-bit chunk per instance [derived from their 97.93 vs 45.57 MiB over 28 chunk tables] |
| Schnorr adaptor, 8-bit digits | 2.37 | 2026/933 §8.1, complete 1,024-bit Assert tx rate | discrete log | 256 adaptors of 65 B per byte |
| Schnorr adaptor, packed fixture | 2.13 | Core-tested 133-input/23-transaction full signed set after funding confirmation | discrete log | one completed adaptor per byte |

**Input-component projections, at the historical 2.2 sat/vB and $95,500 (not total dispute fees):**

These rows are not like-for-like protocol totals. The Lamport and packed-adaptor
columns scale complete signed reveal-set measurements, whereas the
Winternitz-plus-translation column scales a source-reported Assert rate whose
ordinary transaction authorization and complete graph boundary are not
normalized to the fixtures here.

| input | Lamport | Winternitz + translation | adaptor |
|---|---|---|---|
| 1,041,024 (today) | 17.27 MvB, $36,275 | 7.7 MvB, $16,100 | 2.22 MvB, $4,669 |
| 845,952 (tuned) | 14.0 MvB | 6.2 MvB, $13,100 | about 1.81 MvB, $3,794 |
| 329,664 (128 col, 110-bit, short digests) | 5.5 MvB | 2.4 MvB, $5,100 | about 0.70 MvB, $1,479 |
| 213,248 (128 col, 80-bit) | 3.5 MvB | 1.6 MvB, $3,300 | about 0.46 MvB, $956 |

**Not solved.**
- Revealing only a slice of the proof (chunked sub-circuits) needs the challenger to know which slice is wrong, so it needs the proof data. Script cannot bind raw on-chain data to the signed chunk digests without OP_CAT or an in-script hash. A cheating operator can therefore publish garbage data, and the worst case stays the full reveal.
- A short on-chain digest with labels derived from it is laconic OT or witness encryption. Known constructions are DDH- or pairing-based, not hash-based.

## 7g. Winternitz reveal: measured cost and the one-transaction goal (2026-09-29)

**Scope.** The user set two constraints: only Winternitz-style input encodings (no recursion, no proof-format change in this repo), and the goal of fitting the input reveal in a single transaction.

**Measured** (`whir-gc/tests/winternitz_cost.rs`; log in local `data/run-winternitz-cost.txt`). The script is the compact form: a hash ladder with every intermediate kept, the digit picking the one compared with the public key, and one checksum per input. It was executed with the stack limit on, and a raised digit is rejected.

| digit bits | chains per input | script B/chain | witness B/chain | WU per bit | bits in 400k WU | bits in 4M WU |
|---|---|---|---|---|---|---|
| 2 | 491 + 6 | 38.1 | 22.7 | 31.01 | 12,766 | 128,642 |
| 3 | 491 + 4 | 48.1 | 22.9 | 23.99 | 16,203 | 166,449 |
| 4 | 487 + 4 | 68.1 | 22.9 | 23.06 | 15,584 | 173,372 |
| 5 | 480 + 3 | 109.1 | 23.0 | 26.67 | 14,400 | 148,800 |
| 6 | 464 + 3 | 189.1 | 23.0 | 35.66 | 11,136 | 111,360 |

**Against the goal.**
- The best is 4-bit digits at 23.06 WU per bit (5.77 vB). Per chain, 44 B cannot be removed (20-byte key, 20-byte signature, their push bytes, the digit). The ladder costs 2 B per hash step, so larger digits cost more per bit.
- 1,041,024 bits need 24.0M WU: 6 blocks, or 61 standard transactions.
- One transaction needs at most 3.84 WU per bit for a block-size transaction, or 0.38 for a standard one.
- So one transaction holds at most 173,372 bits (consensus limit, non-standard) or 15,584 bits (standard).

**The 2026/1684 layout, measured** (`chunked_winternitz_reveal_cost_per_bit`). Chunks of 32 four-bit message digits, each with a 4-bit and a 5-bit checksum chain (34 chains per 128 bits); 14 chunks per transaction input, peak stack 969.
- 24.71 WU per bit (6.18 vB). For 1,041,024 bits that is 25.7M WU, 2.68× less than the historical unsigned Lamport envelope model (66.2 WU per bit, 68.9M WU). The current transaction-bound signed fixture is 69,062,194 WU and is reported separately above.
- The paper's own Assert is 14,990 WU for 508 bits, 29.5 WU per bit, against 72.8 for its Lamport baseline: 2.47×.
- Digits from 8 bits up were first counted at 2 witness bytes; values of 128 and above take 3. Fixed; only the 8-bit row moved (87.43 to 87.49 WU per bit).
- Off-chain tables: about 14.9 GiB per instance at 1,041,024 bits [derived from the paper's 1.87 MiB per chunk].
- In the paper's BABE integration every kept circuit gets its own on-chain signature (1 + 7 sets). One signature serving all kept instances is the soldering problem, still open for hash-based keys.

## 7h. Rejected prototype: unverified witness, verified on demand (corrected 2026-09-30)

The `unverified_reveal_and_response_on_demand` test remains a historical
capacity model, not a feasible Assert construction. Its earlier conclusion was
wrong for three independent reasons:

- It passes 998 520-byte values as initial Tapscript witness items. Bitcoin
  Core 31.1 standard policy limits each such item to 80 bytes, so the modeled
  spend is non-standard even when its total weight is below the consensus
  limit.
- The drop-only script has no transaction authorization. Anyone can replace
  the witness and redirect the outputs.
- Adding `CHECKSIG` does not fix the data binding. BIP341 commits to the
  transaction and tapleaf, not ordinary witness arguments. A third party can
  replace the dropped payload while preserving the txid and valid signature;
  a child Script also cannot inspect the parent's witness. The annex is signed
  but non-standard and does not provide child introspection.

Consequently, a response containing a different valid opening does not merely
hurt the operator: the first payload can be arbitrary garbage, and no Script
condition proves that the later response opens the same chunk. The 4--8-bit
tables in `run-winternitz-cost.txt` measure byte arithmetic only and must not be
quoted as a standard or secure on-chain protocol.

The current-consensus way to bind bulk data is an ESSPI-style P2TR envelope:
put the payload in a skipped branch of the revealed tapscript, so the TapLeaf
hash/P2TR output commits to it, and require a transaction signature. Our exact
130,128-byte fixture is a 32,850-vB reveal plus a 154-vB wallet-signed commit.
Strict Core 31.1 accepts the unconfirmed parent-child pair and confirms both in
one empty-regtest block. The **33,004-vB result is authenticated transport, not
a complete Assert**: ESSPI's DA-DAG, secondary BitVMX instance, fraud paths,
bonds, timeouts and settlement remain outside it, and raw proof bytes do not
provide the selected input labels required by this garbled verifier.

## 7i. Wider adaptor digits and pointlock (2026-09-30)

The exact serialized adaptor sweep for the 1,041,024-bit input is:

| bits/digit | digits | inputs | reveal tx | reveal vB | funding + reveal vB | 65-B choice table/keyset |
|---:|---:|---:|---:|---:|---:|---:|
| 8 | 130,128 | 133 | 23 | 2,222,213 | 2,228,054 | 2.165 GB |
| 10 | 104,103 | 107 | 18 | 1,777,775 | 1,782,498 | 6.929 GB |
| 11 | 94,639 | 97 | 17 | 1,616,206 | 1,620,499 | 12.598 GB |
| 12 | 86,752 | 89 | 15 | 1,481,461 | 1,485,410 | 23.097 GB |
| 16 | 65,064 | 66 | 12 | 1,111,128 | 1,114,088 | 277.162 GB |

The 8/10/11/12/16-bit transaction shapes are exact serialization tests. The
16-bit row additionally uses real completed BIP340 signatures and passed strict
Core 31.1 policy: a 2,960-vB funding transaction with 66 protocol P2TR outputs
plus one wallet-change output, followed by twelve
reveals, mined in two reveal blocks after funding confirmation. A full reveal
could not be admitted with the unconfirmed funding parent because their cluster
exceeded 101 kvB.

This only establishes the on-chain encoding. It does not instantiate all
`2^16` choices or prove how one digit secret releases exactly the corresponding
16 binary GC labels. The 277.162-GB figure is one independent keyset's simple
`digits * 2^16 * 65` table; multiplication by seven is valid only for seven
independent tables, not an implemented Mosaic-correlated construction. The
10/11-bit rows are the preferred next implementation points.

For Disprove, the corrected fixture uses this implementation's actual 16-byte
garbled output label. With the same timeout sibling, a SHA256 hashlock spend is
386 WU / 97 vB and a false-label-derived Taproot key-path pointlock is 332 WU /
83 vB. Both passed strict Core 31.1 policy, so the fair saving is 54 WU / 14 vB.
The pointlock adds a discrete-log assumption, hides the label on chain and does
not by itself constrain outputs; use a public adaptor presignature or covenant
if fixed slashing outputs or secret extraction are required.

The complete comparison, evidence levels and soft-fork alternatives are in
`assert-disprove-reduction-survey.md`.

## 7j. A hash-based stand-in for the Schnorr adaptor (2026-10-01)

**Question.** The adaptor rows in §7d/§7i are the cheapest input publication
but rest on discrete log. `whir-gc/tests/pq_selector_cost.rs` (n=16) and
`pq_selector_n24_cost.rs` (n=24) model the hash-based replacement: what does
the adaptor's job cost once secp256k1 is removed, and what does it still need?
Both were rerun today; log in `data/run-pq-selector-cost.txt`.

**What the fixtures build.** Each 4-bit digit d is encoded as the pair
(d, 15-d) over two independent 15-step hash chains; a record holds the two
chain nodes per nibble plus the clear bytes. One record covers 64 bits (n=16,
520 B) or 96 bits (n=24, 1,164 B). A batch of records is committed by a Merkle
root over the chain *endpoints* (fixed before the input is known), and one
94-B (n=16) or 118-B (n=24) leaf per transaction carries a SHRINCS key,
CHECKSIGVERIFY, the root, the first record index, the count, and a
hypothetical `OP_CHECKBATCHPAIRSELECT` that re-derives every endpoint from the
openings. The stack is BIP360 P2MR, leaf 0xC2, 6,000-B items.

| variant | records | tx (funding + reveals) | billed vB | vB/bit | vs 8-bit adaptor 2,228,054 vB |
|---|---:|---:|---:|---:|---:|
| n=16, one record per item | 16,266 x 520 B | 1 + 22 | 2,133,778 | 2.050 | -4.23% |
| n=16, canonical 11-record blobs | same | 1 + 22 | 2,122,693 | 2.039 | -4.73% |
| n=24, canonical 5-record blobs | 10,844 x 1,164 B | 1 + 32 | 3,172,934 | 3.048 | +42.4% |
| n=24, one record per item | same | 1 + 32 | 3,179,422 | 3.054 | +42.7% |

- **The n=16 payload is byte-identical to the adaptor's.** 130,128 x 65 B =
  16,266 x 520 B = 8,458,320 B. Two 16-B nodes per nibble is 8 B/bit; one
  65-B completion per byte is 8.125 B/bit. The 4.7% saving is the removal of
  the per-digit scripts (394,507 WU in the adaptor reveal) and the lighter
  framing (3 B per 520-B record instead of 1 B per 65-B item). Nothing else
  moves.
- **Evidence level is E2 for serialization and E4 for consensus.** rust-bitcoin
  serializes the shells exactly, the pair code, endpoint root and canonical
  blob parser are tested with negatives (tampering, reordering, cross-batch
  splices, padding, wrong split), and the 400k-WU packing boundaries are exact
  (762/763 records at n=16; 341/342 at n=24). But P2MR and 0xC2 are drafts,
  SHRINCS bytes are placeholders, 0x03 for a custom n=24 SHRINCS is a reserved
  flag, and the opcode does not exist. No Core replay is possible.
- **The one-signature-per-transaction assumption is the same as for the
  adaptor fixture.** A 548-B SHRINCS item instead of a 64-B Schnorr signature
  costs 23 x 487 WU, about 0.13%. An n-of-n 0xC2 committee would add one such
  item per member per transaction; the fixtures deliberately exclude it.

**Security of the pair code, as tested.** (d, 15-d) is a constant-sum
antichain: from the opening of d one can forward-hash to any (d', e') with
d' <= d and e' <= 15-d, and the only valid codeword in that cone is (d, 15-d).
So a single opening cannot be re-targeted. It is strictly one-time: two
openings a <= b of the same pair key let anyone derive every v in [a, b]
(`two_openings_of_one_pair_key_span_the_whole_interval`). The on-chain layer
enforces one-time use only because each record index appears once under one
root; the operator must never reuse a pair key across instances.

**Quantum level of the chain nodes.** Forging a different digit from a
published opening needs a second preimage of a known chain node. Known nodes
across the input are about 2^22 (520k chains, roughly 8.5 known nodes each),
so the multi-target estimate is:

| n | node bits | single-target quantum | multi-target classical / quantum |
|---:|---:|---:|---|
| 16 | 128 | 64 | about 2^106 / 2^53 |
| 24 | 192 | 96 | about 2^170 / 2^85 |
| 32 | 256 | 128 | about 2^234 / 2^117 |

n=16 sits at the same 53-bit level as the Lamport row in `tab:pq`, which is
the proof system's own 52-bit bottleneck, so it is "no worse than the rest" but
not a post-quantum parameter. n=24 is the first width above the 80s; n=32 is
what the paper's λ_Q = 100 column asks for.

**Projection over (n, k).** A model with payload 2n/k + 1/8 B per bit, 3-B
framing per 6,000-B item, 1,059 WU plus leaf growth per transaction and the
measured funding shell reproduces the exact fixtures within 0.03%
(2,122,619 vs 2,122,693; 3,172,251 vs 3,172,934). Changing the digit width k
changes the chain length to 2^k - 1:

| n | k | payload B/bit | reveal tx | est. total vB | vs adaptor | hashes per digit, worst case |
|---:|---:|---:|---:|---:|---:|---:|
| 16 | 4 | 8.125 | 22 | 2.12 M | -4.7% | 30 |
| 16 | 8 | 4.125 | 11 | 1.08 M | -51.6% | 510 |
| 24 | 4 | 12.125 | 32 | 3.17 M | +42.4% | 30 |
| 24 | 8 | 6.125 | 17 | 1.60 M | -28.0% | 510 |
| 32 | 4 | 16.125 | 43 | 4.23 M | +89.7% | 30 |
| 32 | 8 | 8.125 | 22 | 2.13 M | -4.4% | 510 |

The useful row is **n=32, k=8**: full 256-bit nodes, 117 quantum bits
multi-target, and the same 2.13 MvB as the Schnorr adaptor. The price is
moved into the opcode: up to 510 hash steps per byte, about 66M SHA-256
compressions for the whole input and about 3M per full reveal, against about
7.8M total at k=4. Whether that fits a 0xC2 varops budget is the open
consensus question; the setup cost is unchanged (one 2-node pair key per
digit, no 2^k table), which is the structural advantage over the wider
adaptor's 2^k choice table (§7i).

**What the selector does not do, same as the wider adaptor.** An opening of
digit d releases a hash node, not GC labels. The evaluator still needs the k
binary input labels for d and must not be able to obtain any label of the
complement. The construction that fits is the translation table of §7f and
2026/1684: for each digit and each of the 2^k values, the operator encrypts
the k selected labels under KDF(node_A(d) || node_B(15-d)); the antichain
guarantees only one key is derivable from the on-chain record. At k=4 that is
16 x 4 x 16 B = 1 KB per digit, 266 MB per instance for 260,256 digits; at
k=8 it is 256 x 8 x 16 B = 32 KB per digit, 4.3 GB per instance. The tables
are checked by the cut-and-choose on opened instances and bound to the kept
ones by the soldering that is still unbuilt (§7d open item). None of this is
in the fixtures, so the rows above are input-authentication transport, not a
label-delivery protocol, exactly as the survey says of the 10/11/16-bit
adaptor rows.

**Against the current-consensus hash-based rows.** The same pair code
verified in Script instead of a native opcode is the 4-bit Winternitz ladder
of §7g (23.06 WU per bit, 5.77 vB/bit, about 6.0 MvB) or the safe ACW (2,16)
fixture (11.38 vB/bit, 11.88 MvB). The opcode removes the 2 B of script per
hash step, which is 2.8x and 5.5x. That is the entire case for the soft fork
here: without it a hash-based input costs 2.7 to 5.6 times the adaptor; with
it the hash-based input costs the same as the adaptor at n=32, k=8.

**Judgement.** The selector fixtures answer the §7f question "is the 2.1 MvB
adaptor rate reachable without discrete log": yes on paper, at n=32 and k=8,
under BIP360 plus a new opcode, with the label-delivery table and soldering
still to build. In the paper they belong in the soft-fork column of the
survey's table 8 next to MATT and the native verifier, as the row "keep the
GC, replace only the input authentication". They do not change the
current-consensus conclusion (10/11-bit adaptor next), and they do not change
`tab:pq`: the composed protocol stays bound by the 52-bit proof system and by
pre-signed-graph authorization, which SHRINCS-in-0xC2 would address only once
it exists.

**In the paper (2026-10-01).** §sec:protocol now opens the input discussion
with a "Label selection" paragraph (deliver / exclusive / binding / public),
two TikZ interaction diagrams with lifelines for the garbler/prover, Bitcoin
Script and the evaluator/challenger: `fig:adaptorseq` (Schnorr adaptor:
choice table, pre-signatures, completion, CHECKSIG, extraction, Disprove) and
`fig:hashseq` (pair-complement hash chains with translation ciphertexts; no
evaluator contribution at setup; separate transaction signature), a paragraph "A post-quantum instantiation" and Table `tab:pqsel`
with the rows above. The BIP360 URL in the footnote is from memory and must be
checked; SHRINCS is named without a citation because no stable reference was
verified.

## 7k. The statement as a Ziren compressed proof: measured (2026-10-01)

The user's position: the deployed statement is a recursion proof, and the
recursion is prover-side. To replace the assumed narrow-AIR numbers of §7f with
a real proof, a compressed proof was generated with Ziren (`/data/stephen/Ziren`,
`da7e1f2c`, Plonky3 `4dd0d47a`) for `examples/fibonacci` (n = 500) on the CPU
prover: 4 core shards, 6 recursion shards, 3:33 wall on 8 cores, 20.7 GB peak.
Logs and the two census binaries are in `data/` (`run-ziren-*`,
`ziren_*_census.rs`).

**The verifier is a different verifier.** A compressed Ziren proof is a shard
proof of the compress machine: KoalaBear (p = 2^31 - 2^24 + 1), degree-4
extension, Poseidon2 (width 16, rate 8) Merkle trees and transcript, LogUp-GKR,
a zerocheck, and a jagged-over-WHIR opening with 124/88/85 queries at rates
2^-2/2^-5/2^-8 and 22 bits of query grinding. Our whir-gc verifier (F_{2^128},
Blake3, Plonky3's WHIR) cannot evaluate it. A garbled verifier for it is a new
circuit; the point of the census is to size that circuit and its input.

**The proof, counted.** 191,215 base field elements, 5,927,665 bits at 31 bits
each, 846,439 bytes as bincode. That is 5.7 times the 1,041,024-bit input of
the Keccak verifier, not smaller.

| component | elements | share |
|---|---:|---:|
| WHIR query openings: 7,646 sibling digests of 8 plus 421 leaves of 256 | 169,687 | 89% |
| LogUp-GKR (21 layers, 2,373 sumcheck polynomials, chip openings) | 12,525 | 7% |
| opened values (main 1,624, preprocessed 692, quotient 736) | 3,204 | 2% |
| jagged eval, reduction, packing, y per chip | 4,510 | 2% |
| zerocheck, public values, commitments, heights | about 1,300 | 1% |

The Merkle paths dominate: 248 leaves at depth 20 (two stripe trees times 124
queries), 88 at depth 17, 85 at depth 14. Each sibling is 8 elements (248
bits) and each leaf 256 elements (7,936 bits). Query count and leaf width are
what make this proof large; the recursion AIR's width (579 columns across
eight chips) contributes only the 3,204 opened values.

**The verifier, counted.** From the proof structure and from the compress
root's own trace (its chip heights are the cost of verifying its children
in-circuit: Poseidon2Wide 42,624 rows, ExtAlu 168,448, BaseAlu 103,392, Select
122,560, MemoryVar 151,840 for two children):

| verifier work | count | AND gates at measured gadget cost |
|---|---:|---:|
| Poseidon2 permutations: 7,646 Merkle compressions, 13,472 leaf-row hashes, about 3,800 transcript | about 24,900 | 3.1 x 10^10 at 1,240,747 each |
| extension multiplications: folds, batch combination, sumchecks, constraint evaluation | about 63,000 | 3.8 x 10^9 at 60,615 each |
| total | | about 3.5 x 10^10, about 555 GB garbled at 16 B per gate |

The compress machine's constraints are small (410 constraints, 884
multiplication nodes over 579 columns; `run-ziren-compress-machine-census.txt`)
and are evaluated once at the zerocheck point, so they are not the cost. The
cost is Poseidon2 over a prime field in Boolean gates: 120 Blake3 compressions
per permutation (paper, "Why a binary field"). This is 370 times our 2^18
Keccak verifier (94.1M non-free gates, 1.5 GB) and matches the paper's earlier
estimate of 3.1 x 10^9 gates for a single 2^20 KoalaBear WHIR opening, scaled
by the ten times more Merkle work of three query rounds at 124/88/85 queries.

**On-chain, if published as GC input.** 5.93 Mbit at the measured rates:
adaptor 12.7 MvB, batch opcode 12.2 MvB, WOTS plus translation 43.7 MvB, ACW
67.5 MvB, Lamport 98.3 MvB. All worse than the Keccak AIR by 5.7 times.

**Conclusion.** Taking Ziren's compressed proof as the statement does not give
the 210k-430k-bit input of §7f's narrow-AIR assumption; it gives 5.9 Mbit and a
verifier 370 times larger than the one we garble. Both come from the proof
system choices that make Ziren fast on GPUs: a 31-bit prime field with
Poseidon2 hashing, low-rate codes with 124 queries, and 8-element digests. For
the garbled verifier the statement must be re-encoded by a final wrap stage,
prover-side, into the proof system the garbler is built for: binary field,
Blake3 Merkle trees, high-rate WHIR with few queries, 16-byte digests. Ziren
already has such a stage for BN254 (shrink then wrap). A "wrap to binary WHIR"
stage would make the garbled verifier's statement the wrap AIR, whose width and
height set the input per §7f; that AIR has to verify a KoalaBear Poseidon2
shrink proof inside F_{2^128}, which is the prover-side cost to measure next.
What this session established is the size of the alternative: garbling Ziren's
own compress verifier directly is 555 GB of circuit and 12 MvB of input.

## 7l. Reducing the on-chain data of a recursion-proof statement (2026-10-01)

Starting point: the measured Ziren compressed proof (§7k), 191,215 elements,
5.93 Mbit, 12.7 MvB with adaptors. `data/ziren_whir_model.py` rebuilds its
WHIR part from the round structure (lsh 21, folds 3/6/6, final 6, two stripe
trees of 32 columns in round 0, queries solved for 106 bits per component) and
matches the measurement within 0.1%. Levers, applied cumulatively:

| change | total elements | bits | adaptor | ACW (2,16) |
|---|---:|---:|---:|---:|
| measured: rate 1/4, unique decoding, 22-bit grind | 191,404 | 5.93 M | 12.70 MvB | 67.5 MvB |
| Johnson-bound list decoding | 113,404 | 3.52 M | 7.52 | 40.0 |
| + 48-bit query grinding | 85,644 | 2.65 M | 5.68 | 30.2 |
| + starting rate 1/256 | 44,964 | 1.39 M | 2.98 | 15.9 |
| + folds 3/4/4/4 | 43,340 | 1.34 M | 2.88 | 15.3 |
| + 217-bit digests | 41,908 | 1.30 M | 2.78 | 14.8 |
| + no LogUp-GKR in the wrap | 29,383 | 0.91 M | 1.95 | 10.4 |
| capacity conjecture instead of Johnson (not cumulative with the GKR row) | 32,978 | 1.02 M | 2.19 | 11.6 |

Findings:
- The measured size is a prover-speed choice. Ziren works in the unique
  decoding regime at rate 1/4, where a query is worth 0.68 bits; 124 + 88 + 85
  queries with 256-element leaves are 89% of the proof. Proven list decoding
  and rate 1/256 cut the WHIR part from 169,876 to 23,436 elements (7.2x).
  Those two changes are the bulk of the reduction; folding and digest width are
  a further 13%.
- Grinding is weak for a quantum target: 48 bits of grinding are 24 quantum
  bits. Under the paper's post-quantum framing, the rate change is the lever to
  rely on, and the grinding row should be read as classical only.
- After the WHIR changes, the non-WHIR part (21,528 elements, 0.67 Mbit) is
  half the proof. LogUp-GKR alone is 12,525 elements (21 layers of sumcheck).
  A final wrap of a fixed-shape proof does not need a lookup argument across
  chips; without it the proof is 0.91 Mbit. The jagged round-0 leaves (32
  stripes x 8 positions = 256 elements per leaf, two trees) are the next
  largest item at 7,680 elements.
- What is left at 0.91 Mbit is a jagged multi-chip proof. The binary-field
  narrow-AIR sweep (§7f, `run-input-bits-candidates.txt`) gives 0.25-0.43 Mbit
  for a single plain AIR of 32-128 columns at the same 110-bit terms. So the
  last factor of 2-3 comes from making the wrap a single plain AIR, which is
  also what makes the garbled verifier cheap (binary field, Blake3; §7k).
- Merkle-path deduplication is not a lever once tree caps are used: the
  frontier simulation (`run-merkle-frontier-sim.txt`) saves 1.35% of path
  digests, 0.45% of the input, and a data-dependent multiproof shape does not
  fit a fixed garbled circuit anyway.

The order of magnitude by stage, for one key set:

| stage | input | adaptor | translation gadget | ACW |
|---|---:|---:|---:|---:|
| Ziren compressed proof as is | 5.93 Mbit | 12.7 MvB | 43.7 MvB | 67.5 MvB |
| re-proved with list decoding, rate 1/256, no GKR | 0.91 Mbit | 1.95 MvB | 6.7 MvB | 10.4 MvB |
| single plain binary-field wrap AIR, 128 columns, 2^18 | 0.36 Mbit | 0.78 MvB | 2.7 MvB | 4.1 MvB |
| same at 80-bit terms | 0.25 Mbit | 0.54 MvB | 1.8 MvB | 2.9 MvB |

Multiplied by 7 without soldering in every column. The architectural levers
(raw envelope at 0.032 vB/bit, interactive segment disputes, MATT-style trace
commitments) are unchanged from §7f and the survey: each removes the label
publication only by replacing the garbled-circuit dispute.

## 7m. The Ziren compressed-proof verifier, garbled: measured (2026-10-01)

**What was built.** `whir-gc/src/ziren.rs` translates Ziren's `shrink` recursion
program, the in-circuit verifier of one compressed proof, into a Boolean
circuit instruction by instruction. The program was dumped from Ziren
(`data/ziren_dump_shrink.rs`) for the compressed fibonacci proof of §7k; it
runs and accepts in Ziren's runtime. 1,024,796 instructions: 579,405 extension
ALU (247,934 multiplications, 312 inversions), 203,556 base ALU, 141,020
witness words, 61,280 selects, 23,292 Poseidon2 permutations, 941 bit
decompositions.

- Semantics follow the AIR, not the runtime: asserting divisions become the
  check `in2 != 0 or in1 = 0` (no inversion); computing divisions invert by an
  addition chain (48 squarings, 6 multiplications) and use the norm to
  `F[y]/(y^2-3)` for the extension; selects use a 31-AND multiplexer when the
  bit is a decomposition output and the field formula otherwise; constant
  reads and the 231 committed public values are equality checks; every witness
  word is checked canonical. The output is the AND of all checks.
- Multiplicities count constrained reads only: a bit decomposition reads its
  input unconstrained, so a `mult = 0` result is still computed (found when the
  first build read an unwritten address).
- Ziren's Poseidon2 uses its own round constants (`zkm_primitives::RC_16_30`,
  reduced mod p), not this repo's `poseidon2` crate; they are in
  `whir-gc/src/ziren_constants.rs` and checked against a test vector from the
  program's permutation.
- Witness typing: a word is an extension element only where the honest
  layout holds one (14,966 of 141,020); base-field words have their upper
  limbs fixed to zero, a subset of what the AIR accepts. The first count gave
  every extension-read word four limbs, 11.73 Mbit of input and 40.65 B gates.

**Merkle deduplication, implemented.** The translator finds each Merkle level
(eight selects on one bit feeding one compression), chains levels into paths
and groups them by root: five trees, 124 + 124 paths of depth 20, 88 of depth
17, 85 of depth 14, and the one-path vk allowlist (not deduplicated). For each
multi-path tree the sibling witnesses are replaced by a fixed frontier
(mean + 8 sd of the need count for uniform indices: 1,750 / 1,750 / 1,040 /
750 digests; the real proof needs 1,625 / 1,625 / 939 / 657). Before the first
path: per pair of paths and level, a "same parent" flag; a need flag per
(path, level); a prefix count; an LSB-first compaction network on the metadata
(no collisions in 20,000 random patterns and on the real proof) and its
reverse on the frontier data. Per level the sibling is the frontier digest if
needed, otherwise the node or sibling of an earlier path with the same parent.
Every path is still hashed to its root and compared, so routing affects
completeness only.

**Measured** (`data/run-ziren-gc-count-full.txt`,
`data/run-ziren-gc-eval-dedup.txt`; exact counts with the folding rules of
`CircuitAdapter`/`Streaming`):

| | full paths | deduplicated |
|---|---:|---:|
| non-free gates | 37,901,356,001 | 38,339,147,832 (+1.16%) |
| AND / OR | 35.12 B / 2.78 B | 35.35 B / 2.99 B |
| XOR | 113.10 B | 113.14 B |
| wires | 151.0 B | 151.5 B |
| garbled, 16 B per non-free gate | 606.4 GB | 613.4 GB |
| input bits | 5,763,458 | 5,179,170 (-10.1%) |

Profile of the full-path circuit: Poseidon2 31.44 B (82.95%, 1.35 M per
permutation under Ziren's constants), extension multiplication 6.26 B
(16.52%), everything else 0.53%. Deduplication adds 417 M gates of sibling
routing and 22 M of prologue, and removes 2,356 sibling digests (584,288 bits).

**Correctness.** The deduplicated circuit was evaluated gate by gate on the
real proof (151.5 B wires, 5,030 s): output true, and every value written by
every instruction equals Ziren's runtime semantics (0 mismatches). With witness word 70,510 changed by one, the same
circuit outputs false. The whole test, honest and tampered, took 2:38:38
wall on one core with a 16.3 GB peak.

**Garbling.** The pinned streaming garbler needs a byte per wire for its
liveness plan, 151 GB here, so the whole circuit was counted and evaluated,
not garbled. A real 220,000-instruction prefix (931.6 M non-free gates) was
garbled with random Δ and Blake3 half-gates and self-checked in 478 s: 1.95 M
non-free gates per second per core, peak 7.3 M live wires
(`data/run-ziren-gc-garble-prefix.txt`). At that rate one instance is about
5.4 core-hours, and cut-and-choose at (181, 7) is about 980 core-hours, with
4.3 TB stored by a challenger for the seven kept instances.

**Against the paper's verifier.** 38.3 B against 94.1 M non-free gates for the
2^18 Keccak WHIR verifier: 407 times larger, 613 GB against 1.5 GB per
instance, for an input that is 5.0 times larger (5.18 Mbit against 1.04
Mbit). The cost is Poseidon2 over a prime field in Boolean gates; the
wrap-to-binary-WHIR stage of §7l is what removes both.

## 7n. Ziren's binary stage and narrow recursion, garbled: measured (2026-10-03)

**The pipeline.** Ziren's `feat/binary-whir-blake3` (eigmax) adds two stages
after shrink: `shrink_blake3` (the shrink proof committed with Blake3) and
`shrink_binary`, which proves the recursion program verifying it over
GF(2^128) with Boolean WHIR and Blake3. `binary-recursion` records the binary
stage's verifier, Plonky3's own, as a straight-line tape over GF(2^128) (the
Wiedemann tower, the field of `whir-gc/src/tower.rs`). At `ee5ca380` (local,
unpushed) it also adds the **narrow recursion**: a five-table `TapeMachine`
(ledger, arith, rewire, hash, Blake3 rounds) proves a run of a recorded tape
under the binary stage's own configuration, and that proof's verifier is
recorded again. Level 1 is the binary stage's verifier; level 2 is the tape
machine's verifier on the narrow proof of level 1.

**Translation.** `whir-gc/src/binary_tape.rs` translates a tape op by op with
the semantics of the tape's own `run`: `Add`/`Square`/rewiring are XOR and
wires, `Mul` is `tower::mul`, `Inv` is a 12-multiplication addition chain plus
a non-zero check, `Blake3` is bitvm-gc's tree-mode circuit, `MerkleNode` is one
256-wire multiplexer (the other order is free) plus a compression, selectors
and Merkle bits are checked to be bits, bytes to be bytes, and the zero
padding of element-slot hashes is checked. Output = AND of all checks. Inputs
are typed by use (byte, bit or 128-bit element). Dumps come from
`data/ziren_dump_binary_tape.rs` (format ZTAP v2) and
`data/ziren_dump_binary_tape_v1.rs` (v1, at `f30cd48c`).

**Measured** (fibonacci; exact counts; 16 B per non-free gate; one core):

| | level 1 at f30cd48c (v1 tape) | level 1 at ee5ca380 | level 2 (narrow) |
|---|---:|---:|---:|
| proof verified | 2,246,717 B | 2,233,803 B | 1,468,673 B |
| tape ops / variables | 5.89 M / 9.41 M | 3.56 M / 4.91 M | 1.04 M / 1.17 M |
| non-free gates | 3,607,895,750 | 3,371,420,904 | 757,969,914 |
| Ziren's own estimate | — | 3.91e9 | 8.06e8 |
| XOR / wires | 22.49 B / 26.12 B | 21.02 B / 24.41 B | 4.87 B / 5.64 B |
| garbled | 57.73 GB | 53.94 GB | 12.13 GB |
| input bits | 18,148,352 | 18,050,304 | 11,165,056 |
| honest eval | accepts, 0 of 9.41 M values differ | accepts, 0 of 4.91 M | accepts, 0 of 1.17 M |
| 3 single-input changes | all rejected | all rejected | all rejected |
| streaming garble | 3,519 s, 1.03 M/s, peak 180.7 M live wires | — | 541 s, 1.40 M/s, peak 90.5 M |

Profiles: level 1 at `ee5ca380` is multiplication 84.8%, Blake3 9.0%, Merkle
nodes 5.7%; level 2 is multiplication 51.7%, Merkle nodes 28.7%, Blake3 17.4%,
inversion 1.9%. From v1 to v2 the count fell 6.6%: the tape now records x^2 as
`Square` (97,863 of them, free in characteristic 2, previously full
multipliers), and Merkle ordering moved from 1.64 M byte selects into 18,107
`MerkleNode`s. Ziren's estimate charges 2,187 AND per product (Karatsuba
3^7); the tower multiplier measures about 1,820, hence the 14% gap at level 1.

**The narrow proof.** Tables: ledger 2^24 x 128, arith 2^23 x 512, rewire 2^14
x 16,384, hash 2^16 x 2,048, rounds 2^19 x 4,096 (51,473 compressions).
Proven in 1,033 s on 64 cores (ant-5090-2) with a **446 GiB peak**; OOM-killed
at 300G and 450G caps first (`data/run-ziren-narrow-dump.txt`). Proof
1,468,673 B: main WHIR rounds 451 KB, opened main values 428 KB (23,168),
preprocessed WHIR rounds 358 KB, final openings 157 KB. The binary stage
itself took 779 s (shrink_binary) in the same run.

**A floor at level 2.** In Ziren's own small test (a 16-triple synthetic table
at 2^10 rows; `data/run-ziren-narrow-recursion-small.txt`) level 1 is
4.25e7 AND by Ziren's estimate and level 2 is 6.14e8; on the real proof level
1 is 92x larger (3.91e9) but level 2 only 31% larger (8.06e8). The narrow
verifier's cost is set by the tables' widths and the WHIR schedule, not by
the tape, so a third level would not go below about 6e8-8e8 AND: level 2 is
already close to the fixed point under this schedule.

**Against the paper's verifier and §7m.** Level 2 is 758 M against 94.1 M
non-free gates for the 2^18 Keccak WHIR verifier (8.1x), 12.13 GB against 1.5
GB, with 11.17 Mbit of input against 1.04 Mbit (10.7x). Against the garbled
compressed-proof verifier of §7m (38.3 B gates, 613 GB) it is 50.6x smaller,
but its input is 2.2x larger (11.17 against 5.18 Mbit): the narrow proof is
1.47 MB, and the input is its opened values and WHIR openings. At (181, 7)
cut-and-choose, garbling is 181 x 541 s, about 27 core-hours, and a
challenger stores 7 x 12.13 = 85 GB. The input size, not the circuit, is now
the cost to cut: fewer opened values (narrower tables) and fewer WHIR queries
(rate, Johnson regime: `ee5ca380`'s `narrow_schedules` tabulates them).

**The narrow proof's WHIR schedule** (`data/run-ziren-narrow-schedules.txt`,
derived for the real narrow machine's shapes without proving). Unique
decoding stays near 500 queries a round at every rate and folding (est.
1.13-1.75 MB of WHIR data unpruned); the Johnson regime, which Ziren derives
as proven list decoding up to the Johnson bound (no proximity-gap
conjecture), cuts queries about 5x at the price of prover grinding: rate
1/32 fold 2 is 31 bits (-69% WHIR bytes), rate 1/8 fold 4 is 37 bits (-78%),
rate 1/32 fold 4 is 41 bits (-84%). Rate 1/8 fold 4 was proven
(`data/run-ziren-narrow-dump-johnson-3-4.txt`) and garbled
(`data/run-ziren-narrow-tape-gc-johnson-3-4.txt`):

| narrow schedule | unique, 1/32, fold 4 (default) | Johnson, 1/8, fold 4 |
|---|---:|---:|
| narrow proof | 1,468,673 B | 727,235 B (-50%) |
| WHIR rounds / final openings | 810 KB / 157 KB | 212 KB / 14.5 KB |
| opened values (main + prep) | 447 KB | 447 KB |
| prove (64 cores) / peak memory | 1,033 s / 446 GiB | 5,821 s / 356 GiB |
| of which grinding | seconds | 4,948 s (longest 1,310 s) |
| level-2 tape ops / inputs | 1.04 M / 87,227 | 0.69 M / 41,323 |
| non-free gates | 757,969,914 | 483,917,940 (-36%) |
| garbled | 12.13 GB | 7.74 GB |
| input bits | 11,165,056 | 5,289,344 (-53%) |
| eval / 3 changes | accepts, 0 of 1.17 M differ / rejected | accepts, 0 of 780,062 differ / rejected |
| streaming garble, one core | 541 s (1.40 M/s) | 259 s (1.87 M/s) |

Profile under Johnson: multiplication 67.4%, Blake3 19.4%, Merkle nodes
10.0%, inversion 2.9%. Against the paper's verifier this is 5.1x the gates
(484 M against 94.1 M) and 5.1x the input (5.29 against 1.04 Mbit); against
§7m it is 79x fewer gates at the same input (5.29 against 5.18 Mbit). At
(181, 7), garbling is about 13 core-hours and a challenger stores 54 GB. The
opened values, one 128-bit element per column of the narrow machine (23,168
main + 1,440 preprocessed = 3.15 Mbit), are now 60% of the input; only
narrower tables (a prover-side change in Ziren) remove them. The cost moved
to the prover: 5.6x the proving time, almost all of it proof of work.

**Narrower rewiring rows (Ziren `cf932a58`, 2026-10-04).** The rewiring table
now holds 128 bytes a row (1,024 columns) instead of a 128 x 128 bit matrix
(16,384), and a transpose is 128 splits plus 16 gathers: the narrow machine
opens 7,808 main values instead of 23,168. As committed, `Program::new`
panics on the real level-1 tape ("the program fits 24-bit addresses"; 25
also fails): each transpose allocates 128 aligned outputs and a 2,048-cell
byte block, and the tape has 10,223 transposes. Measured with `ADDR_BITS`
raised to 26 in a local copy (every table's padding still fits), Johnson
1/8 fold 4 (`data/run-ziren-narrow-dump-cf932a58-johnson-3-4.txt`,
`data/run-ziren-narrow-tape-gc-cf932a58-johnson-3-4.txt`):

| Johnson 1/8, fold 4 | ee5ca380 | cf932a58 + ADDR_BITS 26 |
|---|---:|---:|
| tables (main) | ledger 2^24, arith 2^23, rewire 2^14 x 16,384 | ledger 2^25, arith 2^22, rewire 2^21 x 1,024 |
| cells / reads | 6.0 M / 9.2 M | 22.8 M / 25.9 M |
| narrow proof | 727,235 B | 446,677 B (-39%) |
| opened main values | 23,168 (427.5 KB) | 7,808 (139.6 KB) |
| prove (64 cores) / peak | 5,821 s / 356 GiB | 7,930 s / 536 GiB |
| constraint and bus phase | 13.5 min | 45 min, mostly one thread |
| non-free gates | 483,917,940 | 400,877,039 (-17%) |
| garbled | 7.74 GB | 6.41 GB |
| input bits | 5,289,344 | 3,387,648 (-36%) |
| eval / 3 changes | accepts / rejected | accepts, 0 of 601,241 differ / rejected |
| streaming garble, one core | 259 s | 201 s (2.00 M/s, peak 35.7 M live wires) |

Profile: multiplication 69.7%, Blake3 13.1%, Merkle nodes 12.5%, inversion
4.4%. Against the paper's verifier: 4.3x the gates (401 M against 94.1 M)
and 3.3x the input (3.39 against 1.04 Mbit). On chain, at the §7f rates,
the input is 7.2 MvB with adaptors, 6.9 MvB with the n=16 hash selector,
19.5 MvB with 4-bit Winternitz, per key set. At (181, 7): about 10 core-hours
of garbling and 45 GB stored by a challenger. What remains in the input:
WHIR rounds and final openings about 1.87 Mbit, opened values 1.18 Mbit
(7,808 + 1,440), claims, bus and sumcheck about 0.4 Mbit. The two
`cf932a58` regressions to report upstream are the 24-bit address limit and
the 3.3x slower, single-threaded constraint/bus phase.

**Narrower round and hash tables, one paired WHIR opening (Ziren `05fc5742`,
`b8bfde94`): estimated, not measured.** A round row is now half a
quarter-round (512 columns), a compression three hash rows, and the main and
preprocessed commitments are opened by one WHIR run (preprocessed stacked at
the main arity). On the real tape the machine opens 2,688 main and 1,218
preprocessed values (`data/run-ziren-narrow-dump-b8bfde94-oom.txt`; ledger
2^25 x 128, arith 2^22 x 512, rewire 2^21 x 1,024, hash 2^18 x 512, rounds
2^23 x 512). It needs `ADDR_BITS` and `PERMUTATION_ID_BITS` both raised to 26
(a new assert ties them). The narrow proof was OOM-killed at 697.5 GiB in its
constraint/bus phase (about 277 GiB at `cf932a58`), more than the GPU box can
give. An estimate from the `cf932a58` proof (removing the dropped opened
values and 60-85% of the preprocessed WHIR opening) gave 1.8-2.1 Mbit; the
measurement below, once Ziren `f6137ecc` fixed the memory, came in higher.

**Measured at Ziren `f6137ecc`** (the `b8bfde94` design with the memory
fixes; same 26-bit patches; `data/run-ziren-narrow-dump-f6137ecc-johnson-3-4.txt`,
`data/run-ziren-narrow-tape-gc-f6137ecc-johnson-3-4.txt`), Johnson 1/8:

| | cf932a58 | f6137ecc |
|---|---:|---:|
| narrow proof | 446,677 B | 305,868 B (-32%) |
| opened values main / prep | 7,808 / 1,440 | 2,688 / 1,218 |
| WHIR rounds | 220.7 KB (two runs) | 156.9 KB (one paired run, -29%) |
| claims main / prep | 5 / 7 (28.9 KB) | 5 / 19 (52.8 KB) |
| prove (64 cores) / peak | 7,930 s / 536 GiB | 5,754 s / 371 GiB |
| non-free gates | 400,877,039 | 473,888,470 (+18%) |
| garbled | 6.41 GB | 7.58 GB |
| input bits | 3,387,648 | **2,356,864 (-30%)** |
| eval / 3 changes | accepts / rejected | accepts, 0 of 670,581 differ / rejected |
| streaming garble, one core | 201 s | 240 s (1.97 M/s, peak 33.3 M live wires) |

On chain the input is **5.0 MvB with adaptors** (2.13 vB/bit), 4.8 MvB with the
n=16 hash selector, 13.6 MvB with 4-bit Winternitz, per key set: 2.3x the
paper's Keccak verifier (1.04 Mbit). The estimate missed on two counts: the
pairing cut the WHIR rounds by 29%, not by most of the preprocessed opening,
and the preprocessed claims grew from 7 to 19. The circuit grew because the
verifier now combines the two trees' rows at every query and checks more
claims: 222,706 multiplications against 181,235 (multiplication 80.5% of the
gates), while hashing fell 28%. Fewer input bits for more gates is the right
trade, since the input is paid on chain and the gates off chain. One grind of
the paired opening took 2,950 s (the 37-bit grinds of earlier runs took about
1,250 s), either chance or a harder grind under pairing.

**The most aggressive measured point: a third level at Johnson 1/64
(2026-10-04).** The security target sets only the grinding, never the
queries (`data/run-ziren-narrow-schedules-f6137ecc.txt`: 100/108 and 80/88
ask the same queries, 20 grinding bits apart), so lowering it saves proving
time, not input. Rate is the lever, and its price is grinding: at level 2
(arity 34) Johnson 1/32 needs 41-bit grinds, out of reach on CPU. A third
level fixes that: the tape machine proving the level-2 tape is 8x shorter
(arity 31) and the same schedules grind 5 bits less
(`data/run-ziren-narrow-schedules-level3.txt`), so 1/64 (38 bits) is a CPU
job. The dumper's `ZIREN_RECURSE_FROM` mode proves a saved tape on the tape
machine (`data/run-ziren-level3-dump-johnson-{3-4,6-4}.txt`,
`data/run-ziren-level3-tape-gc-johnson-{3-4,6-4}.txt`):

| f6137ecc + 26-bit patches | level 2, 1/8 | level 3, 1/8 | level 3, 1/64 |
|---|---:|---:|---:|
| narrow proof | 305,868 B | 284,554 B | 227,166 B |
| WHIR rounds | 156.9 KB (5) | 141.2 KB (4) | 85.4 KB (4) |
| prove (64 cores) / peak | 5,754 s / 371 GiB | 210 s / 27 GiB | 4,456 s / 62 GiB |
| grinding (longest) | 2,950 s | 23 s | 861 s |
| non-free gates | 473,888,470 | 413,697,815 | **392,391,903** |
| garbled | 7.58 GB | 6.62 GB | **6.28 GB** |
| input bits | 2,356,864 | 2,220,032 | **1,761,024** |
| eval / 3 changes | accepts / rejected | accepts / rejected | accepts, 0 of 552,659 differ / rejected |
| streaming garble, one core | 240 s | 211 s | 205 s |

On chain the measured best is **3.75 MvB with adaptors** (0.083 BTC at 2.2
sat/vB), 3.59 MvB with the n=16 hash selector, 10.2 MvB with 4-bit Winternitz,
per key set: 1.7x the paper's Keccak verifier (1.04 Mbit, 2.2 MvB). What is
left in the proof: WHIR 92.7 KB (41%), opened values 60.5 KB (27%), claims
52.9 KB (23%, of which 19 preprocessed claims 40.9 KB), bus 16.6 KB (7%).

Modelled from this measured proof, the remaining levers: one batched claim
per commitment (-47.3 KB; Plonky3 multi-stark), 200-bit Merkle digests
(-13.9 KB; digest format), Rewire at 512 columns (-8.9 KB; Ziren layout),
Johnson 1/128 at level 3 (-7.4 KB; 40-bit grinds, about 5 h on CPU): proof
about 150 KB, **input about 1.16 Mbit, 2.5 MvB with adaptors**, 2.4 with the
n=16 hash selector, 1.2 with an 8-bit-digit selector, 6.7 with 4-bit
Winternitz. That is about the paper's own verifier, and close to the floor of
this design at 100-bit security: 3,906 opened 128-bit values (0.5 Mbit), WHIR
paths, one claim per commitment and the bus. Beyond it, only the encoding
(wider selector digits, a consensus change) and soldering (one reveal for the
7 kept instances instead of 7) cut the on-chain total.

**GPU grinding, aligned layouts and a fourth level (2026-10-04/05).** Three
experiments in a local copy of Ziren `f6137ecc` and Plonky3 `fb5d0d8`
(`data/run-ziren-align-chain.txt`, `data/run-ziren-align-level4.txt`; code in
`data/zkm_blake3_grind.cu`, `data/p3_patch_gpu_grind.py`,
`data/p3_patch_align.py`, `data/ziren_patch_local_plonky3.py`):

- GPU proof of work. `BinaryChallenger::grind` hashes the pending Blake3
  transcript and a 16-byte candidate. A CUDA kernel absorbs the transcript once
  on the host (the candidate-independent part of the Blake3 tree) and finishes
  each candidate on the GPU. It matches the `blake3` crate from 17 to 70,000
  bytes, every witness is re-checked by `check_witness` on the CPU, and it runs
  about 4-5e10 candidates/s on four RTX 5090s against about 9e7 on 64 cores.
  Level-2 grinding fell from about 5,000 s to 22 s, and 43-47-bit grinds are
  minutes to half an hour, so the rate is no longer bounded by grinding but by
  memory.
- Aligned stacked layout. A table opened as one power-of-two block costs one
  ring-switch claim (128 GF(2^128) elements = 16,384 input bits); a table placed
  at a misaligned offset splits into several. Starting each table at a multiple
  of its own block, and padding the Rounds preprocessed row to 128, takes the
  preprocessed claims from 19 to 5. Aligning every layout broke the binary
  stage's pair opening (`ColumnBatchValueMismatch`), so only all-power-of-two
  layouts (the narrow machine's) are aligned; the binary stage is unchanged.
- Recursion to the fixed point: level 2 at Johnson 1/8, level 3 at 1/512 fold 5,
  level 4 at 1/1024 fold 5 (arity 30, memory 365 GiB). The level-4 tape (285 k
  ops) is the size of level 3's (295 k), so a fifth level gains nothing.

| | level 2, 1/8 | level 3, 1/512 f5 | **level 4, 1/1024 f5** |
|---|---:|---:|---:|
| narrow proof | 277,714 B | 179,560 B | 170,195 B |
| claims main / prep | 5 / 5 | 5 / 5 | 5 / 5 |
| WHIR rounds | 157.7 KB (5) | 66.4 KB (3) | 58.6 KB (3) |
| prove / peak | 900 s / 372 GiB | 3,612 s / 365 GiB | 9,510 s / 365 GiB |
| non-free gates | 322,005,166 | 249,989,457 | **242,454,733** |
| garbled | 5.15 GB | 4.00 GB | **3.88 GB** |
| input bits | 2,135,424 | 1,387,392 | **1,313,920** |
| eval / 3 changes / garble | accepts / rejected / 166 s | accepts / rejected / 134 s | accepts, 0 of 345,760 differ / rejected / 130 s |

On chain, per key set at 2.2 sat/vB: **2.80 MvB with adaptors (0.062 BTC)**,
2.68 MvB with the n=16 hash selector, 1.37 MvB with an 8-bit-digit selector,
7.58 MvB with 4-bit Winternitz (0.167 BTC), 21.8 MvB with Lamport. Against the
paper's Keccak verifier: 2.6x the gates (242 M against 94.1 M) and 1.26x the
input (1.31 against 1.04 Mbit). The claims checks shrank the circuit as much as
the input: the aligned level 2 has 32% fewer gates than the unaligned one.

What is left of the 10,265 input elements: opened values 3,968 (2,688 main +
1,280 preprocessed, 39%), WHIR about 3,900 (38%), claims 1,280 (12%), bus,
sumchecks and root about 1,100. Remaining levers, none an experiment-sized
change: one tensor per commitment for the claims (about -1,100 elements, but the
ring switch contracts the tensor along two different legs, so it is a new
protocol, not a re-weighting); 200-bit Merkle digests (about -6%); a narrower
rewiring row (-512 elements); then only the encoding (wider selector digits, a
consensus change) and soldering. At 100-bit security this design is near its
floor of about 1.1-1.2 Mbit.

**A 64-byte rewiring row (2026-10-05).** The rewiring table's 1,024 columns
were the widest of the narrow machine. A row now holds 64 bytes: a transpose
is 128 splits, 32 half gathers (half h of column 8c + j holds bits 64h .. 64h+63
of the column, pushed at its own cell) and 128 additions joining the halves,
whose bits do not overlap (`data/ziren_rewire64.patch`: `Cell::Half`, an Arith
`Add` per column; arith and hash read cells through `cell_value`). The bus
binds every half as it bound the whole column, so nothing in the argument
changes. Main values fall from 2,688 to 2,176 at every level; level 2 grows
from 2^22 to 2^23 Arith rows (427 GiB peak, 1,422 s). Same schedules as above
(`data/run-ziren-rw64-chain.txt`, `data/run-ziren-rw64-level{3,4}-tape-gc.txt`):

| | level 3, 1/512 f5 | **level 4, 1/1024 f5** |
|---|---:|---:|
| narrow proof | 170,318 B | 158,826 B |
| non-free gates | 241,217,044 | **231,199,237** |
| garbled | 3.86 GB | **3.70 GB** |
| input bits | 1,330,048 | **1,248,384** (-5.0%) |
| eval / 3 changes | accepts / rejected | accepts, 0 of 325,970 differ / rejected |

On chain, per key set at 2.2 sat/vB: **2.66 MvB with adaptors (0.058 BTC)**,
2.55 MvB with the n=16 hash selector, 1.30 MvB with an 8-bit-digit selector,
7.20 MvB with 4-bit Winternitz: 1.20x the paper's Keccak verifier input
(1.04 Mbit) at 2.5x its gates. The 9,753 input elements left: opened values
3,456 (2,176 + 1,280), WHIR about 3,900, claims 1,280, bus about 930, sumchecks
and root about 190.

**Opened values the verifier knows (2026-10-05).** Every column is one
opened 128-bit value, and many are known without the proof: main padding
columns are zero by construction (Arith 127, Rounds 96; the Hash table's
output rows use all 512 columns), and a preprocessed column constant over all
rows of the fixed program evaluates to that constant at any point. The
verifier may read these as constants instead of proof values: the values are
bound into the transcript before the column-combination point is drawn and the
ring-switch claim checks that combination against the commitment, so a prover
whose committed column differs fails it with overwhelming probability (a known
value only adds a constraint), and the honest values equal the constants. No
change to the prover or the proof: the dumper's re-record mode records the
level-4 verifier on the saved proof with them as constants, after checking
each equals its constant in the proof, and the translator gives an unread
proof value no wires (`data/run-ziren-rw64-level4-known.txt`,
`data/run-ziren-rw64-level4-known-tape-gc.txt`). 223 of 2,176 main and 643 of
1,280 preprocessed values are known (padding, address and id bits never set at
this size, flags of kinds that never occur):

| level 4, rw64 | proof values read | non-free gates | garbled | input bits |
|---|---:|---:|---:|---:|
| all values from the proof | 9,753 | 231,199,237 | 3.70 GB | 1,248,384 |
| **known values as constants** | **8,887** | **226,755,501** | **3.63 GB** | **1,137,536** (-8.9%) |

It accepts the real proof with 0 of 314,747 values differing, rejects three
changes of read inputs, and garbles in 190 s. On chain, per key set at 2.2
sat/vB: **2.42 MvB with adaptors (0.053 BTC)**, 2.32 MvB with the n=16 hash
selector, 1.18 MvB with an 8-bit-digit selector, 6.56 MvB with 4-bit
Winternitz: 1.09x the paper's Keccak verifier input. The 637 preprocessed
columns left are row-dependent (addresses, ids, flags). Those equal to a bit
of the row index, or to an indicator of a row prefix, would have evaluations
a verifier computes from the point in a few products, but the dumper's
classifier (`ZIREN_CLASSIFY_PREP`) finds only 17 of the 637 so structured:
not worth a protocol change.

**One ring-switch element for all claims (2026-10-05).** Each opening (main,
preprocessed) sends one 128-element tensor per aligned column block, five per
opening at level 4: 1,280 of the inputs. Claims at points sharing the seven
coordinates an element absorbs (every block at one row point does) can send
one element between them. With claim i's element s_i (weight eq_i on the
first leg), the prover binds the points, draws mu, and sends
T = sum_i (mu^i x 1) s_i. Its columns, weighed by eq_low, must equal
sum_i mu^i reading_i; its rows are those of the element of the weight
W = sum_i mu^i eq_i, so one sumcheck against W's weight multilinear (each
claim's equality scaled by mu^i, on its own sub-slot) ties them to the
packing, r'' drawn after T is bound; the closing weight is
sum_i gate_i * A_i(r') with claim i's equality element scaled by mu^i. A false
reading survives only if sum_i mu^i err_i = 0, at most (k-1)/2^128, the term
lambda already adds to an unmerged batch; the rest is the one-claim ring
switch. Successor views are never merged. A Plonky3 change
(`data/plonky3_merged_claims.patch`: `sumcheck/src/ring_switch/bits/` plus
binary-pcs reading the prover's readings, since a merged proof has no
per-claim element), no Ziren change: the recorded verifier is Plonky3's,
traced. Tests: all ring-switch tests plus new ones (one element sent; a false
reading at any claim, two cancelling errors, a forged row, a tampered surviving
value and an unmerged-shaped proof rejected); p3-sumcheck, p3-binary-pcs,
p3-multi-stark and p3-whir pass except the stacked-layout test our aligned
layout patch already breaks; the narrow-machine test proves, verifies and
records with one element per opening (`data/run-ziren-merged-narrow-small.txt`).
Level 4 re-proved from the same level-3 tape (6.3 h on two GPUs, 382 GB peak)
and re-recorded with the known values (`data/run-ziren-merged-level4.txt`,
`data/run-ziren-merged-level4-tape-gc.txt`):

| level 4, rw64, known values | proof values read | non-free gates | garbled | input bits |
|---|---:|---:|---:|---:|
| one element per claim | 8,887 | 226,755,501 | 3.63 GB | 1,137,536 |
| **merged claims** | **7,863** | **221,687,835** | **3.55 GB** | **1,006,464** (-11.5%) |

It accepts the real proof with 0 of 312,263 values differing, rejects three
changes of read inputs, and garbles in 187 s. On chain, per key set at 2.2
sat/vB: **2.14 MvB with adaptors (0.047 BTC)**, 2.05 MvB with the n=16 hash
selector, 1.04 MvB with an 8-bit-digit selector, 5.80 MvB with 4-bit
Winternitz: **0.97x the paper's Keccak verifier input** (1.04 Mbit). Left:
WHIR about 3,900, main values 1,953, preprocessed values 637, bus about 930,
claims 256, sumchecks and root about 190.

**Shorter Merkle digests and a narrower first fold (2026-10-05).** The
recorded verifier takes every query's whole Merkle path as hints (a program
has one shape, so the pruned multi-proof never enters it): 1,159 sibling
digests of 256 bits, about 30% of the input. Two changes, both re-proving
level 4 from the same level-3 tape:

1. Merkle digests are Blake3 truncated to 25 bytes (200 bits): collisions
   cost `2^100` (birthday), the composed target, and `2^66.7` quantumly
   (BHT), above the proofs' ~50 quantum bits. Ziren: a truncating hasher in
   the binary config; the recorder holds a digest as one element plus a
   9-byte tail, entered byte by byte (72 input bits), hashes nodes over 50
   bytes (select, Blake3, truncate: wiring) and absorbs caps as 25 bytes.
2. The first WHIR round folds 3 variables instead of 5 and keeps its folded
   domain (rates 13, 17, 21 after a starting 1/1024): each first-round query
   opens 8 elements per tree instead of 32, at the same 46-bit grinding.
   Scored over first folds 1-6, later folds 3-7 and per-round rate growth
   (`data/run-ziren-level4-mixed-schedules.txt`); lower starting rates need
   50-bit grinding and a twice larger codeword. Plonky3: a first-round hook
   in the WHIR profile (`data/plonky3_first_round_profile.patch`), Ziren:
   `ZIREN_B_FIRST_ROUND=3,1` (`data/ziren_short_digest_first_round.patch`).

A Merkle cap is already used and pruning cannot help a fixed-shape circuit
(its worst case is the cap). Level 4 proved in 4.8 h at 501 GiB peak, proof
139,857 -> 124,678 B (`data/run-ziren-short-level4.txt`,
`data/run-ziren-short-level4-tape-gc.txt`):

| level 4, known values, merged claims | inputs (bytes / elements) | non-free gates | garbled | input bits |
|---|---:|---:|---:|---:|
| 32-byte digests, fold 5 | 0 / 7,863 | 221,687,835 | 3.55 GB | 1,006,464 |
| **25-byte digests, first fold 3** | **11,826 / 6,257** | **220,159,322** | **3.52 GB** | **895,504** (-11.0%) |

It accepts the real proof with 0 of 419,620 values differing, rejects three
changes of read inputs, and garbles in 116 s. On chain, per key set at 2.2
sat/vB (scaled per bit from the measured encodings): **1.90 MvB with adaptors
(0.042 BTC)**, 1.83 MvB with the n=16 hash selector, 0.93 MvB with an
8-bit-digit selector, 5.16 MvB with 4-bit Winternitz: **0.86x the paper's
Keccak verifier input**.

**Columns read only packed (2026-10-06).** The ledger's value and the
arithmetic operands `a`, `b`, `c` (512 of the 2,176 main columns) are read
by every constraint and bus only as packed elements `sum_k e_k col_k`. An
AIR now declares such groups (`main_packed_groups`), and a table opened only
by its AIR batch sends, in column order, each column outside a group and one
value per group (the forms), binds them, draws `rho`, and runs a degree-two
sumcheck over the column variables of `sum_slots L(u) W(u)`, `L` weighing
form `j`'s columns by `rho^j` (times `e_k` in a group) and `W` the columns at
the row point; it ends at `u*` with the fold `W(u*)`, which is exactly the
reading of the table's one block claim at the column point `u*` that the
ring switch (merged) already checks. The verifier closes the rounds with
`L(u*) W(u*)` and hands the AIR columns that pack to each form (the group's
first column `e_0^-1` times it, the rest zero). Soundness: forms bound before
`rho`, `(forms - 1)/2^128`, plus `2 log2(width)/2^128` for the rounds; the
block claim is unchanged. Plonky3 (`data/plonky3_packed_columns.patch`:
`BaseAir`, `TableSpec`, the main schedule, the column-batch transcript,
planner and trace commitment, with tests: one value per group, opened columns
packing to the true values, every wire value checked, an unpacked proof
refused); Ziren (`data/ziren_packed_columns.patch`: the two tables' groups,
the dumper's known-value positions). Ledger sends 1 + 14 + 1 values instead
of 128, Arith 131 + 18 + 1 instead of 512: 2,176 -> 1,702 main values. Level
4 re-proved (3.5 h, 501 GiB peak, proof 116,250 B) and re-recorded, every
known value checked at its new position (`data/run-ziren-packed-level4.txt`,
`data/run-ziren-packed-level4-tape-gc.txt`):

| level 4, known values, merged claims, short digests, fold 3 | inputs (bytes / elements) | non-free gates | garbled | input bits |
|---|---:|---:|---:|---:|
| every column sent | 11,826 / 6,257 | 220,159,322 | 3.52 GB | 895,504 |
| **Ledger and Arith packed** | **11,826 / 5,783** | **219,233,411** | **3.51 GB** | **834,832** (-6.8%) |

It accepts the real proof with 0 of 417,565 values differing, rejects three
changes of read inputs, and garbles in 116 s. On chain, per key set at 2.2
sat/vB (scaled per bit): **1.78 MvB with adaptors (0.039 BTC)**, 1.70 MvB
with the n=16 hash selector, 0.87 MvB with an 8-bit-digit selector, 4.81 MvB
with 4-bit Winternitz: **0.80x the paper's Keccak verifier input**. The
experiment copies holding every change are `ziren-packed` and
`plonky3-packed` on the box.

**Linear forms, per-round folds and a deep preprocessed cap (2026-10-06).**
Three changes in one level-4 re-prove (the box is shared; one run each was
not available):

1. *Linear forms of every table.* The packed groups generalise: a table's
   constraints and buses, walked symbolically (`ziren` `forms.rs`), are
   normalised to sums of products of linear atoms times one linear form,
   terms with the same atoms merged; the atoms and forms left, reduced to an
   independent set (sparsest first), are every linear form of the columns the
   table reads. A trace sends one value per form when fewer than the columns
   it reads (main: all but Rounds, whose carries read every bit; preprocessed:
   all five), then the column sumcheck; the verifier hands the AIR the columns
   a right inverse makes of the values, a constant matrix (XORs in the GC),
   checked at setup. Census at the narrow test's machine
   (`data/run-ziren-forms-census.txt`): main 2,176 columns -> 633 forms (Rewire
   183, Hash 29, Rounds 416), preprocessed 1,280 -> 308. Main values sent 1,702
   -> 801, preprocessed 1,280 -> 391; a preprocessed form over constant columns
   only is known (120 at level 4). Plonky3 `LinearForms` on `BaseAir`,
   `TableSpec` and the trace commitment (`data/plonky3_linear_forms.patch`),
   Ziren (`data/ziren_linear_forms.patch`).
2. *Per-round WHIR folds* [4, 5, 4, 4], rates [14, 18, 21], 46-bit grinding:
   the best schedule once digests are 200 bits
   (`data/run-ziren-level4-perround-schedules.txt`; model -139 elements).
3. *A deep cap on the preprocessed tree.* Its tree is fixed by the verifying
   key, so the re-record takes its 16,384 nodes 14 layers below the root from
   the proving key as circuit constants (checked to hash to the key's cap). A
   path into it hashes its 15 lower siblings and is compared with the constant
   node a one-hot of the top 14 index bits selects (2^14 indicator ANDs per
   query; the selection is XORs); the siblings above are never read. No
   change to the proof or the native verifier.

Level 4 proved in 2.1 h at 451 GiB peak (proof 91,849 B) and re-recorded
(`data/run-ziren-forms-level4.txt`, `data/run-ziren-forms-level4-tape-gc.txt`):

| level 4 | inputs (bytes / elements) | non-free gates | garbled | input bits |
|---|---:|---:|---:|---:|
| packed Ledger and Arith | 11,826 / 5,783 | 219,233,411 | 3.51 GB | 834,832 |
| **forms, folds, deep cap** | **9,981 / 4,405** | **215,814,232** | **3.45 GB** | **643,688** (-22.9%) |

It accepts the real proof with 0 of 961,415 values differing, rejects three
changes of read inputs, and garbles in 189 s. On chain, per key set at 2.2
sat/vB (scaled per bit): **1.37 MvB with adaptors (0.030 BTC)**, 1.31 MvB
with the n=16 hash selector, 0.67 MvB with an 8-bit-digit selector, 3.71 MvB
with 4-bit Winternitz: **0.62x the paper's Keccak verifier input**.

**One ring switch for both commitments, and eq-factored bus rounds
(2026-10-06).** Two more changes, one re-prove:

1. *Joint ring switch.* The main and preprocessed packings have one arity, so
   the pair's two switches run as one over `t(s, w) = (1 - s) f(w) + s g(w)`:
   main claims at `(0, z)`, preprocessed at `(1, z)`, all ten merged into one
   element and one sumcheck ending at `(r0, r)`; the pair opens `f` and `g`
   at the same `r`, and the verifier checks `(1 - r0) f(r) + r0 g(r)` against
   the surviving value. The second side's reduction is empty (a new
   `JointPaired` opening kind). One 128-element tensor and one sumcheck fewer.
2. *Gruen's factoring in the bus product GKR.* A radix-four round polynomial
   is `l_k(X) h(X)` with `l_k` the linear eq factor of the round's
   coordinate; the prover sends `h` (degree four) at 0, 2, 3, 4, and the
   verifier recovers `h(1) = (s - (1 - r_k) h(0)) / r_k` (one batched
   inversion per layer). One element per round fewer.

Plonky3 `data/plonky3_joint_switch_gruen_bus.patch` (pair switch, opening
kind, bus prover and verifier; the binary-pcs, bus and multi-stark tests
pass), Ziren `data/ziren_joint_switch.patch`. Level 4 proved in 3.2 h
(proof 86,047 B) and re-recorded (`data/run-ziren-joint-level4.txt`,
`data/run-ziren-joint-level4-tape-gc.txt`):

| level 4 | inputs (bytes / elements) | non-free gates | garbled | input bits |
|---|---:|---:|---:|---:|
| forms, folds, deep cap | 9,981 / 4,405 | 215,814,232 | 3.45 GB | 643,688 |
| **joint switch, factored bus** | **9,981 / 4,088** | **216,490,930** | **3.46 GB** | **603,112** (-6.3%) |

It accepts the real proof with 0 of 960,347 values differing, rejects three
changes of read inputs, and garbles in 109 s. On chain, per key set at 2.2
sat/vB (scaled per bit): **1.28 MvB with adaptors (0.028 BTC)**, 1.23 MvB
with the n=16 hash selector, 0.63 MvB with an 8-bit-digit selector, 3.48 MvB
with 4-bit Winternitz: **0.58x the paper's Keccak verifier input**. From the
binary stage's 2.36 Mbit at level 2, the verifier input is down 3.9x.

**Fixed preprocessed relations, one shared forms sumcheck, deep cap 18
(2026-10-07).** A census of the level-4 machine's fixed preprocessed columns
first (`data/run-ziren-prep-rank-level4.txt`, no proving): over GF(2), with
the all-ones column known, the five tables' 1,280 preprocessed columns have
rank 189, 84, 63, 129, 32, and of the 188 preprocessed values read (forms not
over constant columns), only 78 are independent once each form is written over
that column basis. Three changes, one re-prove:

1. *Fixed preprocessed relations.* A preprocessed form is, at every row, a
   fixed GF(2) combination of a column basis and the all-ones column, so a
   form dependent on others is an affine function of their values. The forms
   are cut to the independent ones and the right inverse becomes affine
   (Plonky3: an inverse entry `usize::MAX` is the constant one; Ziren
   `forms.rs` `column_relations`, `over_fixed_trace`, checked on rows of the
   fixed trace). Preprocessed values 391 -> 101 (271 -> 101 read, the rest
   are forms over constant columns, known in the re-record).
2. *One forms sumcheck for every table.* The per-table column sumchecks run as
   one over the widest table's column variables, each table zero above its
   width and read at the trailing coordinates, so the claim is
   `sum_t prefix_t^2 L_t(s_t) w_t` and each table sends only its fold. Main
   values 801 -> 751 (the round coefficients counted in the values section).
3. *Deep preprocessed cap 18.* The re-record takes the fixed tree's level-18
   nodes (262,144) as constants instead of level 14 (16,384); four fewer
   authentication levels per preprocessed query, more selection gates.

Plonky3 `data/plonky3_prep_relations_shared_sumcheck.patch` (plan, transcript,
`table.rs`; a test with a 16-wide, an 8-wide and a plain table, the affine
inverse on one), Ziren `data/ziren_prep_relations_shared_sumcheck.patch`
(`forms.rs`, the dumper's `ZIREN_PREP_RANK` mode). Level 4 proved in 1.8 h
(proof 81,501 B, 473 GB peak) and re-recorded at caps 14 and 18
(`data/run-ziren-rel-level4.txt`, `data/run-ziren-rel-level4-tape-gc.txt`,
`data/run-ziren-rel18-level4-tape-gc.txt`):

| level 4 | inputs (bytes / elements) | non-free gates | garbled | input bits |
|---|---:|---:|---:|---:|
| joint switch, factored bus | 9,981 / 4,088 | 216,490,930 | 3.46 GB | 603,112 |
| relations, shared sumcheck, cap 14 | 9,981 / 3,868 | 217,807,068 | 3.48 GB | 574,952 (-4.7%) |
| **cap 18** | **9,513 / 3,816** | **218,022,788** | **3.49 GB** | **564,552** (-6.4%) |

At cap 18 it accepts the real proof with 0 of 9,831,799 values differing
(the constant nodes are tape variables), rejects three changes of read inputs,
and garbles in 217 s on one core. A deeper cap stops paying: each level
removes one 200-bit node per query but doubles the constants the one-hot
selects from. On chain, per key set at 2.2 sat/vB (scaled per bit): **1.20
MvB with adaptors (0.026 BTC)**, 1.15 MvB with the n=16 hash selector, 0.59
MvB with an 8-bit-digit selector, 3.26 MvB with 4-bit Winternitz: **0.54x
the paper's Keccak verifier input**, and about 38x deferred binding's 31.5 kvB.
From the binary stage's 2.36 Mbit at level 2, the input is down 4.2x.

Not done: moving Rewire's per-bit writes so the bus product GKR loses a level
(estimated -1.2%).

**Why the provers need so much memory.** Every peak measured fits about 16 B
(one GF(2^128) element) per witness bit, main plus preprocessed, times about
1.7: the binary stage, 18.9 Gbit, peaked at 285-290 GB (16 B per bit alone is
281 GiB); the narrow proof at `ee5ca380` holds 14.4 Gbit (214 GiB at 16 B per
bit) and peaked at 356 GiB; at `cf932a58` 21 Gbit (314 GiB) and 536 GiB. The
code shows one source: a preprocessed trace is built as a dense matrix with
one field element per bit (`bits::dense`, what `BaseAir::preprocessed_trace`
returns), 2^33 cells for the ledger's 256 preprocessed columns alone (128
GiB). Main traces are packed 64 rows to a `u64`, so their 16 B per bit must
come from the sumcheck phases folding bit columns with GF(2^128) challenges.
The jump past 697 GiB at `b8bfde94` is not explained by the witness alone
(23 Gbit, about 344 GiB at 16 B per bit).

**Where the memory goes, from the code** (Plonky3 `8c629ab` and Ziren
`b8bfde94`, read and spot-checked; sizes at the real narrow machine, Johnson
1/8). Three allocations dominate, all prover-side:

| allocation | code | size at real scale | lifetime |
|---|---|---:|---|
| bus columns lifted to full-height GF(2^128) polynomials (every column a bus declaration reads, plus selectors and eq per table); folds only truncate | `multi-stark/src/bus/composition.rs:221-282, 400` | ~220 GiB | whole zerocheck |
| preprocessed traces dense, one field element per bit, kept in the proving key | Ziren `bits::dense` -> `multi-stark/src/keys.rs:207-212` | ~161 GiB | whole proof |
| the preprocessed prover data cloned for the paired opening (dense tables + its commitment) | `multi-stark/src/prover.rs:651` | ~181 GiB transient | pair opening |

Smaller: two WHIR commitments (~20 GiB each at rate 1/8), the bus product-GKR
copies (~40 GiB transient, `bus/src/product/prover.rs:77, 121-131`), the AIRs'
`Vec<u8>` preprocessed bytes (~9 GiB), the zerocheck bit planes including
all-zero successor planes (~11-16 GiB). The paired opening keeps main data, the
key's data and the clone alive together, where the unpaired path consumed main
first. The serial 45 minutes are the product GKR (no rayon), the bus lift
(a serial iterator over ~14 G cells) and the clone (a serial memcpy). On the
small test the memory rises through proving and peaks at the very end, at the
pair opening (`data/run-ziren-narrow-small-memory-b8bfde94.txt`: 4.2 GiB after
setup, 11.5 GiB peak).

**Remedies, largest first** (for Ziren/Plonky3): (1) do not clone the
preprocessed prover data, borrow it (-181 GiB transient, a few lines);
(2) keep preprocessed traces packed in the key (-159 GiB resident); (3) do
not lift bus columns to GF(2^128) at full height: evaluate from packed bits
for the first rounds, fold out of place or shrink each round, parallelise
(-~200 GiB and most of the serial time); (4) product GKR without leaf copies,
with rayon (-~27 GiB, serial time); (5) drop the `Vec<u8>` copies and the
zero successor planes (-~15 GiB). (1)-(3) together bring the real narrow
proof from over 697 GiB to an estimated 150-250 GiB. A lower rate no longer
helps much: at 1/8 the codewords are about 40 GiB of the total.

**A hashed proof as private input does not remove the per-bit cost.** The
proposal: one public input h = H(proof), the proof a private input that the
circuit hashes and checks against h. On chain that is 256 bits; the circuit
grows by at most the hash of the proof (about 70-110 M non-free gates, maybe
nearly nothing since the Fiat-Shamir transcript already hashes every element
not bound by a Merkle root). But a private input is the garbler's, and its
labels reach the challenger off chain: a cheating operator withholds them or
sends junk, and Bitcoin cannot tell. The hash check stops equivocation, not
withholding; the per-bit reveal exists to force label release. Labels bound
to a short digest are laconic OT or witness encryption (§7f), both algebraic
(DDH/LWE; pairings in BABE and deferred binding), outside the hash-only scope.

## 8. To fix or check before release

1. bitvm-gc `docs/partial_binding_we.tex` credits BABE to "Goat Research Team".
   The authors are Garg, Kolonelos, Sergeevitch, Sridhar and Tse.
2. BABE's garbled-circuit size: the note says ~4.7·10^8 gates, BABE says a
   22 MiB artifact. Reconcile (see Sec. 2).
3. Garbled-circuit sizes compare differently depending on the unit: non-free
   gates, total gates or bytes. BABE converts 2.7B non-free gates at 16 B each.
   We use non-free gates at 16 B per privacy-free half-gate AND. State the unit
   everywhere.
4. The whir-gc proving time at 2^16 (44 min) was single-threaded, and at 2^18
   (87 min) on 8 cores. Keep the labels.
5. Entries in `refs.bib` marked "not read" are cited second-hand. Read them
   before relying on specific claims (especially Glock's 12 MB, [FBFL25] and
   Argo MAC).
6. **Open after the review, needs the authors.** The title's "Post-Quantum"
   (either retitle or add a quantum analysis); repositioning against 2026/2100 and
   BABE; the on-chain input story (1,041,024 bits); a second AIR; authors and CPU
   model.
7. **After review round 2, needs the authors.**
   - A second AIR: SHA-256 and Blake3 binary AIRs read no next-row columns,
     which needs verifier work.
   - Measuring a quantum-secure configuration: this needs a Plonky3 change,
     either a 256-bit challenge field or repetition, plus a query-heavy profile.
   - A citation for round-by-round soundness of sumcheck.
   - Authors and CPU model.
8. **Review round 3 (2026-09-24).**
   - **Fixed:**
     - Streaming memory: two passes; 1 byte per wire for the plan, 0.61 GiB at
       2^18; 18 bytes per live wire, 41 MB at the 2.26M peak.
     - Theorem 1 now uses *adaptive* authenticity, stated as an assumption for
       Blake3-based free-XOR, with a pointer to BHR12 adaptive.
     - "hardest" became "hash-heavy"; captions tightened.
     - Bibliography pages checked by web search (DBLP API unreachable from the
       server): FNO15 191–219, CKKZ12 39–53, BHT98 LNCS 1380 163–169,
       Grover 212–219, Shor 124–134.
   - **Open, needs the authors:** the title's "Post-Quantum" against the
     measured ~52 quantum bits; authors; CPU model. Adaptive authenticity of
     free-XOR in the ROM is an assumption, not a cited theorem: find a reference
     or prove it.
9. **On-chain part and 2^20 (2026-09-25).**
   - **Resolved:** the on-chain input story (§7d: operator-garbles protocol, three
     input schemes priced, input-size sweep); CPU models (Xeon Platinum 8375C;
     EPYC 9355 for 2^20); the 2^20 row; garbling efficiency (§7e).
   - **Open, needs the authors:** the author list; hash-based soldering to M kept
     instances at a million input bits; a narrower AIR or recursion for a smaller
     input; the adaptive-authenticity reference.
10. **Review round 4 (2026-09-25).**
    - **Fixed:**
      - Garbling before the proof is now measured by
        `garbled_before_the_proof_evaluates_real_proofs`
        (`data/run-garble-then-evaluate.txt`). Evaluation takes 11.5 s at 2^5
        and 17.0 s at 2^8, against 20.6 s and 34.0 s for garbling.
      - A 16-byte Lamport preimage has ≈64-bit quantum strength for one target,
        but the corrected aggregate bound is ≈54 bits across the roughly
        $2^{20}$ alternate openings in one key set and ≈52.6 bits across seven
        independent sets.
      - Citations added: Binius, ring switching, Wiedemann, LFKN, HyperPlonk,
        STIR, Cantor, LCH14, Blake3 and FIPS 202. Their metadata is from memory
        and still needs checking.
      - Related work now covers BitVM3's Table 9 estimate for a garbled STARK
        and TRAPGC-DV.
      - The cut-and-choose setup cost is derived.
      - Tables no longer use resizebox. Fonts are vector (lmodern + T1); the
        PDF had two Type 3 bitmap fonts before.
      - The paper is renamed to `garbled-stark-verifier.tex`.
    - **Open, needs the authors:** the title's "Post-Quantum".
13. **Deferred-binding row (2026-10-01).** `tab:compare` now quotes the
    implementation report "Deferred Binding: Extending BABE for Dynamic Public
    Inputs in GOAT BitVM3" (bitvm2-gc, branch feat/goat-bitvm3): 0.92 GiB per
    finalized instance (740,112 + 57,850,911 + 740,112 non-free gates plus
    31.6 MiB adaptor tables), 3.83 GiB shared artifact, 768 input labels,
    Assert 2,154 B, ChallengeAssert 14,312 B witness + 109,393 B script,
    WronglyChallenged 64 B. The "about 32 kvB" is our arithmetic
    ((2,154 + 14,312 + 109,393 + 64)/4 of witness bytes, no shells). The old
    "(0.5--1.1)x10^9 gates" figure from the April note is retired. The bib entry
    needs a stable URL or date for the report itself. Rows in the table now have
    \addlinespace so the PIPE row's 338 TB no longer sits visually against the
    deferred-binding row.
12. **Table `tab:compare` on-chain column (2026-10-01).** Added "on-chain
    dispute path, as reported": BitVM3's own 2.4 kvB Assert + 93 vB Disprove
    (2026/933 §8.1, about $5 at 2 sat/vB) and BABE's normalization of the
    published BitVM3 experiment to $37.65 (2026/065 Fig. 2); BABE's Table 1
    (9,240 + 17,400 + 149 vB = 26,789 vB, $56.90); PIPEs' one hash / one
    signature without a size; partial-binding WE as BABE + 254|D| Lamport
    bits. Our row: 2.22 MvB adaptor or 11.88 MvB hash-based plus 97 vB
    Disprove, marked as a lower bound on the dispute path. The 2026/2100 and
    DV-Pari rows are n/r. Check BABE's $37.65 is the right BitVM3 figure to
    quote next to 2026/933's $5; the two differ by fee normalization and by
    which transactions are counted.
11. **Label-selection section (2026-10-01).** Verify the BIP360 footnote URL
    and find a citable SHRINCS reference; the batch-opcode rows are hypothetical
    and must stay labelled so.
