//! The dispute of the paper's protocol, end to end on a small circuit, with
//! the on-chain steps executed as Bitcoin Script by `bitcoin-scriptexec`.
//!
//! The statement is "I know `x`, 64 bytes, with `Blake3(x) = h`": one Blake3
//! compression, 512 input bits. The operator garbles it at setup, before it
//! has chosen `x`, and commits to one Lamport key pair per input bit. At
//! dispute time:
//!
//! 1. **Assert** (script). The operator publishes one preimage per bit; the
//!    locking script checks each against that bit's two hashes.
//! 2. **Labels** (off-chain). The challenger reads the published preimages,
//!    learns each bit from which hash it opens, and turns each preimage into
//!    that bit's input label through the operator's translation ciphertexts.
//! 3. **Evaluation** (off-chain). The challenger evaluates the stored garbling
//!    holding only those labels.
//! 4. **Disprove** (script). A hashlock on the label of output value 0: the
//!    challenger can open it exactly when the asserted `x` is wrong.
//!
//! What is left out, and why: transaction signatures and timelocks (the
//! script executor has no transaction to sign; the paper's Take and Challenge
//! transactions are ordinary), and cut-and-choose (one honestly garbled
//! instance; soldering across instances is the open part of the protocol).

mod dispute;

use bitcoin_script::{define_pushable, script};
use dispute::{Lamport, assert_lock, assert_witness, disprove_lock, disproves, read_labels, runs};
use garbled_snark_verifier::circuits::sect233k1::blake3_ckt::{self, U8};
use garbled_snark_verifier::circuits::sect233k1::builder::{CircuitAdapter, CircuitTrait};
use garbled_snark_verifier::core::s::S;
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;
use whir_gc::garble::{self, Garbled};

define_pushable!();

const INPUT_BYTES: usize = 64;
const INPUT_BITS: usize = 8 * INPUT_BYTES;

/// `Blake3(x) == h` as a circuit: 512 input wires (wires `2..514`, byte by
/// byte, least significant bit first), one output wire.
fn preimage_circuit(h: &[u8; 32]) -> (CircuitAdapter, usize) {
    let mut b = CircuitAdapter::default();
    let input: Vec<U8> = (0..INPUT_BYTES).map(|_| core::array::from_fn(|_| b.fresh_one())).collect();
    assert_eq!(input[0][0], 2, "the inputs follow the two constants");
    let digest = blake3_ckt::hash_bytes(&mut b, &input);
    let one = b.one();
    let mut all = one;
    for (byte, &hb) in digest.iter().zip(h) {
        for (k, &wire) in byte.iter().enumerate() {
            let bit_equal = if (hb >> k) & 1 == 1 { wire } else { b.xor_wire(wire, one) };
            all = b.and_wire(all, bit_equal);
        }
    }
    (b, all)
}

fn bits_of(x: &[u8]) -> Vec<bool> {
    x.iter().flat_map(|&v| (0..8).map(move |k| (v >> k) & 1 == 1)).collect()
}

/// What the operator publishes at setup, and what it keeps.
struct Setup {
    /// Kept: the garbling's secrets; the Lamport preimages sit in `keys`.
    garbled: Garbled,
    keys: Lamport,
    /// Published: the circuit (the ciphertexts are in `garbled`), the
    /// translation ciphertexts, and the held labels of the two constant wires.
    circuit: CircuitAdapter,
    output: usize,
    translation: Vec<[S; 2]>,
    constants: [S; 2],
}

fn setup(h: &[u8; 32], rng: &mut ChaCha20Rng) -> Setup {
    let (circuit, output) = preimage_circuit(h);
    let garbled = garble::garble(&circuit, INPUT_BITS, output);
    let keys = Lamport::new(INPUT_BITS, rng);
    let translation = keys.translation(|i, value| garbled.input_label(2 + i, value));
    let constants = [garbled.input_label(0, false), garbled.input_label(1, true)];
    Setup { garbled, keys, circuit, output, translation, constants }
}

/// The challenger's side: from the preimages published on-chain to the
/// output label, holding only public data.
fn challenge(s: &Setup, published: &[[u8; 16]]) -> S {
    let inputs = read_labels(&s.keys.hashes, &s.translation, published);
    garble::evaluate_labels(&s.circuit, &s.garbled.ciphertexts, s.constants, &inputs, s.output).label
}

#[test]
fn a_false_claim_is_disproved_and_a_true_one_is_not() {
    let mut rng = ChaCha20Rng::seed_from_u64(2026);
    let x: [u8; INPUT_BYTES] = core::array::from_fn(|_| rng.random());
    let h = *blake3::hash(&x).as_bytes();

    // Setup, before any claim is made.
    let s = setup(&h, &mut rng);
    let reject = s.garbled.output0;
    let accept = reject ^ s.garbled.delta;
    let lock = assert_lock(&s.keys.hashes);
    let wires = s.circuit.eval_gates(&bits_of(&x));
    assert!(wires[s.output], "the circuit is Blake3(x) == h");
    eprintln!(
        "circuit: {} non-free gates, {} B garbled; Assert leaf {} B for {INPUT_BITS} bits",
        s.garbled.ciphertexts.len(),
        s.garbled.ciphertext_bytes(),
        lock.len()
    );

    // A true claim: the Assert script accepts, the challenger's label is the
    // accept label, and it does not open the Disprove hashlock.
    let honest = s.keys.publish(&bits_of(&x));
    assert!(runs(assert_witness(&honest), lock.clone()), "Assert accepts a well-formed reveal");
    let label = challenge(&s, &honest);
    assert_eq!(label, accept, "the true claim evaluates to the accept label");
    assert!(!disproves(&label, &reject), "no Disprove on a true claim");

    // A false claim: x with one bit flipped. The reveal is well formed, so
    // Assert accepts it, and the challenger's evaluation opens Disprove.
    let mut wrong = x;
    wrong[7] ^= 0x10;
    let dishonest = s.keys.publish(&bits_of(&wrong));
    assert!(runs(assert_witness(&dishonest), lock.clone()), "Assert only checks the reveal is well formed");
    let label = challenge(&s, &dishonest);
    assert_eq!(label, reject, "the false claim evaluates to the reject label");
    assert!(disproves(&label, &reject), "Disprove opens on a false claim");

    // Assert rejects a reveal the operator did not commit to.
    let mut forged = honest.clone();
    forged[100] = rng.random();
    assert!(!runs(assert_witness(&forged), lock), "Assert rejects a preimage outside the keys");
    // And the hashlock takes nothing but the reject label.
    assert!(runs(script! { { reject.0.to_vec() } }, disprove_lock(&reject)));
    assert!(!disproves(&accept, &reject), "the accept label is not the reject label");
}
