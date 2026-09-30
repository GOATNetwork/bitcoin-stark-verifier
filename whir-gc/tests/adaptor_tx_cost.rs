//! Full serialized transaction-cost fixture for the BitVM3/Mosaic Schnorr
//! adaptor-signature input-publication construction.
//!
//! The on-chain objects are ordinary completed BIP340 signatures.  Each one
//! is produced here from an evaluator partial signature and a deterministic
//! test-only garbler secret, and extracting that secret from the completion is
//! checked before the signature is put in the witness.  The Tapscript is the
//! merged BitVM construction:
//!
//! ```text
//! <evaluator x-only key>
//! OP_TUCK OP_CHECKSIGVERIFY OP_CODESEPARATOR   (N - 1 times)
//! OP_CHECKSIG
//! ```
//!
//! Every signature uses SIGHASH_DEFAULT and the code-separator position seen
//! by its CHECKSIG.  The fixture uses real one-leaf P2TR prevouts with BIP341's
//! NUMS internal key, two P2TR outputs per transaction, depth-0 control blocks,
//! and direct transaction-aware verification of every completed signature.
//! Export mode binds the same transactions to real funding outputs for strict
//! Bitcoin Core execution; otherwise synthetic outpoints keep it deterministic.
//! The aggregate below is the signed reveal set, not a total on-chain cost:
//! funding is measured separately, and completion, challenge, timeout, anchor,
//! fee-management, and full dispute-graph transactions are not constructed.

use bitcoin::{
    absolute::LockTime,
    consensus::encode::serialize,
    hashes::{sha256, Hash, HashEngine},
    secp256k1::{
        schnorr::Signature as SchnorrSignature, Message, Parity, PublicKey, Scalar, Secp256k1,
        SecretKey, XOnlyPublicKey,
    },
    sighash::{Prevouts, SighashCache, TapSighashType},
    taproot::{ControlBlock, LeafVersion, TapLeafHash, TaprootBuilder},
    transaction::Version,
    Address, Amount, Network, OutPoint, ScriptBuf, Sequence, TapSighash, Transaction, TxIn, TxOut,
    Txid, Witness,
};
use std::str::FromStr;

const INPUT_BITS: usize = 1_041_024;
const BITS_PER_ADAPTOR_SIGNATURE: usize = 8;
const SOURCE_DIGITS: usize = 128;
const MAX_DIGITS: usize = 998;
const MAX_STACK_ITEMS: usize = 1_000;
const MAX_STANDARD_TX_WEIGHT: u64 = 400_000;
const FUNDING_SATS_PER_INPUT: u64 = 100_000;
const OUTPUT_SATS: u64 = 1_000;

// secp256k1's group order, used to implement BIP340's int(hash) mod n
// without introducing a second elliptic-curve dependency just for the test.
const SECP256K1_ORDER: [u8; 32] = [
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe,
    0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b, 0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x41, 0x41,
];

fn internal_key() -> XOnlyPublicKey {
    // BIP341's H = lift_x(sha256(uncompressed_G)) NUMS point.  No known key
    // path can bypass the adaptor-signature leaf.
    XOnlyPublicKey::from_str("50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0")
        .expect("BIP341 NUMS internal key")
}

fn evaluator_secret(secp: &Secp256k1<bitcoin::secp256k1::All>) -> SecretKey {
    let mut bytes = [0u8; 32];
    bytes[31] = 3;
    let secret = SecretKey::from_slice(&bytes).expect("fixed evaluator scalar");
    let public = PublicKey::from_secret_key(secp, &secret);
    if public.x_only_public_key().1 == Parity::Odd {
        secret.negate()
    } else {
        secret
    }
}

fn evaluator_public(
    secp: &Secp256k1<bitcoin::secp256k1::All>,
    secret: &SecretKey,
) -> XOnlyPublicKey {
    let (public, parity) = PublicKey::from_secret_key(secp, secret).x_only_public_key();
    assert_eq!(parity, Parity::Even, "BIP340 uses the even-Y lift");
    public
}

fn deterministic_secret(label: &[u8], sighash: &[u8; 32], ordinal: u64) -> SecretKey {
    // Test-only deterministic material.  Binding it to both the sighash and a
    // monotonically increasing ordinal prevents nonce reuse inside a fixture.
    for counter in 0u32.. {
        let mut engine = sha256::Hash::engine();
        engine.input(label);
        engine.input(sighash);
        engine.input(&ordinal.to_be_bytes());
        engine.input(&counter.to_be_bytes());
        let bytes = sha256::Hash::from_engine(engine).to_byte_array();
        if let Ok(secret) = SecretKey::from_slice(&bytes) {
            return secret;
        }
    }
    unreachable!("a SHA256 stream eventually gives a valid nonzero scalar")
}

fn scalar_mod_order(mut bytes: [u8; 32]) -> Scalar {
    // A 256-bit SHA256 result is below 2^256, while n is close to 2^256, so at
    // most one subtraction is required.
    if bytes >= SECP256K1_ORDER {
        let mut borrow = 0i16;
        for i in (0..32).rev() {
            let difference = bytes[i] as i16 - SECP256K1_ORDER[i] as i16 - borrow;
            if difference < 0 {
                bytes[i] = (difference + 256) as u8;
                borrow = 1;
            } else {
                bytes[i] = difference as u8;
                borrow = 0;
            }
        }
        assert_eq!(borrow, 0);
    }
    Scalar::from_be_bytes(bytes).expect("hash reduced modulo the group order")
}

fn bip340_challenge(
    nonce_x: XOnlyPublicKey,
    public_key: XOnlyPublicKey,
    message: &[u8; 32],
) -> Scalar {
    let tag_hash = sha256::Hash::hash(b"BIP0340/challenge");
    let mut engine = sha256::Hash::engine();
    engine.input(tag_hash.as_byte_array());
    engine.input(tag_hash.as_byte_array());
    engine.input(&nonce_x.serialize());
    engine.input(&public_key.serialize());
    engine.input(message);
    scalar_mod_order(sha256::Hash::from_engine(engine).to_byte_array())
}

/// Complete one adaptor signature and immediately check both the ordinary
/// Schnorr equation and extraction of the garbler's secret.
fn complete_adaptor_signature(
    secp: &Secp256k1<bitcoin::secp256k1::All>,
    evaluator_secret: &SecretKey,
    sighash: [u8; 32],
    ordinal: u64,
) -> Vec<u8> {
    let evaluator_public = evaluator_public(secp, evaluator_secret);
    let nonce = deterministic_secret(b"whir-gc/adaptor/nonce", &sighash, ordinal);
    let garbler_secret = deterministic_secret(b"whir-gc/adaptor/garbler", &sighash, ordinal);
    let nonce_commitment = PublicKey::from_secret_key(secp, &nonce);
    let garbler_commitment = PublicKey::from_secret_key(secp, &garbler_secret);
    let commitment_sum = nonce_commitment
        .combine(&garbler_commitment)
        .expect("independent commitments do not cancel");
    let (_, sum_parity) = commitment_sum.x_only_public_key();
    let odd_sum = sum_parity == Parity::Odd;

    // If R'=K+T has odd Y, BIP340 uses R=-(K+T).  The evaluator therefore
    // negates its nonce and the garbler subtracts, rather than adds, its share.
    let even_nonce_point = if odd_sum {
        commitment_sum.negate(secp)
    } else {
        commitment_sum
    };
    let (nonce_x, nonce_parity) = even_nonce_point.x_only_public_key();
    assert_eq!(nonce_parity, Parity::Even);
    let challenge = bip340_challenge(nonce_x, evaluator_public, &sighash);

    let adjusted_nonce = if odd_sum { nonce.negate() } else { nonce };
    let evaluator_s = if challenge == Scalar::ZERO {
        adjusted_nonce
    } else {
        let challenge_times_secret = evaluator_secret
            .clone()
            .mul_tweak(&challenge)
            .expect("nonzero challenge times evaluator secret");
        adjusted_nonce
            .add_tweak(&Scalar::from(challenge_times_secret))
            .expect("nonzero evaluator partial signature")
    };
    let garbler_tweak = if odd_sum {
        Scalar::from(garbler_secret.clone().negate())
    } else {
        Scalar::from(garbler_secret.clone())
    };
    let completed_s = evaluator_s
        .clone()
        .add_tweak(&garbler_tweak)
        .expect("nonzero completed signature scalar");

    let mut bytes = [0u8; 64];
    bytes[..32].copy_from_slice(&nonce_x.serialize());
    bytes[32..].copy_from_slice(&completed_s.secret_bytes());
    let signature = SchnorrSignature::from_slice(&bytes).expect("64-byte Schnorr signature");
    secp.verify_schnorr(
        &signature,
        &Message::from_digest(sighash),
        &evaluator_public,
    )
    .expect("completed adaptor signature satisfies BIP340");

    let delta = completed_s
        .add_tweak(&Scalar::from(evaluator_s.negate()))
        .expect("completed and partial signatures differ by a nonzero share");
    let extracted = if odd_sum { delta.negate() } else { delta };
    assert_eq!(
        extracted.secret_bytes(),
        garbler_secret.secret_bytes(),
        "completion reveals exactly the garbler share",
    );
    bytes.to_vec()
}

fn adaptor_leaf(evaluator_public: XOnlyPublicKey, digits: usize) -> ScriptBuf {
    assert!(
        digits >= 2,
        "the optimized repeated-key leaf assumes N >= 2"
    );
    let mut bytes = Vec::with_capacity(3 * digits + 31);
    bytes.push(0x20); // minimal 32-byte push
    bytes.extend_from_slice(&evaluator_public.serialize());
    for _ in 0..digits - 1 {
        bytes.push(0x7d); // OP_TUCK
        bytes.push(0xad); // OP_CHECKSIGVERIFY
        bytes.push(0xab); // OP_CODESEPARATOR
    }
    bytes.push(0xac); // OP_CHECKSIG
    let script = ScriptBuf::from_bytes(bytes);
    assert_eq!(script.len(), 3 * digits + 31);
    script
}

struct AdaptorInput {
    txin: TxIn,
    prevout: TxOut,
    tapscript: ScriptBuf,
    control: ControlBlock,
    output_key: XOnlyPublicKey,
    digits: usize,
}

fn adaptor_input(
    secp: &Secp256k1<bitcoin::secp256k1::All>,
    evaluator_public: XOnlyPublicKey,
    funding_txid: Txid,
    input_index: usize,
    digits: usize,
) -> AdaptorInput {
    let tapscript = adaptor_leaf(evaluator_public, digits);
    let spend_info = TaprootBuilder::new()
        .add_leaf(0, tapscript.clone())
        .expect("one-leaf taptree")
        .finalize(secp, internal_key())
        .expect("one-leaf taptree is complete");
    let control = spend_info
        .control_block(&(tapscript.clone(), LeafVersion::TapScript))
        .expect("control block for the only leaf");
    assert_eq!(control.serialize().len(), 33, "depth-0 control block");
    let output_key = spend_info.output_key().to_x_only_public_key();
    assert!(control.verify_taproot_commitment(secp, output_key, tapscript.as_script(),));

    AdaptorInput {
        txin: TxIn {
            previous_output: OutPoint::new(funding_txid, input_index as u32),
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        },
        prevout: TxOut {
            value: Amount::from_sat(FUNDING_SATS_PER_INPUT),
            script_pubkey: ScriptBuf::new_p2tr_tweaked(spend_info.output_key()),
        },
        tapscript,
        control,
        output_key,
        digits,
    }
}

fn unsigned_transaction(leaves: &[AdaptorInput]) -> Transaction {
    assert!(!leaves.is_empty());
    let output_script = leaves[0].prevout.script_pubkey.clone();
    assert_eq!(output_script.len(), 34, "P2TR scriptPubKey");
    Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: leaves.iter().map(|leaf| leaf.txin.clone()).collect(),
        output: vec![
            TxOut {
                value: Amount::from_sat(OUTPUT_SATS),
                script_pubkey: output_script.clone(),
            },
            TxOut {
                value: Amount::from_sat(OUTPUT_SATS),
                script_pubkey: output_script,
            },
        ],
    }
}

fn witness_arguments(witness: &Witness) -> Vec<Vec<u8>> {
    assert!(witness.len() >= 2);
    witness
        .iter()
        .take(witness.len() - 2)
        .map(<[u8]>::to_vec)
        .collect()
}

/// Check the exact BIP341 messages consumed by the repeated-key adaptor leaf.
///
/// The pinned `bitvm_scriptexec` revision records byte offsets for
/// OP_CODESEPARATOR, while BIP342 commits to opcode positions.  That mismatch
/// produced a false-positive fixture before Bitcoin Core validation exposed it.
/// We therefore verify the completed signatures directly here, and the
/// exported transactions are executed independently by Bitcoin Core 31.1.
fn verify_adaptor_input(
    tx: &Transaction,
    prevouts: &[TxOut],
    input_index: usize,
    leaf: &AdaptorInput,
    evaluator_public: XOnlyPublicKey,
    secp: &Secp256k1<bitcoin::secp256k1::All>,
    arguments: Vec<Vec<u8>>,
) -> (bool, usize) {
    if arguments.len() != leaf.digits || arguments.iter().any(|item| item.len() != 64) {
        return (false, leaf.digits + 2);
    }
    let leaf_hash = TapLeafHash::from_script(leaf.tapscript.as_script(), LeafVersion::TapScript);
    let prevouts_ref = Prevouts::All(prevouts);
    let mut cache = SighashCache::new(tx);
    for signature_index in 0..leaf.digits {
        // Witness elements are bottom-to-top.  The script consumes the completed
        // signatures in the reverse of their serialized witness order.
        let signature_bytes = &arguments[leaf.digits - 1 - signature_index];
        let Ok(signature) = SchnorrSignature::from_slice(signature_bytes) else {
            return (false, leaf.digits + 2);
        };
        let sighash = signature_hash(
            &mut cache,
            input_index,
            &prevouts_ref,
            leaf_hash,
            signature_index,
        );
        if secp
            .verify_schnorr(
                &signature,
                &Message::from_digest(sighash),
                &evaluator_public,
            )
            .is_err()
        {
            return (false, leaf.digits + 2);
        }
    }

    // N witness signatures, then the public-key push and OP_TUCK copy.
    (true, leaf.digits + 2)
}

/// Return the BIP341 message for the CHECKSIG numbered `signature_index` in
/// execution order.  The first check has no prior separator; every later one
/// sees the preceding OP_CODESEPARATOR at opcode position `3*i`.  BIP342 counts
/// a multi-byte push as one opcode, rather than using its byte offset.
fn signature_hash(
    cache: &mut SighashCache<&Transaction>,
    input_index: usize,
    prevouts: &Prevouts<'_, TxOut>,
    leaf_hash: TapLeafHash,
    signature_index: usize,
) -> [u8; 32] {
    let code_separator_position = if signature_index == 0 {
        0xffff_ffff
    } else {
        3 * signature_index as u32
    };
    let mut engine = TapSighash::engine();
    cache
        .taproot_encode_signing_data_to(
            &mut engine,
            input_index,
            prevouts,
            None,
            Some((leaf_hash, code_separator_position)),
            TapSighashType::Default,
        )
        .expect("BIP341 script-spend sighash with code separator");
    TapSighash::from_engine(engine).to_byte_array()
}

/// Complete all adaptor signatures after the full transaction is fixed, put
/// them in reverse execution order, and execute every input.
fn sign_and_execute(
    mut tx: Transaction,
    leaves: &[AdaptorInput],
    evaluator_secret: &SecretKey,
    secp: &Secp256k1<bitcoin::secp256k1::All>,
    next_ordinal: &mut u64,
) -> (Transaction, Vec<TxOut>, usize) {
    let evaluator_public = evaluator_public(secp, evaluator_secret);
    let prevouts: Vec<TxOut> = leaves.iter().map(|leaf| leaf.prevout.clone()).collect();
    let all_signatures: Vec<Vec<Vec<u8>>> = {
        let prevouts_ref = Prevouts::All(&prevouts);
        let mut cache = SighashCache::new(&tx);
        leaves
            .iter()
            .enumerate()
            .map(|(input_index, leaf)| {
                let leaf_hash =
                    TapLeafHash::from_script(leaf.tapscript.as_script(), LeafVersion::TapScript);
                (0..leaf.digits)
                    .map(|signature_index| {
                        let sighash = signature_hash(
                            &mut cache,
                            input_index,
                            &prevouts_ref,
                            leaf_hash,
                            signature_index,
                        );
                        let signature = complete_adaptor_signature(
                            secp,
                            evaluator_secret,
                            sighash,
                            *next_ordinal,
                        );
                        *next_ordinal += 1;
                        assert_eq!(signature.len(), 64);
                        signature
                    })
                    .collect()
            })
            .collect()
    };

    for ((input, leaf), signatures) in tx.input.iter_mut().zip(leaves).zip(all_signatures) {
        for signature in signatures.into_iter().rev() {
            input.witness.push(signature);
        }
        input.witness.push(leaf.tapscript.as_bytes());
        input.witness.push(leaf.control.serialize());

        assert_eq!(input.witness.len(), leaf.digits + 2);
        assert!(input
            .witness
            .iter()
            .take(leaf.digits)
            .all(|item| item.len() == 64));
        assert!(leaf.control.verify_taproot_commitment(
            secp,
            leaf.output_key,
            leaf.tapscript.as_script(),
        ));
        assert!(leaf.digits <= MAX_STACK_ITEMS);
    }

    let mut peak_stack = 0usize;
    for (input_index, (input, leaf)) in tx.input.iter().zip(leaves).enumerate() {
        let (success, peak) = verify_adaptor_input(
            &tx,
            &prevouts,
            input_index,
            leaf,
            evaluator_public,
            secp,
            witness_arguments(&input.witness),
        );
        assert!(success, "adaptor-signature input {input_index} executes");
        assert!(peak <= MAX_STACK_ITEMS);
        peak_stack = peak_stack.max(peak);
    }
    (tx, prevouts, peak_stack)
}

fn build_signed_transaction(
    secp: &Secp256k1<bitcoin::secp256k1::All>,
    evaluator_secret: &SecretKey,
    funding_txid: Txid,
    first_input_index: usize,
    digit_counts: &[usize],
    next_ordinal: &mut u64,
) -> (Transaction, Vec<TxOut>, Vec<AdaptorInput>, usize) {
    let evaluator_public = evaluator_public(secp, evaluator_secret);
    let leaves: Vec<AdaptorInput> = digit_counts
        .iter()
        .enumerate()
        .map(|(offset, &digits)| {
            adaptor_input(
                secp,
                evaluator_public,
                funding_txid,
                first_input_index + offset,
                digits,
            )
        })
        .collect();
    let unsigned = unsigned_transaction(&leaves);
    let (tx, prevouts, peak) =
        sign_and_execute(unsigned, &leaves, evaluator_secret, secp, next_ordinal);
    (tx, prevouts, leaves, peak)
}

fn encode_hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(2 * bytes.len());
    for &byte in bytes {
        out.push(DIGITS[(byte >> 4) as usize] as char);
        out.push(DIGITS[(byte & 0x0f) as usize] as char);
    }
    out
}

/// Export deterministic regtest funding commitments and signed reveals.  A
/// first pass with the all-zero txid defines the ordered funding outputs; a
/// second pass sets WHIR_GC_FUNDING_TXID to the actual confirmed funding txid.
fn export_regtest_fixtures(
    dir: &std::path::Path,
    prevout_scripts: &[ScriptBuf],
    reveals: &[Transaction],
) {
    std::fs::create_dir_all(dir).expect("create adaptor export directory");
    let outputs: Vec<String> = prevout_scripts
        .iter()
        .map(|script| {
            let address = Address::from_script(script, Network::Regtest)
                .expect("P2TR script has a regtest address");
            format!(
                "{{\"{address}\":{:.8}}}",
                FUNDING_SATS_PER_INPUT as f64 / 100_000_000.0
            )
        })
        .collect();
    std::fs::write(
        dir.join("funding_outputs.json"),
        format!("[{}]\n", outputs.join(",")),
    )
    .expect("write adaptor funding outputs");

    let scripts = prevout_scripts
        .iter()
        .enumerate()
        .map(|(i, script)| {
            let address = Address::from_script(script, Network::Regtest).unwrap();
            format!("{i}\t{address}\t{}", encode_hex(script.as_bytes()))
        })
        .collect::<Vec<_>>()
        .join("\n");
    std::fs::write(dir.join("funding_scripts.tsv"), format!("{scripts}\n"))
        .expect("write adaptor funding script manifest");

    for (i, tx) in reveals.iter().enumerate() {
        std::fs::write(
            dir.join(format!("reveal-{i:03}.hex")),
            format!("{}\n", encode_hex(&serialize(tx))),
        )
        .expect("write adaptor reveal transaction");
    }
}

#[test]
fn adaptor_n128_two_p2tr_output_golden_and_negatives() {
    let secp = Secp256k1::new();
    let evaluator_secret = evaluator_secret(&secp);
    let mut ordinal = 0;
    let (tx, prevouts, leaves, peak) = build_signed_transaction(
        &secp,
        &evaluator_secret,
        Txid::all_zeros(),
        0,
        &[SOURCE_DIGITS],
        &mut ordinal,
    );
    let leaf = &leaves[0];

    assert_eq!(leaf.tapscript.len(), 415);
    assert_eq!(leaf.control.serialize().len(), 33);
    assert_eq!(tx.input[0].witness.len(), 130);
    assert_eq!(tx.base_size(), 137);
    assert_eq!(serialize(&tx).len(), 8_912);
    assert_eq!(tx.weight().to_wu(), 9_323);
    assert_eq!(tx.vsize(), 2_331);
    assert_eq!(peak, 130, "N signatures plus pushed key and OP_TUCK copy");
    eprintln!(
        "adaptor N=128 golden: {} serialized bytes, {} WU, {} vB, peak stack {peak}",
        serialize(&tx).len(),
        tx.weight().to_wu(),
        tx.vsize(),
    );

    let arguments = witness_arguments(&tx.input[0].witness);

    // The signatures commit to different code-separator positions, so merely
    // reversing the witness order must fail.
    let mut wrong_order = arguments.clone();
    wrong_order.reverse();
    assert!(
        !verify_adaptor_input(
            &tx,
            &prevouts,
            0,
            leaf,
            evaluator_public(&secp, &evaluator_secret),
            &secp,
            wrong_order,
        )
        .0
    );

    let mut tampered_signature = arguments.clone();
    tampered_signature[0][0] ^= 1;
    assert!(
        !verify_adaptor_input(
            &tx,
            &prevouts,
            0,
            leaf,
            evaluator_public(&secp, &evaluator_secret),
            &secp,
            tampered_signature,
        )
        .0
    );

    // SIGHASH_DEFAULT binds the outputs, rather than merely authenticating a
    // byte string independently of the Bitcoin transaction.
    let mut redirected = tx.clone();
    redirected.output[0].value = Amount::from_sat(OUTPUT_SATS + 1);
    assert!(
        !verify_adaptor_input(
            &redirected,
            &prevouts,
            0,
            leaf,
            evaluator_public(&secp, &evaluator_secret),
            &secp,
            arguments,
        )
        .0
    );

    let mut wrong_control = leaf.control.serialize();
    wrong_control[0] ^= 1;
    let wrong_control =
        ControlBlock::decode(&wrong_control).expect("parity-flipped control block decodes");
    assert!(!wrong_control.verify_taproot_commitment(
        &secp,
        leaf.output_key,
        leaf.tapscript.as_script(),
    ));
}

#[test]
fn adaptor_n998_reaches_the_tapscript_stack_capacity() {
    let secp = Secp256k1::new();
    let evaluator_secret = evaluator_secret(&secp);
    let mut ordinal = 1_000_000;
    let (tx, _, leaves, peak) = build_signed_transaction(
        &secp,
        &evaluator_secret,
        Txid::all_zeros(),
        0,
        &[MAX_DIGITS],
        &mut ordinal,
    );

    assert_eq!(leaves[0].tapscript.len(), 3_025);
    assert_eq!(tx.input[0].witness.len(), 1_000);
    assert_eq!(serialize(&tx).len(), 68_074);
    assert_eq!(tx.weight().to_wu(), 68_485);
    assert_eq!(tx.vsize(), 17_122);
    assert_eq!(peak, MAX_STACK_ITEMS);
    // N=999 would begin with 999 signatures, then the key push and OP_TUCK
    // copy would reach 1001 stack items.  Hence 998 is the exact capacity.
    assert_eq!(MAX_DIGITS + 2, MAX_STACK_ITEMS);
}

fn minimum_input_digit_packing() -> Vec<Vec<usize>> {
    // There are 130,128 eight-bit digits.  131 inputs are information-
    // theoretically necessary at N<=998.  Conditional on using exactly those
    // 131 inputs, this distribution needs 26 standard transactions and
    // minimizes the sum of per-transaction vsize rounding:
    // 4*6 + 3*4 + 19*5 = 131 inputs.
    let mut packing = Vec::with_capacity(26);
    for _ in 0..4 {
        packing.push(vec![998, 998, 998, 998, 998, 865]); // 5,855 digits
    }
    for _ in 0..3 {
        packing.push(vec![998; 4]); // 3,992 digits
    }
    for _ in 0..18 {
        packing.push(vec![998; 5]); // 4,990 digits
    }
    packing.push(vec![998, 998, 998, 998, 920]); // 4,912 digits
    packing
}

#[test]
fn adaptor_minimum_input_packing_is_2_222_397_vbytes() {
    let packing = minimum_input_digit_packing();
    let total_digits = INPUT_BITS / BITS_PER_ADAPTOR_SIGNATURE;
    assert_eq!(INPUT_BITS % BITS_PER_ADAPTOR_SIGNATURE, 0);
    assert_eq!(total_digits, 130_128);
    assert_eq!(packing.len(), 26);
    assert_eq!(packing.iter().map(Vec::len).sum::<usize>(), 131);
    assert_eq!(packing.iter().flatten().sum::<usize>(), total_digits);
    assert!(packing.iter().flatten().all(|&digits| digits <= MAX_DIGITS));

    let secp = Secp256k1::new();
    let evaluator_secret = evaluator_secret(&secp);
    let funding_txid = Txid::all_zeros();
    let mut next_input = 0usize;
    let mut ordinal = 2_000_000u64;
    let mut weights = Vec::with_capacity(packing.len());
    let mut vsizes = Vec::with_capacity(packing.len());
    let mut max_peak = 0usize;

    for digit_counts in &packing {
        let (tx, _, _, peak) = build_signed_transaction(
            &secp,
            &evaluator_secret,
            funding_txid,
            next_input,
            digit_counts,
            &mut ordinal,
        );
        next_input += digit_counts.len();
        let weight = tx.weight().to_wu();
        assert!(weight <= MAX_STANDARD_TX_WEIGHT);
        weights.push(weight);
        vsizes.push(tx.vsize());
        max_peak = max_peak.max(peak);
    }

    assert_eq!(next_input, 131);
    assert_eq!(max_peak, MAX_STACK_ITEMS);
    assert_eq!(weights[..4], [399_936; 4]);
    assert_eq!(weights[4..7], [272_782; 3]);
    assert_eq!(weights[7..25], [340_881; 18]);
    assert_eq!(weights[25], 335_577);
    assert_eq!(vsizes[..4], [99_984; 4]);
    assert_eq!(vsizes[4..7], [68_196; 3]);
    assert_eq!(vsizes[7..25], [85_221; 18]);
    assert_eq!(vsizes[25], 83_895);
    assert_eq!(weights.iter().sum::<u64>(), 8_889_525);
    assert_eq!(vsizes.iter().sum::<usize>(), 2_222_397);
}

fn globally_optimized_reveal_packing() -> Vec<Vec<usize>> {
    // Paying for two extra input shells permits three fewer transaction shells.
    // Seventeen six-input transactions are full, one six-input transaction is
    // shortened by 212 digits, and five five-input transactions are full:
    //
    //   17*5,855 + 5,643 + 5*4,990 = 130,128 digits
    //   18*6 + 5*5                    = 133 inputs
    //
    // A standard two-output transaction cannot carry more than 5,855 digits:
    // five or fewer inputs cap out at 998 digits each; six inputs hit 399,936
    // WU at 5,855 digits and 5,856 would hit 400,004 WU; additional input
    // shells only reduce the weight-limited digit capacity.  Consequently 22
    // transactions carry at most 22*5,855 < 130,128 digits, whereas this
    // 23-transaction construction attains the lower bound.
    let mut packing = Vec::with_capacity(23);
    for _ in 0..17 {
        packing.push(vec![998, 998, 998, 998, 998, 865]); // 5,855 digits
    }
    packing.push(vec![998, 998, 998, 998, 998, 653]); // 5,643 digits
    for _ in 0..5 {
        packing.push(vec![998; 5]); // 4,990 digits
    }
    packing
}

/// Exact transaction shapes for wider adaptor digits. Changing the number of
/// bits represented by one adaptor signature changes only the off-chain choice
/// table; on chain, each chosen digit is still one 64-byte BIP340 signature.
/// These shapes minimize the number of standard reveal transactions first and
/// then the number of P2TR inputs for the fixed 1,041,024-bit instance.
fn wider_digit_packing(bits_per_digit: usize) -> Vec<Vec<usize>> {
    match bits_per_digit {
        8 => globally_optimized_reveal_packing(),
        // ceil(1,041,024 / 10) = 104,103 digits. Seventeen six-input
        // transactions and one five-input transaction are necessary; one of
        // the six-input transactions is shortened by 422 digits.
        10 => {
            let mut packing = vec![vec![998, 998, 998, 998, 998, 865]; 16];
            packing.push(vec![998, 998, 998, 998, 998, 443]);
            packing.push(vec![998; 5]);
            packing
        }
        // 94,639 digits: twelve six-input and five five-input transactions;
        // one six-input transaction is shortened by 571 digits.
        11 => {
            let mut packing = vec![vec![998, 998, 998, 998, 998, 865]; 11];
            packing.push(vec![998, 998, 998, 998, 998, 294]);
            packing.extend((0..5).map(|_| vec![998; 5]));
            packing
        }
        // 86,752 digits: fourteen six-input transactions and one five-input
        // transaction, with one six-input transaction shortened by 208.
        12 => {
            let mut packing = vec![vec![998, 998, 998, 998, 998, 865]; 13];
            packing.push(vec![998, 998, 998, 998, 998, 657]);
            packing.push(vec![998; 5]);
            packing
        }
        // 65,064 digits: six six-input and six five-input transactions; only
        // six digit slots are unused in the final six-input transaction.
        16 => {
            let mut packing = vec![vec![998, 998, 998, 998, 998, 865]; 5];
            packing.push(vec![998, 998, 998, 998, 998, 859]);
            packing.extend((0..6).map(|_| vec![998; 5]));
            packing
        }
        _ => panic!("no audited packing for {bits_per_digit}-bit digits"),
    }
}

/// Serialize the exact witness shape without doing hundreds of thousands of
/// redundant scalar multiplications. The ordinary 64-byte signatures are
/// represented by fixed-size placeholders; `adaptor_n998_...` separately
/// validates the largest input with real completed signatures and BIP341
/// sighashes. Weight and vsize depend only on these serialized lengths.
fn shape_transaction(
    secp: &Secp256k1<bitcoin::secp256k1::All>,
    evaluator_public: XOnlyPublicKey,
    first_input_index: usize,
    digit_counts: &[usize],
) -> Transaction {
    let leaves: Vec<AdaptorInput> = digit_counts
        .iter()
        .enumerate()
        .map(|(offset, &digits)| {
            adaptor_input(
                secp,
                evaluator_public,
                Txid::all_zeros(),
                first_input_index + offset,
                digits,
            )
        })
        .collect();
    let mut tx = unsigned_transaction(&leaves);
    for (input, leaf) in tx.input.iter_mut().zip(&leaves) {
        for _ in 0..leaf.digits {
            input.witness.push([0u8; 64]);
        }
        input.witness.push(leaf.tapscript.as_bytes());
        input.witness.push(leaf.control.serialize());
    }
    tx
}

#[test]
fn wider_adaptor_digits_exact_serialized_sweep() {
    let secp = Secp256k1::new();
    let evaluator_secret = evaluator_secret(&secp);
    let evaluator_public = evaluator_public(&secp, &evaluator_secret);
    let expected = [
        // bits/digit, digits, inputs, reveal txs, reveal WU, reveal vB
        (
            8usize,
            130_128usize,
            133usize,
            23usize,
            8_888_837u64,
            2_222_213usize,
        ),
        (10, 104_103, 107, 18, 7_111_097, 1_777_775),
        (11, 94_639, 97, 17, 6_464_809, 1_616_206),
        (12, 86_752, 89, 15, 5_925_841, 1_481_461),
        (16, 65_064, 66, 12, 4_444_494, 1_111_128),
    ];

    eprintln!(
        "bits/digit | digits | inputs | reveal txs | reveal WU | reveal vB | off-chain table bytes"
    );
    for (bits, digits, inputs, transactions, expected_wu, expected_vb) in expected {
        assert_eq!(digits, INPUT_BITS.div_ceil(bits));
        let packing = wider_digit_packing(bits);
        assert_eq!(packing.len(), transactions);
        assert_eq!(packing.iter().map(Vec::len).sum::<usize>(), inputs);
        assert_eq!(packing.iter().flatten().sum::<usize>(), digits);
        assert!(packing.iter().flatten().all(|&count| count <= MAX_DIGITS));

        let mut first_input = 0usize;
        let mut weight = 0u64;
        let mut vsize = 0usize;
        for digit_counts in &packing {
            let tx = shape_transaction(&secp, evaluator_public, first_input, digit_counts);
            first_input += digit_counts.len();
            assert!(tx.weight().to_wu() <= MAX_STANDARD_TX_WEIGHT);
            weight += tx.weight().to_wu();
            vsize += tx.vsize();
        }
        assert_eq!(weight, expected_wu);
        assert_eq!(vsize, expected_vb);

        // BitVM3 supplies every possible value for each digit off chain. At
        // 65 bytes per adaptor signature (including its sighash byte in the
        // source construction), this is the principal widening tradeoff.
        let table_bytes = digits as u128 * (1u128 << bits) * 65;
        eprintln!(
            "{bits:>10} | {digits:>6} | {inputs:>6} | {transactions:>10} | \
             {weight:>9} | {vsize:>9} | {table_bytes}"
        );
    }
}

#[test]
fn adaptor_16bit_globally_optimized_reveal_is_1_111_128_vbytes() {
    let packing = wider_digit_packing(16);
    let total_digits = INPUT_BITS.div_ceil(16);
    assert_eq!(total_digits, 65_064);
    assert_eq!(packing.len(), 12);
    assert_eq!(packing.iter().map(Vec::len).sum::<usize>(), 66);
    assert_eq!(packing.iter().flatten().sum::<usize>(), total_digits);

    let secp = Secp256k1::new();
    let evaluator_secret = evaluator_secret(&secp);
    let funding_txid = std::env::var("WHIR_GC_FUNDING_TXID")
        .ok()
        .map(|value| value.parse().expect("WHIR_GC_FUNDING_TXID is a txid"))
        .unwrap_or_else(Txid::all_zeros);
    let mut next_input = 0usize;
    let mut ordinal = 8_000_000u64;
    let mut weights = Vec::with_capacity(packing.len());
    let mut vsizes = Vec::with_capacity(packing.len());
    let mut transactions = Vec::with_capacity(packing.len());
    let mut prevout_scripts = Vec::with_capacity(66);
    let mut max_peak = 0usize;

    for digit_counts in &packing {
        let (tx, prevouts, _, peak) = build_signed_transaction(
            &secp,
            &evaluator_secret,
            funding_txid,
            next_input,
            digit_counts,
            &mut ordinal,
        );
        next_input += digit_counts.len();
        assert!(tx.weight().to_wu() <= MAX_STANDARD_TX_WEIGHT);
        weights.push(tx.weight().to_wu());
        vsizes.push(tx.vsize());
        prevout_scripts.extend(prevouts.into_iter().map(|prevout| prevout.script_pubkey));
        max_peak = max_peak.max(peak);
        transactions.push(tx);
    }

    assert_eq!(next_input, 66);
    assert_eq!(max_peak, MAX_STACK_ITEMS);
    assert_eq!(weights[..5], [399_936; 5]);
    assert_eq!(weights[5], 399_528);
    assert_eq!(weights[6..], [340_881; 6]);
    assert_eq!(vsizes[..5], [99_984; 5]);
    assert_eq!(vsizes[5], 99_882);
    assert_eq!(vsizes[6..], [85_221; 6]);
    assert_eq!(weights.iter().sum::<u64>(), 4_444_494);
    assert_eq!(vsizes.iter().sum::<usize>(), 1_111_128);
    eprintln!(
        "{INPUT_BITS} bits via 16-bit adaptor digits: {total_digits} signatures, \
         {next_input} signed P2TR inputs in {} two-output transactions; {} WU; \
         {} vB; max tx {} WU",
        packing.len(),
        weights.iter().sum::<u64>(),
        vsizes.iter().sum::<usize>(),
        weights.iter().max().unwrap(),
    );

    if let Ok(dir) = std::env::var("WHIR_GC_EXPORT_DIR") {
        export_regtest_fixtures(std::path::Path::new(&dir), &prevout_scripts, &transactions);
    }
}

#[test]
fn adaptor_globally_optimized_reveal_is_2_222_213_vbytes() {
    let packing = globally_optimized_reveal_packing();
    let total_digits = INPUT_BITS / BITS_PER_ADAPTOR_SIGNATURE;
    assert_eq!(INPUT_BITS % BITS_PER_ADAPTOR_SIGNATURE, 0);
    assert_eq!(total_digits, 130_128);
    assert_eq!(packing.len(), 23);
    assert_eq!(packing.iter().map(Vec::len).sum::<usize>(), 133);
    assert_eq!(packing.iter().flatten().sum::<usize>(), total_digits);
    assert!(packing.iter().flatten().all(|&digits| digits <= MAX_DIGITS));
    assert_eq!(386u64 + 235 * 6 + 68 * 5_855, 399_936);
    assert_eq!(386u64 + 235 * 6 + 68 * 5_856, 400_004);
    // Even granting every item the four-byte CompactSize saving possible for
    // a tiny leaf, seven or more inputs cannot fit 5,856 digits.
    assert!(386u64 + 231 * 7 + 68 * 5_856 > MAX_STANDARD_TX_WEIGHT);
    assert!(22 * 5_855 < total_digits, "22 transactions cannot suffice");

    let secp = Secp256k1::new();
    let evaluator_secret = evaluator_secret(&secp);
    let funding_txid = std::env::var("WHIR_GC_FUNDING_TXID")
        .ok()
        .map(|value| value.parse().expect("WHIR_GC_FUNDING_TXID is a txid"))
        .unwrap_or_else(Txid::all_zeros);
    let mut next_input = 0usize;
    let mut ordinal = 4_000_000u64;
    let mut weights = Vec::with_capacity(packing.len());
    let mut vsizes = Vec::with_capacity(packing.len());
    let mut transactions = Vec::with_capacity(packing.len());
    let mut prevout_scripts = Vec::with_capacity(133);
    let mut max_peak = 0usize;

    for digit_counts in &packing {
        let (tx, prevouts, _, peak) = build_signed_transaction(
            &secp,
            &evaluator_secret,
            funding_txid,
            next_input,
            digit_counts,
            &mut ordinal,
        );
        next_input += digit_counts.len();
        let weight = tx.weight().to_wu();
        assert!(weight <= MAX_STANDARD_TX_WEIGHT);
        weights.push(weight);
        vsizes.push(tx.vsize());
        prevout_scripts.extend(prevouts.into_iter().map(|prevout| prevout.script_pubkey));
        max_peak = max_peak.max(peak);
        transactions.push(tx);
    }

    assert_eq!(next_input, 133);
    assert_eq!(max_peak, MAX_STACK_ITEMS);
    assert_eq!(weights[..17], [399_936; 17]);
    assert_eq!(weights[17], 385_520);
    assert_eq!(weights[18..], [340_881; 5]);
    assert_eq!(vsizes[..17], [99_984; 17]);
    assert_eq!(vsizes[17], 96_380);
    assert_eq!(vsizes[18..], [85_221; 5]);
    assert_eq!(weights.iter().sum::<u64>(), 8_888_837);
    assert_eq!(vsizes.iter().sum::<usize>(), 2_222_213);
    eprintln!(
        "{INPUT_BITS} bits via adaptor signatures: {} digits, {} signed P2TR inputs in \
         {} two-output transactions; {} WU; {} vB; max tx {} WU",
        total_digits,
        next_input,
        packing.len(),
        weights.iter().sum::<u64>(),
        vsizes.iter().sum::<usize>(),
        weights.iter().max().unwrap(),
    );

    // If the two additional prevouts must also be created on chain, two P2TR
    // outputs add 2*43 = 86 non-witness vbytes (away from CompactSize count
    // boundaries).  Reveal plus funding still saves 184 - 86 = 98 vbytes,
    // before accounting for the three completion parents no longer needed.
    assert_eq!(2_222_397 - 2_222_213, 184);
    assert_eq!(184 - 2 * 43, 98);

    if let Ok(dir) = std::env::var("WHIR_GC_EXPORT_DIR") {
        export_regtest_fixtures(std::path::Path::new(&dir), &prevout_scripts, &transactions);
    }
}
