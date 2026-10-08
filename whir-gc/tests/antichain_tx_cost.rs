//! Executable, transaction-bound cost fixture for the safe Antichain-Winternitz
//! `(k=2, L=16)` input-publication construction.
//!
//! This uses the upstream construction at its pinned revision, including real
//! per-digit chain secrets, public terminals, openings, and posted coordinates.
//! Every P2TR leaf is prefixed by a 64-byte SIGHASH_DEFAULT Schnorr check, uses
//! BIP341's unknown-discrete-log NUMS internal key, and is serialized in a
//! version-2 transaction with two P2TR outputs.  The two outputs model the
//! continuation and anchor/change-shaped edges of a protocol transaction; both
//! are included in every weight below.
//! The aggregate below is the signed reveal set, not a total on-chain cost:
//! funding is measured separately, and completion, challenge, timeout, anchor,
//! fee-management, and full dispute-graph transactions are not constructed.
//!
//! The canonical middle-rank codeword is `[8, 7]`.  Its posted coordinate is a
//! one-byte ScriptNum, so the reported aggregate is the all-nonzero (worst-case)
//! serialized cost.  A separate regression proves that every zero posted
//! coordinate saves exactly one witness byte/WU; costs for concrete data are
//! therefore `W(z) = W(0) - z`.  Both canonical transaction weights are
//! `2 mod 4`, so the exact aggregate vsize is
//! `11_848_875 - sum_t floor((z_t + 2) / 4)`, where `z_t` is the number of zero
//! posted coordinates in transaction `t`.

use acw::{
    acw::{AntichainWinternitz, Parameters, Signature},
    codeword::{antichain_count, canonical_codeword},
    weight::acw_stack,
    HashKind,
};
use bitcoin::{
    absolute::LockTime,
    consensus::encode::serialize,
    hashes::Hash,
    key::{Keypair, Secp256k1},
    secp256k1::{Message, SecretKey, XOnlyPublicKey},
    sighash::{Prevouts, SighashCache, TapSighashType},
    taproot::{ControlBlock, LeafVersion, TapLeafHash, TaprootBuilder},
    transaction::Version,
    Address, Amount, Network, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid,
    Witness,
};
use bitvm_scriptexec::{Exec, ExecCtx, Options, TxTemplate};
use rand08::SeedableRng;
use rand_chacha08::ChaCha20Rng;
use std::str::FromStr;

/// The measured Keccak verifier's input; the golden totals are pinned at this size.
const KECCAK_INPUT_BITS: usize = 1_041_024;

/// The input size to serialize: `WHIR_GC_INPUT_BITS`, else the Keccak verifier's.
fn input_bits() -> usize {
    std::env::var("WHIR_GC_INPUT_BITS")
        .ok()
        .map_or(KECCAK_INPUT_BITS, |s| s.parse().expect("WHIR_GC_INPUT_BITS is a bit count"))
}
const BITS_PER_DIGIT: usize = 4;
const MAX_DIGITS_PER_INPUT: usize = 332;
const INPUTS_PER_TX: usize = 6;
const MAX_STACK_ITEMS: usize = 1_000;
const MAX_STANDARD_TX_WEIGHT: u64 = 400_000;
const FUNDING_SATS_PER_INPUT: u64 = 100_000;
const OUTPUT_SATS: u64 = 1_000;

fn internal_key() -> XOnlyPublicKey {
    // BIP341's H = lift_x(sha256(uncompressed_G)) NUMS point.  No discrete
    // logarithm is known, so the key path cannot bypass the ACW leaf.
    XOnlyPublicKey::from_str("50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0")
        .expect("BIP341 NUMS internal key")
}

fn authorization_keypair(secp: &Secp256k1<bitcoin::secp256k1::All>) -> Keypair {
    let secret = SecretKey::from_slice(&[3u8; 32]).expect("fixed test signing key");
    Keypair::from_secret_key(secp, &secret)
}

/// Put transaction authorization before the one-time opening checks.  The
/// signature is consequently the top initial stack item and is consumed before
/// the first ACW coordinate is inspected.
fn authorized_leaf(authorization_key: XOnlyPublicKey, verifier: ScriptBuf) -> ScriptBuf {
    let mut bytes = Vec::with_capacity(34 + verifier.len());
    bytes.push(0x20); // minimal direct push of a 32-byte x-only public key
    bytes.extend_from_slice(&authorization_key.serialize());
    bytes.push(0xad); // OP_CHECKSIGVERIFY
    bytes.extend_from_slice(verifier.as_bytes());
    ScriptBuf::from_bytes(bytes)
}

fn canonical_codewords(digits: usize) -> Vec<Vec<u32>> {
    let codeword = canonical_codeword(2, 16);
    assert_eq!(codeword, [8, 7]);
    vec![codeword; digits]
}

fn codewords_with_first_zero(digits: usize) -> Vec<Vec<u32>> {
    let mut codewords = canonical_codewords(digits);
    codewords[0] = vec![0, 15];
    codewords
}

struct AcwInput {
    txin: TxIn,
    prevout: TxOut,
    tapscript: ScriptBuf,
    control: ControlBlock,
    output_key: XOnlyPublicKey,
    opening: Signature,
    digits: usize,
}

/// Generate one genuine ACW key/opening and commit its verifier as the only
/// Taproot leaf.  The witness is added only after the complete transaction is
/// fixed, because SIGHASH_DEFAULT commits to that transaction.
fn acw_input(
    rng: &mut ChaCha20Rng,
    secp: &Secp256k1<bitcoin::secp256k1::All>,
    authorization_key: XOnlyPublicKey,
    funding_txid: Txid,
    funding_index: u32,
    codewords: &[Vec<u32>],
) -> AcwInput {
    let digits = codewords.len();
    let parameters = Parameters::new(digits as u32, 2, 16, HashKind::Hash160);
    let (secret_key, public_key) = AntichainWinternitz::keygen(rng, &parameters);
    let opening = AntichainWinternitz::sign(&secret_key, &parameters, codewords);
    let verifier = AntichainWinternitz::verify_script(&public_key, &parameters).compile();
    let tapscript = authorized_leaf(authorization_key, verifier);

    let spend_info = TaprootBuilder::new()
        .add_leaf(0, tapscript.clone())
        .expect("one-leaf ACW taptree")
        .finalize(secp, internal_key())
        .expect("one-leaf ACW taptree is complete");
    let control = spend_info
        .control_block(&(tapscript.clone(), LeafVersion::TapScript))
        .expect("control block for the only leaf");
    let output_key = spend_info.output_key().to_x_only_public_key();
    assert_eq!(control.serialize().len(), 33, "depth-0 control block");
    assert!(control.verify_taproot_commitment(secp, output_key, tapscript.as_script(),));

    AcwInput {
        txin: TxIn {
            previous_output: OutPoint::new(funding_txid, funding_index),
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
        opening,
        digits,
    }
}

fn two_output_transaction(
    leaves: &[AcwInput],
    secp: &Secp256k1<bitcoin::secp256k1::All>,
) -> Transaction {
    // Both outputs have the exact standard P2TR 43-byte TxOut shape.  The NUMS
    // key keeps this measurement from introducing a known key-path bypass.
    let output_script = ScriptBuf::new_p2tr(secp, internal_key(), None);
    assert_eq!(output_script.len(), 34);
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

/// Run an already selected tapleaf against the real transaction and all
/// prevouts.  This makes OP_CHECKSIGVERIFY validate the BIP341 script-spend
/// sighash instead of using a signature stub.
fn execute_input(
    tx: &Transaction,
    prevouts: &[TxOut],
    input_index: usize,
    tapscript: &ScriptBuf,
    arguments: Vec<Vec<u8>>,
) -> (bool, usize) {
    let leaf_hash = TapLeafHash::from_script(tapscript.as_script(), LeafVersion::TapScript);
    let mut exec = Exec::new(
        ExecCtx::Tapscript,
        Options {
            enforce_stack_limit: true,
            ..Options::default()
        },
        TxTemplate {
            tx: tx.clone(),
            prevouts: prevouts.to_vec(),
            input_idx: input_index,
            taproot_annex_scriptleaf: Some((leaf_hash, None)),
        },
        tapscript.clone(),
        arguments,
    )
    .expect("transaction-aware Tapscript executor");
    while exec.exec_next().is_ok() {}
    let success = exec.result().expect("execution terminates").success;
    (success, exec.stats().max_nb_stack_items)
}

/// Sign every leaf only after both outputs and all input outpoints are fixed,
/// then attach `[ACW stack..., schnorr_sig, tapscript, control]`.
fn sign_transaction(
    mut tx: Transaction,
    leaves: &[AcwInput],
    keypair: &Keypair,
    secp: &Secp256k1<bitcoin::secp256k1::All>,
) -> (Transaction, Vec<TxOut>) {
    let prevouts: Vec<TxOut> = leaves.iter().map(|leaf| leaf.prevout.clone()).collect();
    let signatures: Vec<Vec<u8>> = {
        let prevouts_ref = Prevouts::All(&prevouts);
        let mut cache = SighashCache::new(&tx);
        leaves
            .iter()
            .enumerate()
            .map(|(input_index, leaf)| {
                let leaf_hash =
                    TapLeafHash::from_script(leaf.tapscript.as_script(), LeafVersion::TapScript);
                let sighash = cache
                    .taproot_script_spend_signature_hash(
                        input_index,
                        &prevouts_ref,
                        leaf_hash,
                        TapSighashType::Default,
                    )
                    .expect("BIP341 ACW script-spend sighash");
                let message = Message::from(sighash);
                let signature = bitcoin::taproot::Signature {
                    signature: secp.sign_schnorr_no_aux_rand(&message, keypair),
                    sighash_type: TapSighashType::Default,
                }
                .to_vec();
                assert_eq!(signature.len(), 64, "SIGHASH_DEFAULT has no type byte");
                signature
            })
            .collect()
    };

    for ((input, leaf), signature) in tx.input.iter_mut().zip(leaves).zip(signatures) {
        let acw_arguments = acw_stack(&leaf.opening);
        assert_eq!(acw_arguments.len(), 3 * leaf.digits);
        for argument in acw_arguments {
            input.witness.push(argument);
        }
        input.witness.push(signature);
        input.witness.push(leaf.tapscript.as_bytes());
        input.witness.push(leaf.control.serialize());

        assert_eq!(input.witness.len(), 3 * leaf.digits + 3);
        assert_eq!(input.witness.iter().nth(3 * leaf.digits).unwrap().len(), 64);
        assert!(3 * leaf.digits + 1 <= MAX_STACK_ITEMS);
        assert!(leaf.control.verify_taproot_commitment(
            secp,
            leaf.output_key,
            leaf.tapscript.as_script(),
        ));
    }

    (tx, prevouts)
}

fn signed_single_input(
    rng: &mut ChaCha20Rng,
    secp: &Secp256k1<bitcoin::secp256k1::All>,
    authorization_key: XOnlyPublicKey,
    keypair: &Keypair,
    funding_txid: Txid,
    funding_index: u32,
    codewords: Vec<Vec<u32>>,
) -> (Transaction, Vec<TxOut>, AcwInput) {
    let leaf = acw_input(
        rng,
        secp,
        authorization_key,
        funding_txid,
        funding_index,
        &codewords,
    );
    let unsigned = two_output_transaction(std::slice::from_ref(&leaf), secp);
    let (tx, prevouts) = sign_transaction(unsigned, std::slice::from_ref(&leaf), keypair, secp);
    (tx, prevouts, leaf)
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

/// Export deterministic regtest funding commitments and signed reveals.  The
/// first pass fixes the ordered output scripts; the second pass sets
/// WHIR_GC_FUNDING_TXID to the confirmed transaction that created them.
fn export_regtest_fixtures(
    dir: &std::path::Path,
    prevout_scripts: &[ScriptBuf],
    reveals: &[Transaction],
) {
    std::fs::create_dir_all(dir).expect("create Antichain export directory");
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
    .expect("write Antichain funding outputs");

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
        .expect("write Antichain funding script manifest");

    for (i, tx) in reveals.iter().enumerate() {
        std::fs::write(
            dir.join(format!("reveal-{i:03}.hex")),
            format!("{}\n", encode_hex(&serialize(tx))),
        )
        .expect("write Antichain reveal transaction");
    }
}

#[test]
fn signed_acw_d128_executes_and_rejects_forgery_and_transaction_tampering() {
    let secp = Secp256k1::new();
    let keypair = authorization_keypair(&secp);
    let (authorization_key, _) = keypair.x_only_public_key();
    let mut rng = ChaCha20Rng::seed_from_u64(0xac00_0128);

    assert_eq!(antichain_count(2, 16, 15), 16);
    let (tx, prevouts, leaf) = signed_single_input(
        &mut rng,
        &secp,
        authorization_key,
        &keypair,
        Txid::all_zeros(),
        0,
        canonical_codewords(128),
    );
    assert_eq!(leaf.tapscript.len(), 17_571);
    assert_eq!(tx.base_size(), 137, "one input plus two 43-byte outputs");
    assert_eq!(serialize(&tx).len(), 23_447);
    assert_eq!(tx.input[0].witness.len(), 387);
    assert_eq!(tx.weight().to_wu(), 23_858);
    assert_eq!(tx.vsize(), 5_965);

    let arguments = witness_arguments(&tx.input[0].witness);
    let (success, peak) = execute_input(&tx, &prevouts, 0, &leaf.tapscript, arguments.clone());
    assert!(success, "honest signed ACW leaf executes");
    assert!(peak <= MAX_STACK_ITEMS);

    // A wrong opener reaches the still-valid transaction signature, then fails
    // one of the upstream hash-chain terminal checks.
    let mut wrong_opener = arguments.clone();
    wrong_opener[0][0] ^= 1;
    assert!(!execute_input(&tx, &prevouts, 0, &leaf.tapscript, wrong_opener).0);

    // This is upstream's strongest adjacent-codeword attempt: forward-hash the
    // posted-chain opener and lower its claimed coordinate.  That chain passes,
    // but the verifier derives a coordinate one higher for the other chain, whose
    // unchanged opener is then one hash short of its terminal.
    let authorization_signature = arguments.last().expect("authorization signature").clone();
    let mut raised_derived_coordinate = leaf.opening.clone();
    raised_derived_coordinate.0[1].0[0] =
        HashKind::Hash160.digest(&raised_derived_coordinate.0[1].0[0]);
    raised_derived_coordinate.0[1].1[0] -= 1;
    let mut raised_arguments = acw_stack(&raised_derived_coordinate);
    raised_arguments.push(authorization_signature.clone());
    assert!(!execute_input(&tx, &prevouts, 0, &leaf.tapscript, raised_arguments,).0);

    // A coordinate lie without the corresponding chain movement is rejected.
    let mut coordinate_lie = leaf.opening.clone();
    coordinate_lie.0[2].1[0] += 1;
    let mut coordinate_arguments = acw_stack(&coordinate_lie);
    coordinate_arguments.push(authorization_signature);
    assert!(!execute_input(&tx, &prevouts, 0, &leaf.tapscript, coordinate_arguments,).0);

    let mut bad_signature = arguments.clone();
    bad_signature.last_mut().unwrap()[0] ^= 1;
    assert!(!execute_input(&tx, &prevouts, 0, &leaf.tapscript, bad_signature).0);

    // The ordinary Schnorr signature supplies the transaction binding that ACW
    // openings alone do not: redirecting either output invalidates it.
    let mut redirected = tx.clone();
    redirected.output[0].value = Amount::from_sat(OUTPUT_SATS + 1);
    assert!(!execute_input(&redirected, &prevouts, 0, &leaf.tapscript, arguments,).0);

    let mut wrong_control = leaf.control.serialize();
    wrong_control[0] ^= 1; // flip the committed output-key parity bit
    let wrong_control =
        ControlBlock::decode(&wrong_control).expect("parity-flipped control block decodes");
    assert!(!wrong_control.verify_taproot_commitment(
        &secp,
        leaf.output_key,
        leaf.tapscript.as_script(),
    ));

    // ScriptNum zero is encoded as an empty witness vector.  Keep this explicit
    // because an extrapolation that assumes every coordinate costs one byte can
    // differ for real payloads.  At fixed tx shape each zero saves exactly 1 WU.
    let (one_nonzero, _, _) = signed_single_input(
        &mut rng,
        &secp,
        authorization_key,
        &keypair,
        Txid::all_zeros(),
        10_000,
        canonical_codewords(1),
    );
    let (one_zero, _, _) = signed_single_input(
        &mut rng,
        &secp,
        authorization_key,
        &keypair,
        Txid::all_zeros(),
        10_001,
        codewords_with_first_zero(1),
    );
    assert_eq!(one_nonzero.weight().to_wu(), one_zero.weight().to_wu() + 1);
}

#[test]
fn signed_acw_d332_capacity_and_full_input_packing() {
    let secp = Secp256k1::new();
    let keypair = authorization_keypair(&secp);
    let (authorization_key, _) = keypair.x_only_public_key();
    let mut rng = ChaCha20Rng::seed_from_u64(0xac00_0332);

    let (d332, d332_prevouts, d332_leaf) = signed_single_input(
        &mut rng,
        &secp,
        authorization_key,
        &keypair,
        Txid::all_zeros(),
        20_000,
        canonical_codewords(MAX_DIGITS_PER_INPUT),
    );
    assert_eq!(d332_leaf.tapscript.len(), 45_519);
    assert_eq!(d332.input[0].witness.len(), 999);
    assert_eq!(witness_arguments(&d332.input[0].witness).len(), 997);
    assert_eq!(d332.weight().to_wu(), 60_782);
    assert_eq!(d332.vsize(), 15_196);
    let (success, peak) = execute_input(
        &d332,
        &d332_prevouts,
        0,
        &d332_leaf.tapscript,
        witness_arguments(&d332.input[0].witness),
    );
    assert!(success, "D=332 is an executable signed leaf");
    assert_eq!(peak, 999, "main plus alt stack stays below 1,000");
    assert_eq!(MAX_DIGITS_PER_INPUT * BITS_PER_DIGIT, 1_328);

    // D=333 starts with 999 ACW items plus the authorization signature.  The
    // leaf's first public-key push raises that to 1,001, so it is not executable
    // under the consensus stack limit even though the initial witness has 1,000.
    let (d333, d333_prevouts, d333_leaf) = signed_single_input(
        &mut rng,
        &secp,
        authorization_key,
        &keypair,
        Txid::all_zeros(),
        20_001,
        canonical_codewords(MAX_DIGITS_PER_INPUT + 1),
    );
    assert_eq!(witness_arguments(&d333.input[0].witness).len(), 1_000);
    assert!(
        !execute_input(
            &d333,
            &d333_prevouts,
            0,
            &d333_leaf.tapscript,
            witness_arguments(&d333.input[0].witness),
        )
        .0
    );

    let input_bits = input_bits();
    let golden = input_bits == KECCAK_INPUT_BITS;
    let total_digits = input_bits.div_ceil(BITS_PER_DIGIT);
    if golden {
        assert_eq!(input_bits % BITS_PER_DIGIT, 0);
        assert_eq!(total_digits, 260_256);
        assert_eq!(total_digits / MAX_DIGITS_PER_INPUT, 783);
        assert_eq!(total_digits % MAX_DIGITS_PER_INPUT, 300);
    }

    let funding_txid = std::env::var("WHIR_GC_FUNDING_TXID")
        .ok()
        .map(|value| value.parse().expect("WHIR_GC_FUNDING_TXID is a txid"))
        .unwrap_or_else(Txid::all_zeros);
    let mut digits_left = total_digits;
    let mut next_funding_index = 0u32;
    let mut transaction_count = 0usize;
    let mut input_count = 0usize;
    let mut serialized_bytes = 0usize;
    let mut summed_weight = 0u64;
    let mut summed_vsize = 0usize;
    let mut max_tx_weight = 0u64;
    let mut transactions = Vec::with_capacity(131);
    let mut prevout_scripts = Vec::with_capacity(784);

    while digits_left != 0 {
        let input_slots = digits_left
            .div_ceil(MAX_DIGITS_PER_INPUT)
            .min(INPUTS_PER_TX);
        let mut leaves = Vec::with_capacity(input_slots);
        for _ in 0..input_slots {
            let digits = digits_left.min(MAX_DIGITS_PER_INPUT);
            leaves.push(acw_input(
                &mut rng,
                &secp,
                authorization_key,
                funding_txid,
                next_funding_index,
                &canonical_codewords(digits),
            ));
            digits_left -= digits;
            next_funding_index += 1;
        }

        let unsigned = two_output_transaction(&leaves, &secp);
        let (tx, prevouts) = sign_transaction(unsigned, &leaves, &keypair, &secp);
        let weight = tx.weight().to_wu();
        assert!(weight <= MAX_STANDARD_TX_WEIGHT);
        if !golden {
        } else if transaction_count < 130 {
            assert_eq!(tx.input.len(), 6);
            assert_eq!(serialize(&tx).len(), 361_736);
            assert_eq!(weight, 362_762);
            assert_eq!(tx.vsize(), 90_691);
        } else {
            assert_eq!(transaction_count, 130);
            assert_eq!(tx.input.len(), 4);
            assert_eq!(
                leaves.iter().map(|leaf| leaf.digits).collect::<Vec<_>>(),
                [332, 332, 332, 300],
            );
            assert_eq!(serialize(&tx).len(), 235_398);
            assert_eq!(weight, 236_178);
            assert_eq!(tx.vsize(), 59_045);
        }

        transaction_count += 1;
        input_count += tx.input.len();
        serialized_bytes += serialize(&tx).len();
        summed_weight += weight;
        summed_vsize += tx.vsize();
        max_tx_weight = max_tx_weight.max(weight);
        prevout_scripts.extend(prevouts.into_iter().map(|prevout| prevout.script_pubkey));
        transactions.push(tx);
    }

    assert_eq!(input_count, total_digits.div_ceil(MAX_DIGITS_PER_INPUT));
    assert_eq!(transaction_count, input_count.div_ceil(INPUTS_PER_TX));
    if golden {
        assert_eq!(transaction_count, 131);
        assert_eq!(input_count, 784);
        assert_eq!(next_funding_index, 784);
        assert_eq!(max_tx_weight, 362_762);
        assert_eq!(serialized_bytes, 47_261_078);
        assert_eq!(summed_weight, 47_395_238);
        assert_eq!(summed_vsize, 11_848_875);
    }
    eprintln!(
        "{input_bits} bits via safe ACW(2,16): {input_count} signed P2TR inputs in \
         {transaction_count} two-output transactions; {serialized_bytes} serialized bytes; \
         {summed_weight} WU; {summed_vsize} vB; max tx {max_tx_weight} WU"
    );

    if let Ok(dir) = std::env::var("WHIR_GC_EXPORT_DIR") {
        export_regtest_fixtures(std::path::Path::new(&dir), &prevout_scripts, &transactions);
    }
}
