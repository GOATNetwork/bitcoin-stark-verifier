//! Full, transaction-bound serialization for the measured verifier's Lamport
//! Assert input-publication component.
//!
//! Unlike a per-bit script-size estimate, this fixture
//! constructs every P2TR script-path input and every transaction needed for
//! 1,041,024 authenticated bits.  It includes the Lamport preimage witness,
//! a 64-byte SIGHASH_DEFAULT Schnorr authorization signature per input, the
//! authentication tapscript, witness framing, a depth-0 control block, input
//! base fields, one P2TR output per transaction, and transaction-global fields.
//! It executes every signed leaf in a transaction-aware Tapscript interpreter
//! and verifies every Taproot commitment.
//!
//! The outpoints are synthetic and the transactions are not submitted to
//! Bitcoin Core unless the export mode is used with the txid of an actual
//! funding transaction.  The single Schnorr key models one signer or an
//! aggregated committee key; the fixture does not construct the surrounding
//! dispute graph, its completion condition, timeouts, anchors, fee inputs, or
//! post-quantum graph authorization.  It is therefore a serialized measurement
//! of complete Assert transactions, not a total protocol cost.

mod dispute;

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
use dispute::{assert_lock, Lamport, BITS_PER_SCRIPT};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use std::str::FromStr;

/// The measured Keccak verifier's input; the golden totals are pinned at this size.
const KECCAK_INPUT_BITS: usize = 1_041_024;

/// The input size to serialize: `WHIR_GC_INPUT_BITS`, else the Keccak verifier's.
fn input_bits() -> usize {
    std::env::var("WHIR_GC_INPUT_BITS")
        .ok()
        .map_or(KECCAK_INPUT_BITS, |s| s.parse().expect("WHIR_GC_INPUT_BITS is a bit count"))
}
const INPUTS_PER_TX: usize = 6;
const MAX_STACK_ITEMS: usize = 1_000;
const MAX_STANDARD_TX_WEIGHT: u64 = 400_000;
const FUNDING_SATS_PER_INPUT: u64 = 17_000;
const REVEAL_OUTPUT_SATS: u64 = 1_000;

fn internal_key() -> XOnlyPublicKey {
    // BIP341's H = lift_x(sha256(uncompressed_G)) NUMS point.  Unlike the
    // generator used by the raw-transport fixture, no discrete logarithm is
    // known, so the key path cannot bypass the Lamport leaf.
    XOnlyPublicKey::from_str(
        "50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0",
    )
    .expect("BIP341 NUMS internal key")
}

fn authorization_keypair(secp: &Secp256k1<bitcoin::secp256k1::All>) -> Keypair {
    // A deterministic test-only signing key.  A deployed graph would use the
    // operator key or one aggregated committee key and must address quantum-safe
    // transaction authorization separately.
    let secret = SecretKey::from_slice(&[3u8; 32]).expect("fixed signing key");
    Keypair::from_secret_key(secp, &secret)
}

/// Prefix the Lamport authentication program with a transaction-binding
/// Schnorr check.  A direct 32-byte push is 33 bytes and CHECKSIGVERIFY is one.
fn authorized_assert_lock(
    authorization_key: XOnlyPublicKey,
    hashes: &[[[u8; 20]; 2]],
) -> ScriptBuf {
    let lamport = assert_lock(hashes);
    let mut bytes = Vec::with_capacity(34 + lamport.len());
    bytes.push(0x20); // minimal push of the 32-byte x-only public key
    bytes.extend_from_slice(&authorization_key.serialize());
    bytes.push(0xad); // OP_CHECKSIGVERIFY
    bytes.extend_from_slice(lamport.as_bytes());
    ScriptBuf::from_bytes(bytes)
}

struct LamportInput {
    txin: TxIn,
    prevout: TxOut,
    tapscript: ScriptBuf,
    control: ControlBlock,
    output_key: XOnlyPublicKey,
    published: Vec<[u8; 16]>,
}

/// Construct one unsigned authenticated Lamport P2TR input.  Its witness is
/// filled only after the containing transaction's outputs are final.
fn lamport_input(
    secp: &Secp256k1<bitcoin::secp256k1::All>,
    authorization_key: XOnlyPublicKey,
    funding_txid: Txid,
    input_index: usize,
    hashes: &[[[u8; 20]; 2]],
    published: &[[u8; 16]],
) -> LamportInput {
    assert_eq!(hashes.len(), published.len());
    assert!(hashes.len() <= BITS_PER_SCRIPT);

    let tapscript = authorized_assert_lock(authorization_key, hashes);
    let spend_info = TaprootBuilder::new()
        .add_leaf(0, tapscript.clone())
        .expect("one-leaf taptree")
        .finalize(secp, internal_key())
        .expect("one-leaf taptree is complete");
    let control = spend_info
        .control_block(&(tapscript.clone(), LeafVersion::TapScript))
        .expect("control block for the only leaf");
    assert_eq!(control.serialize().len(), 33, "depth-0 control block");
    assert!(control.verify_taproot_commitment(
        secp,
        spend_info.output_key().to_x_only_public_key(),
        tapscript.as_script(),
    ));

    let prevout_script = ScriptBuf::new_p2tr_tweaked(spend_info.output_key());
    LamportInput {
        txin: TxIn {
            previous_output: OutPoint::new(funding_txid, input_index as u32),
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        },
        prevout: TxOut {
            value: Amount::from_sat(FUNDING_SATS_PER_INPUT),
            script_pubkey: prevout_script,
        },
        tapscript,
        control,
        output_key: spend_info.output_key().to_x_only_public_key(),
        published: published.to_vec(),
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

/// Execute one script path with a real transaction, all prevouts and tapleaf
/// hash, so OP_CHECKSIGVERIFY checks the BIP341 signature rather than a stub.
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

/// Sign every input after the complete transaction shape is fixed, then attach
/// `[reversed preimages, signature, tapscript, control block]` witnesses.
fn sign_assert_transaction(
    mut tx: Transaction,
    leaves: &[LamportInput],
    keypair: &Keypair,
    secp: &Secp256k1<bitcoin::secp256k1::All>,
) -> (Transaction, Vec<TxOut>, usize) {
    let prevouts: Vec<TxOut> = leaves.iter().map(|leaf| leaf.prevout.clone()).collect();
    let signatures: Vec<Vec<u8>> = {
        let prevouts_ref = Prevouts::All(&prevouts);
        let mut cache = SighashCache::new(&tx);
        leaves
            .iter()
            .enumerate()
            .map(|(input_index, leaf)| {
                let leaf_hash = TapLeafHash::from_script(
                    leaf.tapscript.as_script(),
                    LeafVersion::TapScript,
                );
                let sighash = cache
                    .taproot_script_spend_signature_hash(
                        input_index,
                        &prevouts_ref,
                        leaf_hash,
                        TapSighashType::Default,
                    )
                    .expect("BIP341 script-spend sighash");
                let message = Message::from(sighash);
                let signature = secp.sign_schnorr_no_aux_rand(&message, keypair);
                let signature = bitcoin::taproot::Signature {
                    signature,
                    sighash_type: TapSighashType::Default,
                }
                .to_vec();
                assert_eq!(signature.len(), 64, "SIGHASH_DEFAULT omits a type byte");
                signature
            })
            .collect()
    };

    for ((input, leaf), signature) in tx.input.iter_mut().zip(leaves).zip(signatures) {
        // Witness items are serialized bottom-to-top.  The signature is on top
        // initially and is consumed before p_0 becomes the Lamport stack top.
        for preimage in leaf.published.iter().rev() {
            input.witness.push(preimage);
        }
        input.witness.push(signature);
        input.witness.push(leaf.tapscript.as_bytes());
        input.witness.push(leaf.control.serialize());

        let initial_stack_items = input.witness.len() - 2;
        assert_eq!(initial_stack_items, leaf.published.len() + 1);
        assert!(initial_stack_items <= MAX_STACK_ITEMS);
        assert!(input
            .witness
            .iter()
            .take(leaf.published.len())
            .all(|item| item.len() == 16));
        assert_eq!(input.witness.iter().nth(leaf.published.len()).unwrap().len(), 64);

        // The control block is checked separately because script executors take
        // an already selected tapleaf rather than validating the P2TR program.
        assert!(leaf.control.verify_taproot_commitment(
            secp,
            leaf.output_key,
            leaf.tapscript.as_script(),
        ));
    }

    let mut peak_stack = 0usize;
    for (input_index, (input, leaf)) in tx.input.iter().zip(leaves).enumerate() {
        let arguments = witness_arguments(&input.witness);
        let (success, peak) = execute_input(
            &tx,
            &prevouts,
            input_index,
            &leaf.tapscript,
            arguments,
        );
        assert!(success, "signed Lamport input {input_index} executes");
        assert!(peak <= MAX_STACK_ITEMS);
        peak_stack = peak_stack.max(peak);
    }

    (tx, prevouts, peak_stack)
}

struct MarkerSpend {
    script_pubkey: ScriptBuf,
    tapscript: ScriptBuf,
    control: ControlBlock,
    output_key: XOnlyPublicKey,
}

/// A transaction-bound one-leaf P2TR completion marker.  The marker remains a
/// graph-shape model, but unlike OP_TRUE it cannot be redirected after reveal.
fn marker_spend(
    secp: &Secp256k1<bitcoin::secp256k1::All>,
    authorization_key: XOnlyPublicKey,
) -> MarkerSpend {
    let mut bytes = Vec::with_capacity(34);
    bytes.push(0x20);
    bytes.extend_from_slice(&authorization_key.serialize());
    bytes.push(0xac); // OP_CHECKSIG
    let tapscript = ScriptBuf::from_bytes(bytes);
    let spend_info = TaprootBuilder::new()
        .add_leaf(0, tapscript.clone())
        .expect("one-leaf marker tree")
        .finalize(secp, internal_key())
        .expect("marker tree is complete");
    let control = spend_info
        .control_block(&(tapscript.clone(), LeafVersion::TapScript))
        .expect("marker control block");
    assert_eq!(tapscript.len(), 34);
    assert_eq!(control.serialize().len(), 33);
    assert!(control.verify_taproot_commitment(
        secp,
        spend_info.output_key().to_x_only_public_key(),
        tapscript.as_script(),
    ));
    MarkerSpend {
        script_pubkey: ScriptBuf::new_p2tr_tweaked(spend_info.output_key()),
        tapscript,
        control,
        output_key: spend_info.output_key().to_x_only_public_key(),
    }
}

fn sign_finalization(
    mut tx: Transaction,
    prevouts: Vec<TxOut>,
    marker: &MarkerSpend,
    keypair: &Keypair,
    secp: &Secp256k1<bitcoin::secp256k1::All>,
) -> Transaction {
    let leaf_hash = TapLeafHash::from_script(
        marker.tapscript.as_script(),
        LeafVersion::TapScript,
    );
    let signatures: Vec<Vec<u8>> = {
        let prevouts_ref = Prevouts::All(&prevouts);
        let mut cache = SighashCache::new(&tx);
        (0..tx.input.len())
            .map(|input_index| {
                let sighash = cache
                    .taproot_script_spend_signature_hash(
                        input_index,
                        &prevouts_ref,
                        leaf_hash,
                        TapSighashType::Default,
                    )
                    .expect("finalization BIP341 sighash");
                let message = Message::from(sighash);
                bitcoin::taproot::Signature {
                    signature: secp.sign_schnorr_no_aux_rand(&message, keypair),
                    sighash_type: TapSighashType::Default,
                }
                .to_vec()
            })
            .collect()
    };

    for (input, signature) in tx.input.iter_mut().zip(signatures) {
        assert_eq!(signature.len(), 64);
        input.witness.push(signature);
        input.witness.push(marker.tapscript.as_bytes());
        input.witness.push(marker.control.serialize());
    }
    assert!(marker.control.verify_taproot_commitment(
        secp,
        marker.output_key,
        marker.tapscript.as_script(),
    ));

    // One representative execution covers the common script/control shape;
    // every input has an independently generated transaction sighash above.
    let arguments = witness_arguments(&tx.input[0].witness);
    let (success, peak) = execute_input(
        &tx,
        &prevouts,
        0,
        &marker.tapscript,
        arguments,
    );
    assert!(success, "signed finalization marker executes");
    assert_eq!(peak, 2, "signature and pushed public key are the peak stack");
    tx
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

fn export_regtest_fixtures(
    dir: &std::path::Path,
    prevout_scripts: &[ScriptBuf],
    reveals: &[Transaction],
    finalization: &Transaction,
) {
    std::fs::create_dir_all(dir).expect("create export directory");
    let outputs: Vec<String> = prevout_scripts
        .iter()
        .map(|script| {
            let address = Address::from_script(script, Network::Regtest)
                .expect("P2TR script has a regtest address");
            format!("{{\"{address}\":{:.8}}}", FUNDING_SATS_PER_INPUT as f64 / 100_000_000.0)
        })
        .collect();
    std::fs::write(
        dir.join("funding_outputs.json"),
        format!("[{}]\n", outputs.join(",")),
    )
    .expect("write funding outputs");

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
        .expect("write funding script manifest");

    for (i, tx) in reveals.iter().enumerate() {
        std::fs::write(
            dir.join(format!("reveal-{i:03}.hex")),
            format!("{}\n", encode_hex(&serialize(tx))),
        )
        .expect("write reveal transaction");
    }
    std::fs::write(
        dir.join("finalization.hex"),
        format!("{}\n", encode_hex(&serialize(finalization))),
    )
    .expect("write finalization transaction");
}

#[test]
fn serialized_lamport_assert_component_for_measured_verifier() {
    let secp = Secp256k1::new();
    let authorization_keypair = authorization_keypair(&secp);
    let (authorization_key, _) = authorization_keypair.x_only_public_key();
    let mut rng = ChaCha20Rng::seed_from_u64(2026);
    let input_bits = input_bits();
    let golden = input_bits == KECCAK_INPUT_BITS;
    let keys = Lamport::new(input_bits, &mut rng);
    // Any bit pattern has the same serialized size.  Alternating values also
    // exercises both sides of every Lamport pair.
    let bits: Vec<bool> = (0..input_bits).map(|i| i % 2 == 1).collect();
    let published = keys.publish(&bits);

    let funding_txid = std::env::var("WHIR_GC_FUNDING_TXID")
        .ok()
        .map(|value| value.parse().expect("WHIR_GC_FUNDING_TXID is a txid"))
        .unwrap_or_else(Txid::all_zeros);
    let marker = marker_spend(&secp, authorization_key);
    let mut transactions = Vec::new();
    let mut pending = Vec::with_capacity(INPUTS_PER_TX);
    let mut prevout_scripts = Vec::with_capacity(1_044);
    let mut total_script_bytes = 0usize;
    let mut max_stack_items = 0usize;

    for (input_index, (hashes, reveal)) in keys
        .hashes
        .chunks(BITS_PER_SCRIPT)
        .zip(published.chunks(BITS_PER_SCRIPT))
        .enumerate()
    {
        let input = lamport_input(
            &secp,
            authorization_key,
            funding_txid,
            input_index,
            hashes,
            reveal,
        );
        total_script_bytes += input.tapscript.len();
        prevout_scripts.push(input.prevout.script_pubkey.clone());
        pending.push(input);

        if pending.len() == INPUTS_PER_TX
            || (input_index + 1) * BITS_PER_SCRIPT >= input_bits
        {
            let unsigned = Transaction {
                version: Version::TWO,
                lock_time: LockTime::ZERO,
                input: pending.iter().map(|leaf| leaf.txin.clone()).collect(),
                output: vec![TxOut {
                    value: Amount::from_sat(REVEAL_OUTPUT_SATS),
                    script_pubkey: marker.script_pubkey.clone(),
                }],
            };
            let (tx, prevouts, peak) = sign_assert_transaction(
                unsigned,
                &pending,
                &authorization_keypair,
                &secp,
            );
            max_stack_items = max_stack_items.max(peak);
            assert!(tx.weight().to_wu() <= MAX_STANDARD_TX_WEIGHT);

            if transactions.is_empty() {
                // Lamport authentication rejects a changed preimage while the
                // still-valid transaction signature reaches the hash checks.
                let mut bad_preimage = witness_arguments(&tx.input[0].witness);
                bad_preimage[0][0] ^= 1;
                assert!(!execute_input(
                    &tx,
                    &prevouts,
                    0,
                    &pending[0].tapscript,
                    bad_preimage,
                )
                .0);

                let mut bad_signature = witness_arguments(&tx.input[0].witness);
                let signature_index = pending[0].published.len();
                bad_signature[signature_index][0] ^= 1;
                assert!(!execute_input(
                    &tx,
                    &prevouts,
                    0,
                    &pending[0].tapscript,
                    bad_signature,
                )
                .0);

                // SIGHASH_DEFAULT binds the output; Lamport openings alone do
                // not, which is why the ordinary signature belongs in the leaf.
                let mut redirected = tx.clone();
                redirected.output[0].value = Amount::from_sat(REVEAL_OUTPUT_SATS + 1);
                assert!(!execute_input(
                    &redirected,
                    &prevouts,
                    0,
                    &pending[0].tapscript,
                    witness_arguments(&tx.input[0].witness),
                )
                .0);

                let mut wrong_control = pending[0].control.serialize();
                wrong_control[0] ^= 1; // flip the committed output-key parity
                let wrong_control = ControlBlock::decode(&wrong_control)
                    .expect("parity-flipped control block still decodes");
                assert!(!wrong_control.verify_taproot_commitment(
                    &secp,
                    pending[0].output_key,
                    pending[0].tapscript.as_script(),
                ));
            }

            transactions.push(tx);
            pending.clear();
        }
    }
    assert!(pending.is_empty());

    let leaves = keys.hashes.len().div_ceil(BITS_PER_SCRIPT);
    assert_eq!(transactions.len(), leaves.div_ceil(INPUTS_PER_TX));
    assert!(max_stack_items <= MAX_STACK_ITEMS);
    if golden {
        assert_eq!(leaves, 1_044);
        assert_eq!(transactions.len(), 174);
        assert!(transactions.iter().all(|tx| tx.input.len() == INPUTS_PER_TX));
    }

    let serialized_bytes: usize = transactions.iter().map(|tx| serialize(tx).len()).sum();
    let serialized_sizes: Vec<usize> =
        transactions.iter().map(|tx| serialize(tx).len()).collect();
    let base_bytes: usize = transactions.iter().map(Transaction::base_size).sum();
    let weight: u64 = transactions.iter().map(|tx| tx.weight().to_wu()).sum();
    let vsize: usize = transactions.iter().map(Transaction::vsize).sum();
    let weights: Vec<u64> = transactions.iter().map(|tx| tx.weight().to_wu()).collect();
    let vsizes: Vec<usize> = transactions.iter().map(Transaction::vsize).collect();

    eprintln!(
        "{input_bits} authenticated bits: {leaves} P2TR inputs in {} transactions; \
         scripts {total_script_bytes} B; serialized {serialized_bytes} B; base {base_bytes} B; \
         total {weight} WU; summed vsize {vsize} vB; peak stack {max_stack_items}; \
         first/full tx {} WU ({} vB); final tx {} WU ({} vB)",
        transactions.len(),
        weights[0],
        transactions[0].vsize(),
        weights[weights.len() - 1],
        transactions[transactions.len() - 1].vsize(),
    );

    if golden {
        assert_eq!(max_stack_items, 1_000);
        assert_eq!(total_script_bytes, 51_046_716);
        assert_eq!(serialized_bytes, 68_906_116);
        assert_eq!(base_bytes, 52_026);
        assert_eq!(weight, 69_062_194);
        assert_eq!(vsize, 17_265_635);
        assert_eq!(serialized_sizes[..173], [396_349; 173]);
        assert_eq!(serialized_sizes[173], 337_739);
        assert_eq!(weights[..173], [397_246; 173]);
        assert_eq!(weights[173], 338_636);
        assert_eq!(vsizes[..173], [99_312; 173]);
        assert_eq!(vsizes[173], 84_659);
    }

    // A compact join transaction demonstrates the graph edge that cannot be
    // relayed while the 174 large parents are all unconfirmed under the Core
    // cluster-size limit.  It becomes independently standard once they are
    // confirmed.
    let finalization_prevouts: Vec<TxOut> =
        transactions.iter().map(|tx| tx.output[0].clone()).collect();
    let finalization = Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: transactions
            .iter()
            .map(|tx| TxIn {
                previous_output: OutPoint::new(tx.compute_txid(), 0),
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            })
            .collect(),
        output: vec![TxOut {
            value: Amount::from_sat(REVEAL_OUTPUT_SATS),
            script_pubkey: marker.script_pubkey.clone(),
        }],
    };
    let finalization = sign_finalization(
        finalization,
        finalization_prevouts,
        &marker,
        &authorization_keypair,
        &secp,
    );
    assert!(finalization.weight().to_wu() < MAX_STANDARD_TX_WEIGHT);
    if golden {
        assert_eq!(serialize(&finalization).len(), 30_679);
        assert_eq!(finalization.weight().to_wu(), 52_240);
        assert_eq!(finalization.vsize(), 13_060);
    }
    eprintln!(
        "finalization: {} parents, {} B serialized, {} WU, {} vB",
        finalization.input.len(),
        serialize(&finalization).len(),
        finalization.weight().to_wu(),
        finalization.vsize(),
    );

    if let Ok(dir) = std::env::var("WHIR_GC_EXPORT_DIR") {
        export_regtest_fixtures(
            std::path::Path::new(&dir),
            &prevout_scripts,
            &transactions,
            &finalization,
        );
    }
}
