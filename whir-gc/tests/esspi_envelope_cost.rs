//! Exact commit/reveal transport fixture for an ESSPI-style P2TR envelope.
//!
//! This measures an authenticated publication of the verifier's 130,128-byte
//! input.  The payload is embedded in a skipped branch of the revealed
//! tapscript, so the commit output binds every byte through its TapLeaf hash.
//! A real SIGHASH_DEFAULT Schnorr signature authorizes the reveal.  This is a
//! transport component, not a complete ESSPI/BitVMX protocol: the secondary
//! fraud-proof instance, DA timeouts, challenges, bonds, and settlement graph
//! remain outside this fixture.

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
use std::str::FromStr;

const INPUT_BYTES: usize = 130_128;
const COMMIT_OUTPUT_SATS: u64 = 100_000;
const REVEAL_OUTPUT_SATS: u64 = 66_000;
const MAX_STANDARD_TX_WEIGHT: u64 = 400_000;

fn internal_key() -> XOnlyPublicKey {
    XOnlyPublicKey::from_str("50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0")
        .expect("BIP341 NUMS internal key")
}

fn publisher_keypair(secp: &Secp256k1<bitcoin::secp256k1::All>) -> Keypair {
    let secret = SecretKey::from_slice(&[7u8; 32]).expect("fixed test-only publisher key");
    Keypair::from_secret_key(secp, &secret)
}

fn push_data(script: &mut Vec<u8>, data: &[u8]) {
    match data.len() {
        0 => script.push(0x00),
        1..=75 => script.push(data.len() as u8),
        76..=255 => {
            script.push(0x4c); // OP_PUSHDATA1
            script.push(data.len() as u8);
        }
        256..=520 => {
            script.push(0x4d); // OP_PUSHDATA2
            script.extend_from_slice(&(data.len() as u16).to_le_bytes());
        }
        _ => panic!("envelope chunks must respect the 520-byte element limit"),
    }
    script.extend_from_slice(data);
}

fn envelope_leaf(publisher_key: XOnlyPublicKey, payload: &[u8]) -> ScriptBuf {
    let mut script = Vec::with_capacity(payload.len() + payload.len().div_ceil(520) * 3 + 40);
    script.push(0x20); // minimal 32-byte push
    script.extend_from_slice(&publisher_key.serialize());
    script.push(0xac); // OP_CHECKSIG; leaves true on the stack
    script.push(0x00); // OP_FALSE
    script.push(0x63); // OP_IF; the payload branch is not executed
    for chunk in payload.chunks(520) {
        push_data(&mut script, chunk);
    }
    script.push(0x68); // OP_ENDIF
    ScriptBuf::from_bytes(script)
}

struct Envelope {
    prevout: TxOut,
    tapscript: ScriptBuf,
    control: ControlBlock,
}

fn envelope(
    secp: &Secp256k1<bitcoin::secp256k1::All>,
    publisher_key: XOnlyPublicKey,
    payload: &[u8],
) -> Envelope {
    let tapscript = envelope_leaf(publisher_key, payload);
    let spend_info = TaprootBuilder::new()
        .add_leaf(0, tapscript.clone())
        .expect("one-leaf envelope taptree")
        .finalize(secp, internal_key())
        .expect("one-leaf envelope taptree is complete");
    let control = spend_info
        .control_block(&(tapscript.clone(), LeafVersion::TapScript))
        .expect("control block for envelope leaf");
    assert_eq!(control.serialize().len(), 33);
    assert!(control.verify_taproot_commitment(
        secp,
        spend_info.output_key().to_x_only_public_key(),
        tapscript.as_script(),
    ));
    Envelope {
        prevout: TxOut {
            value: Amount::from_sat(COMMIT_OUTPUT_SATS),
            script_pubkey: ScriptBuf::new_p2tr_tweaked(spend_info.output_key()),
        },
        tapscript,
        control,
    }
}

fn signed_reveal(
    secp: &Secp256k1<bitcoin::secp256k1::All>,
    keypair: &Keypair,
    commit_txid: Txid,
    commit_vout: u32,
    envelope: &Envelope,
) -> Transaction {
    let (publisher_key, _) = keypair.x_only_public_key();
    let destination = ScriptBuf::new_p2tr(secp, publisher_key, None);
    let mut tx = Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::new(commit_txid, commit_vout),
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(REVEAL_OUTPUT_SATS),
            script_pubkey: destination,
        }],
    };

    let prevouts = [envelope.prevout.clone()];
    let prevouts_ref = Prevouts::All(&prevouts);
    let leaf_hash =
        TapLeafHash::from_script(envelope.tapscript.as_script(), LeafVersion::TapScript);
    let sighash = SighashCache::new(&tx)
        .taproot_script_spend_signature_hash(0, &prevouts_ref, leaf_hash, TapSighashType::Default)
        .expect("BIP341 envelope script-spend sighash");
    let message = Message::from(sighash);
    let signature = secp.sign_schnorr_no_aux_rand(&message, keypair);
    secp.verify_schnorr(&signature, &message, &publisher_key)
        .expect("envelope authorization signature verifies");
    let signature = bitcoin::taproot::Signature {
        signature,
        sighash_type: TapSighashType::Default,
    }
    .to_vec();
    assert_eq!(signature.len(), 64);

    tx.input[0].witness.push(signature);
    tx.input[0].witness.push(envelope.tapscript.as_bytes());
    tx.input[0].witness.push(envelope.control.serialize());
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

#[test]
fn esspi_p2tr_envelope_exact_serialization() {
    let secp = Secp256k1::new();
    let keypair = publisher_keypair(&secp);
    let (publisher_key, _) = keypair.x_only_public_key();
    let payload: Vec<u8> = (0..INPUT_BYTES).map(|i| (i % 251) as u8).collect();
    let envelope = envelope(&secp, publisher_key, &payload);
    let commit_txid = std::env::var("ESSPI_COMMIT_TXID")
        .ok()
        .map(|value| value.parse().expect("ESSPI_COMMIT_TXID is a txid"))
        .unwrap_or_else(Txid::all_zeros);
    let commit_vout = std::env::var("ESSPI_COMMIT_VOUT")
        .ok()
        .map(|value| value.parse().expect("ESSPI_COMMIT_VOUT is a u32"))
        .unwrap_or(0);
    let reveal = signed_reveal(&secp, &keypair, commit_txid, commit_vout, &envelope);

    assert_eq!(payload.len(), INPUT_BYTES);
    assert_eq!(envelope.tapscript.len(), 130_917);
    assert_eq!(reveal.input[0].witness.len(), 3);
    assert_eq!(reveal.base_size(), 94);
    assert_eq!(serialize(&reveal).len(), 131_118);
    assert_eq!(reveal.weight().to_wu(), 131_400);
    assert_eq!(reveal.vsize(), 32_850);
    assert!(reveal.weight().to_wu() <= MAX_STANDARD_TX_WEIGHT);
    eprintln!(
        "ESSPI envelope: {INPUT_BYTES} payload B, {}-B tapscript, {} serialized B, \
         {} WU, {} vB",
        envelope.tapscript.len(),
        serialize(&reveal).len(),
        reveal.weight().to_wu(),
        reveal.vsize(),
    );

    if let Ok(dir) = std::env::var("ESSPI_EXPORT_DIR") {
        let dir = std::path::Path::new(&dir);
        std::fs::create_dir_all(dir).expect("create ESSPI export directory");
        let address = Address::from_script(&envelope.prevout.script_pubkey, Network::Regtest)
            .expect("envelope prevout has a regtest P2TR address");
        std::fs::write(dir.join("commit-address.txt"), format!("{address}\n"))
            .expect("write commit address");
        std::fs::write(
            dir.join("commit-script.hex"),
            format!(
                "{}\n",
                encode_hex(envelope.prevout.script_pubkey.as_bytes())
            ),
        )
        .expect("write commit script");
        std::fs::write(
            dir.join("reveal.hex"),
            format!("{}\n", encode_hex(&serialize(&reveal))),
        )
        .expect("write reveal transaction");
    }
}
