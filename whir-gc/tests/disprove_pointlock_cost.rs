//! Exact Disprove comparison: this verifier's 16-byte-label SHA256 hashlock and a Taproot
//! key-path point lock derived from the false-output label.
//!
//! The point-lock output uses `s = SHA256(domain || false_label)` as its
//! internal-key secret and retains a timeout tapscript.  A challenger learning
//! the false label can derive the tweaked BIP341 key and publish an ordinary
//! 64-byte key-path signature.  This changes neither the Assert authentication
//! problem nor the number of Disprove transactions; it only trims an already
//! small fraud spend.

use bitcoin::{
    absolute::LockTime,
    consensus::encode::serialize,
    hashes::{sha256, Hash, HashEngine},
    key::{Keypair, Secp256k1, TapTweak},
    secp256k1::{Message, SecretKey, XOnlyPublicKey},
    sighash::{Prevouts, SighashCache, TapSighashType},
    taproot::{ControlBlock, LeafVersion, TaprootBuilder},
    transaction::Version,
    Address, Amount, Network, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid,
    Witness,
};
use std::str::FromStr;

const PREVOUT_SATS: u64 = 1_000;
// `whir-gc` garbling uses 128-bit wire labels. Keep this fixture aligned with
// the actual Disprove preimage instead of the 32-byte secret used by BitVM3's
// published 370-WU accounting example.
const FALSE_LABEL: [u8; 16] = [0x42; 16];

fn nums_key() -> XOnlyPublicKey {
    XOnlyPublicKey::from_str("50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0")
        .expect("BIP341 NUMS internal key")
}

fn timeout_key() -> XOnlyPublicKey {
    let secp = Secp256k1::new();
    let secret = SecretKey::from_slice(&[9u8; 32]).expect("fixed timeout key");
    Keypair::from_secret_key(&secp, &secret)
        .x_only_public_key()
        .0
}

fn timeout_leaf() -> ScriptBuf {
    // <144> OP_CHECKSEQUENCEVERIFY OP_DROP <timeout key> OP_CHECKSIG
    let mut bytes = vec![0x02, 0x90, 0x00, 0xb2, 0x75, 0x20];
    bytes.extend_from_slice(&timeout_key().serialize());
    bytes.push(0xac);
    ScriptBuf::from_bytes(bytes)
}

fn hashlock_leaf() -> ScriptBuf {
    let digest = sha256::Hash::hash(&FALSE_LABEL);
    let mut bytes = Vec::with_capacity(35);
    bytes.push(0xa8); // OP_SHA256
    bytes.push(0x20); // 32-byte push
    bytes.extend_from_slice(digest.as_byte_array());
    bytes.push(0x87); // OP_EQUAL
    let script = ScriptBuf::from_bytes(bytes);
    assert_eq!(script.len(), 35);
    script
}

fn pointlock_keypair(secp: &Secp256k1<bitcoin::secp256k1::All>) -> Keypair {
    for counter in 0u32.. {
        let mut engine = sha256::Hash::engine();
        engine.input(b"garbled-stark-verifier/disprove-pointlock/v1");
        engine.input(&FALSE_LABEL);
        engine.input(&counter.to_be_bytes());
        let candidate = sha256::Hash::from_engine(engine).to_byte_array();
        if let Ok(secret) = SecretKey::from_slice(&candidate) {
            return Keypair::from_secret_key(secp, &secret);
        }
    }
    unreachable!("a SHA256 stream eventually yields a valid scalar")
}

struct ScriptPathLock {
    prevout: TxOut,
    script: ScriptBuf,
    control: ControlBlock,
}

fn hashlock(secp: &Secp256k1<bitcoin::secp256k1::All>, include_timeout: bool) -> ScriptPathLock {
    let script = hashlock_leaf();
    let builder = if include_timeout {
        TaprootBuilder::new()
            .add_leaf(1, script.clone())
            .expect("hashlock leaf")
            .add_leaf(1, timeout_leaf())
            .expect("timeout leaf")
    } else {
        TaprootBuilder::new()
            .add_leaf(0, script.clone())
            .expect("standalone hashlock leaf")
    };
    let spend_info = builder
        .finalize(secp, nums_key())
        .expect("complete hashlock taptree");
    let control = spend_info
        .control_block(&(script.clone(), LeafVersion::TapScript))
        .expect("hashlock control block");
    assert_eq!(
        control.serialize().len(),
        if include_timeout { 65 } else { 33 }
    );
    ScriptPathLock {
        prevout: TxOut {
            value: Amount::from_sat(PREVOUT_SATS),
            script_pubkey: ScriptBuf::new_p2tr_tweaked(spend_info.output_key()),
        },
        script,
        control,
    }
}

fn pointlock(secp: &Secp256k1<bitcoin::secp256k1::All>) -> (TxOut, bitcoin::key::TweakedKeypair) {
    let keypair = pointlock_keypair(secp);
    let (internal_key, _) = keypair.x_only_public_key();
    let spend_info = TaprootBuilder::new()
        .add_leaf(0, timeout_leaf())
        .expect("timeout leaf")
        .finalize(secp, internal_key)
        .expect("pointlock plus timeout taptree");
    let tweaked = keypair.tap_tweak(secp, spend_info.merkle_root());
    assert_eq!(
        tweaked.public_parts().0,
        spend_info.output_key(),
        "the false-label-derived secret controls the Taproot key path",
    );
    (
        TxOut {
            value: Amount::from_sat(PREVOUT_SATS),
            script_pubkey: ScriptBuf::new_p2tr_tweaked(spend_info.output_key()),
        },
        tweaked,
    )
}

fn burn_transaction(funding_txid: Txid, funding_vout: u32) -> Transaction {
    // Six-byte script makes the non-witness body exactly 66 bytes, so the
    // witness-only difference between hashlock and pointlock stays explicit.
    let burn = ScriptBuf::from_bytes(vec![0x6a, 0x04, b'G', b'C', b'D', b'P']);
    Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::new(funding_txid, funding_vout),
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::ZERO,
            script_pubkey: burn,
        }],
    }
}

fn hashlock_spend(funding_txid: Txid, funding_vout: u32, lock: &ScriptPathLock) -> Transaction {
    let mut tx = burn_transaction(funding_txid, funding_vout);
    tx.input[0].witness.push(FALSE_LABEL);
    tx.input[0].witness.push(lock.script.as_bytes());
    tx.input[0].witness.push(lock.control.serialize());
    tx
}

fn pointlock_spend(
    secp: &Secp256k1<bitcoin::secp256k1::All>,
    funding_txid: Txid,
    funding_vout: u32,
    prevout: &TxOut,
    tweaked: bitcoin::key::TweakedKeypair,
) -> Transaction {
    let mut tx = burn_transaction(funding_txid, funding_vout);
    let prevouts = [prevout.clone()];
    let sighash = SighashCache::new(&tx)
        .taproot_key_spend_signature_hash(0, &Prevouts::All(&prevouts), TapSighashType::Default)
        .expect("BIP341 key-spend sighash");
    let message = Message::from(sighash);
    let signature = secp.sign_schnorr_no_aux_rand(&message, tweaked.as_keypair());
    secp.verify_schnorr(
        &signature,
        &message,
        tweaked.public_parts().0.as_x_only_public_key(),
    )
    .expect("point-lock key-path signature verifies");
    tx.input[0].witness.push(
        bitcoin::taproot::Signature {
            signature,
            sighash_type: TapSighashType::Default,
        }
        .to_vec(),
    );
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
fn disprove_hashlock_vs_pointlock_exact_serialization() {
    let secp = Secp256k1::new();
    let funding_txid = std::env::var("DISPROVE_FUNDING_TXID")
        .ok()
        .map(|value| value.parse().expect("DISPROVE_FUNDING_TXID is a txid"))
        .unwrap_or_else(Txid::all_zeros);
    let paper_hashlock = hashlock(&secp, false);
    let full_hashlock = hashlock(&secp, true);
    let (pointlock_prevout, tweaked) = pointlock(&secp);

    let paper = hashlock_spend(funding_txid, 0, &paper_hashlock);
    let full = hashlock_spend(funding_txid, 0, &full_hashlock);
    let point = pointlock_spend(&secp, funding_txid, 1, &pointlock_prevout, tweaked);

    assert_eq!(paper.base_size(), 66);
    assert_eq!(paper.weight().to_wu(), 354);
    assert_eq!(paper.vsize(), 89);
    assert_eq!(full.weight().to_wu(), 386);
    assert_eq!(full.vsize(), 97);
    assert_eq!(point.weight().to_wu(), 332);
    assert_eq!(point.vsize(), 83);
    assert_eq!(serialize(&paper).len(), 156);
    assert_eq!(serialize(&full).len(), 188);
    assert_eq!(serialize(&point).len(), 134);
    eprintln!(
        "Disprove: 16-byte hashlock {} WU/{} vB; hashlock+timeout {} WU/{} vB; \
         pointlock+timeout {} WU/{} vB",
        paper.weight().to_wu(),
        paper.vsize(),
        full.weight().to_wu(),
        full.vsize(),
        point.weight().to_wu(),
        point.vsize(),
    );

    if let Ok(dir) = std::env::var("DISPROVE_EXPORT_DIR") {
        let dir = std::path::Path::new(&dir);
        std::fs::create_dir_all(dir).expect("create Disprove export directory");
        let hashlock_address =
            Address::from_script(&full_hashlock.prevout.script_pubkey, Network::Regtest)
                .expect("hashlock P2TR address");
        let pointlock_address =
            Address::from_script(&pointlock_prevout.script_pubkey, Network::Regtest)
                .expect("pointlock P2TR address");
        std::fs::write(
            dir.join("hashlock-address.txt"),
            format!("{hashlock_address}\n"),
        )
        .expect("write hashlock address");
        std::fs::write(
            dir.join("pointlock-address.txt"),
            format!("{pointlock_address}\n"),
        )
        .expect("write pointlock address");
        std::fs::write(
            dir.join("hashlock-script.hex"),
            format!(
                "{}\n",
                encode_hex(full_hashlock.prevout.script_pubkey.as_bytes())
            ),
        )
        .expect("write hashlock script");
        std::fs::write(
            dir.join("pointlock-script.hex"),
            format!(
                "{}\n",
                encode_hex(pointlock_prevout.script_pubkey.as_bytes())
            ),
        )
        .expect("write pointlock script");
        std::fs::write(
            dir.join("hashlock-spend.hex"),
            format!("{}\n", encode_hex(&serialize(&full))),
        )
        .expect("write hashlock spend");
        std::fs::write(
            dir.join("pointlock-spend.hex"),
            format!("{}\n", encode_hex(&serialize(&point))),
        )
        .expect("write pointlock spend");
    }
}
