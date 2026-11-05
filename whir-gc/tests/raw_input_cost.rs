//! Serialization cost of publishing the verifier's raw input bits in a
//! standard-policy-shaped Tapscript witness.
//!
//! This fixture executes the leaf scripts and verifies their Taproot control
//! blocks, but it uses synthetic outpoints and does not call Bitcoin Core's
//! `testmempoolaccept`.  It therefore validates serialization, weight, stack
//! shape, and the script path rather than admission of a spend of real UTXOs.
//! The leaf scripts deliberately drop every byte and return true; they do not
//! authenticate a payload or bind bits to garbled-circuit labels.

use bitcoin::{
    absolute::LockTime,
    consensus::encode::serialize,
    hashes::Hash,
    key::Secp256k1,
    secp256k1::XOnlyPublicKey,
    taproot::{LeafVersion, TaprootBuilder},
    transaction::Version,
    Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid, Witness,
};
use bitcoin_script::{define_pushable, script};
use std::str::FromStr;

define_pushable!();

const INPUT_BITS: usize = 1_041_024;
const INPUT_BYTES: usize = INPUT_BITS.div_ceil(8);
const POLICY_ITEM_BYTES: usize = 80;
const MAX_STACK_ITEMS: usize = 1_000;
const MAX_STANDARD_TX_WEIGHT: u64 = 400_000;

fn drop_script(items: usize) -> ScriptBuf {
    // OP_2DROP for pairs, OP_DROP for an odd tail, then OP_TRUE. Tapscript
    // removes the legacy 201-op and 10,000-byte script limits.
    let mut bytes = vec![0x6d; items / 2];
    if items % 2 == 1 {
        bytes.push(0x75);
    }
    bytes.push(0x51);
    ScriptBuf::from_bytes(bytes)
}

/// A witness and the P2TR scriptPubKey that actually commits to its tapscript.
fn raw_input_witness(bytes: usize) -> (Witness, ScriptBuf) {
    let items = bytes.div_ceil(POLICY_ITEM_BYTES);
    assert!(items <= MAX_STACK_ITEMS);

    let stack: Vec<Vec<u8>> = (0..items)
        .map(|i| {
            let len = (bytes - i * POLICY_ITEM_BYTES).min(POLICY_ITEM_BYTES);
            vec![0u8; len]
        })
        .collect();
    let tapscript = drop_script(items);
    let execution = bitcoin_scriptexec::execute_script(script! {
        for item in stack.clone() { { item } }
        { tapscript.clone() }
    });
    assert!(
        execution.success,
        "raw-input leaf script failed: {:?}",
        execution.error
    );
    assert!(execution.stats.max_nb_stack_items <= MAX_STACK_ITEMS);

    let mut witness = Witness::new();
    for item in stack {
        witness.push(item);
    }
    let secp = Secp256k1::verification_only();
    // The x-coordinate of secp256k1's generator is a fixed valid internal key.
    let internal_key = XOnlyPublicKey::from_str(
        "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
    )
    .expect("fixed internal key");
    let spend_info = TaprootBuilder::new()
        .add_leaf(0, tapscript.clone())
        .expect("one-leaf taptree")
        .finalize(&secp, internal_key)
        .expect("one-leaf taptree is complete");
    let control = spend_info
        .control_block(&(tapscript.clone(), LeafVersion::TapScript))
        .expect("control block for the only leaf");
    assert!(control.verify_taproot_commitment(
        &secp,
        spend_info.output_key().to_x_only_public_key(),
        tapscript.as_script(),
    ));
    witness.push(tapscript.as_bytes());
    witness.push(control.serialize());
    (
        witness,
        ScriptBuf::new_p2tr_tweaked(spend_info.output_key()),
    )
}

#[test]
fn raw_verifier_input_fits_one_standard_weight_transaction() {
    let first_bytes = MAX_STACK_ITEMS * POLICY_ITEM_BYTES;
    let chunks = [first_bytes, INPUT_BYTES - first_bytes];
    assert_eq!(chunks, [80_000, 50_128]);
    assert_eq!(
        chunks
            .iter()
            .map(|n| n.div_ceil(POLICY_ITEM_BYTES))
            .sum::<usize>(),
        1_627
    );

    let spends: Vec<_> = chunks.into_iter().map(raw_input_witness).collect();
    let input = spends
        .iter()
        .enumerate()
        .map(|(vout, (witness, _prevout_script))| TxIn {
            previous_output: OutPoint::new(Txid::all_zeros(), vout as u32),
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: witness.clone(),
        })
        .collect();
    let tx = Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input,
        output: vec![TxOut {
            value: Amount::from_sat(1_000),
            script_pubkey: spends[0].1.clone(),
        }],
    };

    let serialized = serialize(&tx);
    let weight = tx.weight().to_wu();
    eprintln!(
        "{INPUT_BITS} bits = {INPUT_BYTES} payload bytes; 1627 data items over 2 inputs; serialized {} B; stripped {} B; weight {weight} WU; vsize {} vB",
        serialized.len(),
        tx.base_size(),
        tx.vsize(),
    );

    assert_eq!(serialized.len(), 132_788);
    assert_eq!(tx.base_size(), 135);
    assert_eq!(weight, 133_193);
    assert_eq!(tx.vsize(), 33_299);
    assert!(weight < MAX_STANDARD_TX_WEIGHT);
    assert!(tx.input.iter().all(|input| {
        // Exclude tapscript and control block from the initial stack.
        input.witness.len() - 2 <= MAX_STACK_ITEMS
            && input
                .witness
                .iter()
                .take(input.witness.len() - 2)
                .all(|item| item.len() <= POLICY_ITEM_BYTES)
    }));
}
