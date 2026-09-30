//! Exact serialization/cost fixture for a hypothetical 192-bit-node
//! P2MR + custom-SHRINCS batched pair selector.
//!
//! This is deliberately a serialization model, not an executable Bitcoin
//! protocol:
//!
//! * BIP360 P2MR and the 0xC2 tapscript leaf are draft proposals.
//! * `OP_CHECKBATCHPAIRSELECT` is a hypothetical native opcode.
//! * The current SHRINCS draft fixes `n = 16`.  This fixture extrapolates its
//!   published formulas to `n = 24`: 48 WOTS+C chains, a 72-byte public key,
//!   and a minimum depth-one stateful signature of 1,204 bytes.  The signature
//!   bytes are deterministic placeholders and are never claimed to verify.
//!   A hypothetical future algorithm flag 0x03 identifies this custom instance;
//!   current 0xC2 drafts leave 0x03 reserved/auto-success, so this is not
//!   deployed signature verification.
//! * One SHRINCS-shaped authorization item is charged per transaction.  This
//!   assumes one authorizer, or a future threshold/MPC construction with the
//!   same on-chain shape.  It is not an n-of-n committee cost.
//!
//! Everything that rust-bitcoin can serialize today is serialized exactly:
//! transaction shells, CompactSize fields, P2MR v2 outputs, 0xC2 scripts,
//! depth-one control blocks, selector payloads, and authorization witnesses.
//! The endpoint root commits to all 48 public chain endpoints per record, so
//! it is independent of the later-selected input digits.
//!
//! Two witness layouts are measured.  `CanonicalFivePerBlob` is recommended:
//! it packs at most five complete 1,164-byte records into a C2 stack item
//! (5,820 bytes), never straddles a record, and requires the hypothetical
//! opcode to reject a wrong blob count, a non-full interior blob, trailing
//! bytes, missing records, duplicates, or reordering.  `OneRecordPerItem` is
//! retained as a directly comparable baseline.

use bitcoin::{
    absolute::LockTime,
    consensus::encode::serialize,
    hashes::{sha256, Hash, HashEngine},
    transaction::Version,
    Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid, Witness,
};

const INPUT_BITS: usize = 1_041_024;
const INPUT_BYTES: usize = INPUT_BITS / 8;

const N: usize = 24;
const BITS_PER_RECORD: usize = 96;
const CLEAR_BYTES_PER_RECORD: usize = BITS_PER_RECORD / 8;
const DIGITS_PER_RECORD: usize = BITS_PER_RECORD / 4;
const COORDINATES_PER_RECORD: usize = 2 * DIGITS_PER_RECORD;
const CHAIN_MAX: u8 = 15;
const SELECTOR_OPENING_BYTES: usize = COORDINATES_PER_RECORD * N;
const SELECTOR_RECORD_BYTES: usize = SELECTOR_OPENING_BYTES + CLEAR_BYTES_PER_RECORD;
const RECORDS: usize = INPUT_BITS / BITS_PER_RECORD;

const MAX_C2_STACK_ITEM_BYTES: usize = 6_000;
const RECORDS_PER_CANONICAL_BLOB: usize = MAX_C2_STACK_ITEM_BYTES / SELECTOR_RECORD_BYTES;
const MAX_STANDARD_TX_WEIGHT: u64 = 400_000;
const MAX_STANDARD_STACK_ITEMS: usize = 1_000;
const RECORDS_PER_FULL_REVEAL: usize = 341;
const REVEAL_TRANSACTIONS: usize = 32;

// Extrapolation of the SHRINCS draft's n=16 formulas to n=24:
//   WOTS_C_CHAIN_COUNT = ceil(8*n / 4) = 48
//   WOTS_C_CHAINS_SIZE = 48*n = 1,152
//   FXMSS_SIGNATURE_SIZE_MIN = 2 + 1,152 + n = 1,178
//   SHRINCS_SF_SIGNATURE_SIZE_MIN = 1 + n + 1 + 1,178 = 1,204
//   SHRINCS_PUBLIC_KEY_BYTES = 3*n = 72
const CUSTOM_SHRINCS_CHAIN_COUNT: usize = 48;
const CUSTOM_SHRINCS_SIGNATURE_BYTES: usize = 1_204;
const CUSTOM_SHRINCS_PUBLIC_KEY_BYTES: usize = 72;
// 0x03 is hypothetical. The current 0xC2 draft defines only 0x01 SHRINCS-n16
// and 0x02 BIP340; treating reserved 0x03 as verification would be unsafe.
const CUSTOM_SHRINCS_ALGORITHM_FLAG: u8 = 0x03;

const PQ_LEAF_VERSION: u8 = 0xc2;
const P2MR_CONTROL_BYTE: u8 = 0xc3;
const P2MR_CONTROL_BYTES: usize = 33;
const OP_CHECKBATCHPAIRSELECT: u8 = 0xbb;
const FUNDING_OUTPUT_SATS: u64 = 100_000;
const REVEAL_OUTPUT_SATS: u64 = 1_000;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RecordPacking {
    OneRecordPerItem,
    CanonicalFivePerBlob,
}

impl RecordPacking {
    fn mode_opcode(self) -> u8 {
        match self {
            Self::OneRecordPerItem => 0x51,     // OP_1
            Self::CanonicalFivePerBlob => 0x52, // OP_2
        }
    }

    fn records_per_item(self) -> usize {
        match self {
            Self::OneRecordPerItem => 1,
            Self::CanonicalFivePerBlob => RECORDS_PER_CANONICAL_BLOB,
        }
    }

    fn item_count(self, record_count: usize) -> usize {
        record_count.div_ceil(self.records_per_item())
    }
}

fn tagged_hash(tag: &[u8], message: &[u8]) -> [u8; 32] {
    let tag_hash = sha256::Hash::hash(tag);
    let mut engine = sha256::Hash::engine();
    engine.input(tag_hash.as_byte_array());
    engine.input(tag_hash.as_byte_array());
    engine.input(message);
    sha256::Hash::from_engine(engine).to_byte_array()
}

fn compact_size(value: usize) -> Vec<u8> {
    match value {
        0..=0xfc => vec![value as u8],
        0xfd..=0xffff => {
            let mut encoded = vec![0xfd];
            encoded.extend_from_slice(&(value as u16).to_le_bytes());
            encoded
        }
        0x1_0000..=0xffff_ffff => {
            let mut encoded = vec![0xfe];
            encoded.extend_from_slice(&(value as u32).to_le_bytes());
            encoded
        }
        _ => {
            let mut encoded = vec![0xff];
            encoded.extend_from_slice(&(value as u64).to_le_bytes());
            encoded
        }
    }
}

fn tapleaf_hash(leaf_version: u8, script: &ScriptBuf) -> [u8; 32] {
    assert_eq!(leaf_version & 1, 0);
    let mut preimage = Vec::with_capacity(1 + 9 + script.len());
    preimage.push(leaf_version);
    preimage.extend_from_slice(&compact_size(script.len()));
    preimage.extend_from_slice(script.as_bytes());
    tagged_hash(b"TapLeaf", &preimage)
}

fn tapbranch_hash(left: [u8; 32], right: [u8; 32]) -> [u8; 32] {
    let (first, second) = if left <= right {
        (left, right)
    } else {
        (right, left)
    };
    let mut children = [0u8; 64];
    children[..32].copy_from_slice(&first);
    children[32..].copy_from_slice(&second);
    tagged_hash(b"TapBranch", &children)
}

fn p2mr_script_pubkey(root: [u8; 32]) -> ScriptBuf {
    let mut script = Vec::with_capacity(34);
    script.push(0x52); // OP_2: witness version 2.
    script.push(0x20); // Direct 32-byte witness-program push.
    script.extend_from_slice(&root);
    let script = ScriptBuf::from_bytes(script);
    assert_eq!(script.len(), 34);
    script
}

#[derive(Clone)]
struct P2mrSpend {
    script_pubkey: ScriptBuf,
    leaf_script: ScriptBuf,
    control_block: Vec<u8>,
}

fn depth_one_p2mr_spend(leaf_script: ScriptBuf, sibling_script: &ScriptBuf) -> P2mrSpend {
    let leaf = tapleaf_hash(PQ_LEAF_VERSION, &leaf_script);
    let sibling = tapleaf_hash(PQ_LEAF_VERSION, sibling_script);
    let root = tapbranch_hash(leaf, sibling);
    let mut control_block = Vec::with_capacity(P2MR_CONTROL_BYTES);
    control_block.push(P2MR_CONTROL_BYTE);
    control_block.extend_from_slice(&sibling);

    let spend = P2mrSpend {
        script_pubkey: p2mr_script_pubkey(root),
        leaf_script,
        control_block,
    };
    assert_p2mr_commitment(&spend);
    spend
}

fn assert_p2mr_commitment(spend: &P2mrSpend) {
    assert_eq!(spend.script_pubkey.len(), 34);
    assert_eq!(spend.script_pubkey.as_bytes()[..2], [0x52, 0x20]);
    assert_eq!(spend.control_block.len(), P2MR_CONTROL_BYTES);
    assert_eq!(spend.control_block[0], P2MR_CONTROL_BYTE);
    assert_eq!(spend.control_block[0] & 0xfe, PQ_LEAF_VERSION);

    let leaf = tapleaf_hash(spend.control_block[0] & 0xfe, &spend.leaf_script);
    let sibling: [u8; 32] = spend.control_block[1..]
        .try_into()
        .expect("depth-one P2MR control block");
    let root = tapbranch_hash(leaf, sibling);
    assert_eq!(&spend.script_pubkey.as_bytes()[2..], &root);
}

fn dummy_custom_shrincs_public_key(key_index: u32) -> [u8; CUSTOM_SHRINCS_PUBLIC_KEY_BYTES] {
    let mut public_key = [0u8; CUSTOM_SHRINCS_PUBLIC_KEY_BYTES];
    for (part, chunk) in public_key.chunks_exact_mut(N).enumerate() {
        let mut seed = Vec::with_capacity(8);
        seed.extend_from_slice(&key_index.to_le_bytes());
        seed.extend_from_slice(&(part as u32).to_le_bytes());
        chunk.copy_from_slice(&tagged_hash(b"PQSelectorN24/DummyPk", &seed)[..N]);
    }
    public_key
}

fn dummy_custom_shrincs_signature(key_index: u32) -> Vec<u8> {
    // SERIALIZATION ONLY: no verifier accepts this deterministic placeholder.
    let mut signature = vec![0u8; CUSTOM_SHRINCS_SIGNATURE_BYTES];
    for (block_index, block) in signature.chunks_mut(32).enumerate() {
        let mut seed = Vec::with_capacity(8);
        seed.extend_from_slice(&key_index.to_le_bytes());
        seed.extend_from_slice(&(block_index as u32).to_le_bytes());
        let digest = tagged_hash(b"PQSelectorN24/DummySig", &seed);
        block.copy_from_slice(&digest[..block.len()]);
    }
    signature
}

fn push_flagged_custom_shrincs_key(script: &mut Vec<u8>, key_index: u32) {
    // Hypothetical 0x03 || 72-byte public key is a 73-byte direct push (still <= 75).
    script.push((1 + CUSTOM_SHRINCS_PUBLIC_KEY_BYTES) as u8);
    script.push(CUSTOM_SHRINCS_ALGORITHM_FLAG);
    script.extend_from_slice(&dummy_custom_shrincs_public_key(key_index));
}

fn authorization_leaf(key_index: u32) -> ScriptBuf {
    let mut script = Vec::with_capacity(75);
    push_flagged_custom_shrincs_key(&mut script, key_index);
    script.push(0xac); // Hypothetical 0xC2 CHECKSIG for custom n=24.
    assert_eq!(script.len(), 75);
    ScriptBuf::from_bytes(script)
}

fn selector_leaf(
    key_index: u32,
    selector_root: [u8; 32],
    first_record_index: u32,
    record_count: usize,
    packing: RecordPacking,
) -> ScriptBuf {
    assert!(record_count <= u16::MAX as usize);
    let mut script = Vec::with_capacity(118);

    push_flagged_custom_shrincs_key(&mut script, key_index);
    script.push(0xad); // Hypothetical 0xC2 CHECKSIGVERIFY.
    script.push(32);
    script.extend_from_slice(&selector_root);
    script.push(4);
    script.extend_from_slice(&first_record_index.to_le_bytes());
    script.push(2);
    script.extend_from_slice(&(record_count as u16).to_le_bytes());
    script.push(packing.mode_opcode());

    // Proposed semantics: consume exactly the number of blobs implied by the
    // committed record count and mode.  For mode 2, every interior blob must
    // contain exactly five whole records and the final blob exactly the
    // remaining 1..=5 records.  No record may straddle an item and no trailing
    // bytes are accepted. After consuming the four metadata items, the top
    // blob is the last blob pushed by `reveal_transaction`; parse the blob
    // segment from its deepest item to its topmost item, then parse records in
    // byte order. Bind consecutive global indexes, recompute all 48 endpoints,
    // and compare the ordered root.
    script.push(OP_CHECKBATCHPAIRSELECT);
    assert_eq!(script.len(), 118);
    ScriptBuf::from_bytes(script)
}

fn sibling_leaf(key_index: u32) -> ScriptBuf {
    authorization_leaf(key_index ^ 0x8000_0000)
}

fn encode_digit(digit: u8) -> [u8; 2] {
    assert!(digit <= CHAIN_MAX);
    [digit, CHAIN_MAX - digit]
}

fn can_forward_derive(source: [u8; 2], target: [u8; 2]) -> bool {
    source.into_iter().zip(target).all(|(from, to)| to <= from)
}

fn chain_seed(record_index: u32, coordinate_index: u8) -> [u8; N] {
    // Deterministic public fixture material, not a secret-key generator. It
    // exercises serialization, indexing, and forward-chain structure but
    // intentionally provides no unforgeability in this cost model.
    let mut message = [0u8; 5];
    message[..4].copy_from_slice(&record_index.to_le_bytes());
    message[4] = coordinate_index;
    tagged_hash(b"PQSelectorN24/ChainSeed", &message)[..N]
        .try_into()
        .expect("24-byte chain seed")
}

fn chain_step(
    record_index: u32,
    coordinate_index: u8,
    from_remaining: u8,
    node: [u8; N],
) -> [u8; N] {
    assert!((1..=CHAIN_MAX).contains(&from_remaining));
    let mut message = [0u8; N + 7];
    message[0] = 1;
    message[1..5].copy_from_slice(&record_index.to_le_bytes());
    message[5] = coordinate_index;
    message[6] = from_remaining;
    message[7..].copy_from_slice(&node);
    sha256::Hash::hash(&message).to_byte_array()[..N]
        .try_into()
        .expect("24-byte truncated hash")
}

fn chain_node(record_index: u32, coordinate_index: u8, remaining_steps: u8) -> [u8; N] {
    assert!(remaining_steps <= CHAIN_MAX);
    let mut node = chain_seed(record_index, coordinate_index);
    for from_remaining in (remaining_steps + 1..=CHAIN_MAX).rev() {
        node = chain_step(record_index, coordinate_index, from_remaining, node);
    }
    node
}

fn forward_to_remaining(
    record_index: u32,
    coordinate_index: u8,
    source_remaining: u8,
    target_remaining: u8,
    mut node: [u8; N],
) -> [u8; N] {
    assert!(target_remaining <= source_remaining);
    for from_remaining in (target_remaining + 1..=source_remaining).rev() {
        node = chain_step(record_index, coordinate_index, from_remaining, node);
    }
    node
}

fn selector_record(record_index: u32, clear: &[u8]) -> Vec<u8> {
    assert_eq!(clear.len(), CLEAR_BYTES_PER_RECORD);
    let mut record = Vec::with_capacity(SELECTOR_RECORD_BYTES);
    let mut coordinate_index = 0u8;

    for &byte in clear {
        for digit in [byte >> 4, byte & 0x0f] {
            for remaining_steps in encode_digit(digit) {
                record.extend_from_slice(&chain_node(
                    record_index,
                    coordinate_index,
                    remaining_steps,
                ));
                coordinate_index += 1;
            }
        }
    }
    assert_eq!(coordinate_index as usize, COORDINATES_PER_RECORD);
    assert_eq!(record.len(), SELECTOR_OPENING_BYTES);
    record.extend_from_slice(clear);
    assert_eq!(record.len(), SELECTOR_RECORD_BYTES);
    record
}

fn selector_endpoint_record(record_index: u32) -> Vec<u8> {
    let mut endpoints = Vec::with_capacity(SELECTOR_OPENING_BYTES);
    for coordinate_index in 0..COORDINATES_PER_RECORD as u8 {
        endpoints.extend_from_slice(&chain_node(record_index, coordinate_index, 0));
    }
    assert_eq!(endpoints.len(), SELECTOR_OPENING_BYTES);
    endpoints
}

fn selector_endpoint_root(first_record_index: u32, endpoint_records: &[Vec<u8>]) -> [u8; 32] {
    assert!(!endpoint_records.is_empty());
    let mut layer: Vec<[u8; 32]> = endpoint_records
        .iter()
        .enumerate()
        .map(|(offset, endpoints)| {
            assert_eq!(endpoints.len(), SELECTOR_OPENING_BYTES);
            let mut leaf = Vec::with_capacity(4 + endpoints.len());
            leaf.extend_from_slice(&(first_record_index + offset as u32).to_le_bytes());
            leaf.extend_from_slice(endpoints);
            tagged_hash(b"PQSelectorN24/EndpointLeaf", &leaf)
        })
        .collect();

    while layer.len() > 1 {
        let mut parent = Vec::with_capacity(layer.len().div_ceil(2));
        for pair in layer.chunks(2) {
            let right = pair.get(1).copied().unwrap_or(pair[0]);
            let mut children = [0u8; 64];
            children[..32].copy_from_slice(&pair[0]);
            children[32..].copy_from_slice(&right);
            parent.push(tagged_hash(b"PQSelectorN24/EndpointNode", &children));
        }
        layer = parent;
    }
    layer[0]
}

fn verify_selector_record(record_index: u32, record: &[u8]) -> Option<Vec<u8>> {
    if record.len() != SELECTOR_RECORD_BYTES {
        return None;
    }
    let clear = &record[SELECTOR_OPENING_BYTES..];
    let mut coordinate_index = 0u8;
    let mut opening_offset = 0usize;
    let mut endpoints = Vec::with_capacity(SELECTOR_OPENING_BYTES);

    for &byte in clear {
        for digit in [byte >> 4, byte & 0x0f] {
            for remaining_steps in encode_digit(digit) {
                let opener: [u8; N] = record[opening_offset..opening_offset + N]
                    .try_into()
                    .expect("fixed-width selector opener");
                opening_offset += N;
                endpoints.extend_from_slice(&forward_to_remaining(
                    record_index,
                    coordinate_index,
                    remaining_steps,
                    0,
                    opener,
                ));
                coordinate_index += 1;
            }
        }
    }
    if coordinate_index as usize != COORDINATES_PER_RECORD
        || opening_offset != SELECTOR_OPENING_BYTES
    {
        return None;
    }
    Some(endpoints)
}

fn pack_record_items(records: &[Vec<u8>], packing: RecordPacking) -> Vec<Vec<u8>> {
    records
        .chunks(packing.records_per_item())
        .map(|records_in_item| {
            let mut item = Vec::with_capacity(records_in_item.len() * SELECTOR_RECORD_BYTES);
            for record in records_in_item {
                assert_eq!(record.len(), SELECTOR_RECORD_BYTES);
                item.extend_from_slice(record);
            }
            assert!(item.len() <= MAX_C2_STACK_ITEM_BYTES);
            item
        })
        .collect()
}

fn verify_selector_items(
    first_record_index: u32,
    expected_record_count: usize,
    items: &[Vec<u8>],
    expected_root: [u8; 32],
    packing: RecordPacking,
) -> bool {
    if expected_record_count == 0 || items.len() != packing.item_count(expected_record_count) {
        return false;
    }

    let records_per_item = packing.records_per_item();
    let mut endpoint_records = Vec::with_capacity(expected_record_count);
    let mut record_offset = 0usize;
    for (item_index, item) in items.iter().enumerate() {
        let remaining = expected_record_count - record_offset;
        let expected_in_item = remaining.min(records_per_item);
        if item_index + 1 < items.len() && expected_in_item != records_per_item {
            return false;
        }
        if item.len() != expected_in_item * SELECTOR_RECORD_BYTES
            || item.len() > MAX_C2_STACK_ITEM_BYTES
        {
            return false;
        }

        let mut chunks = item.chunks_exact(SELECTOR_RECORD_BYTES);
        for record in &mut chunks {
            let Some(endpoints) =
                verify_selector_record(first_record_index + record_offset as u32, record)
            else {
                return false;
            };
            endpoint_records.push(endpoints);
            record_offset += 1;
        }
        if !chunks.remainder().is_empty() {
            return false;
        }
    }

    record_offset == expected_record_count
        && selector_endpoint_root(first_record_index, &endpoint_records) == expected_root
}

struct Batch {
    first_record_index: u32,
    records: Vec<Vec<u8>>,
    selector_root: [u8; 32],
}

fn make_batch(first_record_index: u32, clear_records: &[&[u8]]) -> Batch {
    let records: Vec<Vec<u8>> = clear_records
        .iter()
        .enumerate()
        .map(|(offset, clear)| selector_record(first_record_index + offset as u32, clear))
        .collect();
    let endpoint_records: Vec<Vec<u8>> = (0..clear_records.len())
        .map(|offset| selector_endpoint_record(first_record_index + offset as u32))
        .collect();
    Batch {
        first_record_index,
        records,
        selector_root: selector_endpoint_root(first_record_index, &endpoint_records),
    }
}

fn make_batches(input: &[u8]) -> Vec<Batch> {
    assert_eq!(input.len(), INPUT_BYTES);
    let clear_records: Vec<&[u8]> = input.chunks_exact(CLEAR_BYTES_PER_RECORD).collect();
    assert_eq!(clear_records.len(), RECORDS);

    let mut batches = Vec::with_capacity(REVEAL_TRANSACTIONS);
    let mut first = 0usize;
    while first < clear_records.len() {
        let count = (clear_records.len() - first).min(RECORDS_PER_FULL_REVEAL);
        batches.push(make_batch(
            first as u32,
            &clear_records[first..first + count],
        ));
        first += count;
    }
    assert_eq!(batches.len(), REVEAL_TRANSACTIONS);
    assert!(batches[..31]
        .iter()
        .all(|batch| batch.records.len() == RECORDS_PER_FULL_REVEAL));
    assert_eq!(batches[31].records.len(), 273);
    batches
}

fn batch_spend(batch_index: usize, batch: &Batch, packing: RecordPacking) -> P2mrSpend {
    let key_index = batch_index as u32 + 1;
    depth_one_p2mr_spend(
        selector_leaf(
            key_index,
            batch.selector_root,
            batch.first_record_index,
            batch.records.len(),
            packing,
        ),
        &sibling_leaf(key_index),
    )
}

fn attach_authorization_witness(input: &mut TxIn, spend: &P2mrSpend, key_index: u32) {
    input
        .witness
        .push(dummy_custom_shrincs_signature(key_index));
    input.witness.push(spend.leaf_script.as_bytes());
    input.witness.push(&spend.control_block);
}

fn funding_assert_transaction(batches: &[Batch], packing: RecordPacking) -> Transaction {
    let funding_key_index = 0u32;
    let predecessor_spend = depth_one_p2mr_spend(
        authorization_leaf(funding_key_index),
        &sibling_leaf(funding_key_index),
    );
    // The already-existing predecessor is outside the measured boundary. Use
    // a nonzero deterministic placeholder so it cannot be confused with the
    // all-zero txid convention in transaction fixtures.
    let predecessor_txid = Txid::from_byte_array(tagged_hash(
        b"PQSelectorN24/FixturePredecessorTxid",
        b"funding-assert-input",
    ));
    assert_ne!(predecessor_txid, Txid::all_zeros());
    let mut input = TxIn {
        previous_output: OutPoint::new(predecessor_txid, 0),
        script_sig: ScriptBuf::new(),
        sequence: Sequence::MAX,
        witness: Witness::new(),
    };
    attach_authorization_witness(&mut input, &predecessor_spend, funding_key_index);

    Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![input],
        output: batches
            .iter()
            .enumerate()
            .map(|(index, batch)| TxOut {
                value: Amount::from_sat(FUNDING_OUTPUT_SATS),
                script_pubkey: batch_spend(index, batch, packing).script_pubkey,
            })
            .collect(),
    }
}

fn reveal_transaction(
    funding_txid: Txid,
    funding_vout: u32,
    batch_index: usize,
    batch: &Batch,
    packing: RecordPacking,
) -> Transaction {
    let spend = batch_spend(batch_index, batch, packing);
    let items = pack_record_items(&batch.records, packing);
    assert!(verify_selector_items(
        batch.first_record_index,
        batch.records.len(),
        &items,
        batch.selector_root,
        packing,
    ));

    let mut input = TxIn {
        previous_output: OutPoint::new(funding_txid, funding_vout),
        script_sig: ScriptBuf::new(),
        sequence: Sequence::MAX,
        witness: Witness::new(),
    };
    for item in items {
        input.witness.push(item);
    }
    input
        .witness
        .push(dummy_custom_shrincs_signature(batch_index as u32 + 1));
    input.witness.push(spend.leaf_script.as_bytes());
    input.witness.push(&spend.control_block);
    assert!(input.witness.len() <= MAX_STANDARD_STACK_ITEMS);
    assert!(input
        .witness
        .iter()
        .all(|item| item.len() <= MAX_C2_STACK_ITEM_BYTES));

    let continuation_key = 10_000u32 + batch_index as u32;
    let continuation = depth_one_p2mr_spend(
        authorization_leaf(continuation_key),
        &sibling_leaf(continuation_key),
    );
    Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![input],
        output: vec![TxOut {
            value: Amount::from_sat(REVEAL_OUTPUT_SATS),
            script_pubkey: continuation.script_pubkey,
        }],
    }
}

#[derive(Debug)]
struct Cost {
    funding_weight: u64,
    funding_vsize: usize,
    funding_serialized: usize,
    reveal_weights: Vec<u64>,
    reveal_vsizes: Vec<usize>,
    reveal_serialized: Vec<usize>,
    total_weight: u64,
    billed_vsize: usize,
    total_serialized: usize,
}

fn measure(batches: &[Batch], packing: RecordPacking) -> Cost {
    let funding = funding_assert_transaction(batches, packing);
    let funding_txid = funding.compute_txid();
    let reveals: Vec<Transaction> = batches
        .iter()
        .enumerate()
        .map(|(index, batch)| reveal_transaction(funding_txid, index as u32, index, batch, packing))
        .collect();
    let reveal_weights: Vec<u64> = reveals.iter().map(|tx| tx.weight().to_wu()).collect();
    let reveal_vsizes: Vec<usize> = reveals.iter().map(Transaction::vsize).collect();
    let reveal_serialized: Vec<usize> = reveals.iter().map(|tx| serialize(tx).len()).collect();
    let total_weight = funding.weight().to_wu() + reveal_weights.iter().copied().sum::<u64>();
    let billed_vsize = funding.vsize() + reveal_vsizes.iter().copied().sum::<usize>();
    let total_serialized =
        serialize(&funding).len() + reveal_serialized.iter().copied().sum::<usize>();

    Cost {
        funding_weight: funding.weight().to_wu(),
        funding_vsize: funding.vsize(),
        funding_serialized: serialize(&funding).len(),
        reveal_weights,
        reveal_vsizes,
        reveal_serialized,
        total_weight,
        billed_vsize,
        total_serialized,
    }
}

#[test]
fn n24_pair_code_and_canonical_blob_parser_are_binding() {
    assert_eq!(CUSTOM_SHRINCS_CHAIN_COUNT, COORDINATES_PER_RECORD);
    for source_digit in 0..=CHAIN_MAX {
        for target_digit in 0..=CHAIN_MAX {
            assert_eq!(
                can_forward_derive(encode_digit(source_digit), encode_digit(target_digit)),
                source_digit == target_digit
            );
        }
    }

    let first = 41u32;
    let clears = [
        [0x05; CLEAR_BYTES_PER_RECORD],
        [0xa7; CLEAR_BYTES_PER_RECORD],
        [0x3c; CLEAR_BYTES_PER_RECORD],
        [0xee; CLEAR_BYTES_PER_RECORD],
        [0x19; CLEAR_BYTES_PER_RECORD],
        [0x80; CLEAR_BYTES_PER_RECORD],
    ];
    let clear_refs: Vec<&[u8]> = clears.iter().map(|clear| clear.as_slice()).collect();
    let batch = make_batch(first, &clear_refs);
    let packing = RecordPacking::CanonicalFivePerBlob;
    let items = pack_record_items(&batch.records, packing);
    assert_eq!(items.len(), 2);
    assert_eq!(items[0].len(), 5 * SELECTOR_RECORD_BYTES);
    assert_eq!(items[1].len(), SELECTOR_RECORD_BYTES);
    assert!(verify_selector_items(
        first,
        batch.records.len(),
        &items,
        batch.selector_root,
        packing,
    ));

    // The committed endpoint root is fixed by the keys and indexes, not by a
    // later input choice. A completely different set of clear digits therefore
    // verifies against the same precommitted root when supplied with its proper
    // one-time openings.
    let alternate_clears = [[0xf0; CLEAR_BYTES_PER_RECORD]; 6];
    let alternate_refs: Vec<&[u8]> = alternate_clears
        .iter()
        .map(|clear| clear.as_slice())
        .collect();
    let alternate_batch = make_batch(first, &alternate_refs);
    assert_ne!(batch.records, alternate_batch.records);
    assert_eq!(batch.selector_root, alternate_batch.selector_root);
    let alternate_items = pack_record_items(&alternate_batch.records, packing);
    assert!(verify_selector_items(
        first,
        alternate_batch.records.len(),
        &alternate_items,
        batch.selector_root,
        packing,
    ));

    let mut trailing = items.clone();
    trailing[1].push(0);
    assert!(!verify_selector_items(
        first,
        batch.records.len(),
        &trailing,
        batch.selector_root,
        packing,
    ));
    let mut non_full_interior = items.clone();
    let moved = non_full_interior[0].split_off(4 * SELECTOR_RECORD_BYTES);
    non_full_interior[1].splice(0..0, moved);
    assert!(!verify_selector_items(
        first,
        batch.records.len(),
        &non_full_interior,
        batch.selector_root,
        packing,
    ));
    let mut reordered_records = batch.records.clone();
    reordered_records.swap(0, 1);
    let reordered = pack_record_items(&reordered_records, packing);
    assert!(!verify_selector_items(
        first,
        batch.records.len(),
        &reordered,
        batch.selector_root,
        packing,
    ));
    assert!(!verify_selector_items(
        first + 1,
        batch.records.len(),
        &items,
        batch.selector_root,
        packing,
    ));
}

#[test]
fn pq_selector_n24_exact_funding_reveal_and_maximal_record_aligned_packing_cost() {
    assert_eq!(INPUT_BYTES, 130_128);
    assert_eq!(RECORDS, 10_844);
    assert_eq!(DIGITS_PER_RECORD, 24);
    assert_eq!(COORDINATES_PER_RECORD, 48);
    assert_eq!(SELECTOR_OPENING_BYTES, 1_152);
    assert_eq!(SELECTOR_RECORD_BYTES, 1_164);
    assert_eq!(RECORDS_PER_CANONICAL_BLOB, 5);
    assert_eq!(5 * SELECTOR_RECORD_BYTES, 5_820);
    assert!(6 * SELECTOR_RECORD_BYTES > MAX_C2_STACK_ITEM_BYTES);
    assert_eq!(compact_size(SELECTOR_RECORD_BYTES).len(), 3);
    assert_eq!(3 + SELECTOR_RECORD_BYTES, 1_167);
    assert_eq!(compact_size(5 * SELECTOR_RECORD_BYTES).len(), 3);
    assert_eq!(3 + 5 * SELECTOR_RECORD_BYTES, 5_823);
    assert_eq!(compact_size(CUSTOM_SHRINCS_SIGNATURE_BYTES).len(), 3);
    assert_eq!(3 + CUSTOM_SHRINCS_SIGNATURE_BYTES, 1_207);
    assert!(CUSTOM_SHRINCS_SIGNATURE_BYTES <= MAX_C2_STACK_ITEM_BYTES);

    let input: Vec<u8> = (0..INPUT_BYTES).map(|index| (index % 251) as u8).collect();
    let batches = make_batches(&input);
    assert_eq!(
        batches
            .iter()
            .map(|batch| batch.records.len())
            .sum::<usize>(),
        RECORDS
    );
    assert!(batches.iter().enumerate().all(|(index, batch)| {
        batch_spend(index, batch, RecordPacking::CanonicalFivePerBlob)
            .leaf_script
            .len()
            == 118
    }));

    let packed = measure(&batches, RecordPacking::CanonicalFivePerBlob);
    assert_eq!(packed.funding_serialized, 2_747);
    assert_eq!(packed.funding_weight, 7_028);
    assert_eq!(packed.funding_vsize, 1_757);
    assert_eq!(packed.reveal_weights[..31], [398_870; 31]);
    assert_eq!(packed.reveal_weights[31], 319_676);
    assert_eq!(packed.reveal_vsizes[..31], [99_718; 31]);
    assert_eq!(packed.reveal_vsizes[31], 79_919);
    assert_eq!(packed.reveal_serialized[..31], [398_588; 31]);
    assert_eq!(packed.reveal_serialized[31], 319_394);
    assert_eq!(packed.total_weight, 12_691_674);
    assert_eq!(packed.total_weight / 4, 3_172_918);
    assert_eq!(packed.total_weight % 4, 2);
    assert_eq!(packed.billed_vsize, 3_172_934);
    assert_eq!(packed.total_serialized, 12_678_369);

    let one_per_item = measure(&batches, RecordPacking::OneRecordPerItem);
    assert_eq!(one_per_item.funding_serialized, 2_747);
    assert_eq!(one_per_item.funding_weight, 7_028);
    assert_eq!(one_per_item.funding_vsize, 1_757);
    assert_eq!(one_per_item.reveal_weights[..31], [399_688; 31]);
    assert_eq!(one_per_item.reveal_weights[31], 320_332);
    assert_eq!(one_per_item.reveal_vsizes[..31], [99_922; 31]);
    assert_eq!(one_per_item.reveal_vsizes[31], 80_083);
    assert_eq!(one_per_item.reveal_serialized[..31], [399_406; 31]);
    assert_eq!(one_per_item.reveal_serialized[31], 320_050);
    assert_eq!(one_per_item.total_weight, 12_717_688);
    assert_eq!(one_per_item.total_weight / 4, 3_179_422);
    assert_eq!(one_per_item.total_weight % 4, 0);
    assert_eq!(one_per_item.billed_vsize, 3_179_422);
    assert_eq!(one_per_item.total_serialized, 12_704_383);
    assert_eq!(one_per_item.billed_vsize - packed.billed_vsize, 6_488);

    assert!(packed
        .reveal_weights
        .iter()
        .chain(one_per_item.reveal_weights.iter())
        .all(|&weight| weight <= MAX_STANDARD_TX_WEIGHT));
    assert_eq!(1 + batches.len(), 33);

    // Exact packing boundary.  At 341 records, canonical packing needs 69
    // blobs and one-record packing needs 341 items.  The next record exceeds
    // 400,000 WU in both layouts.  These formulas include the exact witness
    // item-count CompactSize transition: one byte for 72 packed stack items,
    // three bytes for 344 one-record stack items.
    assert_eq!(RecordPacking::CanonicalFivePerBlob.item_count(341), 69);
    assert_eq!(RecordPacking::CanonicalFivePerBlob.item_count(342), 69);
    assert_eq!(1_739u64 + 1_164 * 341 + 3 * 69, 398_870);
    assert_eq!(1_739u64 + 1_164 * 342 + 3 * 69, 400_034);
    assert_eq!(1_741u64 + 1_167 * 341, 399_688);
    assert_eq!(1_741u64 + 1_167 * 342, 400_855);
    assert!(400_034 > MAX_STANDARD_TX_WEIGHT);
    assert!(400_855 > MAX_STANDARD_TX_WEIGHT);

    eprintln!(
        "n=24 selector candidate (HYPOTHETICAL/SERIALIZATION ONLY): {INPUT_BITS} bits, \
         {RECORDS} x {SELECTOR_RECORD_BYTES}-B records; canonical 5-record \
         blobs: {} WU = {}.{} weight-vB, {} billed vB, 33 tx, max reveal {} \
         WU; one-record items: {} WU = {} weight-vB, {} billed vB, 33 tx, \
         max reveal {} WU; one tx-level signature assumes one authorizer or \
         same-size aggregate",
        packed.total_weight,
        packed.total_weight / 4,
        5,
        packed.billed_vsize,
        packed.reveal_weights.iter().max().unwrap(),
        one_per_item.total_weight,
        one_per_item.total_weight / 4,
        one_per_item.billed_vsize,
        one_per_item.reveal_weights.iter().max().unwrap(),
    );
}
