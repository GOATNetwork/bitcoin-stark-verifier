//! Serialization and cost fixture for a hypothetical P2MR + SHRINCS-derived
//! batched pair selector.
//!
//! This `n = 16` selector is **not** an end-to-end post-quantum-secure
//! parameter set: a 16-byte hash-chain node offers at most about 64 bits of
//! single-target generic quantum preimage security, and less in the large
//! multi-target setting modeled here. The fixture remains useful as an exact
//! transaction-envelope baseline; a wider, jointly reviewed parameter set is
//! required for a post-quantum security claim.
//!
//! This fixture deliberately separates facts that can be tested today from
//! proposed consensus and cryptographic machinery:
//!
//! * The transactions, witness CompactSize framing, P2MR v2 scriptPubKeys,
//!   depth-one control blocks, scripts, and weights are serialized exactly by
//!   rust-bitcoin.
//! * `E(d) = (d, 15-d)` is tested exhaustively.  A WOTS opening can only move
//!   each coordinate forward, so no opening for one valid pair can derive a
//!   different valid pair.
//! * The 520-byte records contain 32 genuine 16-byte forward-chain nodes for
//!   sixteen nibbles, followed by the eight bytes those nibbles encode.  The
//!   committed batch root is over the 32 chain endpoints for every record, not
//!   over the selected openings, so it can be fixed before the input is known.
//! * The 548-byte SHRINCS signatures and 48-byte public keys are exact-sized,
//!   deterministic placeholders.  They are SERIALIZATION ONLY; this test does
//!   not claim to implement or verify SHRINCS.
//!
//! Leaf version 0xC2 and P2MR (BIP360) are draft soft-fork proposals.  The
//! one-byte `OP_CHECKBATCHPAIRSELECT` below is a hypothetical native opcode;
//! its intended semantics are documented at its construction site.  Thus the
//! fixture is an exact byte/weight simulation of the proposed transaction
//! shape, not something current Bitcoin Core can execute.
//!
//! There is one transaction-level SHRINCS authorization per transaction.  That
//! assumes a single authorizing key, or a future threshold/MPC aggregate that
//! still produces one SHRINCS-shaped item.  A committee expressed with the
//! draft 0xC2 `OP_CHECKSIGADD` construction needs one signature per member and
//! is intentionally not included in these numbers.

use bitcoin::{
    absolute::LockTime,
    consensus::encode::serialize,
    hashes::{sha256, Hash, HashEngine},
    transaction::Version,
    Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid, Witness,
};

const INPUT_BITS: usize = 1_041_024;
const INPUT_BYTES: usize = INPUT_BITS / 8;
const BITS_PER_RECORD: usize = 64;
const RECORDS: usize = INPUT_BITS / BITS_PER_RECORD;

const N: usize = 16;
const NIBBLES_PER_RECORD: usize = 16;
const COORDINATES_PER_RECORD: usize = 2 * NIBBLES_PER_RECORD;
const CHAIN_MAX: u8 = 15;
const SELECTOR_OPENING_BYTES: usize = COORDINATES_PER_RECORD * N;
const CLEAR_BYTES_PER_RECORD: usize = BITS_PER_RECORD / 8;
const SELECTOR_RECORD_BYTES: usize = SELECTOR_OPENING_BYTES + CLEAR_BYTES_PER_RECORD;

// The current SHRINCS draft's minimum stateful signature is a depth-one
// signature: 531 + ceil(1/8) + 16*1 = 548 bytes.  Each transaction uses an
// independent depth-one key, so this cost model never reuses state.
const SHRINCS_SIGNATURE_BYTES: usize = 548;
const SHRINCS_PUBLIC_KEY_BYTES: usize = 48;
const SHRINCS_ALGORITHM_FLAG: u8 = 0x01;

const PQ_LEAF_VERSION: u8 = 0xc2;
// In the current P2MR draft, the control byte for a 0xC2 leaf has its low bit
// set.  A depth-one proof then contains one 32-byte sibling: 1 + 32 = 33 B.
const P2MR_CONTROL_BYTE: u8 = 0xc3;
const P2MR_CONTROL_BYTES: usize = 33;
const OP_CHECKBATCHPAIRSELECT: u8 = 0xbb;
const SELECTOR_MODE_PAIR_COMPLEMENT: u8 = 1;
const SELECTOR_MODE_PAIR_COMPLEMENT_BLOBS: u8 = 2;

// Leaf version 0xC2 raises the stack-element limit to 6000 bytes. Eleven
// fixed-width selector records occupy 5720 bytes, while twelve would occupy
// 6240 bytes and are therefore invalid.
const RECORDS_PER_BLOB: usize = 11;
const FULL_BLOB_BYTES: usize = RECORDS_PER_BLOB * SELECTOR_RECORD_BYTES;
const MAX_C2_STACK_ELEMENT_BYTES: usize = 6_000;

const MAX_STANDARD_TX_WEIGHT: u64 = 400_000;
const RECORDS_PER_FULL_REVEAL: usize = 762;
const RECORDS_PER_FULL_BLOB_REVEAL: usize = 766;
const REVEAL_TRANSACTIONS: usize = 22;
const FUNDING_OUTPUT_SATS: u64 = 100_000;
const REVEAL_OUTPUT_SATS: u64 = 1_000;

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
    assert_eq!(leaf_version & 1, 0, "tapleaf version must be even");
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
    script.push(0x52); // OP_2: SegWit witness version 2.
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
    assert_eq!(control_block.len(), P2MR_CONTROL_BYTES);

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
        .expect("depth-one control block has one sibling");
    let root = tapbranch_hash(leaf, sibling);
    assert_eq!(&spend.script_pubkey.as_bytes()[2..], &root);
}

fn dummy_shrincs_public_key(key_index: u32) -> [u8; SHRINCS_PUBLIC_KEY_BYTES] {
    let mut public_key = [0u8; SHRINCS_PUBLIC_KEY_BYTES];
    for (part, chunk) in public_key.chunks_exact_mut(N).enumerate() {
        let mut seed = Vec::with_capacity(8);
        seed.extend_from_slice(&key_index.to_le_bytes());
        seed.extend_from_slice(&(part as u32).to_le_bytes());
        chunk.copy_from_slice(&tagged_hash(b"PQSelector/DummyShrincsPk", &seed)[..N]);
    }
    public_key
}

fn dummy_shrincs_signature(key_index: u32) -> Vec<u8> {
    // SERIALIZATION ONLY.  This is deliberately not accepted as a SHRINCS
    // signature by any verifier; its sole purpose is exact witness sizing.
    let mut signature = vec![0u8; SHRINCS_SIGNATURE_BYTES];
    for (block_index, block) in signature.chunks_mut(32).enumerate() {
        let mut seed = Vec::with_capacity(8);
        seed.extend_from_slice(&key_index.to_le_bytes());
        seed.extend_from_slice(&(block_index as u32).to_le_bytes());
        let digest = tagged_hash(b"PQSelector/DummyShrincsSig", &seed);
        block.copy_from_slice(&digest[..block.len()]);
    }
    assert_eq!(signature.len(), SHRINCS_SIGNATURE_BYTES);
    signature
}

fn push_flagged_shrincs_key(script: &mut Vec<u8>, key_index: u32) {
    // flag || 48-byte SHRINCS public key is a 49-byte direct push.
    script.push(49);
    script.push(SHRINCS_ALGORITHM_FLAG);
    script.extend_from_slice(&dummy_shrincs_public_key(key_index));
}

fn authorization_leaf(key_index: u32) -> ScriptBuf {
    let mut script = Vec::with_capacity(51);
    push_flagged_shrincs_key(&mut script, key_index);
    script.push(0xac); // 0xC2 OP_CHECKSIG using algorithm flag 0x01.
    assert_eq!(script.len(), 51);
    ScriptBuf::from_bytes(script)
}

fn selector_leaf_for_mode(
    key_index: u32,
    selector_root: [u8; 32],
    first_record_index: u32,
    record_count: usize,
    selector_mode: u8,
) -> ScriptBuf {
    assert!(record_count <= u16::MAX as usize);
    assert!(matches!(
        selector_mode,
        SELECTOR_MODE_PAIR_COMPLEMENT | SELECTOR_MODE_PAIR_COMPLEMENT_BLOBS
    ));
    let mut script = Vec::with_capacity(94);

    push_flagged_shrincs_key(&mut script, key_index);
    script.push(0xad); // 0xC2 OP_CHECKSIGVERIFY.

    script.push(32);
    script.extend_from_slice(&selector_root);

    // The chain-step tweak binds a record's global index.  The native batch
    // verifier must therefore receive the committed first index explicitly.
    script.push(4);
    script.extend_from_slice(&first_record_index.to_le_bytes());

    // A fixed-width two-byte count keeps every batch leaf the same size.
    script.push(2);
    script.extend_from_slice(&(record_count as u16).to_le_bytes());
    script.push(0x50 + selector_mode); // OP_1/OP_2: selector serialization mode.

    // Proposed semantics: consume `record_count` records plus
    // root/first-index/count/mode. After consuming the four metadata items,
    // the top payload item is the *last* record/blob because the witness pushes
    // payloads in increasing index order. The opcode must therefore reconstruct
    // the ordered batch from the deepest item to the topmost item; merely
    // assigning increasing indexes in pop order would reverse the batch.
    // Mode 1 requires one exactly-520-byte stack item per record. Mode 2
    // requires canonical blobs containing eleven records per non-tail item.
    // Both modes recompute the ordered endpoint root from the pair-chain
    // openings. Missing, duplicate, reordered, padded, or non-canonically
    // split records fail. 0xbb is merely the one-byte serialization assigned
    // to that hypothetical native operation in this fixture.
    script.push(OP_CHECKBATCHPAIRSELECT);

    assert_eq!(script.len(), 94);
    ScriptBuf::from_bytes(script)
}

fn selector_leaf(
    key_index: u32,
    selector_root: [u8; 32],
    first_record_index: u32,
    record_count: usize,
) -> ScriptBuf {
    selector_leaf_for_mode(
        key_index,
        selector_root,
        first_record_index,
        record_count,
        SELECTOR_MODE_PAIR_COMPLEMENT,
    )
}

fn selector_blob_leaf(
    key_index: u32,
    selector_root: [u8; 32],
    first_record_index: u32,
    record_count: usize,
) -> ScriptBuf {
    selector_leaf_for_mode(
        key_index,
        selector_root,
        first_record_index,
        record_count,
        SELECTOR_MODE_PAIR_COMPLEMENT_BLOBS,
    )
}

fn sibling_leaf(key_index: u32) -> ScriptBuf {
    // The unselected branch is also a hash-based authorization branch, rather
    // than an ECC recovery path or an unspendable depth-zero shortcut.
    authorization_leaf(key_index ^ 0x8000_0000)
}

fn encode_digit(digit: u8) -> [u8; 2] {
    assert!(digit <= CHAIN_MAX);
    [digit, CHAIN_MAX - digit]
}

fn can_forward_derive(source: [u8; 2], target: [u8; 2]) -> bool {
    // Coordinates count the hash steps remaining to the public endpoint.
    // Forward hashing can only decrease that count.
    source.into_iter().zip(target).all(|(from, to)| to <= from)
}

fn chain_seed(record_index: u32, coordinate_index: u8) -> [u8; N] {
    // Deterministic public fixture material, not a secret-key generator. It
    // makes chain/index behavior reproducible but provides no unforgeability;
    // the cost test's cryptographic claims are limited to structure and size.
    let mut message = [0u8; 5];
    message[..4].copy_from_slice(&record_index.to_le_bytes());
    message[4] = coordinate_index;
    tagged_hash(b"PQSelector/ChainSeed", &message)[..N]
        .try_into()
        .expect("16-byte chain seed")
}

fn chain_step(
    record_index: u32,
    coordinate_index: u8,
    from_remaining: u8,
    node: [u8; N],
) -> [u8; N] {
    assert!((1..=CHAIN_MAX).contains(&from_remaining));
    // WOTS-style address separation: a node from another record, coordinate,
    // or chain position cannot be transplanted into this hash-chain step.
    let mut message = [0u8; N + 7];
    message[0] = 1; // chain-step domain byte
    message[1..5].copy_from_slice(&record_index.to_le_bytes());
    message[5] = coordinate_index;
    message[6] = from_remaining;
    message[7..].copy_from_slice(&node);
    sha256::Hash::hash(&message).to_byte_array()[..N]
        .try_into()
        .expect("16-byte truncated hash")
}

fn chain_node(record_index: u32, coordinate_index: u8, remaining_steps: u8) -> [u8; N] {
    assert!(remaining_steps <= CHAIN_MAX);
    let mut node = chain_seed(record_index, coordinate_index);
    // `chain_seed` is X_15. Hashing X_i once gives X_{i-1}; X_0 is the
    // public endpoint. This is the remaining-steps convention used in the
    // accompanying security argument.
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
            for position in encode_digit(digit) {
                record.extend_from_slice(&chain_node(record_index, coordinate_index, position));
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
            tagged_hash(b"PQSelector/EndpointLeaf", &leaf)
        })
        .collect();

    while layer.len() > 1 {
        let mut parent = Vec::with_capacity(layer.len().div_ceil(2));
        for pair in layer.chunks(2) {
            let right = pair.get(1).copied().unwrap_or(pair[0]);
            let mut children = [0u8; 64];
            children[..32].copy_from_slice(&pair[0]);
            children[32..].copy_from_slice(&right);
            parent.push(tagged_hash(b"PQSelector/Node", &children));
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

                let endpoint = forward_to_remaining(
                    record_index,
                    coordinate_index,
                    remaining_steps,
                    0,
                    opener,
                );
                endpoints.extend_from_slice(&endpoint);
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

fn verify_selector_batch(
    first_record_index: u32,
    expected_count: usize,
    records: &[Vec<u8>],
    expected_root: [u8; 32],
) -> bool {
    if records.len() != expected_count || records.is_empty() {
        return false;
    }

    let mut endpoint_records = Vec::with_capacity(records.len());
    for (offset, record) in records.iter().enumerate() {
        let Some(endpoints) = verify_selector_record(first_record_index + offset as u32, record)
        else {
            return false;
        };
        endpoint_records.push(endpoints);
    }
    selector_endpoint_root(first_record_index, &endpoint_records) == expected_root
}

fn pack_selector_blobs(records: &[Vec<u8>]) -> Vec<Vec<u8>> {
    assert!(!records.is_empty());
    assert!(FULL_BLOB_BYTES <= MAX_C2_STACK_ELEMENT_BYTES);
    assert!((RECORDS_PER_BLOB + 1) * SELECTOR_RECORD_BYTES > MAX_C2_STACK_ELEMENT_BYTES);

    records
        .chunks(RECORDS_PER_BLOB)
        .map(|record_chunk| {
            let mut blob = Vec::with_capacity(record_chunk.len() * SELECTOR_RECORD_BYTES);
            for record in record_chunk {
                assert_eq!(record.len(), SELECTOR_RECORD_BYTES);
                blob.extend_from_slice(record);
            }
            assert!(blob.len() <= MAX_C2_STACK_ELEMENT_BYTES);
            blob
        })
        .collect()
}

/// Parse the unique mode-2 encoding: every non-tail blob contains exactly
/// eleven records and the tail contains exactly the committed remainder.
/// Consequently there is no accepted padding or alternative blob split for a
/// fixed record stream.
fn unpack_canonical_selector_blobs(
    expected_record_count: usize,
    blobs: &[Vec<u8>],
) -> Option<Vec<Vec<u8>>> {
    if expected_record_count == 0 {
        return None;
    }
    let expected_blob_count = expected_record_count.div_ceil(RECORDS_PER_BLOB);
    if blobs.len() != expected_blob_count {
        return None;
    }

    let tail_record_count = expected_record_count - (expected_blob_count - 1) * RECORDS_PER_BLOB;
    let mut records = Vec::with_capacity(expected_record_count);
    for (blob_index, blob) in blobs.iter().enumerate() {
        let records_in_blob = if blob_index + 1 == expected_blob_count {
            tail_record_count
        } else {
            RECORDS_PER_BLOB
        };
        let expected_blob_bytes = records_in_blob * SELECTOR_RECORD_BYTES;
        if blob.len() != expected_blob_bytes || blob.len() > MAX_C2_STACK_ELEMENT_BYTES {
            return None;
        }
        for record in blob.chunks_exact(SELECTOR_RECORD_BYTES) {
            records.push(record.to_vec());
        }
    }
    if records.len() != expected_record_count {
        return None;
    }
    Some(records)
}

fn verify_selector_blob_batch(
    first_record_index: u32,
    expected_record_count: usize,
    blobs: &[Vec<u8>],
    expected_root: [u8; 32],
) -> bool {
    let Some(records) = unpack_canonical_selector_blobs(expected_record_count, blobs) else {
        return false;
    };
    verify_selector_batch(
        first_record_index,
        expected_record_count,
        &records,
        expected_root,
    )
}

struct Batch {
    first_record_index: u32,
    records: Vec<Vec<u8>>,
    selector_root: [u8; 32],
    spend: P2mrSpend,
}

fn make_batches(input: &[u8]) -> Vec<Batch> {
    assert_eq!(input.len(), INPUT_BYTES);
    assert_eq!(input.len() % CLEAR_BYTES_PER_RECORD, 0);
    let clear_records: Vec<&[u8]> = input.chunks_exact(CLEAR_BYTES_PER_RECORD).collect();
    assert_eq!(clear_records.len(), RECORDS);

    let mut batches = Vec::with_capacity(REVEAL_TRANSACTIONS);
    let mut next_record = 0usize;
    while next_record < clear_records.len() {
        let first_record_index = next_record as u32;
        let record_count = (clear_records.len() - next_record).min(RECORDS_PER_FULL_REVEAL);
        let records: Vec<Vec<u8>> = (0..record_count)
            .map(|offset| {
                let index = next_record + offset;
                selector_record(index as u32, clear_records[index])
            })
            .collect();
        let endpoint_records: Vec<Vec<u8>> = (0..record_count)
            .map(|offset| selector_endpoint_record(first_record_index + offset as u32))
            .collect();
        let root = selector_endpoint_root(first_record_index, &endpoint_records);
        let key_index = batches.len() as u32 + 1;
        let leaf_script = selector_leaf(key_index, root, first_record_index, record_count);
        let spend = depth_one_p2mr_spend(leaf_script, &sibling_leaf(key_index));
        batches.push(Batch {
            first_record_index,
            records,
            selector_root: root,
            spend,
        });
        next_record += record_count;
    }

    assert_eq!(batches.len(), REVEAL_TRANSACTIONS);
    assert_eq!(
        batches[..21]
            .iter()
            .map(|b| b.records.len())
            .collect::<Vec<_>>(),
        [RECORDS_PER_FULL_REVEAL; 21]
    );
    assert_eq!(batches[21].records.len(), 264);
    batches
}

fn make_blob_batches(input: &[u8]) -> Vec<Batch> {
    assert_eq!(input.len(), INPUT_BYTES);
    assert_eq!(input.len() % CLEAR_BYTES_PER_RECORD, 0);
    let clear_records: Vec<&[u8]> = input.chunks_exact(CLEAR_BYTES_PER_RECORD).collect();
    assert_eq!(clear_records.len(), RECORDS);

    let mut batches = Vec::with_capacity(REVEAL_TRANSACTIONS);
    let mut next_record = 0usize;
    while next_record < clear_records.len() {
        let first_record_index = next_record as u32;
        let record_count = (clear_records.len() - next_record).min(RECORDS_PER_FULL_BLOB_REVEAL);
        let records: Vec<Vec<u8>> = (0..record_count)
            .map(|offset| {
                let index = next_record + offset;
                selector_record(index as u32, clear_records[index])
            })
            .collect();
        let endpoint_records: Vec<Vec<u8>> = (0..record_count)
            .map(|offset| selector_endpoint_record(first_record_index + offset as u32))
            .collect();
        let root = selector_endpoint_root(first_record_index, &endpoint_records);
        let key_index = batches.len() as u32 + 1;
        let leaf_script = selector_blob_leaf(key_index, root, first_record_index, record_count);
        let spend = depth_one_p2mr_spend(leaf_script, &sibling_leaf(key_index));
        batches.push(Batch {
            first_record_index,
            records,
            selector_root: root,
            spend,
        });
        next_record += record_count;
    }

    assert_eq!(batches.len(), REVEAL_TRANSACTIONS);
    assert_eq!(
        batches[..21]
            .iter()
            .map(|batch| batch.records.len())
            .collect::<Vec<_>>(),
        [RECORDS_PER_FULL_BLOB_REVEAL; 21]
    );
    assert_eq!(batches[21].records.len(), 180);
    batches
}

fn attach_authorization_witness(input: &mut TxIn, spend: &P2mrSpend, key_index: u32) {
    input.witness.push(dummy_shrincs_signature(key_index));
    input.witness.push(spend.leaf_script.as_bytes());
    input.witness.push(&spend.control_block);
    assert_eq!(input.witness.len(), 3);
}

fn funding_assert_transaction(batches: &[Batch]) -> Transaction {
    assert_eq!(batches.len(), REVEAL_TRANSACTIONS);

    // The external predecessor is modeled as a depth-one P2MR output and this
    // input includes its full PQ witness.  The predecessor transaction itself
    // is outside the measured protocol boundary, as any accounting boundary
    // must start from some already-existing UTXO.
    let funding_key_index = 0u32;
    let predecessor_spend = depth_one_p2mr_spend(
        authorization_leaf(funding_key_index),
        &sibling_leaf(funding_key_index),
    );
    assert_p2mr_commitment(&predecessor_spend);

    // Use a structurally ordinary, non-null outpoint. The predecessor itself
    // remains outside the measured boundary, so this txid need not resolve in
    // the serialization fixture.
    let predecessor_txid = Txid::from_byte_array(tagged_hash(
        b"PQSelector/FixturePredecessorTxid",
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
            .map(|batch| TxOut {
                value: Amount::from_sat(FUNDING_OUTPUT_SATS),
                script_pubkey: batch.spend.script_pubkey.clone(),
            })
            .collect(),
    }
}

fn reveal_transaction(
    funding_txid: Txid,
    funding_vout: u32,
    batch_index: usize,
    batch: &Batch,
) -> Transaction {
    let mut input = TxIn {
        previous_output: OutPoint::new(funding_txid, funding_vout),
        script_sig: ScriptBuf::new(),
        sequence: Sequence::MAX,
        witness: Witness::new(),
    };

    // Records sit below the transaction authorization signature.  The script's
    // CHECKSIGVERIFY consumes that top argument; the proposed native selector
    // then consumes and validates the records against its committed root.
    for record in &batch.records {
        input.witness.push(record);
    }
    input
        .witness
        .push(dummy_shrincs_signature(batch_index as u32 + 1));
    input.witness.push(batch.spend.leaf_script.as_bytes());
    input.witness.push(&batch.spend.control_block);
    assert_eq!(input.witness.len(), batch.records.len() + 3);

    // Keep the reveal output on a P2MR/PQ path as well.  Its eventual spend is
    // not part of input publication and is therefore not included here.
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

fn reveal_blob_transaction(
    funding_txid: Txid,
    funding_vout: u32,
    batch_index: usize,
    batch: &Batch,
) -> Transaction {
    let blobs = pack_selector_blobs(&batch.records);
    assert!(verify_selector_blob_batch(
        batch.first_record_index,
        batch.records.len(),
        &blobs,
        batch.selector_root,
    ));

    let mut input = TxIn {
        previous_output: OutPoint::new(funding_txid, funding_vout),
        script_sig: ScriptBuf::new(),
        sequence: Sequence::MAX,
        witness: Witness::new(),
    };

    // Blobs preserve increasing global record order. CHECKSIGVERIFY consumes
    // the signature first; the mode-2 selector then parses the deepest blob
    // first and enforces the unique full-blob/tail split.
    for blob in &blobs {
        input.witness.push(blob);
    }
    input
        .witness
        .push(dummy_shrincs_signature(batch_index as u32 + 1));
    input.witness.push(batch.spend.leaf_script.as_bytes());
    input.witness.push(&batch.spend.control_block);
    assert_eq!(input.witness.len(), blobs.len() + 3);

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

#[test]
fn pair_complement_code_is_an_exhaustive_forward_antichain() {
    let seed_left = chain_seed(0, 0);
    let seed_right = chain_seed(0, 1);

    // Exercise every actually reachable segment of both concrete chains.
    for coordinate_index in 0..2 {
        for source_remaining in 0..=CHAIN_MAX {
            for target_remaining in 0..=source_remaining {
                let derived = forward_to_remaining(
                    0,
                    coordinate_index,
                    source_remaining,
                    target_remaining,
                    chain_node(0, coordinate_index, source_remaining),
                );
                assert_eq!(
                    derived,
                    chain_node(0, coordinate_index, target_remaining),
                    "X_{source_remaining} must hash forward to X_{target_remaining}"
                );
            }
        }
    }

    for source_digit in 0..=CHAIN_MAX {
        let source = encode_digit(source_digit);
        for target_digit in 0..=CHAIN_MAX {
            let target = encode_digit(target_digit);
            let derivable = can_forward_derive(source, target);
            assert_eq!(
                derivable,
                source_digit == target_digit,
                "E({source_digit}) must not derive E({target_digit})"
            );

            // A valid target is reachable only when both concrete chain nodes
            // can be advanced to its two remaining-step coordinates.
            if derivable {
                let left =
                    forward_to_remaining(0, 0, source[0], target[0], chain_node(0, 0, source[0]));
                let right =
                    forward_to_remaining(0, 1, source[1], target[1], chain_node(0, 1, source[1]));
                assert_eq!(left, chain_node(0, 0, target[0]));
                assert_eq!(right, chain_node(0, 1, target[1]));
            }
        }
    }

    assert_ne!(seed_left, seed_right, "coordinates use independent seeds");
    assert!(
        (0..=CHAIN_MAX).all(|digit| encode_digit(digit).into_iter().sum::<u8>() == CHAIN_MAX),
        "all valid pairs lie on the constant-sum antichain"
    );
}

#[test]
fn two_openings_of_one_pair_key_span_the_whole_interval() {
    // Antichain non-equivocation is strictly one-time.  If the same pair key
    // opens a <= b, the attacker takes the first-chain node from b and the
    // second-chain node from a, deriving every v in [a,b].
    for a in 0..=CHAIN_MAX {
        for b in a..=CHAIN_MAX {
            for v in 0..=CHAIN_MAX {
                let algebraically_reachable = v <= b && CHAIN_MAX - v <= CHAIN_MAX - a;
                assert_eq!(algebraically_reachable, (a..=b).contains(&v));

                if algebraically_reachable {
                    let left = forward_to_remaining(0, 0, b, v, chain_node(0, 0, b));
                    let right = forward_to_remaining(
                        0,
                        1,
                        CHAIN_MAX - a,
                        CHAIN_MAX - v,
                        chain_node(0, 1, CHAIN_MAX - a),
                    );
                    assert_eq!(left, chain_node(0, 0, v));
                    assert_eq!(right, chain_node(0, 1, CHAIN_MAX - v));
                }
            }
        }
    }
}

#[test]
fn endpoint_root_rejects_tampering_reordering_and_cross_context_splices() {
    let first_record_index = 41u32;
    let records = vec![
        selector_record(first_record_index, &[0x05; CLEAR_BYTES_PER_RECORD]),
        selector_record(first_record_index + 1, &[0xa7; CLEAR_BYTES_PER_RECORD]),
    ];
    let endpoint_records = vec![
        selector_endpoint_record(first_record_index),
        selector_endpoint_record(first_record_index + 1),
    ];
    let root = selector_endpoint_root(first_record_index, &endpoint_records);
    assert!(verify_selector_batch(
        first_record_index,
        records.len(),
        &records,
        root,
    ));

    let mut bad_opener = records.clone();
    bad_opener[0][0] ^= 1;
    assert!(!verify_selector_batch(
        first_record_index,
        records.len(),
        &bad_opener,
        root,
    ));

    let mut bad_clear_digit = records.clone();
    bad_clear_digit[0][SELECTOR_OPENING_BYTES] ^= 0x10;
    assert!(!verify_selector_batch(
        first_record_index,
        records.len(),
        &bad_clear_digit,
        root,
    ));

    let mut cross_coordinate = records.clone();
    let (first, rest) = cross_coordinate[0].split_at_mut(N);
    first.swap_with_slice(&mut rest[..N]);
    assert!(!verify_selector_batch(
        first_record_index,
        records.len(),
        &cross_coordinate,
        root,
    ));

    let mut reordered = records.clone();
    reordered.swap(0, 1);
    assert!(!verify_selector_batch(
        first_record_index,
        records.len(),
        &reordered,
        root,
    ));

    let duplicated = vec![records[0].clone(), records[0].clone()];
    assert!(!verify_selector_batch(
        first_record_index,
        records.len(),
        &duplicated,
        root,
    ));
    assert!(!verify_selector_batch(
        first_record_index,
        records.len(),
        &records[..1],
        root,
    ));
    assert!(!verify_selector_batch(
        first_record_index + 1,
        records.len(),
        &records,
        root,
    ));
}

#[test]
fn canonical_blob_parser_rejects_malleated_record_streams() {
    let first_record_index = 91u32;
    let records: Vec<Vec<u8>> = (0..23)
        .map(|offset| {
            selector_record(
                first_record_index + offset,
                &[(offset as u8).wrapping_mul(17); CLEAR_BYTES_PER_RECORD],
            )
        })
        .collect();
    let endpoint_records: Vec<Vec<u8>> = (0..records.len())
        .map(|offset| selector_endpoint_record(first_record_index + offset as u32))
        .collect();
    let root = selector_endpoint_root(first_record_index, &endpoint_records);
    let blobs = pack_selector_blobs(&records);

    assert_eq!(FULL_BLOB_BYTES, 5_720);
    assert_eq!(
        blobs.iter().map(Vec::len).collect::<Vec<_>>(),
        [5_720, 5_720, 520]
    );
    assert_eq!(
        unpack_canonical_selector_blobs(records.len(), &blobs),
        Some(records.clone())
    );
    assert!(verify_selector_blob_batch(
        first_record_index,
        records.len(),
        &blobs,
        root,
    ));

    let mut missing_blob = blobs.clone();
    missing_blob.pop();
    assert!(!verify_selector_blob_batch(
        first_record_index,
        records.len(),
        &missing_blob,
        root,
    ));

    let mut extra_blob = blobs.clone();
    extra_blob.push(Vec::new());
    assert!(!verify_selector_blob_batch(
        first_record_index,
        records.len(),
        &extra_blob,
        root,
    ));

    let mut duplicate_blob = blobs.clone();
    duplicate_blob[1] = duplicate_blob[0].clone();
    assert!(!verify_selector_blob_batch(
        first_record_index,
        records.len(),
        &duplicate_blob,
        root,
    ));

    let mut reordered_blobs = blobs.clone();
    reordered_blobs.swap(0, 1);
    assert!(!verify_selector_blob_batch(
        first_record_index,
        records.len(),
        &reordered_blobs,
        root,
    ));

    let mut duplicate_record = blobs.clone();
    let first_record = duplicate_record[0][..SELECTOR_RECORD_BYTES].to_vec();
    duplicate_record[0][SELECTOR_RECORD_BYTES..2 * SELECTOR_RECORD_BYTES]
        .copy_from_slice(&first_record);
    assert!(!verify_selector_blob_batch(
        first_record_index,
        records.len(),
        &duplicate_record,
        root,
    ));

    let mut reordered_records = blobs.clone();
    let first_record = reordered_records[0][..SELECTOR_RECORD_BYTES].to_vec();
    let second_record =
        reordered_records[0][SELECTOR_RECORD_BYTES..2 * SELECTOR_RECORD_BYTES].to_vec();
    reordered_records[0][..SELECTOR_RECORD_BYTES].copy_from_slice(&second_record);
    reordered_records[0][SELECTOR_RECORD_BYTES..2 * SELECTOR_RECORD_BYTES]
        .copy_from_slice(&first_record);
    assert!(!verify_selector_blob_batch(
        first_record_index,
        records.len(),
        &reordered_records,
        root,
    ));

    let mut trailing_byte = blobs.clone();
    trailing_byte.last_mut().unwrap().push(0);
    assert!(!verify_selector_blob_batch(
        first_record_index,
        records.len(),
        &trailing_byte,
        root,
    ));

    let mut noncanonical_split = blobs.clone();
    let moved_byte = noncanonical_split[0].pop().unwrap();
    noncanonical_split[1].insert(0, moved_byte);
    assert!(!verify_selector_blob_batch(
        first_record_index,
        records.len(),
        &noncanonical_split,
        root,
    ));

    assert!(unpack_canonical_selector_blobs(0, &[]).is_none());
    assert!(unpack_canonical_selector_blobs(records.len() - 1, &blobs).is_none());
    assert!(!verify_selector_blob_batch(
        first_record_index + 1,
        records.len(),
        &blobs,
        root,
    ));
}

#[test]
fn pq_selector_exact_funding_and_reveal_cost() {
    assert_eq!(INPUT_BYTES, 130_128);
    assert_eq!(RECORDS, 16_266);
    assert_eq!(SELECTOR_OPENING_BYTES, 512);
    assert_eq!(SELECTOR_RECORD_BYTES, 520);
    assert_eq!(compact_size(SELECTOR_RECORD_BYTES).len(), 3);
    assert_eq!(3 + SELECTOR_RECORD_BYTES, 523, "framed selector record");
    assert_eq!(compact_size(SHRINCS_SIGNATURE_BYTES).len(), 3);
    assert_eq!(3 + SHRINCS_SIGNATURE_BYTES, 551, "framed SHRINCS item");

    let input: Vec<u8> = (0..INPUT_BYTES).map(|index| (index % 251) as u8).collect();
    let batches = make_batches(&input);
    assert_eq!(
        batches
            .iter()
            .map(|batch| batch.records.len())
            .sum::<usize>(),
        RECORDS
    );
    assert!(batches.iter().all(|batch| {
        batch
            .records
            .iter()
            .all(|record| record.len() == SELECTOR_RECORD_BYTES)
            && verify_selector_batch(
                batch.first_record_index,
                batch.records.len(),
                &batch.records,
                batch.selector_root,
            )
            && batch.spend.leaf_script.len() == 94
            && batch.spend.control_block.len() == P2MR_CONTROL_BYTES
            && batch.spend.script_pubkey.len() == 34
    }));

    let funding = funding_assert_transaction(&batches);
    assert_eq!(funding.input.len(), 1);
    assert_eq!(funding.output.len(), REVEAL_TRANSACTIONS);
    assert_eq!(funding.base_size(), 997);
    assert_eq!(serialize(&funding).len(), 1_637);
    assert_eq!(funding.weight().to_wu(), 4_628);
    assert_eq!(funding.vsize(), 1_157);

    let funding_txid = funding.compute_txid();
    let reveals: Vec<Transaction> = batches
        .iter()
        .enumerate()
        .map(|(index, batch)| reveal_transaction(funding_txid, index as u32, index, batch))
        .collect();
    let reveal_weights: Vec<u64> = reveals.iter().map(|tx| tx.weight().to_wu()).collect();
    let reveal_vsizes: Vec<usize> = reveals.iter().map(Transaction::vsize).collect();

    assert!(reveal_weights
        .iter()
        .all(|&weight| weight <= MAX_STANDARD_TX_WEIGHT));
    assert_eq!(reveal_weights[..21], [399_587; 21]);
    assert_eq!(reveal_weights[21], 139_133);
    assert_eq!(
        reveals[..21]
            .iter()
            .map(|tx| serialize(tx).len())
            .collect::<Vec<_>>(),
        [399_305; 21]
    );
    assert_eq!(serialize(&reveals[21]).len(), 138_851);

    // Exact packing boundary for this one-input/one-output, 94-byte-leaf
    // shape.  Every additional 520-byte record costs 523 WU after CompactSize
    // framing, so 762 fits and 763 does not.
    assert_eq!(1_061u64 + 523 * RECORDS_PER_FULL_REVEAL as u64, 399_587);
    assert!(1_061u64 + 523 * (RECORDS_PER_FULL_REVEAL as u64 + 1) > MAX_STANDARD_TX_WEIGHT);
    assert!(21 * RECORDS_PER_FULL_REVEAL < RECORDS);

    let reveal_weight: u64 = reveal_weights.iter().sum();
    let reveal_vsize: usize = reveal_vsizes.iter().sum();
    let total_weight = funding.weight().to_wu() + reveal_weight;
    let billed_vsize = funding.vsize() + reveal_vsize;
    let total_serialized_bytes =
        serialize(&funding).len() + reveals.iter().map(|tx| serialize(tx).len()).sum::<usize>();

    assert_eq!(reveal_weight, 8_530_460);
    assert_eq!(reveal_vsize, 2_132_621);
    assert_eq!(total_serialized_bytes, 8_525_893);
    assert_eq!(total_weight, 8_535_088);
    assert_eq!(total_weight / 4, 2_133_772);
    assert_eq!(total_weight % 4, 0);
    assert_eq!(billed_vsize, 2_133_778);
    assert_eq!(1 + reveals.len(), 23, "one funding/assert plus 22 reveals");

    eprintln!(
        "n=16 selector (SERIALIZATION ONLY; NOT PQ-SECURE): {INPUT_BITS} bits, {RECORDS} x \
         {SELECTOR_RECORD_BYTES}-B records, {} funding/assert + {} reveals, \
         {total_weight} WU = {}.{} weight-vB, {billed_vsize} billed vB; max \
         reveal {} WU; one tx-level SHRINCS item assumes one key or aggregate",
        1,
        reveals.len(),
        total_weight / 4,
        match total_weight % 4 {
            0 => 0,
            1 => 25,
            2 => 5,
            3 => 75,
            _ => unreachable!(),
        },
        reveal_weights.iter().max().expect("at least one reveal"),
    );
}

#[test]
fn pq_selector_canonical_blob_exact_cost() {
    assert_eq!(FULL_BLOB_BYTES, 5_720);
    assert!(FULL_BLOB_BYTES <= MAX_C2_STACK_ELEMENT_BYTES);
    assert_eq!(compact_size(FULL_BLOB_BYTES).len(), 3);

    let input: Vec<u8> = (0..INPUT_BYTES).map(|index| (index % 251) as u8).collect();
    let batches = make_blob_batches(&input);
    assert_eq!(
        batches
            .iter()
            .map(|batch| batch.records.len())
            .sum::<usize>(),
        RECORDS
    );

    for (batch_index, batch) in batches.iter().enumerate() {
        let blobs = pack_selector_blobs(&batch.records);
        assert!(verify_selector_blob_batch(
            batch.first_record_index,
            batch.records.len(),
            &blobs,
            batch.selector_root,
        ));
        assert_eq!(batch.spend.leaf_script.len(), 94);
        assert_eq!(batch.spend.control_block.len(), P2MR_CONTROL_BYTES);
        assert_eq!(batch.spend.script_pubkey.len(), 34);

        let expected_blob_count = if batch_index < 21 { 70 } else { 17 };
        let expected_tail_bytes = if batch_index < 21 {
            7 * SELECTOR_RECORD_BYTES
        } else {
            4 * SELECTOR_RECORD_BYTES
        };
        assert_eq!(blobs.len(), expected_blob_count);
        assert!(blobs[..blobs.len() - 1]
            .iter()
            .all(|blob| blob.len() == FULL_BLOB_BYTES));
        assert_eq!(blobs.last().unwrap().len(), expected_tail_bytes);
    }

    let funding = funding_assert_transaction(&batches);
    assert_eq!(funding.input.len(), 1);
    assert_eq!(funding.output.len(), REVEAL_TRANSACTIONS);
    assert_eq!(funding.base_size(), 997);
    assert_eq!(serialize(&funding).len(), 1_637);
    assert_eq!(funding.weight().to_wu(), 4_628);
    assert_eq!(funding.vsize(), 1_157);

    let funding_txid = funding.compute_txid();
    let reveals: Vec<Transaction> = batches
        .iter()
        .enumerate()
        .map(|(index, batch)| reveal_blob_transaction(funding_txid, index as u32, index, batch))
        .collect();
    let reveal_weights: Vec<u64> = reveals.iter().map(|tx| tx.weight().to_wu()).collect();
    let reveal_vsizes: Vec<usize> = reveals.iter().map(Transaction::vsize).collect();

    assert!(reveal_weights
        .iter()
        .all(|&weight| weight <= MAX_STANDARD_TX_WEIGHT));
    assert_eq!(reveal_weights[..21], [399_589; 21]);
    assert_eq!(reveal_weights[21], 94_710);
    assert_eq!(reveal_vsizes[..21], [99_898; 21]);
    assert_eq!(reveal_vsizes[21], 23_678);
    assert_eq!(
        reveals[..21]
            .iter()
            .map(|tx| serialize(tx).len())
            .collect::<Vec<_>>(),
        [399_307; 21]
    );
    assert_eq!(serialize(&reveals[21]).len(), 94_428);

    // With seventy blob items the witness item-count prefix is one byte. The
    // remaining fixed transaction/witness fields cost 1059 WU; blob payloads
    // cost 520 WU per record plus one three-byte CompactSize per blob.
    assert_eq!(
        1_059u64 + 520 * RECORDS_PER_FULL_BLOB_REVEAL as u64 + 3 * 70,
        399_589
    );
    assert!(
        1_059u64 + 520 * (RECORDS_PER_FULL_BLOB_REVEAL as u64 + 1) + 3 * 70
            > MAX_STANDARD_TX_WEIGHT
    );

    let reveal_weight: u64 = reveal_weights.iter().sum();
    let reveal_vsize: usize = reveal_vsizes.iter().sum();
    let total_weight = funding.weight().to_wu() + reveal_weight;
    let billed_vsize = funding.vsize() + reveal_vsize;
    let total_serialized_bytes =
        serialize(&funding).len() + reveals.iter().map(|tx| serialize(tx).len()).sum::<usize>();

    assert_eq!(reveal_weight, 8_486_079);
    assert_eq!(reveal_vsize, 2_121_536);
    assert_eq!(total_serialized_bytes, 8_481_512);
    assert_eq!(total_weight, 8_490_707);
    assert_eq!(total_weight / 4, 2_122_676);
    assert_eq!(total_weight % 4, 3);
    assert_eq!(billed_vsize, 2_122_693);
    assert_eq!(1 + reveals.len(), 23, "one funding/assert plus 22 reveals");

    eprintln!(
        "n=16 selector canonical blobs (SERIALIZATION ONLY; NOT PQ-SECURE): {INPUT_BITS} bits, \
         {RECORDS} x {SELECTOR_RECORD_BYTES}-B records, {RECORDS_PER_BLOB} \
         records/full blob, {} funding/assert + {} reveals, {total_weight} WU, \
         {billed_vsize} billed vB; max reveal {} WU",
        1,
        reveals.len(),
        reveal_weights.iter().max().expect("at least one reveal"),
    );
}
