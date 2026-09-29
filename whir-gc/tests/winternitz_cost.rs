//! What a Winternitz reveal of the verifier's input costs on-chain, and how
//! many input bits one transaction can hold.
//!
//! The script is the compact form: per chain, the signature is hashed forward
//! `W - 1` times with every intermediate value kept, the digit picks the one
//! that must equal the public key, and the digits are summed against the
//! checksum chains. Each run is executed by `bitcoin-scriptexec` with the
//! stack limit on, on an honest signature and on one with a digit raised.

use bitcoin::hashes::{hash160, Hash};
use bitcoin_script::{define_pushable, script};
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;

define_pushable!();

/// Checksum digits for `n` message digits of `d` bits.
fn checksum_digits(n: usize, d: usize) -> usize {
    let max = n * ((1 << d) - 1);
    let mut c = 0;
    while (1usize << (d * c)) <= max {
        c += 1;
    }
    c
}

/// Verify `n` message chains and their checksum chains. Witness: per chain
/// `sig digit`, chain 0 on top.
fn verify(pks: &[[u8; 20]], n: usize, d: usize) -> bitcoin::ScriptBuf {
    let w = 1usize << d;
    let c = pks.len() - n;
    script! {
        for pk in pks {
            // sig digit
            OP_DUP OP_TOALTSTACK
            OP_SWAP
            for _ in 0..w - 1 { OP_DUP OP_HASH160 }
            // digit h_0 .. h_{W-1}; the digit picks h_{W-1-digit}
            { w as u32 } OP_ROLL OP_PICK
            { pk.to_vec() } OP_EQUALVERIFY
            for _ in 0..w / 2 { OP_2DROP }
        }
        // The checksum the signature carries, most significant digit first.
        0
        for _ in 0..c {
            for _ in 0..d { OP_DUP OP_ADD }
            OP_FROMALTSTACK OP_ADD
        }
        for _ in 0..n { OP_FROMALTSTACK OP_ADD }
        { (n * (w - 1)) as u32 } OP_EQUALVERIFY
        OP_TRUE
    }
}

fn chain(sk: &[u8; 20], steps: usize) -> [u8; 20] {
    (0..steps).fold(*sk, |acc, _| hash160::Hash::hash(&acc).to_byte_array())
}

/// The witness as script pushes, and its size as witness stack items.
fn witness(sks: &[[u8; 20]], digits: &[usize]) -> (bitcoin::ScriptBuf, usize) {
    let items: Vec<(Vec<u8>, u32)> = sks.iter().zip(digits).map(|(sk, &v)| (chain(sk, v).to_vec(), v as u32)).collect();
    // A stack item is a length byte and its bytes. The number 0 is empty,
    // and a number from 128 takes two bytes, since the top bit is the sign.
    let size = digits.iter().map(|&v| 21 + if v == 0 { 1 } else if v < 128 { 2 } else { 3 }).sum();
    (script! { for (s, v) in items.into_iter().rev() { { s } { v } } }, size)
}

/// Weight of one input besides its script and stack items: the outpoint,
/// sequence and empty scriptSig at 4 WU per byte, and the witness's item
/// count, script length and a control block for a tree of depth 1.
const INPUT_OVERHEAD_WU: usize = 41 * 4 + 3 + 3 + 1 + 65;
/// The transaction's own fields and one output.
const TX_OVERHEAD_WU: usize = 10 * 4 + 2 + 43 * 4;

#[test]
fn winternitz_reveal_cost_per_bit() {
    let mut rng = ChaCha20Rng::seed_from_u64(7);
    let input_bits = 1_041_024usize;
    eprintln!("digit | chains per input | script B/chain | witness B/chain | WU per bit | bits in 400k WU | bits in 4M WU | WU for {input_bits} bits");
    for d in 2usize..=8 {
        let w = 1usize << d;
        // As many message chains as the 1000-item limit allows: two witness
        // items per chain still to come, the ladder, and the altstack.
        let mut n = (1000 - w - 2) / 2;
        while 2 * (n + checksum_digits(n, d)) + w + 2 > 1000 {
            n -= 1;
        }
        let c = checksum_digits(n, d);
        let sks: Vec<[u8; 20]> = (0..n + c).map(|_| rng.random()).collect();
        let pks: Vec<[u8; 20]> = sks.iter().map(|sk| chain(sk, w - 1)).collect();
        let mut digits: Vec<usize> = (0..n).map(|_| rng.random_range(0..w)).collect();
        let sum: usize = digits.iter().map(|&v| w - 1 - v).sum();
        digits.extend((0..c).map(|j| (sum >> (d * j)) & (w - 1)));

        let lock = verify(&pks, n, d);
        let (wit, wit_size) = witness(&sks, &digits);
        let info = bitcoin_scriptexec::execute_script(script! { { wit } { lock.clone() } });
        assert!(info.success, "d = {d}: an honest signature verifies: {:?}", info.error);
        assert!(info.stats.max_nb_stack_items <= 1000, "d = {d}: within the stack limit");

        // A raised message digit with the checksum untouched does not verify.
        let at = digits.iter().position(|&v| v + 1 < w).expect("some digit below the maximum");
        let mut forged = digits.clone();
        forged[at] += 1;
        let (bad, _) = witness(&sks, &forged);
        assert!(!bitcoin_scriptexec::execute_script(script! { { bad } { lock.clone() } }).success, "d = {d}: a raised digit");

        let bits = n * d;
        let input_wu = lock.len() + wit_size + INPUT_OVERHEAD_WU;
        let per_bit = input_wu as f64 / bits as f64;
        let fit = |budget: usize| (budget - TX_OVERHEAD_WU) / input_wu * bits;
        eprintln!(
            "d = {d} | {} (+{c} checksum) | {:.1} | {:.1} | {per_bit:.2} | {} | {} | {:.1}M",
            n,
            lock.len() as f64 / (n + c) as f64,
            wit_size as f64 / (n + c) as f64,
            fit(400_000),
            fit(4_000_000),
            input_bits as f64 * per_bit / 1e6,
        );
    }
}

/// One chain of `d`-bit digits: `sig digit` on top, the digit left on the
/// altstack.
fn verify_chain(pk: &[u8; 20], d: usize) -> bitcoin::ScriptBuf {
    let w = 1usize << d;
    script! {
        OP_DUP OP_TOALTSTACK
        OP_SWAP
        for _ in 0..w - 1 { OP_DUP OP_HASH160 }
        { w as u32 } OP_ROLL OP_PICK
        { pk.to_vec() } OP_EQUALVERIFY
        for _ in 0..w / 2 { OP_2DROP }
    }
}

const CHUNK_DIGITS: usize = 32;

/// The layout of ePrint 2026/1684: chunks of 32 message digits of 4 bits,
/// each with its own checksum `sum(15 - digit) = 32 u + v`, split into a
/// 4-bit major digit `u` and a 5-bit minor digit `v`. 34 chains per chunk.
fn verify_chunks(pks: &[[u8; 20]]) -> bitcoin::ScriptBuf {
    script! {
        for chunk in pks.chunks(CHUNK_DIGITS + 2) {
            for pk in &chunk[..CHUNK_DIGITS] { { verify_chain(pk, 4) } }
            { verify_chain(&chunk[CHUNK_DIGITS], 4) }
            { verify_chain(&chunk[CHUNK_DIGITS + 1], 5) }
            // v, then u: 32 u + v, plus the digits, is 32 * 15.
            OP_FROMALTSTACK OP_FROMALTSTACK
            for _ in 0..5 { OP_DUP OP_ADD }
            OP_ADD
            for _ in 0..CHUNK_DIGITS { OP_FROMALTSTACK OP_ADD }
            { (CHUNK_DIGITS * 15) as u32 } OP_EQUALVERIFY
        }
        OP_TRUE
    }
}

#[test]
fn chunked_winternitz_reveal_cost_per_bit() {
    let mut rng = ChaCha20Rng::seed_from_u64(8);
    let input_bits = 1_041_024usize;
    // Chunks per input under the 1000-item limit: 68 witness items per chunk
    // and the widest ladder on top.
    let chunks = (1000 - 34) / (2 * (CHUNK_DIGITS + 2));
    let mut sks: Vec<[u8; 20]> = Vec::new();
    let mut pks: Vec<[u8; 20]> = Vec::new();
    let mut digits: Vec<usize> = Vec::new();
    for _ in 0..chunks {
        let message: Vec<usize> = (0..CHUNK_DIGITS).map(|_| rng.random_range(0..16)).collect();
        let weight: usize = message.iter().map(|&v| 15 - v).sum();
        for (j, &v) in message.iter().chain(&[weight / 32, weight % 32]).enumerate() {
            let steps = if j == CHUNK_DIGITS + 1 { 31 } else { 15 };
            let sk: [u8; 20] = rng.random();
            pks.push(chain(&sk, steps));
            sks.push(sk);
            digits.push(v);
        }
    }
    let lock = verify_chunks(&pks);
    let (wit, wit_size) = witness(&sks, &digits);
    let info = bitcoin_scriptexec::execute_script(script! { { wit } { lock.clone() } });
    assert!(info.success, "an honest signature verifies: {:?}", info.error);
    assert!(info.stats.max_nb_stack_items <= 1000);

    let mut forged = digits.clone();
    let at = forged.iter().position(|&v| v < 15).expect("a digit below the maximum");
    forged[at] += 1;
    let (bad, _) = witness(&sks, &forged);
    assert!(!bitcoin_scriptexec::execute_script(script! { { bad } { lock.clone() } }).success, "a raised digit");

    let bits = chunks * CHUNK_DIGITS * 4;
    let input_wu = lock.len() + wit_size + INPUT_OVERHEAD_WU;
    let per_bit = input_wu as f64 / bits as f64;
    let fit = |budget: usize| (budget - TX_OVERHEAD_WU) / input_wu * bits;
    eprintln!(
        "chunked (32 + 2 chains per 128 bits): {chunks} chunks per input, peak stack {}, script {} B, witness {} B, \
         {per_bit:.2} WU per bit; {} bits in 400k WU, {} bits in 4M WU; {:.1}M WU for {input_bits} bits in {} chunks",
        info.stats.max_nb_stack_items,
        lock.len(),
        wit_size,
        fit(400_000),
        fit(4_000_000),
        input_bits as f64 * per_bit / 1e6,
        input_bits.div_ceil(CHUNK_DIGITS * 4),
    );
}
