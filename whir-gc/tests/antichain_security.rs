//! Exhaustive security regressions for the pinned Antichain-Winternitz
//! `(k = 2, L = 16)` construction.
//!
//! These tests execute the real upstream verifier script.  They distinguish
//! the construction's intended one-opening non-equivocation property from a
//! protocol-level requirement that is just as important: one public key must
//! never be opened twice.  Two openings for values `a` and `b` reveal enough
//! chain material to open every value in the inclusive interval between them;
//! for a multi-digit message those intervals compose independently, producing
//! "Frankenstein" messages that were never opened by the signer.
//!
//! "Exhaustive" below means exhaustive over the 16 x 16 value grid and the
//! strongest witnesses obtainable by forward-hashing the disclosed nodes. It
//! does not enumerate arbitrary 160-bit preimages and is not, by itself, a
//! proof of cryptographic unforgeability. Rejection outside the forward
//! closure still relies on the hash function's preimage/collision assumptions.

use acw::{
    acw::{AntichainWinternitz, Parameters, PublicKey, Signature},
    weight::acw_stack,
    HashKind,
};
use bitcoin::{
    absolute::LockTime, hashes::Hash, taproot::TapLeafHash, transaction::Version, ScriptBuf,
    Transaction,
};
use bitvm_scriptexec::{Exec, ExecCtx, Options, TxTemplate};
use rand08::SeedableRng;
use rand_chacha08::ChaCha20Rng;

const L: u32 = 16;
const MAX_COORD: u32 = L - 1;

fn execute(verifier: &ScriptBuf, opening: &Signature) -> bool {
    let exec = Exec::new(
        ExecCtx::Tapscript,
        Options {
            enforce_stack_limit: true,
            ..Options::default()
        },
        TxTemplate {
            tx: Transaction {
                version: Version::TWO,
                lock_time: LockTime::ZERO,
                input: vec![],
                output: vec![],
            },
            prevouts: vec![],
            input_idx: 0,
            taproot_annex_scriptleaf: Some((TapLeafHash::all_zeros(), None)),
        },
        verifier.clone(),
        acw_stack(opening),
    );
    let mut exec = match exec {
        Ok(exec) => exec,
        Err(_) => return false,
    };
    while exec.exec_next().is_ok() {}
    exec.result().is_some_and(|result| result.success)
}

fn forward(hash: HashKind, value: &[u8], count: u32) -> Vec<u8> {
    let mut value = value.to_vec();
    for _ in 0..count {
        value = hash.digest(&value);
    }
    value
}

fn codeword(value: u32) -> Vec<u32> {
    assert!(value < L);
    vec![value, MAX_COORD - value]
}

/// Build the strongest target-`v` witness available after seeing openings for
/// `a` and `b`.  Chain 0 takes the larger source value; chain 1 takes the
/// smaller.  The resulting witness is genuine exactly when
/// `min(a,b) <= v <= max(a,b)`.  Outside that interval one chain would require
/// a preimage, so this function leaves that chain at its closest known node.
fn combine_digit(
    hash: HashKind,
    opening_a: &Signature,
    opening_b: &Signature,
    digit: usize,
    a: u32,
    b: u32,
    target: u32,
) -> (Vec<Vec<u8>>, Vec<u32>) {
    assert!(a < L && b < L && target < L);
    let (high, high_opening) = if a >= b {
        (a, opening_a)
    } else {
        (b, opening_b)
    };
    let (low, low_opening) = if a <= b {
        (a, opening_a)
    } else {
        (b, opening_b)
    };

    // Upstream's complement convention reveals chain 0 at position 15-a and
    // chain 1 at position a.  Forward hashing therefore moves the first chain
    // toward smaller claimed values and the second toward larger ones.
    let mut opener_0 = high_opening.0[digit].0[0].clone();
    if target <= high {
        opener_0 = forward(hash, &opener_0, high - target);
    }
    let mut opener_1 = low_opening.0[digit].0[1].clone();
    if target >= low {
        opener_1 = forward(hash, &opener_1, target - low);
    }

    (vec![opener_0, opener_1], codeword(target))
}

fn key_and_openings(values: &[u32], seed: u64) -> (Parameters, PublicKey, Vec<Signature>) {
    let parameters = Parameters::new(values.len() as u32, 2, L, HashKind::Hash160);
    let mut rng = ChaCha20Rng::seed_from_u64(seed);
    let (secret_key, public_key) = AntichainWinternitz::keygen(&mut rng, &parameters);
    let openings = values
        .iter()
        .map(|&value| {
            let words = vec![codeword(value); values.len()];
            AntichainWinternitz::sign(&secret_key, &parameters, &words)
        })
        .collect();
    (parameters, public_key, openings)
}

#[test]
fn every_single_opening_rejects_forward_attempts_for_all_other_values() {
    let values: Vec<u32> = (0..L).collect();
    let (parameters, public_key, openings) = key_and_openings(&values, 0xac00_0016);

    // `key_and_openings` made 16-digit signatures to share one key.  Exercise
    // digit 0 in a one-digit verifier so every (source,target) pair is checked
    // without conflating the result with the other digits.
    let one_parameters = Parameters::new(1, 2, L, HashKind::Hash160);
    let one_public_key = PublicKey(vec![public_key.0[0].clone()]);
    let verifier = AntichainWinternitz::verify_script(&one_public_key, &one_parameters).compile();

    let mut accepted_honest = 0usize;
    let mut rejected_forgeries = 0usize;
    for source in 0..L {
        let honest = Signature(vec![openings[source as usize].0[0].clone()]);
        assert!(execute(&verifier, &honest), "honest value {source}");
        accepted_honest += 1;

        for target in 0..L {
            if target == source {
                continue;
            }
            let forged_digit = combine_digit(
                HashKind::Hash160,
                &honest,
                &honest,
                0,
                source,
                source,
                target,
            );
            let forged = Signature(vec![forged_digit]);
            assert!(
                !execute(&verifier, &forged),
                "single opening {source} must not derive {target}"
            );
            rejected_forgeries += 1;
        }
    }

    assert_eq!(parameters.message_digit_len, L);
    assert_eq!(accepted_honest, 16);
    assert_eq!(rejected_forgeries, 16 * 15);
    eprintln!(
        "single-open exhaustive: {accepted_honest} honest accepted, \
         {rejected_forgeries} unequal source/target attempts rejected"
    );
}

#[test]
fn two_openings_forward_derive_exactly_the_closed_interval() {
    let parameters = Parameters::new(1, 2, L, HashKind::Hash160);
    let mut rng = ChaCha20Rng::seed_from_u64(0xac00_2bad);
    let (secret_key, public_key) = AntichainWinternitz::keygen(&mut rng, &parameters);
    let verifier = AntichainWinternitz::verify_script(&public_key, &parameters).compile();
    let openings: Vec<Signature> = (0..L)
        .map(|value| AntichainWinternitz::sign(&secret_key, &parameters, &[codeword(value)]))
        .collect();

    let mut accepted_inside = 0usize;
    let mut accepted_new_values = 0usize;
    let mut rejected_outside = 0usize;
    for a in 0..L {
        for b in 0..L {
            let low = a.min(b);
            let high = a.max(b);
            for target in 0..L {
                let forged = Signature(vec![combine_digit(
                    HashKind::Hash160,
                    &openings[a as usize],
                    &openings[b as usize],
                    0,
                    a,
                    b,
                    target,
                )]);
                let accepted = execute(&verifier, &forged);
                let expected = (low..=high).contains(&target);
                assert_eq!(
                    accepted, expected,
                    "two openings ({a},{b}) targeting {target}"
                );
                if accepted {
                    accepted_inside += 1;
                    if target != a && target != b {
                        accepted_new_values += 1;
                    }
                } else {
                    rejected_outside += 1;
                }
            }
        }
    }

    // Sum_{a,b} (|a-b|+1) for a,b in [0,15].
    assert_eq!(accepted_inside, 1_616);
    assert_eq!(accepted_new_values, 1_120);
    assert_eq!(rejected_outside, 4_096 - 1_616);
    eprintln!(
        "double-open exhaustive: {accepted_inside} interval targets accepted \
         ({accepted_new_values} values distinct from both openings), \
         {rejected_outside} outside-interval attempts rejected"
    );
}

#[test]
fn two_multi_digit_openings_create_frankenstein_messages() {
    const DIGITS: usize = 2;
    let parameters = Parameters::new(DIGITS as u32, 2, L, HashKind::Hash160);
    let mut rng = ChaCha20Rng::seed_from_u64(0xac00_f00d);
    let (secret_key, public_key) = AntichainWinternitz::keygen(&mut rng, &parameters);
    let verifier = AntichainWinternitz::verify_script(&public_key, &parameters).compile();

    let values_a = [0u32, 15];
    let values_b = [15u32, 0];
    let words_a: Vec<Vec<u32>> = values_a.into_iter().map(codeword).collect();
    let words_b: Vec<Vec<u32>> = values_b.into_iter().map(codeword).collect();
    let opening_a = AntichainWinternitz::sign(&secret_key, &parameters, &words_a);
    let opening_b = AntichainWinternitz::sign(&secret_key, &parameters, &words_b);

    let mut accepted = 0usize;
    for target_0 in 0..L {
        for target_1 in 0..L {
            let target = [target_0, target_1];
            let forged = Signature(
                target
                    .into_iter()
                    .enumerate()
                    .map(|(digit, value)| {
                        combine_digit(
                            HashKind::Hash160,
                            &opening_a,
                            &opening_b,
                            digit,
                            values_a[digit],
                            values_b[digit],
                            value,
                        )
                    })
                    .collect(),
            );
            assert!(execute(&verifier, &forged), "target {target:?}");
            accepted += 1;
        }
    }
    assert_eq!(accepted, 16usize.pow(DIGITS as u32));

    // Run an actual 16-nibble verifier too, with a target distinct from both
    // extreme source messages in every digit.
    const FULL_DIGITS: usize = 16;
    let full_parameters = Parameters::new(FULL_DIGITS as u32, 2, L, HashKind::Hash160);
    let mut full_rng = ChaCha20Rng::seed_from_u64(0xac00_0064);
    let (full_secret_key, full_public_key) =
        AntichainWinternitz::keygen(&mut full_rng, &full_parameters);
    let full_verifier =
        AntichainWinternitz::verify_script(&full_public_key, &full_parameters).compile();
    let full_values_a = [0u32; FULL_DIGITS];
    let full_values_b = [15u32; FULL_DIGITS];
    let full_words_a: Vec<Vec<u32>> = full_values_a.into_iter().map(codeword).collect();
    let full_words_b: Vec<Vec<u32>> = full_values_b.into_iter().map(codeword).collect();
    let full_opening_a =
        AntichainWinternitz::sign(&full_secret_key, &full_parameters, &full_words_a);
    let full_opening_b =
        AntichainWinternitz::sign(&full_secret_key, &full_parameters, &full_words_b);
    let full_target: Vec<u32> = (0..FULL_DIGITS)
        .map(|digit| (digit % 14 + 1) as u32)
        .collect();
    let full_forgery = Signature(
        full_target
            .iter()
            .copied()
            .enumerate()
            .map(|(digit, value)| {
                combine_digit(
                    HashKind::Hash160,
                    &full_opening_a,
                    &full_opening_b,
                    digit,
                    full_values_a[digit],
                    full_values_b[digit],
                    value,
                )
            })
            .collect(),
    );
    assert!(execute(&full_verifier, &full_forgery));

    // The extreme pair spans all 16^16 = 2^64 possible 64-bit records.
    let full_record_forgeable = 16u128.pow(16);
    assert_eq!(full_record_forgeable, 1u128 << 64);
    eprintln!(
        "multi-digit double-open: all {accepted} two-nibble targets accepted; \
         the 16-nibble analogue spans {full_record_forgeable} targets"
    );
}

#[test]
fn openers_cannot_be_transplanted_between_digit_keys() {
    let parameters = Parameters::new(2, 2, L, HashKind::Hash160);
    let mut rng = ChaCha20Rng::seed_from_u64(0xac00_add5);
    let (secret_key, public_key) = AntichainWinternitz::keygen(&mut rng, &parameters);
    let verifier = AntichainWinternitz::verify_script(&public_key, &parameters).compile();
    let opening = AntichainWinternitz::sign(&secret_key, &parameters, &[codeword(5), codeword(5)]);
    assert!(execute(&verifier, &opening));

    let mut transplanted = opening.clone();
    transplanted.0.swap(0, 1);
    assert!(
        !execute(&verifier, &transplanted),
        "independent per-digit public terminals must bind each opener to its digit"
    );
}
