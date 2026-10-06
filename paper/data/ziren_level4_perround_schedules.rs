//! Temporary (whir-gc measurement): WHIR schedules with a first-round folding
//! of its own and per-round rates, at the level-4 narrow machine's shapes,
//! scored in garbled-verifier input elements (128-bit), without proving.

use p3_binary_pcs::whir::{BooleanWhirDomain, ProofShape};
use p3_sumcheck::ring_switch::bits::BitRingSwitch;
use p3_sumcheck::TableShape;
use p3_whir::{FoldingFactor, ProtocolParameters, SecurityAssumption, WhirConfig, WhirConfigError};
use zkm_binary_stark::config::paired_arity;
use zkm_binary_stark::{Challenger, F};

fn config(packed: usize, rate: usize, folding: FoldingFactor, rates: Vec<usize>, security: usize)
    -> Result<WhirConfig<F, F, Challenger>, String> {
    let mut pow_bits = 0;
    loop {
        let parameters = ProtocolParameters {
            starting_log_inv_rate: rate,
            round_log_inv_rates: rates.clone(),
            folding_factor: folding.clone(),
            soundness_type: SecurityAssumption::JohnsonBound,
            security_level: security,
            pow_bits,
        };
        match WhirConfig::new_with_domain(packed, parameters, &BooleanWhirDomain::default()) {
            Ok(c) => return Ok(c),
            Err(WhirConfigError::PowBitsExceedBudget { required, .. }) if required > pow_bits && required <= 56 => pow_bits = required,
            Err(e) => return Err(format!("{e:?}")),
        }
    }
}

/// Input elements of a paired opening: digests count twice (256 bits), the
/// first round's queries open a second tree (the preprocessed commitment).
fn inputs(c: &WhirConfig<F, F, Challenger>) -> (usize, usize, usize, usize) {
    let s = ProofShape::of(c, 1);
    let r0 = &c.round_parameters()[0];
    let q0 = r0.num_queries;
        let second_digests = q0 * r0.log_folded_domain_size;
    let total = (200 * (s.merkle_digests + second_digests)
        + 128 * (s.opened_base_elements + s.opened_extension_elements + s.sent_base_elements
            + s.sent_extension_elements + (q0 << r0.folding_factor)))
        / 128;
    (total, s.merkle_digests, s.opened_base_elements + s.opened_extension_elements, s.grinding_bits)
}

#[test]
#[ignore]
fn level4_mixed_schedules() {
    let main: Vec<TableShape> = [(21, 128), (19, 512), (16, 512), (14, 512), (19, 512)]
        .iter().map(|&(h, w)| TableShape::new(h, w)).collect();
    let prep: Vec<TableShape> = [(21, 256), (19, 128), (16, 512), (14, 256), (19, 128)]
        .iter().map(|&(h, w)| TableShape::new(h, w)).collect();
    let arity = paired_arity(&main, &prep);
    let packed = arity - BitRingSwitch::<F>::ABSORBED;
    println!("paired arity {arity}, packed {packed}");
    let security = 108;
    let reference = config(packed, 10, FoldingFactor::Constant(5), vec![], security).unwrap();
    let (t, d, o, p) = inputs(&reference);
    println!("reference johnson 10, fold 5: {t} input elements ({d} digests, {o} opened), pow {p}");
    let current = config(packed, 10, FoldingFactor::ConstantFromSecondRound(3, 5), vec![13, 17, 21], security).unwrap();
    let (t, d, o, p) = inputs(&current);
    println!("current fold (3,5) rates [13,17,21]: {t} input elements ({d} digests, {o} opened), pow {p}");
    let mut found = Vec::new();
    for rate in [10usize] {
        // Per-round folds: a first fold, then up to four rounds of 2..6, the rest final.
        let mut schedules: Vec<Vec<usize>> = Vec::new();
        for f0 in 2..=6usize {
            for a in 2..=6usize { for b in 2..=6usize { for c in 0..=6usize {
                let mut v = vec![f0, a, b];
                if c > 0 { v.push(c); }
                if v.iter().sum::<usize>() <= packed { schedules.push(v); }
            }}}
        }
        for schedule in schedules {
            let folding = FoldingFactor::PerRound(schedule.clone());
            let Ok(base) = config(packed, rate, folding.clone(), vec![], security) else { continue };
            let rounds = base.round_parameters().len();
            for mask in 0..(1usize << rounds) {
                let mut r = rate;
                let rates: Vec<usize> = (0..rounds).map(|i| {
                    r += schedule[i] - 1 + ((mask >> i) & 1);
                    r
                }).collect();
                if let Ok(c) = config(packed, rate, folding.clone(), rates.clone(), security) {
                    let (t, d, o, p) = inputs(&c);
                    let qs: Vec<String> = c.round_parameters().iter()
                        .map(|r| format!("f{} {}q/{}b", r.folding_factor, r.num_queries, r.pow_bits.max(r.folding_pow_bits)))
                        .collect();
                    found.push((t, p, format!("folds {schedule:?} rates {rates:?}: {t} input elements ({d} digests, {o} opened), pow {p}; [{}] terminal {}q", qs.join(", "), c.terminal().num_queries)));
                }
            }
        }
    }
    found.sort();
    for max_pow in [46usize, 47, 48] {
        println!("--- best with pow <= {max_pow}");
        for (_, _, line) in found.iter().filter(|(_, p, _)| *p <= max_pow).take(8) {
            println!("{line}");
        }
    }
}
