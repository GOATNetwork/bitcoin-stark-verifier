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
    let second = (q0 << r0.folding_factor) + 2 * q0 * r0.log_folded_domain_size;
    let total = 2 * s.merkle_digests + s.opened_base_elements + s.opened_extension_elements
        + s.sent_base_elements + s.sent_extension_elements + second;
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
    println!("reference johnson 10, fold 5: {t} inputs ({d} digests, {o} opened), pow {p}");
    let mut found = Vec::new();
    for rate in [9usize, 10, 11] {
        for f0 in 1..=6usize {
            for f in 3..=7usize {
                let folding = FoldingFactor::ConstantFromSecondRound(f0, f);
                let Ok(base) = config(packed, rate, folding.clone(), vec![], security) else { continue };
                let schedule: Vec<usize> = std::iter::once(f0)
                    .chain(base.round_parameters().iter().skip(1).map(|r| r.folding_factor)).collect();
                let rounds = base.round_parameters().len();
                // Per-round rate growth: f_i - 1 (the default) or f_i (the domain kept).
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
                        found.push((t, p, format!("rate {rate} fold ({f0},{f}) rates {rates:?}: {t} inputs ({d} digests, {o} opened), pow {p}, codeword 2^{} ; [{}] terminal {}q", packed + rate, qs.join(", "), c.terminal().num_queries)));
                    }
                }
            }
        }
    }
    found.sort();
    for max_pow in [46usize, 48, 50] {
        println!("--- best with pow <= {max_pow}");
        for (_, _, line) in found.iter().filter(|(_, p, _)| *p <= max_pow).take(8) {
            println!("{line}");
        }
    }
}
