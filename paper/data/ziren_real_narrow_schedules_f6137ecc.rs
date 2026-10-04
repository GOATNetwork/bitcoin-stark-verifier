//! Temporary (whir-gc measurement): the WHIR schedules of the narrow machine
//! at the shapes it has at f6137ecc for the real fibonacci binary-stage
//! verifier tape, both commitments at the paired arity, read off the derived
//! configurations without proving.

use p3_binary_pcs::whir::{BooleanWhirDomain, ProofShape};
use p3_sumcheck::ring_switch::bits::BitRingSwitch;
use p3_sumcheck::TableShape;
use zkm_binary_stark::config::paired_arity;
use zkm_binary_stark::{BinarySchedule, Challenger, F};

#[test]
#[ignore]
fn real_narrow_schedules() {
    let main: Vec<TableShape> = [(25, 128), (22, 512), (21, 1024), (18, 512), (23, 512)]
        .iter()
        .map(|&(h, w)| TableShape::new(h, w))
        .collect();
    let prep: Vec<TableShape> = [(25, 256), (22, 128), (21, 512), (18, 256), (23, 64)]
        .iter()
        .map(|&(h, w)| TableShape::new(h, w))
        .collect();
    let arity = paired_arity(&main, &prep);
    let packed = arity - BitRingSwitch::<F>::ABSORBED;
    println!("paired arity {arity}, packed {packed}");
    let specs = std::env::var("ZIREN_B_SCHEDULES").unwrap_or_else(|_| {
        "unique,5,4;johnson,2,4;johnson,3,4;johnson,4,4;johnson,5,4;johnson,6,4;johnson,8,4;johnson,5,3;johnson,5,5;johnson,6,5".into()
    });
    for (security, term) in [(100usize, 108usize), (80, 88)] {
        for spec in specs.split(';') {
            let parts: Vec<&str> = spec.split(',').collect();
            let regime = match parts[0] {
                "johnson" => p3_examples::binary::WhirRegime::Johnson,
                _ => p3_examples::binary::WhirRegime::UniqueDecoding,
            };
            let schedule = BinarySchedule {
                regime,
                log_inv_rate: parts[1].parse().unwrap(),
                folding: parts[2].parse().unwrap(),
                security_bits: security,
                term_security_bits: term,
                ..BinarySchedule::default()
            };
            let profile = BinarySchedule { folding: schedule.folding.min(packed), ..schedule }.profile();
            match profile.config::<F, F, Challenger, _>(packed, &BooleanWhirDomain::default()) {
                Ok(config) => {
                    let s = ProofShape::of(&config, 1);
                    let rounds: Vec<String> = config
                        .round_parameters()
                        .iter()
                        .map(|r| format!("{}q/{}b", r.num_queries, r.pow_bits.max(r.folding_pow_bits)))
                        .collect();
                    let bytes = 32 * s.merkle_digests
                        + 16 * (s.opened_base_elements
                            + s.opened_extension_elements
                            + s.sent_base_elements
                            + s.sent_extension_elements);
                    println!(
                        "sec {security}/{term} {spec:<12} pow {:>2} bits, {:>4} queries, {:>5} digests, opened {}/{}, ~{} B one commitment unpruned; rounds [{}]",
                        s.grinding_bits,
                        s.stir_queries,
                        s.merkle_digests,
                        s.opened_base_elements,
                        s.opened_extension_elements,
                        bytes,
                        rounds.join(", ")
                    );
                }
                Err(error) => println!("sec {security}/{term} {spec:<12} {error}"),
            }
        }
    }
}
