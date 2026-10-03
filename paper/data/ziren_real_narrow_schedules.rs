//! Temporary (whir-gc measurement): the WHIR schedules of the narrow machine
//! at the shapes it has for the real fibonacci binary-stage verifier tape,
//! read off the derived configurations without proving.

use p3_binary_pcs::whir::{BooleanWhirDomain, ProofShape};
use p3_sumcheck::layout::plan_stacked_layout;
use p3_sumcheck::ring_switch::bits::BitRingSwitch;
use p3_sumcheck::TableShape;
use zkm_binary_stark::{BinarySchedule, Challenger, F};

#[test]
#[ignore]
fn real_narrow_schedules() {
    let main: Vec<TableShape> = [(24, 128), (23, 512), (14, 16384), (16, 2048), (19, 4096)]
        .iter()
        .map(|&(h, w)| TableShape::new(h, w))
        .collect();
    let prep: Vec<TableShape> = [(24, 256), (23, 128), (14, 512), (16, 512), (19, 32)]
        .iter()
        .map(|&(h, w)| TableShape::new(h, w))
        .collect();
    let specs = std::env::var("ZIREN_B_SCHEDULES").unwrap_or_else(|_| {
        "unique,5,4;unique,3,4;unique,4,4;unique,6,4;unique,8,4;unique,5,2;unique,5,3;unique,5,5;unique,5,6;\
         johnson,3,4;johnson,4,4;johnson,5,4;johnson,6,4;johnson,8,4;johnson,5,2;johnson,5,3;johnson,5,5;johnson,5,6"
            .into()
    });
    println!("spec           table: arity, pow bits, queries, digests, opened base/ext, sent base/ext, est bytes");
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
            ..BinarySchedule::default()
        };
        let mut total = 0usize;
        for (label, shapes) in [("main", &main), ("prep", &prep)] {
            let arity = plan_stacked_layout(shapes).0;
            let packed = arity - BitRingSwitch::<F>::ABSORBED;
            let profile = BinarySchedule { folding: schedule.folding.min(packed), ..schedule }.profile();
            match profile.config::<F, F, Challenger, _>(packed, &BooleanWhirDomain::default()) {
                Ok(config) => {
                    let s = ProofShape::of(&config, 1);
                    let bytes = 32 * s.merkle_digests
                        + 16 * (s.opened_base_elements
                            + s.opened_extension_elements
                            + s.sent_base_elements
                            + s.sent_extension_elements);
                    total += bytes;
                    println!(
                        "{spec:<14} {label}: arity {arity}, pow {} bits, {} queries, {} digests, opened {}/{}, sent {}/{}, ~{} B",
                        s.grinding_bits,
                        s.stir_queries,
                        s.merkle_digests,
                        s.opened_base_elements,
                        s.opened_extension_elements,
                        s.sent_base_elements,
                        s.sent_extension_elements,
                        bytes
                    );
                }
                Err(error) => println!("{spec:<14} {label}: arity {arity}: {error}"),
            }
        }
        println!("{spec:<14} both: ~{total} B unpruned");
    }
}
