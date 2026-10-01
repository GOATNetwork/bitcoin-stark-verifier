//! Chips of the compress (recursion) machine: width, preprocessed width,
//! symbolic constraint count and quotient degree. These fix the per-row cost
//! of the zerocheck constraint evaluation a verifier of this proof performs.
use p3_air::BaseAir;
use p3_uni_stark::{get_symbolic_constraints, AirLayout, SymbolicExpression};
use zkm_pcs::air::MachineAir;
use zkm_pcs::PROOF_MAX_NUM_PVS;
use zkm_sdk::InnerSC;
use zkm_recursion_core::machine::RecursionAir;

type F = zkm_pcs::InnerVal;
const COMPRESS_DEGREE: usize = 3;

fn count_nodes(e: &SymbolicExpression<F>, seen: &mut std::collections::HashSet<usize>, muls: &mut u64, adds: &mut u64) {
    let key = e as *const _ as usize;
    if !seen.insert(key) { return; }
    match e {
        SymbolicExpression::Add { x, y, .. } | SymbolicExpression::Sub { x, y, .. } => { *adds += 1; count_nodes(x, seen, muls, adds); count_nodes(y, seen, muls, adds); }
        SymbolicExpression::Mul { x, y, .. } => { *muls += 1; count_nodes(x, seen, muls, adds); count_nodes(y, seen, muls, adds); }
        SymbolicExpression::Neg { x, .. } => { count_nodes(x, seen, muls, adds); }
        _ => {}
    }
}

fn main() {
    let machine = RecursionAir::<F, COMPRESS_DEGREE>::compress_machine(InnerSC::default());
    let mut total_cols = 0usize;
    let mut total_constraints = 0usize;
    let mut total_muls = 0u64;
    let mut total_adds = 0u64;
    println!("{:<20} {:>6} {:>5} {:>12} {:>8} {:>10} {:>10} {:>6} {:>6}", "chip", "width", "prep", "constraints", "logq", "mul nodes", "add nodes", "sends", "recvs");
    for chip in machine.chips() {
        let width = BaseAir::<F>::width(&chip.air);
        let prep = MachineAir::<F>::preprocessed_width(&chip.air);
        let cs = get_symbolic_constraints(&chip.air, AirLayout { preprocessed_width: prep, main_width: width, num_public_values: PROOF_MAX_NUM_PVS, ..Default::default() });
        let (mut m, mut a) = (0u64, 0u64);
        let mut seen = std::collections::HashSet::new();
        for c in &cs { count_nodes(c, &mut seen, &mut m, &mut a); }
        println!("{:<20} {:>6} {:>5} {:>12} {:>8} {:>10} {:>10} {:>6} {:>6}", chip.name(), width, prep, cs.len(), chip.log_quotient_degree(), m, a, chip.sends().len(), chip.receives().len());
        total_cols += width + prep; total_constraints += cs.len(); total_muls += m; total_adds += a;
    }
    println!("total columns {total_cols}, constraints {total_constraints}, mul nodes {total_muls}, add nodes {total_adds}");
}
