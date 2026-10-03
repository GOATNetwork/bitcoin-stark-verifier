//! Dump Ziren's shrink program -- the recursion program that verifies one
//! compressed proof -- and its witness stream for a given compressed proof, in
//! a flat little-endian u32 format read by whir-gc's translator.  The program
//! is run in Ziren's own runtime first, so the dump is of an accepting run.
use std::io::Write;

use p3_field::PrimeField32;
use p3_symmetric::Permutation;
use zkm_prover::components::DefaultProverComponents;
use zkm_prover::ZKMProver;
use zkm_pcs::MachineProver;
use zkm_recursion_circuit::machine::ZKMWrapBasefoldWitnessValues;
use zkm_recursion_circuit::witness::Witnessable;
use zkm_recursion_compiler::config::InnerConfig;
use zkm_recursion_core::air::Block;
use zkm_recursion_core::runtime::Instruction;
use zkm_recursion_core::{MemAccessKind, Runtime};
use zkm_sdk::{InnerSC, ZKMProof, ZKMProofWithPublicValues};

type F = p3_koala_bear::KoalaBear;
type EF = p3_field::extension::BinomialExtensionField<F, 4>;

struct W(Vec<u8>);
impl W {
    fn u8(&mut self, v: u8) { self.0.push(v); }
    fn u32(&mut self, v: u32) { self.0.extend_from_slice(&v.to_le_bytes()); }
    fn f(&mut self, v: F) { self.u32(v.as_canonical_u32()); }
    fn blk(&mut self, b: &Block<F>) { for x in b.0 { self.f(x); } }
}

fn main() {
    let path = std::env::args().nth(1).expect("compressed proof path");
    let out = std::env::args().nth(2).expect("output path");
    let proof = ZKMProofWithPublicValues::load(&path).expect("load");
    let ZKMProof::Compressed(reduced) = proof.proof else { panic!("not a compressed proof") };
    let reduced = *reduced;

    let prover = ZKMProver::<DefaultProverComponents>::new();
    let compressed_vk = reduced.vk.clone();
    let basefold_proof = *reduced.proof.jagged_shard_proof.clone();
    let vk_merkle_data = prover.make_basefold_merkle_proofs(std::slice::from_ref(&compressed_vk)).expect("vk allowed");
    let input = ZKMWrapBasefoldWitnessValues { vks_and_proofs: vec![(compressed_vk, basefold_proof)], vk_merkle_data };
    let program = prover.shrink_program_basefold(&input);

    let mut witness_stream: Vec<Block<F>> = Vec::new();
    Witnessable::<InnerConfig>::write(&input, &mut witness_stream);

    let perm = prover.shrink_prover.machine().config().perm.clone();
    let mut runtime = Runtime::<F, EF, _>::new(program.clone(), perm.clone());
    runtime.witness_stream = witness_stream.clone().into();
    runtime.run().expect("shrink program runs");
    let pv = runtime.record.public_values;
    let pv_vec: Vec<F> = pv.as_array().to_vec();
    let pv_arr: &[F] = &pv_vec;

    let mut counts = std::collections::BTreeMap::<&str, usize>::new();
    let mut w = W(Vec::new());
    w.0.extend_from_slice(b"ZSHR");
    w.u32(1);
    let n = program.iter_instructions().count();
    w.u32(n as u32);
    w.u32(program.total_memory as u32);
    for ins in program.iter_instructions() {
        match ins {
            Instruction::BaseAlu(i) => { *counts.entry("BaseAlu").or_default() += 1; w.u8(0); w.u8(i.opcode as u8); w.f(i.mult); w.f(i.addrs.out.0); w.f(i.addrs.in1.0); w.f(i.addrs.in2.0); }
            Instruction::ExtAlu(i) => { *counts.entry("ExtAlu").or_default() += 1; w.u8(1); w.u8(i.opcode as u8); w.f(i.mult); w.f(i.addrs.out.0); w.f(i.addrs.in1.0); w.f(i.addrs.in2.0); }
            Instruction::Mem(i) => { *counts.entry(if i.kind == MemAccessKind::Read { "MemRead" } else { "MemWrite" }).or_default() += 1; w.u8(2); w.u8(if i.kind == MemAccessKind::Read { 0 } else { 1 }); w.f(i.mult); w.f(i.addrs.inner.0); w.blk(&i.vals.inner); }
            Instruction::Poseidon2(i) => { *counts.entry("Poseidon2").or_default() += 1; w.u8(3); for m in i.mults { w.f(m); } for a in i.addrs.output { w.f(a.0); } for a in i.addrs.input { w.f(a.0); } }
            Instruction::Select(i) => { *counts.entry("Select").or_default() += 1; w.u8(4); w.f(i.mult1); w.f(i.mult2); w.f(i.addrs.bit.0); w.f(i.addrs.out1.0); w.f(i.addrs.out2.0); w.f(i.addrs.in1.0); w.f(i.addrs.in2.0); }
            Instruction::HintBits(i) => { *counts.entry("HintBits").or_default() += 1; w.u8(5); w.u32(i.output_addrs_mults.len() as u32); w.f(i.input_addr.0); for (a, m) in &i.output_addrs_mults { w.f(a.0); w.f(*m); } }
            Instruction::HintAddCurve(i) => {
                *counts.entry("HintAddCurve").or_default() += 1; w.u8(6);
                for v in [&i.output_x_addrs_mults, &i.output_y_addrs_mults] { w.u32(v.len() as u32); for (a, m) in v.iter() { w.f(a.0); w.f(*m); } }
                for v in [&i.input1_x_addrs, &i.input1_y_addrs, &i.input2_x_addrs, &i.input2_y_addrs] { w.u32(v.len() as u32); for a in v.iter() { w.f(a.0); } }
            }
            Instruction::Print(_) => { *counts.entry("Print").or_default() += 1; w.u8(7); }
            Instruction::HintExt2Felts(i) | Instruction::Ext2Felts(i) => {
                *counts.entry("Ext2Felts").or_default() += 1; w.u8(8); w.f(i.input_addr.0); for (a, m) in i.output_addrs_mults { w.f(a.0); w.f(m); }
            }
            Instruction::CommitPublicValues(i) => {
                *counts.entry("CommitPublicValues").or_default() += 1; w.u8(10);
                let a = i.pv_addrs.as_array(); w.u32(a.len() as u32); for x in a.iter() { w.f(x.0); }
            }
            Instruction::Hint(i) => { *counts.entry("Hint").or_default() += 1; w.u8(11); w.u32(i.output_addrs_mults.len() as u32); for (a, m) in &i.output_addrs_mults { w.f(a.0); w.f(*m); } }
        }
    }
    // Witness stream.
    w.u32(witness_stream.len() as u32);
    for b in &witness_stream { w.blk(b); }
    // Committed public values of the accepting run.
    w.u32(pv_arr.len() as u32);
    for x in pv_arr { w.f(*x); }
    // A Poseidon2 test vector of the permutation the program uses.
    let tv: [F; 16] = core::array::from_fn(|i| F::new(i as u32));
    let o = perm.permute(tv);
    for x in o { w.f(x); }
    std::fs::File::create(&out).unwrap().write_all(&w.0).unwrap();
    let hint_felts: usize = witness_stream.len();
    eprintln!("instructions {n}, total_memory {}, witness blocks {hint_felts}", program.total_memory);
    for (k, v) in counts { eprintln!("  {k}: {v}"); }
    eprintln!("public values {}", pv_arr.len());
}
