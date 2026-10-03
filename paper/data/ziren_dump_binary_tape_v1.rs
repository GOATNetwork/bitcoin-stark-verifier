//! Prove a fibonacci execution through the binary stage, record the binary
//! stage's verifier on that real proof as a tape over GF(2^128), and dump the
//! tape, its inputs and its honest values for whir-gc's garbled-circuit
//! translator.  Run with `--ignored --nocapture`; `ZIREN_TAPE_OUT` names the
//! output directory.  A saved binary proof (`binary_proof.bin`,
//! `binary_program.bin`, `binary_digest.bin`) is reused when present.
use std::io::Write;
use std::path::PathBuf;

use p3_multi_stark::verify;
use zkm_binary_recursion::challenger::TracedChallenger;
use zkm_binary_recursion::config::{lift_key, reread, TracedConfig, TracedProof};
use p3_binary_field::TowerLevel;
use zkm_binary_recursion::{record, Op, Operand, Traced};
use zkm_binary_stark::machine::RecursionMachine;
use zkm_binary_stark::{BinarySchedule, TRANSCRIPT_DOMAIN};
use zkm_core_executor::ZKMContext;
use zkm_core_machine::io::ZKMStdin;
use zkm_core_machine::utils::setup_logger;
use zkm_pcs::ZKMProverOpts;
use zkm_prover::components::DefaultProverComponents;
use zkm_prover::ZKMProver;

struct W(Vec<u8>);
impl W {
    fn u8(&mut self, v: u8) {
        self.0.push(v);
    }
    fn u32(&mut self, v: u32) {
        self.0.extend_from_slice(&v.to_le_bytes());
    }
    fn u64(&mut self, v: u64) {
        self.0.extend_from_slice(&v.to_le_bytes());
    }
    fn u128(&mut self, v: u128) {
        self.0.extend_from_slice(&v.to_le_bytes());
    }
    fn operand(&mut self, o: &Operand) {
        match o {
            Operand::Var(v) => {
                self.u8(0);
                self.u32(*v);
            }
            Operand::Const(c) => {
                self.u8(1);
                self.u128(c.to_repr());
            }
        }
    }
    fn operands(&mut self, os: &[Operand]) {
        self.u32(os.len() as u32);
        for o in os {
            self.operand(o);
        }
    }
}

#[test]
#[ignore]
fn dump_binary_stage_verifier_tape() {
    setup_logger();
    let out = PathBuf::from(std::env::var("ZIREN_TAPE_OUT").unwrap_or_else(|_| "tape-out".into()));
    std::fs::create_dir_all(&out).unwrap();
    let (proof_path, program_path, digest_path) =
        (out.join("binary_proof.bin"), out.join("binary_program.bin"), out.join("binary_digest.bin"));

    if !proof_path.exists() {
        let elf = test_artifacts::FIBONACCI_ELF;
        let opts = ZKMProverOpts::default();
        let prover = ZKMProver::<DefaultProverComponents>::new();
        let (_, pk_d, program, vk) = prover.setup(elf);
        let mut stdin = ZKMStdin::new();
        stdin.write(&10u32);
        let core_proof = prover.prove_core(&pk_d, program, &stdin, opts, ZKMContext::default()).unwrap();
        let compressed = prover.compress(&vk, core_proof, vec![], opts).unwrap();
        let shrink = prover.shrink_blake3(compressed, opts).unwrap();
        let binary = prover.shrink_binary(shrink).unwrap();
        prover.verify_shrink_binary(&binary).unwrap();
        std::fs::write(&proof_path, bincode::serialize(&binary.proof).unwrap()).unwrap();
        std::fs::write(&program_path, bincode::serialize(&*binary.program).unwrap()).unwrap();
        std::fs::write(&digest_path, bincode::serialize(&binary.digest).unwrap()).unwrap();
        eprintln!("binary proof saved: {} bytes", std::fs::metadata(&proof_path).unwrap().len());
    }

    let proof: zkm_binary_stark::config::MachineProof =
        bincode::deserialize(&std::fs::read(&proof_path).unwrap()).unwrap();
    let program: zkm_recursion_core::RecursionProgram<p3_koala_bear::KoalaBear> =
        bincode::deserialize(&std::fs::read(&program_path).unwrap()).unwrap();
    let digest: [u32; zkm_recursion_core::DIGEST_SIZE] =
        bincode::deserialize(&std::fs::read(&digest_path).unwrap()).unwrap();

    let schedule = BinarySchedule::default();
    let machine = RecursionMachine::new(&program, &schedule).expect("machine");
    machine.verify(&proof, &digest).expect("the binary proof verifies natively");
    let (main, preprocessed) = machine.shapes();
    let config = TracedConfig::new(&main, &preprocessed, &schedule).expect("traced config");
    let vk = lift_key(machine.verifying_key());

    let started = std::time::Instant::now();
    let (verdict, tape) = record(|| {
        let public: [Traced; zkm_recursion_core::DIGEST_SIZE] =
            RecursionMachine::public_values(&digest).map(Traced::input);
        let traced: TracedProof = reread(&proof);
        let instances = machine.verifier_instances(&vk, &public);
        let mut challenger = TracedChallenger::new(TRANSCRIPT_DOMAIN);
        verify(&config, instances, &traced, 0, &mut challenger).map_err(|e| format!("{e:?}"))
    });
    verdict.expect("the traced verifier accepts the real proof");
    eprintln!(
        "recorded in {:.1} s: {} ops, {} variables, {} inputs, {} hashed bytes",
        started.elapsed().as_secs_f64(),
        tape.ops.len(),
        tape.values.len(),
        tape.inputs.len(),
        tape.hashed_bytes()
    );
    let kinds = tape.census();
    eprintln!("census {:?} {:?}", zkm_binary_recursion::Tape::KINDS, kinds);
    let replay = tape.run(&tape.inputs).expect("the tape accepts its own inputs");
    assert_eq!(replay, tape.values, "the tape reproduces its values");

    let mut w = W(Vec::new());
    w.0.extend_from_slice(b"ZTAP");
    w.u32(1);
    w.u64(tape.ops.len() as u64);
    for op in &tape.ops {
        match op {
            Op::Input(n) => {
                w.u8(0);
                w.u64(*n as u64);
            }
            Op::Add(a, b) => {
                w.u8(1);
                w.operand(a);
                w.operand(b);
            }
            Op::Mul(a, b) => {
                w.u8(2);
                w.operand(a);
                w.operand(b);
            }
            Op::Inv(a) => {
                w.u8(3);
                w.operand(a);
            }
            Op::AssertEq(a, b) => {
                w.u8(4);
                w.operand(a);
                w.operand(b);
            }
            Op::AssertNonZero(a) => {
                w.u8(5);
                w.operand(a);
            }
            Op::ToBytes(a) => {
                w.u8(6);
                w.operand(a);
            }
            Op::FromBytes(v) => {
                w.u8(7);
                w.operands(v);
            }
            Op::ByteBits(a) => {
                w.u8(8);
                w.operand(a);
            }
            Op::Blake3(v) => {
                w.u8(9);
                w.operands(v);
            }
            Op::Transpose(v) => {
                w.u8(10);
                w.operands(v);
            }
            Op::Select(s, a, b) => {
                w.u8(11);
                w.operand(s);
                w.operand(a);
                w.operand(b);
            }
        }
    }
    w.u64(tape.inputs.len() as u64);
    for x in &tape.inputs {
        w.u128(x.to_repr());
    }
    w.u64(tape.values.len() as u64);
    for x in &tape.values {
        w.u128(x.to_repr());
    }
    let mut f = std::fs::File::create(out.join("binary_tape.bin")).unwrap();
    f.write_all(&w.0).unwrap();
    eprintln!("tape written: {} bytes", w.0.len());
}
