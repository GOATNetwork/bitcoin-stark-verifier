//! Prove a fibonacci execution through the binary stage, record the binary
//! stage's verifier on that real proof as a tape over GF(2^128) (level 1),
//! prove that tape's run on the narrow recursion's tape machine and record
//! the tape machine's verifier on it (level 2), and dump both tapes, with
//! their inputs and honest values, for whir-gc's garbled-circuit translator
//! (format ZTAP v2).  Run with `--ignored --nocapture`; `ZIREN_TAPE_OUT`
//! names the output directory.  A saved binary proof (`binary_proof.bin`,
//! `binary_program.bin`, `binary_digest.bin`) is reused when present.
//! `ZIREN_B_SCHEDULE` (as `johnson,3,4`: regime, -log2 rate, folding) sets
//! the narrow proof's WHIR schedule, with grinding allowed to 40 bits
//! (`ZIREN_B_MAX_GRIND` raises it); the
//! default is the binary stage's own.  Level-2 files then carry the spec.
//! `ZIREN_RECURSE_FROM` names a saved tape (ZTAP v2, as this writes them)
//! instead: the binary stage is skipped, the tape's run is proved on the
//! tape machine (its first `MAX_PUBLIC` inputs public) and the next level's
//! verifier is recorded, to `ZIREN_RECURSE_TO` (a file name in the output
//! directory).
use std::io::Write;
use std::path::PathBuf;

use p3_multi_stark::verify;
use zkm_binary_recursion::challenger::TracedChallenger;
use zkm_binary_recursion::config::{lift_key, record_verification, reread, Instance, TracedConfig, TracedProof};
use zkm_binary_recursion::machine::program::Program;
use zkm_binary_recursion::machine::{TapeAir, TapeMachine};
use p3_binary_field::TowerLevel;
use zkm_binary_recursion::{record, Op, Operand, Tape, Traced};
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
    if let Ok(from) = std::env::var("ZIREN_RECURSE_FROM") {
        let tape = read_tape(std::path::Path::new(&from));
        let replay = tape.run(&tape.inputs).expect("the saved tape accepts its own inputs");
        assert_eq!(replay, tape.values, "the saved tape reproduces its values");
        eprintln!("recursing from {from}: {} ops, {} inputs", tape.ops.len(), tape.inputs.len());
        let to = std::env::var("ZIREN_RECURSE_TO").expect("ZIREN_RECURSE_TO names the next level's tape");
        recurse("next level", &tape, zkm_binary_recursion::machine::ledger::MAX_PUBLIC, &out, &to);
        return;
    }
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
    eprintln!("level 1 recorded in {:.1} s", started.elapsed().as_secs_f64());
    write_tape("level 1", &tape, &out.join("binary_tape.bin"));

    // Level 2: the narrow recursion.  The tape machine proves the run of the
    // level-1 tape, whose first DIGEST_SIZE inputs are public, and its own
    // verifier is recorded on that proof.
    let (_, tag) = narrow_schedule();
    recurse("level 2", &tape, zkm_recursion_core::DIGEST_SIZE, &out, &format!("narrow_tape{tag}.bin"));
}

/// Prove the run of `tape` on the tape machine under the narrow schedule,
/// its first `num_public` inputs public, verify the proof, record the tape
/// machine's verifier on it and write that tape to `out/to`.
fn recurse(label: &str, tape: &Tape, num_public: usize, out: &std::path::Path, to: &str) {
    let started = std::time::Instant::now();
    let program = Program::new(tape, num_public);
    eprintln!("tape machine program: {}", program.census());
    let (narrow_schedule, _) = narrow_schedule();
    eprintln!("narrow schedule: {narrow_schedule:?}");
    let narrow_machine = TapeMachine::new(program, &narrow_schedule).expect("the tape machine");
    for air in narrow_machine.airs() {
        eprintln!(
            "  {:>7}: 2^{} rows x {} + {} prep",
            air.name(),
            air.log_height(),
            p3_air::BaseAir::<zkm_binary_stark::F>::width(air),
            p3_air::BaseAir::<zkm_binary_stark::F>::preprocessed_width(air)
        );
    }
    eprintln!("tape machine set up in {:.1} s", started.elapsed().as_secs_f64());
    let started = std::time::Instant::now();
    let narrow_public = narrow_machine.public_values(&tape.inputs);
    let narrow = narrow_machine.prove(tape, &tape.inputs).expect("the tape machine proves the run");
    let narrow_bytes = postcard::to_allocvec(&narrow).expect("serializes");
    eprintln!("narrow proof: {} bytes in {:.1} s", narrow_bytes.len(), started.elapsed().as_secs_f64());
    std::fs::write(out.join(to.replace("tape", "proof")), &narrow_bytes).unwrap();
    narrow_machine.verify(&narrow, &narrow_public).expect("the narrow proof verifies");
    for (part, bytes) in zkm_binary_stark::config::proof_breakdown(&narrow) {
        eprintln!("    {part:<55} {bytes:>9} B");
    }
    let (main, preprocessed) = narrow_machine.shapes();
    let instances: Vec<Instance<'_, TapeAir>> = narrow_machine
        .airs()
        .iter()
        .map(|air| Instance {
            air,
            log_height: air.log_height(),
            public_values: match air {
                TapeAir::Ledger(_) => &narrow_public,
                _ => &[],
            },
        })
        .collect();
    let started = std::time::Instant::now();
    let (verdict, own) = record_verification(
        &instances,
        &main,
        &preprocessed,
        &narrow_schedule,
        narrow_machine.verifying_key(),
        &narrow,
    );
    verdict.expect("the recorded verifier accepts the narrow proof");
    eprintln!("{label} recorded in {:.1} s", started.elapsed().as_secs_f64());
    write_tape(label, &own, &out.join(to));
}

/// A tape as `write_tape` wrote it (ZTAP v2).
fn read_tape(path: &std::path::Path) -> Tape {
    use zkm_binary_recursion::F;
    struct R<'a>(&'a [u8], usize);
    impl R<'_> {
        fn take(&mut self, n: usize) -> &[u8] {
            self.1 += n;
            &self.0[self.1 - n..self.1]
        }
        fn u8(&mut self) -> u8 {
            self.take(1)[0]
        }
        fn u32(&mut self) -> u32 {
            u32::from_le_bytes(self.take(4).try_into().unwrap())
        }
        fn u64(&mut self) -> u64 {
            u64::from_le_bytes(self.take(8).try_into().unwrap())
        }
        fn f(&mut self) -> F {
            F::from_repr(u128::from_le_bytes(self.take(16).try_into().unwrap()))
        }
        fn opd(&mut self) -> Operand {
            match self.u8() {
                0 => Operand::Var(self.u32()),
                1 => Operand::Const(self.f()),
                t => panic!("operand tag {t}"),
            }
        }
        fn opds(&mut self) -> Vec<Operand> {
            let n = self.u32() as usize;
            (0..n).map(|_| self.opd()).collect()
        }
    }
    let bytes = std::fs::read(path).unwrap();
    assert_eq!(&bytes[..4], b"ZTAP", "not a tape");
    let mut r = R(&bytes, 4);
    assert_eq!(r.u32(), 2, "tape version");
    let n = r.u64() as usize;
    let mut ops = Vec::with_capacity(n);
    for _ in 0..n {
        let tag = r.u8();
        ops.push(match tag {
            0 => Op::Input(r.u64() as usize),
            1 => Op::Add(r.opd(), r.opd()),
            2 => Op::Mul(r.opd(), r.opd()),
            3 => Op::Inv(r.opd()),
            4 => Op::AssertEq(r.opd(), r.opd()),
            5 => Op::AssertNonZero(r.opd()),
            6 => Op::ToBytes(r.opd()),
            7 => Op::FromBytes(r.opds()),
            8 => Op::ByteBits(r.opd()),
            9 => {
                let slots = r.opds();
                Op::Blake3 { slots, len: r.u64() as usize }
            }
            10 => Op::Transpose(r.opds()),
            11 => Op::Select(r.opd(), r.opd(), r.opd()),
            12 => {
                let bit = r.opd();
                let cur = [r.opd(), r.opd()];
                let sib = [r.opd(), r.opd()];
                Op::MerkleNode { bit, cur, sib }
            }
            13 => Op::Square(r.opd()),
            t => panic!("op tag {t}"),
        });
    }
    let inputs: Vec<F> = (0..r.u64()).map(|_| r.f()).collect();
    let values: Vec<F> = (0..r.u64()).map(|_| r.f()).collect();
    assert_eq!(r.1, bytes.len(), "trailing bytes");
    let mut defined = Vec::with_capacity(ops.len());
    let mut next: u32 = 0;
    for op in &ops {
        let k = op.defines() as u32;
        defined.push(if k > 0 { Some(next) } else { None });
        next += k;
    }
    assert_eq!(next as usize, values.len(), "every variable has a value");
    Tape { ops, values, defined, inputs }
}

/// The narrow proof's schedule and a file-name tag: the stage's default, or
/// the regime, rate and folding `ZIREN_B_SCHEDULE` names.
fn narrow_schedule() -> (BinarySchedule, String) {
    let Ok(spec) = std::env::var("ZIREN_B_SCHEDULE") else { return (BinarySchedule::default(), String::new()) };
    let parts: Vec<&str> = spec.split(',').collect();
    let regime = match parts[0] {
        "johnson" => p3_examples::binary::WhirRegime::Johnson,
        _ => p3_examples::binary::WhirRegime::UniqueDecoding,
    };
    let mut schedule = BinarySchedule {
        regime,
        log_inv_rate: parts[1].parse().expect("a rate"),
        folding: parts[2].parse().expect("a folding factor"),
        ..BinarySchedule::default()
    };
    schedule.budget.max_grinding_bits =
        std::env::var("ZIREN_B_MAX_GRIND").ok().and_then(|v| v.parse().ok()).unwrap_or(40);
    (schedule, format!("-{}", spec.replace(',', "-")))
}

fn write_tape(label: &str, tape: &Tape, path: &std::path::Path) {
    eprintln!(
        "{label}: {} ops, {} variables, {} inputs, {} hashed bytes; garbled estimate {}",
        tape.ops.len(),
        tape.values.len(),
        tape.inputs.len(),
        tape.hashed_bytes(),
        tape.and_gates()
    );
    let kinds = tape.census();
    eprintln!("{label} census {:?} {:?}", Tape::KINDS, kinds);
    let replay = tape.run(&tape.inputs).expect("the tape accepts its own inputs");
    assert_eq!(replay, tape.values, "the tape reproduces its values");

    let mut w = W(Vec::new());
    w.0.extend_from_slice(b"ZTAP");
    w.u32(2);
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
            Op::Blake3 { slots, len } => {
                w.u8(9);
                w.operands(slots);
                w.u64(*len as u64);
            }
            Op::MerkleNode { bit, cur, sib } => {
                w.u8(12);
                w.operand(bit);
                cur.iter().chain(sib).for_each(|o| w.operand(o));
            }
            Op::Square(a) => {
                w.u8(13);
                w.operand(a);
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
    let mut f = std::fs::File::create(path).unwrap();
    f.write_all(&w.0).unwrap();
    eprintln!("{label} tape written: {} bytes", w.0.len());
}
