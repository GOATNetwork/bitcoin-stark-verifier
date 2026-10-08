//! The verifier of Ziren's binary stage, from its recorded tape, as a garbled
//! circuit: exact gate counts, gate-level evaluation against the tape's
//! honest values on a real binary-stage proof, a tampered proof, and a full
//! garbling with the streaming garbler.
//!
//! The tape is dumped by Ziren's `crates/prover/tests/dump_binary_tape.rs` (added by
//! `patches/ziren-9398469a.patch`): the binary
//! stage's verifier (`binary_tape.bin`, level 1) or the narrow recursion's
//! verifier (`narrow_tape.bin`, level 2). Set `BINARY_TAPE_DUMP` or put it at
//! `target/binary-tape.bin`. Run with
//! `cargo test --release -p whir-gc --test binary_tape -- --ignored --nocapture`.

use garbled_snark_verifier::circuits::sect233k1::builder::CircuitTrait;
use garbled_snark_verifier::circuits::sect233k1::stream::{Plan, Streaming};
use whir_gc::binary_tape::{self, BTape, Options, Report};
use whir_gc::ziren::{Count, Eval};

fn tape() -> Option<BTape> {
    let path = std::env::var("BINARY_TAPE_DUMP")
        .unwrap_or_else(|_| concat!(env!("CARGO_MANIFEST_DIR"), "/../target/binary-tape.bin").into());
    Some(binary_tape::parse(&std::fs::read(path).ok()?))
}

fn print(name: &str, r: &Report, and: usize, or: usize, xor: usize, wires: usize, secs: f64) {
    let nf = and + or;
    eprintln!(
        "{name}: {nf} non-free gates ({and} AND, {or} OR), {xor} XOR, {wires} wires; garbled {:.2} GB at 16 B per non-free gate; inputs {} bits ({} byte, {} bit, {} full-width inputs; {} unread); built in {secs:.0} s",
        nf as f64 * 16.0 / 1e9,
        r.input_bits,
        r.inputs_by_width[0],
        r.inputs_by_width[1],
        r.inputs_by_width[2],
        r.unread_inputs,
    );
    let mut parts = r.profile.parts.clone();
    parts.sort_by_key(|p| std::cmp::Reverse(p.1));
    for (n, g, c) in parts {
        eprintln!("  {n:<15} {g:>14} non-free {:>6.2}%  ({c} ops)", 100.0 * g as f64 / nf.max(1) as f64);
    }
    assert_eq!(r.profile.total(), nf);
}

#[test]
#[ignore]
fn gate_counts() {
    let Some(t) = tape() else { return };
    let start = std::time::Instant::now();
    let mut b = Count::default();
    let r = binary_tape::translate(&mut b, &t, &t.inputs, Options { check_values: false, limit: None });
    print("binary-stage verifier", &r, b.and, b.or, b.xor, b.wires(), start.elapsed().as_secs_f64());
}

#[test]
#[ignore]
fn accepts_the_real_proof_and_rejects_a_tampered_one() {
    let Some(t) = tape() else { return };
    let start = std::time::Instant::now();
    let mut b = Eval::default();
    let r = binary_tape::translate(&mut b, &t, &t.inputs, Options { check_values: true, limit: None });
    let accepted = b.get(r.output);
    eprintln!(
        "honest proof: output {accepted}; {} wires evaluated in {:.0} s; {} of {} values differ from the tape",
        b.wires(),
        start.elapsed().as_secs_f64(),
        r.mismatches.len(),
        t.values.len()
    );
    assert!(r.mismatches.is_empty(), "first mismatches {:?}", &r.mismatches[..r.mismatches.len().min(5)]);
    assert!(accepted, "the circuit accepts the real binary-stage proof");

    // Change single inputs spread over the proof -- two field elements and
    // one digest byte (tape v1) or the last field element, a digest half in
    // v2: each is rejected.
    let widths = binary_tape::input_widths(&t);
    let read = binary_tape::input_reads(&t);
    let full: Vec<usize> =
        (0..t.inputs.len()).filter(|&i| read[i] && widths[i] == binary_tape::InputWidth::Full).collect();
    let bytes: Vec<usize> =
        (0..t.inputs.len()).filter(|&i| read[i] && widths[i] == binary_tape::InputWidth::Byte).collect();
    let mut rejected = 0;
    let third = if bytes.is_empty() { full[full.len() - 1] } else { bytes[bytes.len() / 2] };
    let picks: Vec<usize> = vec![full[full.len() / 3], full[2 * full.len() / 3], third];
    for &i in &picks {
        let mut inputs = t.inputs.clone();
        inputs[i] ^= 1;
        let mut b = Eval::default();
        let r = binary_tape::translate(&mut b, &t, &inputs, Options { check_values: false, limit: None });
        let accepted = b.get(r.output);
        eprintln!("input {i} changed: output {accepted}");
        if !accepted {
            rejected += 1;
        }
    }
    assert_eq!(rejected, picks.len(), "every single-input change is rejected");
}

#[test]
#[ignore]
fn garbles_with_the_streaming_garbler() {
    let Some(t) = tape() else { return };
    let opts = Options { check_values: false, limit: None };
    let start = std::time::Instant::now();
    let mut plan = Plan::new();
    let r = binary_tape::translate(&mut plan, &t, &t.inputs, opts);
    plan.keep(r.output);
    let plan_secs = start.elapsed().as_secs_f64();
    let wires = plan.wires();
    let start = std::time::Instant::now();
    let mut s = Streaming::planned(plan, false);
    let r = binary_tape::translate(&mut s, &t, &t.inputs, opts);
    let secs = start.elapsed().as_secs_f64();
    let nf = s.non_free_gates();
    eprintln!(
        "streamed: {nf} non-free gates garbled and checked in {secs:.0} s ({:.2} M/s, one core), plan {plan_secs:.0} s over {wires} wires, peak {} live wires; output {}",
        nf as f64 / secs / 1e6,
        s.peak_live(),
        s.value(r.output)
    );
    assert!(s.value(r.output), "the garbled circuit accepts the real proof");
    let _ = s.gate_counts();
}

#[test]
#[ignore]
fn input_widths_follow_the_proof_format() {
    let Some(t) = tape() else { return };
    let w = binary_tape::input_widths(&t);
    let count = |x| w.iter().filter(|&&y| y == x).count();
    let (byte, bit, full) =
        (count(binary_tape::InputWidth::Byte), count(binary_tape::InputWidth::Bit), count(binary_tape::InputWidth::Full));
    eprintln!(
        "{} inputs: {byte} bytes, {bit} bits, {full} field elements = {} bits ({:.0} bytes)",
        w.len(),
        8 * byte + bit + 128 * full,
        (8 * byte + bit + 128 * full) as f64 / 8.0
    );
}
