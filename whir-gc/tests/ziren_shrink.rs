//! Ziren's compressed-proof verifier (its `shrink` recursion program) as a
//! garbled circuit: exact gate counts, with and without Merkle deduplication,
//! and gate-level evaluation on a real compressed proof.
//!
//! The dump is produced by `paper/data/ziren_dump_shrink.rs` from a Ziren
//! compressed proof; set `ZIREN_SHRINK_DUMP` or put it at
//! `target/ziren-shrink.bin`. Run with
//! `cargo test --release -p whir-gc --test ziren_shrink -- --ignored --nocapture`.

use whir_gc::ziren::{self, Count, Dump, Eval, Options, Report, Translator, Tree};

fn dump() -> Option<Dump> {
    let path = std::env::var("ZIREN_SHRINK_DUMP").unwrap_or_else(|_| concat!(env!("CARGO_MANIFEST_DIR"), "/../target/ziren-shrink.bin").into());
    let bytes = std::fs::read(&path).ok()?;
    Some(ziren::parse(&bytes))
}

/// Fixed frontier per tree depth: mean + 8 standard deviations of the
/// number of levels needing a fresh digest for uniform query indices
/// (200,000 trials: depth 20, 124 paths 1631.1 ± 14.2; depth 17, 88 paths
/// 937.0 ± 11.9; depth 14, 85 paths 654.7 ± 11.4).
fn trees(d: &Dump) -> Vec<Tree> {
    let mut t = ziren::merkle_trees(d);
    for tree in &mut t {
        tree.frontier = match (tree.depth, tree.paths.len()) {
            (20, 124) => 1750,
            (17, 88) => 1040,
            (14, 85) => 750,
            _ => 0,
        };
    }
    t
}

fn tampered(d: &Dump) -> (Vec<[u32; 4]>, usize) {
    // Change one witness word that the verifier hashes into a Merkle leaf:
    // the first witness word that the native run reports as rejected when
    // changed, searching from the middle of the stream.
    let mut w = d.witness.clone();
    for i in (d.witness.len() / 2)..d.witness.len() {
        let orig = w[i];
        w[i][0] = (w[i][0] + 1) % ziren::P;
        if !ziren::run_native(d, &w).failures.is_empty() {
            return (w, i);
        }
        w[i] = orig;
    }
    panic!("no rejecting tamper found")
}

#[test]
#[ignore]
fn native_semantics_accept_the_real_proof() {
    let Some(d) = dump() else { return };
    let mut s: [u32; 16] = core::array::from_fn(|i| i as u32);
    ziren::permute(&mut s);
    assert_eq!(s, d.poseidon2_test, "the program's Poseidon2 under Ziren's constants");
    let n = ziren::run_native(&d, &d.witness);
    assert!(n.failures.is_empty(), "honest run fails at {:?}", &n.failures[..n.failures.len().min(5)]);
    let t = trees(&d);
    for tree in &t {
        let bits: Vec<Vec<bool>> = tree.paths.iter().map(|p| p.iter().map(|lv| n.mem[lv.bit as usize][0] == 1).collect()).collect();
        let need = ziren::needs(&bits).iter().filter(|&&x| x).count();
        eprintln!("tree depth {} paths {}: {} sibling digests, {} needed with deduplication, frontier {}", tree.depth, tree.paths.len(), tree.depth * tree.paths.len(), need, tree.frontier);
        assert!(tree.paths.len() == 1 || need <= tree.frontier);
    }
    let (_, i) = tampered(&d);
    eprintln!("tampered witness word {i} is rejected natively");
}

fn print(name: &str, r: &Report, and: usize, or: usize, xor: usize, wires: usize, secs: f64) {
    let nf = and + or;
    eprintln!(
        "{name}: {nf} non-free gates ({and} AND, {or} OR), {xor} XOR, {wires} wires; garbled {:.1} GB at 16 B per non-free gate; inputs {} bits ({} witness + {} frontier); built in {secs:.0} s",
        nf as f64 * 16.0 / 1e9,
        r.input_bits,
        r.hint_input_bits,
        r.frontier_input_bits,
    );
    for (depth, paths, f) in &r.frontier_digests {
        eprintln!("  tree depth {depth}, {paths} paths: {} digests replaced by {f}", depth * paths);
    }
    let mut parts = r.profile.parts.clone();
    parts.sort_by_key(|p| std::cmp::Reverse(p.1));
    for (n, g, c) in parts {
        eprintln!("  {n:<26} {g:>16} non-free {:>6.2}%  ({c} instructions)", 100.0 * g as f64 / nf as f64);
    }
    assert_eq!(r.profile.total(), nf);
}

#[test]
#[ignore]
fn gate_counts_with_and_without_merkle_deduplication() {
    let Some(d) = dump() else { return };
    let n = ziren::run_native(&d, &d.witness);
    let t = trees(&d);
    let variants: Vec<bool> = match std::env::var("ZIREN_VARIANT").as_deref() {
        Ok("full") => vec![false],
        Ok("dedup") => vec![true],
        _ => vec![false, true],
    };
    for dedup in variants {
        let start = std::time::Instant::now();
        let mut b = Count::default();
        let r = Translator::new(&mut b, &d, &n, &d.witness, &t, Options { dedup, limit: None, check_writes: false }).run();
        let (and, or, xor, wires) = (b.and, b.or, b.xor, b.wires());
        print(if dedup { "with Merkle deduplication" } else { "full Merkle paths" }, &r, and, or, xor, wires, start.elapsed().as_secs_f64());
    }
}

#[test]
#[ignore]
fn deduplicated_circuit_accepts_the_real_proof_and_rejects_a_tampered_one() {
    let Some(d) = dump() else { return };
    let t = trees(&d);
    let n = ziren::run_native(&d, &d.witness);
    let start = std::time::Instant::now();
    let mut b = Eval::default();
    let report = Translator::new(&mut b, &d, &n, &d.witness, &t, Options { dedup: true, limit: None, check_writes: true }).run();
    let accepted = b.get(report.output);
    let secs = start.elapsed().as_secs_f64();
    print("with Merkle deduplication (evaluated)", &report, b.and, b.or, b.xor, b.wires(), secs);
    eprintln!("honest proof: output {accepted}; {} wires evaluated in {secs:.0} s; {} values differ from the native run", b.wires(), report.mismatches.len());
    assert!(report.mismatches.is_empty(), "first mismatches {:?}", &report.mismatches[..report.mismatches.len().min(5)]);
    assert!(accepted, "the circuit accepts the real compressed proof");
    drop(b);

    let (w, i) = tampered(&d);
    let n = ziren::run_native(&d, &w);
    let mut b = Eval::default();
    let report = Translator::new(&mut b, &d, &n, &w, &t, Options { dedup: true, limit: None, check_writes: false }).run();
    let accepted = b.get(report.output);
    eprintln!("witness word {i} changed: output {accepted}");
    assert!(!accepted, "the circuit rejects a tampered proof");
}

/// Garble a real prefix of the translated verifier with the streaming
/// garbler (random Δ, Blake3 half-gates), to measure throughput on these
/// gadgets. The whole circuit cannot be streamed under a 32 GB cap: the
/// liveness plan costs a byte per wire.
#[test]
#[ignore]
fn garbling_throughput_on_a_real_prefix() {
    use garbled_snark_verifier::circuits::sect233k1::stream::{Plan, Streaming};
    let Some(d) = dump() else { return };
    let t = trees(&d);
    let n = ziren::run_native(&d, &d.witness);
    let limit = std::env::var("ZIREN_PREFIX").ok().and_then(|v| v.parse().ok()).unwrap_or(200_000);
    let opts = Options { dedup: true, limit: Some(limit), check_writes: false };
    let mut plan = Plan::new();
    let r = Translator::new(&mut plan, &d, &n, &d.witness, &t, opts).run();
    plan.keep(r.output);
    let start = std::time::Instant::now();
    let mut s = Streaming::planned(plan, false);
    let r = Translator::new(&mut s, &d, &n, &d.witness, &t, opts).run();
    let secs = start.elapsed().as_secs_f64();
    let nf = s.non_free_gates();
    eprintln!(
        "prefix of {limit} instructions: {nf} non-free gates garbled and checked in {secs:.1} s, {:.2} M non-free gates/s on one core; prefix accepted so far: {}; peak live wires {}",
        nf as f64 / secs / 1e6,
        s.value(r.output),
        s.peak_live()
    );
}
