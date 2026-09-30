//! Deterministic Monte Carlo for the input-size effect of retaining WHIR's
//! pruned Merkle multiproofs.
//!
//! Run with:
//! `cargo test -p whir-gc --test merkle_frontier_sim --release -- --ignored --nocapture`

use std::collections::BTreeMap;

use whir_gc::reference::{self, Sponge};

const QUERIES: [usize; 4] = [33, 20, 15, 12];
// The transcript samples indices in these full domains.  The current cap has
// height five, leaving authentication paths of depths 18, 17, 16 and 15.
const INDEX_WIDTHS: [usize; 4] = [23, 22, 21, 20];
const CAP_HEIGHT: usize = 5;
const CURRENT_INPUT_BITS: usize = 1_041_024;
const DIGEST_BITS: usize = 256;

#[derive(Clone)]
struct SplitMixSponge {
    state: u64,
    bytes: [u8; 8],
    cursor: usize,
}

impl SplitMixSponge {
    fn new(seed: u64) -> Self {
        Self {
            state: seed,
            bytes: [0; 8],
            cursor: 8,
        }
    }

    fn refill(&mut self) {
        self.state = self.state.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.state;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^= z >> 31;
        self.bytes = z.to_le_bytes();
        self.cursor = 0;
    }
}

impl Sponge for SplitMixSponge {
    fn observe(&mut self, _byte: u8) {}

    fn sample(&mut self) -> u8 {
        if self.cursor == self.bytes.len() {
            self.refill();
        }
        let out = self.bytes[self.cursor];
        self.cursor += 1;
        out
    }
}

/// Boundary digests for one binary tree.  This is the same frontier count as
/// `whir_gc::pruned::walk_frontier`: at every level, a parent with one present
/// child needs one boundary digest and a parent with two present children needs
/// none.
fn tree_boundaries(indices: &[usize], depth: usize) -> usize {
    if indices.is_empty() {
        return 0;
    }
    let mut nodes = indices.to_vec();
    nodes.sort_unstable();
    nodes.dedup();
    let mut boundaries = 0;
    for _ in 0..depth {
        let children = nodes.len();
        for node in &mut nodes {
            *node >>= 1;
        }
        nodes.dedup();
        boundaries += 2 * nodes.len() - children;
    }
    boundaries
}

/// The cap is a forest of 2^cap_height independent trees.  Queries in
/// different cap roots cannot share any below-cap authentication nodes.
fn forest_boundaries(indices: &[usize], index_width: usize, cap_height: usize) -> usize {
    let depth = index_width - cap_height;
    let low_mask = (1usize << depth) - 1;
    let mut by_root: BTreeMap<usize, Vec<usize>> = BTreeMap::new();
    for &index in indices {
        by_root
            .entry(index >> depth)
            .or_default()
            .push(index & low_mask);
    }
    by_root
        .values()
        .map(|low| tree_boundaries(low, depth))
        .sum()
}

fn percentile(sorted: &[usize], numerator: usize, denominator: usize) -> usize {
    sorted[(sorted.len() - 1) * numerator / denominator]
}

#[test]
#[ignore = "one-million-sample deterministic simulation"]
fn current_whir_pruned_multiproof_savings() {
    let trials = std::env::var("MERKLE_SIM_TRIALS")
        .ok()
        .map_or(1_000_000, |s| {
            s.parse().expect("MERKLE_SIM_TRIALS is an integer")
        });
    let full_by_round: Vec<usize> = QUERIES
        .iter()
        .zip(INDEX_WIDTHS)
        .map(|(&q, width)| q * (width - CAP_HEIGHT))
        .collect();
    let full: usize = full_by_round.iter().sum();
    assert_eq!(full, 1_354);

    let mut rng = SplitMixSponge::new(0x6d65_726b_6c65_2026);
    let mut round_sums = [0u64; 4];
    let mut totals = Vec::with_capacity(trials);
    for _ in 0..trials {
        let mut total = 0;
        for round in 0..4 {
            // Calls the repository's exact stratified-query assembly routine.
            let indices = reference::stir_queries(&mut rng, INDEX_WIDTHS[round], QUERIES[round]);
            let boundaries = forest_boundaries(&indices, INDEX_WIDTHS[round], CAP_HEIGHT);
            round_sums[round] += boundaries as u64;
            total += boundaries;
        }
        totals.push(total);
    }
    totals.sort_unstable();
    let sum: u64 = totals.iter().map(|&x| x as u64).sum();
    let mean = sum as f64 / trials as f64;
    let saved = full as f64 - mean;
    let saved_bits = saved * DIGEST_BITS as f64;
    let resulting_bits = CURRENT_INPUT_BITS as f64 - saved_bits;

    println!("trials={trials}, cap_height={CAP_HEIGHT}");
    println!(
        "round | queries | full_width | path_depth | full_digests | mean_pruned_digests | mean_saved"
    );
    for round in 0..4 {
        let round_mean = round_sums[round] as f64 / trials as f64;
        println!(
            "{} | {} | {} | {} | {} | {:.6} | {:.6}",
            round + 1,
            QUERIES[round],
            INDEX_WIDTHS[round],
            INDEX_WIDTHS[round] - CAP_HEIGHT,
            full_by_round[round],
            round_mean,
            full_by_round[round] as f64 - round_mean,
        );
    }
    println!(
        "total full={full}, mean_pruned={mean:.6}, mean_saved={saved:.6} digests ({:.4}% of path digests)",
        100.0 * saved / full as f64,
    );
    println!(
        "p0/p1/p50/p99/p100 pruned digests={}/{}/{}/{}/{}",
        totals[0],
        percentile(&totals, 1, 100),
        percentile(&totals, 50, 100),
        percentile(&totals, 99, 100),
        totals[trials - 1],
    );
    println!(
        "ideal data-only result={resulting_bits:.2} bits, saving={saved_bits:.2} bits ({:.4}% of all verifier inputs)",
        100.0 * saved_bits / CURRENT_INPUT_BITS as f64,
    );

    // Reproduce the tempting but incorrect ~10% estimate: sampling in the
    // below-cap path domain makes the strata cover one tree.  In the real
    // transcript they cover the full domain, and mostly select different cap
    // roots, where sharing is impossible.
    let comparison_trials = trials.min(200_000);
    let mut wrong_rng = SplitMixSponge::new(0x7772_6f6e_6720_6361);
    let mut wrong_sum = 0u64;
    for _ in 0..comparison_trials {
        for round in 0..4 {
            let depth = INDEX_WIDTHS[round] - CAP_HEIGHT;
            let indices = reference::stir_queries(&mut wrong_rng, depth, QUERIES[round]);
            wrong_sum += tree_boundaries(&indices, depth) as u64;
        }
    }
    let wrong_mean = wrong_sum as f64 / comparison_trials as f64;
    let wrong_saved_bits = (full as f64 - wrong_mean) * DIGEST_BITS as f64;
    println!(
        "incorrect below-cap stratification model ({comparison_trials} trials): mean_pruned={wrong_mean:.6}, saving={:.4}% of all inputs",
        100.0 * wrong_saved_bits / CURRENT_INPUT_BITS as f64,
    );

    // Basic exact checks for the frontier counter.
    assert_eq!(tree_boundaries(&[0], 3), 3);
    assert_eq!(tree_boundaries(&[0, 1], 3), 2);
    assert_eq!(tree_boundaries(&(0..8).collect::<Vec<_>>(), 3), 0);
}
