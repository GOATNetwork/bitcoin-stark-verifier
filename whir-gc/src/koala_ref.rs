//! A plain-Rust Poseidon2 over KoalaBear, following Plonky3 exactly: the
//! width-16 instance's parameters and the reference functions the KoalaBear
//! circuits ([`crate::koala`], [`crate::ziren`]) are built and checked against.
//!
//! Moved from the Script verifier's `poseidon2` crate (`constants.rs`,
//! `reference.rs`), keeping only what `whir-gc` uses.
//!
//! The parameters are transcribed from Plonky3's `koala-bear/src/poseidon2.rs`
//! (`KOALABEAR_POSEIDON2_RC_16_*`), generated with the Grain LFSR at
//! `field_type=1, alpha=3, n=31, t=16, R_F=8, R_P=20`. Values are canonical,
//! not Montgomery: Plonky3 writes them as literals and passes them through
//! `KoalaBear::new`, which converts on the way in. This is Plonky3's *default*
//! instance; Ziren's own constants are in [`crate::ziren_constants`].

/// The KoalaBear prime, 2^31 - 2^24 + 1.
pub const P: u32 = 0x7f000001;

/// State width.
pub const WIDTH: usize = 16;

/// S-box degree. `KOALABEAR_S_BOX_DEGREE` in Plonky3.
pub const D: u32 = 3;

/// Round constants for the four initial external rounds.
pub const EXTERNAL_INITIAL: [[u32; WIDTH]; 4] = [
    [
        0x7ee56a48, 0x11367045, 0x12e41941, 0x7ebbc12b, 0x1970b7d5, 0x662b60e8,
        0x3e4990c6, 0x679f91f5, 0x350813bb, 0x00874ad4, 0x28a0081a, 0x18fa5872,
        0x5f25b071, 0x5e5d5998, 0x5e6fd3e7, 0x5b2e2660,
    ],
    [
        0x6f1837bf, 0x3fe6182b, 0x1edd7ac5, 0x57470d00, 0x43d486d5, 0x1982c70f,
        0x0ea53af9, 0x61d6165b, 0x51639c00, 0x2dec352c, 0x2950e531, 0x2d2cb947,
        0x08256cef, 0x1a0109f6, 0x1f51faf3, 0x5cef1c62,
    ],
    [
        0x3d65e50e, 0x33d91626, 0x133d5a1e, 0x0ff49b0d, 0x38900cd1, 0x2c22cc3f,
        0x28852bb2, 0x06c65a02, 0x7b2cf7bc, 0x68016e1a, 0x15e16bc0, 0x5248149a,
        0x6dd212a0, 0x18d6830a, 0x5001be82, 0x64dac34e,
    ],
    [
        0x5902b287, 0x426583a0, 0x0c921632, 0x3fe028a5, 0x245f8e49, 0x43bb297e,
        0x7873dbd9, 0x3cc987df, 0x286bb4ce, 0x640a8dcd, 0x512a8e36, 0x03a4cf55,
        0x481837a2, 0x03d6da84, 0x73726ac7, 0x760e7fdf,
    ],
];

/// Round constants for the four terminal external rounds.
pub const EXTERNAL_FINAL: [[u32; WIDTH]; 4] = [
    [
        0x43e7dc24, 0x259a5d61, 0x27e85a3b, 0x1b9133fa, 0x343e5628, 0x485cd4c2,
        0x16e269f5, 0x165b60c6, 0x25f683d9, 0x124f81f9, 0x174331f9, 0x77344dc5,
        0x5a821dba, 0x5fc4177f, 0x54153bf5, 0x5e3f1194,
    ],
    [
        0x3bdbf191, 0x088c84a3, 0x68256c9b, 0x3c90bbc6, 0x6846166a, 0x03f4238d,
        0x463335fb, 0x5e3d3551, 0x6e59ae6f, 0x32d06cc0, 0x596293f3, 0x6c87edb2,
        0x08fc60b5, 0x34bcca80, 0x24f007f3, 0x62731c6f,
    ],
    [
        0x1e1db6c6, 0x0ca409bb, 0x585c1e78, 0x56e94edc, 0x16d22734, 0x18e11467,
        0x7b2c3730, 0x770075e4, 0x35d1b18c, 0x22be3db5, 0x4fb1fbb7, 0x477cb3ed,
        0x7d5311c6, 0x5b62ae7d, 0x559c5fa8, 0x77f15048,
    ],
    [
        0x3211570b, 0x490fef6a, 0x77ec311f, 0x2247171b, 0x4e0ac711, 0x2edf69c9,
        0x3b5a8850, 0x65809421, 0x5619b4aa, 0x362019a7, 0x6bf9d4ed, 0x5b413dff,
        0x617e181e, 0x5e7ab57b, 0x33ad7833, 0x3466c7ca,
    ],
];

/// Round constants for the partial rounds. Only `state[0]` takes one.
pub const INTERNAL: [u32; 20] = [
    0x54dfeb5d, 0x7d40afd6, 0x722cb316, 0x106a4573, 0x45a7ccdb, 0x44061375,
    0x154077a5, 0x45744faa, 0x4eb5e5ee, 0x3794e83f, 0x47c7093c, 0x5694903c,
    0x69cb6299, 0x373df84c, 0x46a0df58, 0x46b8758a, 0x3241ebcb, 0x0b09d233,
    0x1af42357, 0x1e66cec2,
];

#[inline]
pub fn add(a: u32, b: u32) -> u32 {
    let s = a as u64 + b as u64;
    (if s >= P as u64 { s - P as u64 } else { s }) as u32
}

#[inline]
pub fn sub(a: u32, b: u32) -> u32 {
    if a >= b {
        a - b
    } else {
        a + P - b
    }
}

#[inline]
pub fn mul(a: u32, b: u32) -> u32 {
    ((a as u64 * b as u64) % P as u64) as u32
}

#[inline]
pub fn double(a: u32) -> u32 {
    add(a, a)
}

/// `a / 2^k`, i.e. `a * (2^k)^-1`.
pub fn div_2exp(a: u32, k: u32) -> u32 {
    let half = ((P as u64 + 1) / 2) as u32;
    let mut acc = a;
    for _ in 0..k {
        acc = mul(acc, half);
    }
    acc
}

/// The S-box, `x^3`.
pub fn sbox(x: u32) -> u32 {
    debug_assert_eq!(D, 3);
    mul(mul(x, x), x)
}

/// Plonky3's `apply_mat4`, the 4x4 MDS block.
fn apply_mat4(x: &mut [u32; 4]) {
    let t01 = add(x[0], x[1]);
    let t23 = add(x[2], x[3]);
    let t0123 = add(t01, t23);
    let t01123 = add(t0123, x[1]);
    let t01233 = add(t0123, x[3]);
    x[3] = add(t01233, double(x[0]));
    x[1] = add(t01123, double(x[2]));
    x[0] = add(t01123, t01);
    x[2] = add(t01233, t23);
}

/// Plonky3's `mds_light_permutation` for a width that is a multiple of four:
/// `M4` on each chunk, then add the four column sums.
pub fn mds_light(state: &mut [u32; WIDTH]) {
    for chunk in state.chunks_exact_mut(4) {
        let mut c: [u32; 4] = chunk.try_into().unwrap();
        apply_mat4(&mut c);
        chunk.copy_from_slice(&c);
    }
    let mut sums = [0u32; 4];
    for (k, s) in sums.iter_mut().enumerate() {
        for j in (0..WIDTH).step_by(4) {
            *s = add(*s, state[j + k]);
        }
    }
    for (i, e) in state.iter_mut().enumerate() {
        *e = add(*e, sums[i % 4]);
    }
}

/// Plonky3's internal linear layer for KoalaBear at width 16.
///
/// `new[i] = full_sum + V[i] * old[i]` with
/// `V = [-2, 1, 2, 1/2, 3, 4, -1/2, -3, -4, 1/2^8, 1/8, 1/2^24, -1/2^8, -1/8, -1/16, -1/2^24]`.
/// Plonky3 handles `state[0]` outside the diagonal, as `part_sum - state[0]`,
/// which is the same thing.
pub fn internal_linear(state: &mut [u32; WIDTH]) {
    let mut part_sum = 0u32;
    for s in state.iter().skip(1) {
        part_sum = add(part_sum, *s);
    }
    let full_sum = add(part_sum, state[0]);
    let s = *state;

    state[0] = sub(part_sum, s[0]);
    state[1] = add(s[1], full_sum);
    state[2] = add(double(s[2]), full_sum);
    state[3] = add(div_2exp(s[3], 1), full_sum);
    state[4] = add(full_sum, add(double(s[4]), s[4]));
    state[5] = add(full_sum, double(double(s[5])));
    state[6] = sub(full_sum, div_2exp(s[6], 1));
    state[7] = sub(full_sum, add(double(s[7]), s[7]));
    state[8] = sub(full_sum, double(double(s[8])));
    state[9] = add(div_2exp(s[9], 8), full_sum);
    state[10] = add(div_2exp(s[10], 3), full_sum);
    state[11] = add(div_2exp(s[11], 24), full_sum);
    state[12] = sub(full_sum, div_2exp(s[12], 8));
    state[13] = sub(full_sum, div_2exp(s[13], 3));
    state[14] = sub(full_sum, div_2exp(s[14], 4));
    state[15] = sub(full_sum, div_2exp(s[15], 24));
}

/// The full permutation (the oracle the circuits' tests compare against).
#[cfg(test)]
pub fn permute(state: &mut [u32; WIDTH]) {
    mds_light(state);
    for rc in EXTERNAL_INITIAL.iter() {
        for (s, c) in state.iter_mut().zip(rc.iter()) {
            *s = sbox(add(*s, *c));
        }
        mds_light(state);
    }
    for c in INTERNAL.iter() {
        state[0] = sbox(add(state[0], *c));
        internal_linear(state);
    }
    for rc in EXTERNAL_FINAL.iter() {
        for (s, c) in state.iter_mut().zip(rc.iter()) {
            *s = sbox(add(*s, *c));
        }
        mds_light(state);
    }
}

/// Quartic extension arithmetic, `KoalaBear[X]/(X^4 - 3)`.
pub mod ext4 {
    use super::{add as fadd, mul as fmul, sub as fsub};
    /// The non-residue.
    pub const W: u32 = 3;

    pub fn add(a: [u32; 4], b: [u32; 4]) -> [u32; 4] {
        core::array::from_fn(|i| fadd(a[i], b[i]))
    }

    pub fn sub(a: [u32; 4], b: [u32; 4]) -> [u32; 4] {
        core::array::from_fn(|i| fsub(a[i], b[i]))
    }

    /// Schoolbook, as Plonky3's generic `binomial_mul` branch does it.
    pub fn mul(a: [u32; 4], b: [u32; 4]) -> [u32; 4] {
        let mut res = [0u32; 4];
        for i in 0..4 {
            for j in 0..4 {
                let t = fmul(a[i], b[j]);
                if i + j >= 4 {
                    res[i + j - 4] = fadd(res[i + j - 4], fmul(W, t));
                } else {
                    res[i + j] = fadd(res[i + j], t);
                }
            }
        }
        res
    }
}

/// `PaddingFreeSponge<_, 16, 8, 8>`, Plonky3's row hash.
///
/// Overwrite the first `RATE` state elements with each chunk and permute. A
/// partial final chunk overwrites only what it fills and leaves the rest of the
/// state alone — no padding, no length tag, which is what distinguishes this
/// from the challenger's duplex.
#[cfg(test)]
pub fn hash_row(row: &[u32]) -> [u32; 8] {
    const RATE: usize = 8;
    let mut state = [0u32; WIDTH];
    for chunk in row.chunks(RATE) {
        state[..chunk.len()].copy_from_slice(chunk);
        permute(&mut state);
    }
    state[..8].try_into().expect("state is wider than a digest")
}

#[cfg(test)]
mod tests {
    //! The reference must agree with Plonky3's own
    //! `default_koalabear_poseidon2_16`: if Plonky3 changes its constants or
    //! its linear layers, this fails rather than the circuits quietly computing
    //! a different hash.

    use super::{permute, P, WIDTH};
    use p3_field::PrimeField32;
    use p3_koala_bear::{default_koalabear_poseidon2_16, KoalaBear};
    use p3_symmetric::Permutation;
    use rand::{Rng, SeedableRng};
    use rand_chacha::ChaCha20Rng;

    fn plonky3(raw: [u32; WIDTH]) -> Vec<u32> {
        let mut theirs: [KoalaBear; WIDTH] = core::array::from_fn(|i| KoalaBear::new(raw[i]));
        default_koalabear_poseidon2_16().permute_mut(&mut theirs);
        theirs.iter().map(|x| x.as_canonical_u32()).collect()
    }

    #[test]
    fn reference_matches_plonky3() {
        let mut rng = ChaCha20Rng::seed_from_u64(7);
        for _ in 0..8 {
            let raw: [u32; WIDTH] = core::array::from_fn(|_| rng.random_range(0..P));
            let mut ours = raw;
            permute(&mut ours);
            assert_eq!(ours.to_vec(), plonky3(raw), "reference diverged from Plonky3");
        }
    }

    /// The all-zero input is the case most likely to hide a missing round constant.
    #[test]
    fn reference_matches_plonky3_on_zero() {
        let mut ours = [0u32; WIDTH];
        permute(&mut ours);
        assert_eq!(ours.to_vec(), plonky3([0u32; WIDTH]));
    }
}
