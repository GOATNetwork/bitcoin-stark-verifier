//! The verifier of Ziren's binary stage as a Boolean circuit, from its tape.
//!
//! Ziren's `binary-recursion` crate records the binary stage's verifier --
//! Plonky3's multi-STARK verifier over `GF(2^128)` with Boolean WHIR and
//! Blake3 -- as a straight-line program: a tape of operations on values of
//! `GF(2^128)` (the Wiedemann tower field, the same `BinaryField128` the
//! [`crate::tower`] gadgets implement). This module translates the tape
//! operation by operation, with the semantics of the tape's own `run`:
//!
//! * `Add` is XOR, `Mul` is [`tower::mul`], `Inv` checks its operand is not
//!   zero and inverts by an addition chain of free squarings and twelve
//!   multiplications;
//! * `AssertEq` and `AssertNonZero` become check bits;
//! * an operand read as a byte (by `FromBytes`, `ByteBits` or `Blake3`) must
//!   hold one, and a selector must hold `0` or `1`; where the wires do not
//!   already guarantee it, that is a check bit too;
//! * `ToBytes`, `FromBytes`, `ByteBits`, `Transpose` and `Square` are
//!   wiring and XOR;
//! * `Blake3` is the tree-mode Blake3 circuit of `bitvm-gc`, over bytes
//!   (tape v1) or over the first `len` little-endian bytes of whole elements,
//!   the rest checked zero (v2);
//! * `MerkleNode` (v2) orders its two digests by a bit, one 256-wire
//!   multiplexer (the other order is free), and hashes the 64 bytes;
//! * `Select` is a 128-wire multiplexer.
//!
//! The output is the AND of every check. A proof input that must hold a byte
//! is 8 circuit-input bits: one read as a byte operand, or a data operand of
//! a select whose output must, or asserted equal to a byte. The proof
//! serializes its Merkle digests as bytes, and those reach their hashes
//! through Merkle-order selects and root comparisons; this recognises them,
//! and the honest value is asserted to be a byte. An input read only as a
//! selector is 1 bit, and every other is 128.
//!
//! The dump this reads is written by Ziren's `crates/prover/tests/dump_binary_tape.rs`,
//! which `patches/ziren-9398469a.patch` adds.

use garbled_snark_verifier::circuits::sect233k1::blake3_ckt as blake3;
use garbled_snark_verifier::circuits::sect233k1::builder::CircuitTrait;
use garbled_snark_verifier::circuits::sect233k1::stream::ValuedBuilder;

use crate::koala::mux_words;
use crate::tower;
use crate::ziren::Probe;

pub const W: usize = 128;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Opd {
    Var(u32),
    Const(u128),
}

#[derive(Clone, Debug)]
pub enum TOp {
    Input(u64),
    Add(Opd, Opd),
    Mul(Opd, Opd),
    Inv(Opd),
    AssertEq(Opd, Opd),
    AssertNonZero(Opd),
    ToBytes(Opd),
    FromBytes(Vec<Opd>),
    ByteBits(Opd),
    Blake3(Vec<Opd>),
    Transpose(Vec<Opd>),
    Select(Opd, Opd, Opd),
    /// Tape v2: the digest of the first `len` bytes of the slots, as two
    /// elements.
    Blake3Slots { slots: Vec<Opd>, len: usize },
    /// Tape v2: the digest of `cur ‖ sib`, or `sib ‖ cur` if the bit is one.
    MerkleNode { bit: Opd, cur: [Opd; 2], sib: [Opd; 2] },
    Square(Opd),
}

impl TOp {
    /// Variables the operation defines.
    pub fn defines(&self) -> usize {
        match self {
            TOp::Input(_)
            | TOp::Add(..)
            | TOp::Mul(..)
            | TOp::Square(_)
            | TOp::Inv(_)
            | TOp::FromBytes(_)
            | TOp::Select(..) => 1,
            TOp::Blake3Slots { .. } | TOp::MerkleNode { .. } => 2,
            TOp::AssertEq(..) | TOp::AssertNonZero(_) => 0,
            TOp::ToBytes(_) => 16,
            TOp::ByteBits(_) => 8,
            TOp::Blake3(_) => 32,
            TOp::Transpose(_) => 128,
        }
    }

    pub fn operands(&self) -> Vec<Opd> {
        match self {
            TOp::Input(_) => vec![],
            TOp::Add(a, b) | TOp::Mul(a, b) | TOp::AssertEq(a, b) => vec![*a, *b],
            TOp::Inv(a) | TOp::AssertNonZero(a) | TOp::ToBytes(a) | TOp::ByteBits(a) | TOp::Square(a) => vec![*a],
            TOp::FromBytes(v) | TOp::Blake3(v) | TOp::Transpose(v) | TOp::Blake3Slots { slots: v, .. } => v.clone(),
            TOp::MerkleNode { bit, cur, sib } => vec![*bit, cur[0], cur[1], sib[0], sib[1]],
            TOp::Select(s, a, b) => vec![*s, *a, *b],
        }
    }

    pub fn kind(&self) -> &'static str {
        match self {
            TOp::Input(_) => "input",
            TOp::Add(..) => "add",
            TOp::Mul(..) => "mul",
            TOp::Inv(_) => "inv",
            TOp::AssertEq(..) => "assert_eq",
            TOp::AssertNonZero(_) => "assert_nonzero",
            TOp::ToBytes(_) => "to_bytes",
            TOp::FromBytes(_) => "from_bytes",
            TOp::ByteBits(_) => "byte_bits",
            TOp::Blake3(_) => "blake3",
            TOp::Transpose(_) => "transpose",
            TOp::Select(..) => "select",
            TOp::Blake3Slots { .. } => "blake3",
            TOp::MerkleNode { .. } => "merkle_node",
            TOp::Square(_) => "square",
        }
    }
}

pub struct BTape {
    pub ops: Vec<TOp>,
    pub inputs: Vec<u128>,
    pub values: Vec<u128>,
}

struct Rd<'a> {
    d: &'a [u8],
    o: usize,
}
impl Rd<'_> {
    fn u8(&mut self) -> u8 {
        self.o += 1;
        self.d[self.o - 1]
    }
    fn u32(&mut self) -> u32 {
        self.o += 4;
        u32::from_le_bytes(self.d[self.o - 4..self.o].try_into().unwrap())
    }
    fn u64(&mut self) -> u64 {
        self.o += 8;
        u64::from_le_bytes(self.d[self.o - 8..self.o].try_into().unwrap())
    }
    fn u128(&mut self) -> u128 {
        self.o += 16;
        u128::from_le_bytes(self.d[self.o - 16..self.o].try_into().unwrap())
    }
    fn opd(&mut self) -> Opd {
        match self.u8() {
            0 => Opd::Var(self.u32()),
            1 => Opd::Const(self.u128()),
            t => panic!("operand tag {t}"),
        }
    }
    fn opds(&mut self) -> Vec<Opd> {
        let n = self.u32() as usize;
        (0..n).map(|_| self.opd()).collect()
    }
}

pub fn parse(bytes: &[u8]) -> BTape {
    assert_eq!(&bytes[..4], b"ZTAP", "not a binary-stage tape");
    let mut r = Rd { d: bytes, o: 4 };
    let version = r.u32();
    assert!(version == 1 || version == 2, "tape version {version}");
    let n = r.u64() as usize;
    let mut ops = Vec::with_capacity(n);
    for _ in 0..n {
        let t = r.u8();
        ops.push(match t {
            0 => TOp::Input(r.u64()),
            1 => TOp::Add(r.opd(), r.opd()),
            2 => TOp::Mul(r.opd(), r.opd()),
            3 => TOp::Inv(r.opd()),
            4 => TOp::AssertEq(r.opd(), r.opd()),
            5 => TOp::AssertNonZero(r.opd()),
            6 => TOp::ToBytes(r.opd()),
            7 => TOp::FromBytes(r.opds()),
            8 => TOp::ByteBits(r.opd()),
            9 if version == 1 => TOp::Blake3(r.opds()),
            9 => {
                let slots = r.opds();
                TOp::Blake3Slots { slots, len: r.u64() as usize }
            }
            10 => TOp::Transpose(r.opds()),
            11 => {
                let s = r.opd();
                let a = r.opd();
                let b = r.opd();
                TOp::Select(s, a, b)
            }
            12 if version == 2 => {
                let bit = r.opd();
                let cur = [r.opd(), r.opd()];
                let sib = [r.opd(), r.opd()];
                TOp::MerkleNode { bit, cur, sib }
            }
            13 if version == 2 => TOp::Square(r.opd()),
            _ => panic!("op tag {t} in tape v{version}"),
        });
    }
    let ni = r.u64() as usize;
    let inputs = (0..ni).map(|_| r.u128()).collect();
    let nv = r.u64() as usize;
    let values = (0..nv).map(|_| r.u128()).collect();
    assert_eq!(r.o, bytes.len(), "trailing bytes in tape");
    BTape { ops, inputs, values }
}

/// Whether each proof input is read by any operation.
pub fn input_reads(t: &BTape) -> Vec<bool> {
    let total: usize = t.ops.iter().map(TOp::defines).sum();
    let mut read = vec![false; total];
    for op in &t.ops {
        for o in op.operands() {
            if let Opd::Var(v) = o {
                read[v as usize] = true;
            }
        }
    }
    let mut by_input = vec![false; t.inputs.len()];
    let mut var = 0usize;
    for op in &t.ops {
        if let TOp::Input(n) = op {
            by_input[*n as usize] = read[var];
        }
        var += op.defines();
    }
    by_input
}

/// How each proof input is read: as a byte only, as a selector only, or as
/// a field element.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InputWidth {
    Byte,
    Bit,
    Full,
}

pub fn input_widths(t: &BTape) -> Vec<InputWidth> {
    // Variables in definition order, with the op that defines each.
    let mut def_op: Vec<usize> = Vec::new();
    let mut var_input: Vec<Option<usize>> = Vec::new();
    for (k, op) in t.ops.iter().enumerate() {
        for _ in 0..op.defines() {
            def_op.push(k);
            var_input.push(if let TOp::Input(n) = op { Some(*n as usize) } else { None });
        }
    }
    let total = def_op.len();
    // A byte by construction: the outputs of ToBytes, ByteBits and Blake3.
    let byte_wired: Vec<bool> =
        def_op.iter().map(|&k| matches!(t.ops[k], TOp::ToBytes(_) | TOp::ByteBits(_) | TOp::Blake3(_))).collect();
    // A byte by necessity: read as a byte operand, or a data operand of a
    // select whose output is, or asserted equal to a byte.  Digest bytes of
    // the proof reach their hash through Merkle-order selects and root
    // comparisons, so this is how the proof format's bytes are recognised.
    let mut forced = vec![false; total];
    let set = |o: &Opd, forced: &mut Vec<bool>| -> bool {
        if let Opd::Var(v) = o {
            if !forced[*v as usize] {
                forced[*v as usize] = true;
                return true;
            }
        }
        false
    };
    let is_byte = |o: &Opd, forced: &Vec<bool>| -> bool {
        match o {
            Opd::Var(v) => forced[*v as usize] || byte_wired[*v as usize],
            Opd::Const(c) => *c < 256,
        }
    };
    let mut changed = true;
    while changed {
        changed = false;
        let mut var = total;
        for op in t.ops.iter().rev() {
            var -= op.defines();
            match op {
                TOp::FromBytes(v) | TOp::Blake3(v) => {
                    for o in v {
                        changed |= set(o, &mut forced);
                    }
                }
                TOp::ByteBits(o) => changed |= set(o, &mut forced),
                TOp::Select(_, x, y) => {
                    if forced[var] {
                        changed |= set(x, &mut forced);
                        changed |= set(y, &mut forced);
                    }
                }
                TOp::AssertEq(x, y) => {
                    if is_byte(y, &forced) {
                        changed |= set(x, &mut forced);
                    }
                    if is_byte(x, &forced) {
                        changed |= set(y, &mut forced);
                    }
                }
                _ => {}
            }
        }
    }
    // Selector-only inputs: every use is as a select's selector.
    let mut selector_only = vec![true; t.inputs.len()];
    let mut used = vec![false; t.inputs.len()];
    for op in &t.ops {
        let (sel, rest) = match op {
            TOp::Select(s, x, y) => (Some(*s), vec![*x, *y]),
            TOp::MerkleNode { bit, cur, sib } => (Some(*bit), vec![cur[0], cur[1], sib[0], sib[1]]),
            other => (None, other.operands()),
        };
        if let Some(Opd::Var(v)) = sel {
            if let Some(i) = var_input[v as usize] {
                used[i] = true;
            }
        }
        for o in rest {
            if let Opd::Var(v) = o {
                if let Some(i) = var_input[v as usize] {
                    used[i] = true;
                    selector_only[i] = false;
                }
            }
        }
    }
    let mut widths = vec![InputWidth::Full; t.inputs.len()];
    for v in 0..total {
        if let Some(i) = var_input[v] {
            widths[i] = if forced[v] {
                assert!(t.inputs[i] < 256, "input {i} is forced to a byte but holds {:#x}", t.inputs[i]);
                InputWidth::Byte
            } else if used[i] && selector_only[i] {
                assert!(t.inputs[i] < 2, "input {i} is a selector but holds {:#x}", t.inputs[i]);
                InputWidth::Bit
            } else {
                InputWidth::Full
            };
        }
    }
    widths
}

// ---------------------------------------------------------------------------
// Gadgets.
// ---------------------------------------------------------------------------

fn not<T: CircuitTrait>(b: &mut T, x: usize) -> usize {
    let one = b.one();
    b.xor_wire(x, one)
}

fn or_all<T: CircuitTrait>(b: &mut T, xs: &[usize]) -> usize {
    let mut v: Vec<usize> = xs.to_vec();
    if v.is_empty() {
        return b.zero();
    }
    while v.len() > 1 {
        let mut n = Vec::with_capacity(v.len().div_ceil(2));
        for c in v.chunks(2) {
            n.push(if c.len() == 2 { b.or_wire(c[0], c[1]) } else { c[0] });
        }
        v = n;
    }
    v[0]
}

fn is_zero<T: CircuitTrait>(b: &mut T, xs: &[usize]) -> usize {
    let o = or_all(b, xs);
    not(b, o)
}

/// `x^(2^128 - 2)`: `a_k = x^(2^k - 1)` up to `k = 127` by
/// `a_{2k} = a_k^(2^k)·a_k`, `a_{k+1} = a_k^2·x`, then one squaring.
/// Squarings are linear in the tower basis (no AND gates).
pub fn inverse<T: CircuitTrait>(b: &mut T, x: &[usize]) -> Vec<usize> {
    fn sq_n<T: CircuitTrait>(b: &mut T, v: &[usize], n: usize) -> Vec<usize> {
        let mut t = v.to_vec();
        for _ in 0..n {
            t = tower::square(b, &t);
        }
        t
    }
    let mut a = x.to_vec(); // a_1
    let mut k = 1usize;
    for bit in [1usize, 1, 1, 1, 1, 1] {
        // 127 = 0b1111111: double then add one, six times.
        let t = sq_n(b, &a, k);
        a = tower::mul(b, &t, &a);
        k *= 2;
        if bit == 1 {
            let t = tower::square(b, &a);
            a = tower::mul(b, &t, x);
            k += 1;
        }
    }
    debug_assert_eq!(k, 127);
    tower::square(b, &a)
}

/// The Blake3 digest of `msg` as two elements, its low and high sixteen
/// bytes, little-endian.
fn digest_halves<T: CircuitTrait>(b: &mut T, msg: &[[usize; 8]]) -> [Vec<usize>; 2] {
    let digest = blake3::hash_bytes(b, msg);
    let wires: Vec<usize> = digest.iter().flat_map(|by| by.iter().copied()).collect();
    [wires[..W].to_vec(), wires[W..].to_vec()]
}

// ---------------------------------------------------------------------------
// The translation.
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug)]
pub struct Options {
    /// Compare every defined variable against the tape's honest values.
    pub check_values: bool,
    /// Stop after this many operations.
    pub limit: Option<usize>,
}

#[derive(Default, Debug, Clone)]
pub struct Profile {
    pub parts: Vec<(&'static str, usize, usize)>,
}

impl Profile {
    fn add(&mut self, name: &'static str, gates: usize) {
        if let Some(e) = self.parts.iter_mut().find(|e| e.0 == name) {
            e.1 += gates;
            e.2 += 1;
        } else {
            self.parts.push((name, gates, 1));
        }
    }
    pub fn total(&self) -> usize {
        self.parts.iter().map(|e| e.1).sum()
    }
}

pub struct Report {
    pub output: usize,
    pub input_bits: usize,
    pub inputs_by_width: [usize; 3],
    /// Inputs the circuit never reads: no wires, no labels, nothing to publish.
    pub unread_inputs: usize,
    pub profile: Profile,
    pub mismatches: Vec<u32>,
}

fn non_free<T: CircuitTrait>(b: &T) -> usize {
    let c = b.gate_counts();
    c.direct_and + c.direct_or
}

pub fn translate<T: ValuedBuilder + Probe>(b: &mut T, t: &BTape, inputs: &[u128], opts: Options) -> Report {
    let widths = input_widths(t);
    // Remaining reads per variable, to free wires after their last use.
    let total_vars: usize = t.ops.iter().map(TOp::defines).sum();
    let mut reads = vec![0u32; total_vars];
    for op in &t.ops {
        for o in op.operands() {
            if let Opd::Var(v) = o {
                reads[v as usize] += 1;
            }
        }
    }
    let mut vars: Vec<Option<Box<[usize]>>> = vec![None; total_vars];
    let mut ok = b.one();
    let mut profile = Profile::default();
    let mut mismatches = Vec::new();
    let mut next: u32 = 0;
    let mut input_bits = 0usize;
    let mut by_width = [0usize; 3];
    let mut unread_inputs = 0usize;
    let zero = b.zero();

    // Read an operand's wires, releasing a variable after its last read.
    macro_rules! get {
        ($o:expr) => {{
            match $o {
                Opd::Var(v) => {
                    let w = vars[*v as usize].as_ref().unwrap_or_else(|| panic!("variable {v} read before written")).to_vec();
                    reads[*v as usize] -= 1;
                    if reads[*v as usize] == 0 {
                        vars[*v as usize] = None;
                    }
                    w
                }
                Opd::Const(c) => tower::constant(b, *c, W),
            }
        }};
    }

    for (k, op) in t.ops.iter().enumerate() {
        if opts.limit.is_some_and(|l| k >= l) {
            break;
        }
        let before = non_free(b);
        let mut checks: Vec<usize> = Vec::new();
        let mut outs: Vec<Vec<usize>> = Vec::with_capacity(op.defines());
        {
            // A byte operand: its low eight wires, checking the rest zero
            // unless the wiring already guarantees it.
            let byte = |b: &mut T, w: Vec<usize>, checks: &mut Vec<usize>| -> [usize; 8] {
                if w[8..].iter().any(|&x| x != zero) {
                    checks.push(is_zero(b, &w[8..]));
                }
                core::array::from_fn(|i| w[i])
            };
            // A bit operand: its low wire, checking the rest zero unless the
            // wiring already guarantees it.
            let bit = |b: &mut T, w: Vec<usize>, checks: &mut Vec<usize>| -> usize {
                if w[1..].iter().any(|&x| x != zero) {
                    checks.push(is_zero(b, &w[1..]));
                }
                w[0]
            };
            match op {
                TOp::Input(_) if reads[next as usize] == 0 => {
                    // A proof value the verifier never reads (one it knows,
                    // read as a constant instead) is not a circuit input.
                    unread_inputs += 1;
                    outs.push(vec![zero; W]);
                }
                TOp::Input(n) => {
                    let v = inputs[*n as usize];
                    let width = match widths[*n as usize] {
                        InputWidth::Byte => {
                            by_width[0] += 1;
                            8
                        }
                        InputWidth::Bit => {
                            by_width[1] += 1;
                            1
                        }
                        InputWidth::Full => {
                            by_width[2] += 1;
                            W
                        }
                    };
                    input_bits += width;
                    let mut w = Vec::with_capacity(W);
                    for i in 0..width {
                        let x = b.fresh_one();
                        b.set_input(x, (v >> i) & 1 == 1);
                        w.push(x);
                    }
                    w.resize(W, zero);
                    outs.push(w);
                }
                TOp::Add(x, y) => {
                    let (x, y) = (get!(x), get!(y));
                    outs.push(tower::add(b, &x, &y));
                }
                TOp::Mul(x, y) => {
                    let (x, y) = (get!(x), get!(y));
                    outs.push(tower::mul(b, &x, &y));
                }
                TOp::Square(x) => {
                    let x = get!(x);
                    outs.push(tower::square(b, &x));
                }
                TOp::Inv(x) => {
                    let x = get!(x);
                    let z = is_zero(b, &x);
                    checks.push(not(b, z));
                    outs.push(inverse(b, &x));
                }
                TOp::AssertEq(x, y) => {
                    let (x, y) = (get!(x), get!(y));
                    let d = tower::add(b, &x, &y);
                    checks.push(is_zero(b, &d));
                }
                TOp::AssertNonZero(x) => {
                    let x = get!(x);
                    let z = is_zero(b, &x);
                    checks.push(not(b, z));
                }
                TOp::ToBytes(x) => {
                    let x = get!(x);
                    for i in 0..16 {
                        let mut w = x[8 * i..8 * i + 8].to_vec();
                        w.resize(W, zero);
                        outs.push(w);
                    }
                }
                TOp::FromBytes(v) => {
                    let mut w = Vec::with_capacity(W);
                    for o in v {
                        let x = get!(o);
                        w.extend(byte(b, x, &mut checks));
                    }
                    w.resize(W, zero);
                    outs.push(w);
                }
                TOp::ByteBits(o) => {
                    let x = get!(o);
                    let by = byte(b, x, &mut checks);
                    for &bit in by.iter() {
                        let mut w = vec![bit];
                        w.resize(W, zero);
                        outs.push(w);
                    }
                }
                TOp::Blake3(v) => {
                    let mut msg: Vec<[usize; 8]> = Vec::with_capacity(v.len());
                    for o in v {
                        let x = get!(o);
                        msg.push(byte(b, x, &mut checks));
                    }
                    let digest = blake3::hash_bytes(b, &msg);
                    for by in digest.iter() {
                        let mut w = by.to_vec();
                        w.resize(W, zero);
                        outs.push(w);
                    }
                }
                TOp::Transpose(rows) => {
                    let rows: Vec<Vec<usize>> = rows.iter().map(|o| get!(o)).collect();
                    for v in 0..W {
                        let mut w: Vec<usize> = rows.iter().map(|r| r[v]).collect();
                        w.resize(W, zero);
                        outs.push(w);
                    }
                }
                TOp::Select(s, x, y) => {
                    let s = get!(s);
                    let s = bit(b, s, &mut checks);
                    let (x, y) = (get!(x), get!(y));
                    outs.push(mux_words(b, s, &x, &y));
                }
                TOp::Blake3Slots { slots, len } => {
                    let mut msg: Vec<[usize; 8]> = Vec::with_capacity(16 * slots.len());
                    let mut past: Vec<usize> = Vec::new();
                    for o in slots {
                        let x = get!(o);
                        for i in 0..16 {
                            let by: [usize; 8] = core::array::from_fn(|j| x[8 * i + j]);
                            if msg.len() < *len {
                                msg.push(by);
                            } else {
                                past.extend(by.iter().copied().filter(|&w| w != zero));
                            }
                        }
                    }
                    assert_eq!(msg.len(), *len, "op {k}: slots shorter than the message");
                    if !past.is_empty() {
                        checks.push(is_zero(b, &past));
                    }
                    outs.extend(digest_halves(b, &msg));
                }
                TOp::MerkleNode { bit: s, cur, sib } => {
                    let s = get!(s);
                    let s = bit(b, s, &mut checks);
                    let cur: Vec<usize> = [get!(&cur[0]), get!(&cur[1])].concat();
                    let sib: Vec<usize> = [get!(&sib[0]), get!(&sib[1])].concat();
                    // left = s ? sib : cur; right = cur + sib + left.
                    let left = mux_words(b, s, &cur, &sib);
                    let right: Vec<usize> = (0..2 * W)
                        .map(|i| {
                            let t = b.xor_wire(cur[i], sib[i]);
                            b.xor_wire(t, left[i])
                        })
                        .collect();
                    let msg: Vec<[usize; 8]> =
                        left.chunks(8).chain(right.chunks(8)).map(|c| core::array::from_fn(|j| c[j])).collect();
                    outs.extend(digest_halves(b, &msg));
                }
            }
        }
        for c in checks {
            ok = b.and_wire(ok, c);
        }
        debug_assert_eq!(outs.len(), op.defines());
        for w in outs {
            if opts.check_values {
                let got = w.iter().enumerate().fold(0u128, |acc, (i, &x)| acc | (u128::from(b.probe(x)) << i));
                if got != t.values[next as usize] {
                    mismatches.push(next);
                }
            }
            if reads[next as usize] > 0 {
                vars[next as usize] = Some(w.into_boxed_slice());
            }
            next += 1;
        }
        let after = non_free(b);
        profile.add(op.kind(), after - before);
    }
    Report { output: ok, input_bits, inputs_by_width: by_width, unread_inputs, profile, mismatches }
}
