//! Ziren's compressed-proof verifier as a Boolean circuit.
//!
//! Ziren verifies a compressed proof *in circuit* with its `shrink` recursion
//! program: a straight-line program over KoalaBear (`p = 2^31 - 2^24 + 1`)
//! and its quartic extension, with Poseidon2, a select gate, bit
//! decompositions and a witness stream. That program is exactly the verifier
//! a garbled circuit for a Ziren statement must compute, so this module
//! translates it instruction by instruction:
//!
//! * field and extension arithmetic, Poseidon2 and selects become gates
//!   (the [`koala`] gadgets);
//! * a witness word (`Hint`) becomes 31 or 124 circuit-input bits, checked
//!   canonical;
//! * every AIR constraint that can fail becomes one check bit, and the circuit
//!   output is the AND of all of them. The asserting divisions
//!   (`DivFAssert`, `DivEAssert`) are constrained by `in2 · out = in1` with a
//!   free `out`, so their check is `in2 ≠ 0 ∨ in1 = 0`, with no inversion;
//!   a computing division (`mult > 0`) inverts and checks the same condition;
//!   constant reads and the committed public values are equality checks;
//! * an instruction whose result is never read (`mult = 0`) and that
//!   constrains nothing is dropped.
//!
//! **Merkle deduplication.** The program verifies every WHIR query's Merkle
//! path independently, with each sibling read from the witness. With
//! [`Options::dedup`] each tree's sibling witnesses are replaced by a fixed
//! number of *frontier* digests: a path's sibling at a level is taken from an
//! earlier path of the same tree when one shares its parent (that path's node
//! or its sibling), and otherwise from the next frontier digest. The routing
//! is computed from the index bits, before the first path: equality flags per
//! pair of paths and level, a prefix count of the levels that need a fresh
//! digest, and a log-depth expansion network that moves the k-th frontier
//! digest to the k-th such level. Each path is still hashed to its root and
//! compared, so the routing affects completeness only: any sibling value
//! that makes a path reach the committed root is a valid opening.
//!
//! The dump this reads is written by a Ziren test (`ziren_dump_shrink.rs`) kept
//! with the local measurement logs, not in this repository.

use std::collections::HashMap;

use garbled_snark_verifier::circuits::sect233k1::builder::{
    CircuitTrait, CustomGateParams, CustomGateType, GateCounts, GateOperation, Template,
};
use garbled_snark_verifier::circuits::sect233k1::stream::ValuedBuilder;
use poseidon2::reference as r;

use crate::koala::{self, Ext, Fp, BITS};
use crate::ziren_constants as zc;

/// Ziren's Poseidon2, natively.
pub fn permute(state: &mut [u32; 16]) {
    r::mds_light(state);
    for rc in zc::EXTERNAL_INITIAL.iter() {
        for (s, c) in state.iter_mut().zip(rc.iter()) {
            *s = r::sbox(r::add(*s, *c));
        }
        r::mds_light(state);
    }
    for c in zc::INTERNAL.iter() {
        state[0] = r::sbox(r::add(state[0], *c));
        r::internal_linear(state);
    }
    for rc in zc::EXTERNAL_FINAL.iter() {
        for (s, c) in state.iter_mut().zip(rc.iter()) {
            *s = r::sbox(r::add(*s, *c));
        }
        r::mds_light(state);
    }
}


pub const P: u32 = 0x7f00_0001;
const DIGEST: usize = 8;

// ---------------------------------------------------------------------------
// The dump.
// ---------------------------------------------------------------------------

#[derive(Clone, Debug)]
pub enum Ins {
    BaseAlu { op: u8, mult: u32, out: u32, in1: u32, in2: u32 },
    ExtAlu { op: u8, mult: u32, out: u32, in1: u32, in2: u32 },
    MemRead { addr: u32, val: [u32; 4] },
    MemWrite { addr: u32, val: [u32; 4] },
    Poseidon2 { out: [u32; 16], inp: [u32; 16] },
    Select { bit: u32, out1: u32, out2: u32, in1: u32, in2: u32 },
    HintBits { input: u32, outs: Vec<u32> },
    Print,
    Ext2Felts { input: u32, outs: [u32; 4] },
    CommitPv { addrs: Vec<u32> },
    Hint { outs: Vec<u32> },
}

pub const ADD: u8 = 0;
pub const SUB: u8 = 1;
pub const MUL: u8 = 2;
pub const DIV: u8 = 3;
pub const DIV_ASSERT: u8 = 4;

pub struct Dump {
    pub instrs: Vec<Ins>,
    pub total_memory: usize,
    pub witness: Vec<[u32; 4]>,
    pub public_values: Vec<u32>,
    pub poseidon2_test: [u32; 16],
}

struct Rd<'a> {
    d: &'a [u8],
    o: usize,
}
impl Rd<'_> {
    fn u8(&mut self) -> u8 {
        let v = self.d[self.o];
        self.o += 1;
        v
    }
    fn u32(&mut self) -> u32 {
        let v = u32::from_le_bytes(self.d[self.o..self.o + 4].try_into().unwrap());
        self.o += 4;
        v
    }
    fn arr<const N: usize>(&mut self) -> [u32; N] {
        core::array::from_fn(|_| self.u32())
    }
}

pub fn parse(bytes: &[u8]) -> Dump {
    assert_eq!(&bytes[..4], b"ZSHR", "not a shrink dump");
    let mut r = Rd { d: bytes, o: 4 };
    assert_eq!(r.u32(), 1, "dump version");
    let n = r.u32() as usize;
    let total_memory = r.u32() as usize;
    let mut instrs = Vec::with_capacity(n);
    for _ in 0..n {
        let t = r.u8();
        instrs.push(match t {
            0 | 1 => {
                let op = r.u8();
                let (mult, out, in1, in2) = (r.u32(), r.u32(), r.u32(), r.u32());
                if t == 0 {
                    Ins::BaseAlu { op, mult, out, in1, in2 }
                } else {
                    Ins::ExtAlu { op, mult, out, in1, in2 }
                }
            }
            2 => {
                let kind = r.u8();
                let _mult = r.u32();
                let addr = r.u32();
                let val = r.arr::<4>();
                if kind == 0 {
                    Ins::MemRead { addr, val }
                } else {
                    Ins::MemWrite { addr, val }
                }
            }
            3 => {
                let _mults = r.arr::<16>();
                let out = r.arr::<16>();
                let inp = r.arr::<16>();
                Ins::Poseidon2 { out, inp }
            }
            4 => {
                let (_m1, _m2) = (r.u32(), r.u32());
                let (bit, out1, out2, in1, in2) = (r.u32(), r.u32(), r.u32(), r.u32(), r.u32());
                Ins::Select { bit, out1, out2, in1, in2 }
            }
            5 => {
                let c = r.u32() as usize;
                let input = r.u32();
                let outs = (0..c)
                    .map(|_| {
                        let a = r.u32();
                        r.u32();
                        a
                    })
                    .collect();
                Ins::HintBits { input, outs }
            }
            6 => panic!("HintAddCurve is not used by the shrink program"),
            7 => Ins::Print,
            8 => {
                let input = r.u32();
                let outs = core::array::from_fn(|_| {
                    let a = r.u32();
                    r.u32();
                    a
                });
                Ins::Ext2Felts { input, outs }
            }
            10 => {
                let c = r.u32() as usize;
                Ins::CommitPv { addrs: (0..c).map(|_| r.u32()).collect() }
            }
            11 => {
                let c = r.u32() as usize;
                let outs = (0..c)
                    .map(|_| {
                        let a = r.u32();
                        r.u32();
                        a
                    })
                    .collect();
                Ins::Hint { outs }
            }
            _ => panic!("unknown instruction tag {t}"),
        });
    }
    let nw = r.u32() as usize;
    let witness = (0..nw).map(|_| r.arr::<4>()).collect();
    let npv = r.u32() as usize;
    let public_values = (0..npv).map(|_| r.u32()).collect();
    let poseidon2_test = r.arr::<16>();
    assert_eq!(r.o, bytes.len(), "trailing bytes in dump");
    Dump { instrs, total_memory, witness, public_values, poseidon2_test }
}

// ---------------------------------------------------------------------------
// Native semantics: Ziren's runtime, with the AIR's acceptance conditions.
// ---------------------------------------------------------------------------

fn pow(mut x: u32, mut e: u32) -> u32 {
    let mut acc = 1u32;
    while e > 0 {
        if e & 1 == 1 {
            acc = r::mul(acc, x);
        }
        x = r::mul(x, x);
        e >>= 1;
    }
    acc
}

pub fn inv(x: u32) -> u32 {
    pow(x, P - 2)
}

/// `a^{-1}` in `F[x]/(x^4 - 3)` by the norm to `F[y]/(y^2 - 3)`, `y = x^2`,
/// and then to `F`: the formulas the circuit uses.
pub fn ext_inv(a: [u32; 4]) -> [u32; 4] {
    let [a0, a1, a2, a3] = a;
    let m = r::mul;
    let (sa0, sa1, sa2, sa3) = (m(a0, a0), m(a1, a1), m(a2, a2), m(a3, a3));
    let a0a2 = m(a0, a2);
    let a1a3 = m(a1, a3);
    // b0 = a0² + 3a2² - 6 a1a3,  b1 = 2 a0a2 - a1² - 3 a3²
    let b0 = r::sub(r::add(sa0, m(3, sa2)), m(6, a1a3));
    let b1 = r::sub(r::sub(m(2, a0a2), sa1), m(3, sa3));
    let n = r::sub(m(b0, b0), m(3, m(b1, b1)));
    let ninv = inv(n);
    let c0 = m(b0, ninv);
    let c1 = r::sub(0, m(b1, ninv));
    let r0 = r::add(m(a0, c0), m(3, m(a2, c1)));
    let r2 = r::add(m(a0, c1), m(a2, c0));
    let r1 = r::sub(0, r::add(m(a1, c0), m(3, m(a3, c1))));
    let r3 = r::sub(0, r::add(m(a1, c1), m(a3, c0)));
    [r0, r1, r2, r3]
}

pub struct Native {
    pub mem: Vec<[u32; 4]>,
    /// Instruction indices whose AIR condition fails.
    pub failures: Vec<usize>,
}

pub fn run_native(d: &Dump, witness: &[[u32; 4]]) -> Native {
    let mut mem = vec![[0u32; 4]; d.total_memory];
    let mut failures = Vec::new();
    let mut w = 0usize;
    let felt = |v: u32| [v, 0, 0, 0];
    for (k, ins) in d.instrs.iter().enumerate() {
        match ins {
            Ins::BaseAlu { op, mult, out, in1, in2 } => {
                let (x, y) = (mem[*in1 as usize][0], mem[*in2 as usize][0]);
                let v = match *op {
                    ADD => r::add(x, y),
                    SUB => r::sub(x, y),
                    MUL => r::mul(x, y),
                    _ => {
                        if y != 0 {
                            r::mul(x, inv(y))
                        } else if x == 0 {
                            1
                        } else {
                            if *op == DIV_ASSERT || *mult != 0 {
                                failures.push(k);
                            }
                            0
                        }
                    }
                };
                mem[*out as usize] = felt(v);
            }
            Ins::ExtAlu { op, mult, out, in1, in2 } => {
                let (x, y) = (mem[*in1 as usize], mem[*in2 as usize]);
                let v = match *op {
                    ADD => r::ext4::add(x, y),
                    SUB => r::ext4::sub(x, y),
                    MUL => r::ext4::mul(x, y),
                    _ => {
                        if y != [0; 4] {
                            r::ext4::mul(x, ext_inv(y))
                        } else if x == [0; 4] {
                            [1, 0, 0, 0]
                        } else {
                            if *op == DIV_ASSERT || *mult != 0 {
                                failures.push(k);
                            }
                            [0; 4]
                        }
                    }
                };
                mem[*out as usize] = v;
            }
            Ins::MemRead { addr, val } => {
                if mem[*addr as usize] != *val {
                    failures.push(k);
                }
            }
            Ins::MemWrite { addr, val } => mem[*addr as usize] = *val,
            Ins::Poseidon2 { out, inp } => {
                let mut s: [u32; 16] = core::array::from_fn(|i| mem[inp[i] as usize][0]);
                permute(&mut s);
                for i in 0..16 {
                    mem[out[i] as usize] = felt(s[i]);
                }
            }
            Ins::Select { bit, out1, out2, in1, in2 } => {
                let (b, x, y) = (mem[*bit as usize][0], mem[*in1 as usize][0], mem[*in2 as usize][0]);
                let o1 = r::add(x, r::mul(b, r::sub(y, x)));
                let o2 = r::sub(r::add(x, y), o1);
                mem[*out1 as usize] = felt(o1);
                mem[*out2 as usize] = felt(o2);
            }
            Ins::HintBits { input, outs } => {
                let v = mem[*input as usize][0];
                for (i, a) in outs.iter().enumerate() {
                    mem[*a as usize] = felt(if i < 32 { (v >> i) & 1 } else { 0 });
                }
            }
            Ins::Print => {}
            Ins::Ext2Felts { input, outs } => {
                let v = mem[*input as usize];
                for i in 0..4 {
                    mem[outs[i] as usize] = felt(v[i]);
                }
            }
            Ins::CommitPv { addrs } => {
                for (i, a) in addrs.iter().enumerate() {
                    if mem[*a as usize][0] != d.public_values[i] {
                        failures.push(k);
                    }
                }
            }
            Ins::Hint { outs } => {
                for a in outs {
                    mem[*a as usize] = witness[w];
                    w += 1;
                }
            }
        }
    }
    assert_eq!(w, witness.len(), "witness consumed exactly");
    Native { mem, failures }
}

// ---------------------------------------------------------------------------
// Merkle paths in the program.
// ---------------------------------------------------------------------------

#[derive(Clone, Debug)]
pub struct Level {
    /// Index of the level's first select.
    pub first: usize,
    pub bit: u32,
    pub val: [u32; DIGEST],
    pub sib: [u32; DIGEST],
    pub out: [u32; DIGEST],
}

#[derive(Clone, Debug)]
pub struct Tree {
    /// Paths in program order; each is its levels, leaf level first.
    pub paths: Vec<Vec<Level>>,
    pub depth: usize,
    /// Instruction index of the tree's first select.
    pub start: usize,
    /// Fixed number of frontier digests the circuit takes for this tree.
    pub frontier: usize,
}

/// Find every Merkle level (eight selects on one bit feeding one Poseidon2
/// compression), chain the levels into paths, and group the paths by the
/// root they are compared against.
pub fn merkle_trees(d: &Dump) -> Vec<Tree> {
    let mut levels: Vec<Level> = Vec::new();
    for (k, ins) in d.instrs.iter().enumerate() {
        let Ins::Poseidon2 { out, inp } = ins else { continue };
        if k < 8 {
            continue;
        }
        let sels: Vec<_> = d.instrs[k - 8..k]
            .iter()
            .filter_map(|i| match i {
                Ins::Select { bit, out1, out2, in1, in2 } => Some((*bit, *out1, *out2, *in1, *in2)),
                _ => None,
            })
            .collect();
        if sels.len() != 8 || sels.iter().any(|s| s.0 != sels[0].0) {
            continue;
        }
        let out1: Vec<u32> = sels.iter().map(|s| s.1).collect();
        let out2: Vec<u32> = sels.iter().map(|s| s.2).collect();
        if inp[..8] != out1[..] || inp[8..] != out2[..] {
            continue;
        }
        levels.push(Level {
            first: k - 8,
            bit: sels[0].0,
            val: core::array::from_fn(|i| sels[i].3),
            sib: core::array::from_fn(|i| sels[i].4),
            out: core::array::from_fn(|i| out[i]),
        });
    }
    let by_out: HashMap<[u32; DIGEST], usize> = levels.iter().enumerate().map(|(j, l)| (l.out, j)).collect();
    let mut next: HashMap<usize, usize> = HashMap::new();
    for (j, l) in levels.iter().enumerate() {
        if let Some(&p) = by_out.get(&l.val) {
            next.insert(p, j);
        }
    }
    // The root of a path: the operands its final output is subtracted from.
    let mut sub_of: HashMap<u32, u32> = HashMap::new();
    for ins in &d.instrs {
        if let Ins::BaseAlu { op: SUB, in1, in2, .. } = ins {
            sub_of.entry(*in1).or_insert(*in2);
        }
    }
    let mut groups: HashMap<(Vec<u32>, usize), Vec<Vec<Level>>> = HashMap::new();
    for (j, l) in levels.iter().enumerate() {
        if by_out.contains_key(&l.val) {
            continue;
        }
        let mut path = vec![j];
        while let Some(&n) = next.get(path.last().unwrap()) {
            path.push(n);
        }
        let root: Vec<u32> = levels[*path.last().unwrap()].out.iter().map(|a| sub_of.get(a).copied().unwrap_or(u32::MAX)).collect();
        let lv: Vec<Level> = path.iter().map(|&i| levels[i].clone()).collect();
        groups.entry((root, lv.len())).or_default().push(lv);
    }
    let mut trees: Vec<Tree> = groups
        .into_values()
        .map(|mut paths| {
            paths.sort_by_key(|p| p[0].first);
            let depth = paths[0].len();
            let start = paths[0][0].first;
            Tree { paths, depth, start, frontier: 0 }
        })
        .collect();
    trees.sort_by_key(|t| t.start);
    trees
}

/// The levels of a tree that need a fresh frontier digest, in order
/// `(path, level)`, given each path's index bits (leaf level first): those
/// whose parent no earlier path shares.
pub fn needs(bits: &[Vec<bool>]) -> Vec<bool> {
    let d = bits[0].len();
    let key = |p: usize, l: usize| -> Vec<bool> { bits[p][l + 1..].to_vec() };
    let mut out = Vec::new();
    for p in 0..bits.len() {
        for l in 0..d {
            let k = key(p, l);
            out.push(!(0..p).any(|q| key(q, l) == k));
        }
    }
    out
}

// ---------------------------------------------------------------------------
// Two builders: exact gate counting, and plaintext evaluation.
// ---------------------------------------------------------------------------

fn counts(and: usize, xor: usize, or: usize) -> GateCounts {
    GateCounts { direct_and: and, direct_xor: xor, direct_or: or, custom: 0, custom_and: 0, custom_xor: 0, custom_or: 0 }
}

macro_rules! fold_rules {
    () => {
        fn xor_fold(x: usize, y: usize) -> Option<usize> {
            if x == y {
                Some(0)
            } else if x == 0 {
                Some(y)
            } else if y == 0 {
                Some(x)
            } else {
                None
            }
        }
        fn or_fold(x: usize, y: usize) -> Option<usize> {
            if x == y {
                Some(x)
            } else if x == 1 || y == 1 {
                Some(1)
            } else if x == 0 {
                Some(y)
            } else if y == 0 {
                Some(x)
            } else {
                None
            }
        }
        fn and_fold(x: usize, y: usize) -> Option<usize> {
            if x == y {
                Some(x)
            } else if x == 0 || y == 0 {
                Some(0)
            } else if x == 1 {
                Some(y)
            } else if y == 1 {
                Some(x)
            } else {
                None
            }
        }
    };
}

/// Counts gates with the folding of `CircuitAdapter`/`Streaming`, rule for
/// rule, and stores nothing per wire.
pub struct Count {
    next: usize,
    pub and: usize,
    pub xor: usize,
    pub or: usize,
    empty: Vec<GateOperation>,
}

impl Default for Count {
    fn default() -> Self {
        Self { next: 2, and: 0, xor: 0, or: 0, empty: Vec::new() }
    }
}

impl Count {
    fold_rules!();
    pub fn wires(&self) -> usize {
        self.next
    }
}

impl CircuitTrait for Count {
    fn fresh_one(&mut self) -> usize {
        self.next += 1;
        self.next - 1
    }
    fn fresh<const N: usize>(&mut self) -> [usize; N] {
        core::array::from_fn(|_| self.fresh_one())
    }
    fn zero(&mut self) -> usize {
        0
    }
    fn one(&mut self) -> usize {
        1
    }
    fn xor_wire(&mut self, x: usize, y: usize) -> usize {
        if let Some(w) = Self::xor_fold(x, y) {
            return w;
        }
        self.xor += 1;
        self.fresh_one()
    }
    fn or_wire(&mut self, x: usize, y: usize) -> usize {
        if let Some(w) = Self::or_fold(x, y) {
            return w;
        }
        self.or += 1;
        self.fresh_one()
    }
    fn and_wire(&mut self, x: usize, y: usize) -> usize {
        if let Some(w) = Self::and_fold(x, y) {
            return w;
        }
        self.and += 1;
        self.fresh_one()
    }
    fn push_custom_gate(&mut self, _: CustomGateParams, _: usize) {
        unimplemented!()
    }
    fn get_gates(&self) -> &Vec<GateOperation> {
        &self.empty
    }
    fn gate_counts(&self) -> GateCounts {
        counts(self.and, self.xor, self.or)
    }
    fn next_wire(&self) -> usize {
        self.next
    }
    fn init_circuit_config_for_custom_gate(&mut self, _: CustomGateType) -> &Template {
        unimplemented!()
    }
    fn get_template(&self, _: CustomGateType) -> Option<&Template> {
        None
    }
}

impl ValuedBuilder for Count {
    fn set_input(&mut self, _: usize, _: bool) {}
}

const CHUNK_WORDS: usize = 1 << 24;

/// Evaluates every gate as it is emitted, one bit per wire.
pub struct Eval {
    chunks: Vec<Box<[u64]>>,
    next: usize,
    pub and: usize,
    pub xor: usize,
    pub or: usize,
    empty: Vec<GateOperation>,
}

impl Default for Eval {
    fn default() -> Self {
        let mut e = Self { chunks: Vec::new(), next: 0, and: 0, xor: 0, or: 0, empty: Vec::new() };
        let z = e.fresh_one();
        let o = e.fresh_one();
        e.set(z, false);
        e.set(o, true);
        e
    }
}

impl Eval {
    fold_rules!();
    pub fn get(&self, w: usize) -> bool {
        let (c, i) = (w / (CHUNK_WORDS * 64), w % (CHUNK_WORDS * 64));
        (self.chunks[c][i / 64] >> (i % 64)) & 1 == 1
    }
    fn set(&mut self, w: usize, v: bool) {
        let (c, i) = (w / (CHUNK_WORDS * 64), w % (CHUNK_WORDS * 64));
        let word = &mut self.chunks[c][i / 64];
        if v {
            *word |= 1 << (i % 64);
        } else {
            *word &= !(1 << (i % 64));
        }
    }
    fn alloc(&mut self, v: bool) -> usize {
        let w = self.fresh_one();
        self.set(w, v);
        w
    }
    pub fn wires(&self) -> usize {
        self.next
    }
}

impl CircuitTrait for Eval {
    fn fresh_one(&mut self) -> usize {
        if self.next == self.chunks.len() * CHUNK_WORDS * 64 {
            self.chunks.push(vec![0u64; CHUNK_WORDS].into_boxed_slice());
        }
        self.next += 1;
        self.next - 1
    }
    fn fresh<const N: usize>(&mut self) -> [usize; N] {
        core::array::from_fn(|_| self.fresh_one())
    }
    fn zero(&mut self) -> usize {
        0
    }
    fn one(&mut self) -> usize {
        1
    }
    fn xor_wire(&mut self, x: usize, y: usize) -> usize {
        if let Some(w) = Self::xor_fold(x, y) {
            return w;
        }
        self.xor += 1;
        let v = self.get(x) ^ self.get(y);
        self.alloc(v)
    }
    fn or_wire(&mut self, x: usize, y: usize) -> usize {
        if let Some(w) = Self::or_fold(x, y) {
            return w;
        }
        self.or += 1;
        let v = self.get(x) | self.get(y);
        self.alloc(v)
    }
    fn and_wire(&mut self, x: usize, y: usize) -> usize {
        if let Some(w) = Self::and_fold(x, y) {
            return w;
        }
        self.and += 1;
        let v = self.get(x) & self.get(y);
        self.alloc(v)
    }
    fn push_custom_gate(&mut self, _: CustomGateParams, _: usize) {
        unimplemented!()
    }
    fn get_gates(&self) -> &Vec<GateOperation> {
        &self.empty
    }
    fn gate_counts(&self) -> GateCounts {
        counts(self.and, self.xor, self.or)
    }
    fn next_wire(&self) -> usize {
        self.next
    }
    fn init_circuit_config_for_custom_gate(&mut self, _: CustomGateType) -> &Template {
        unimplemented!()
    }
    fn get_template(&self, _: CustomGateType) -> Option<&Template> {
        None
    }
}

impl ValuedBuilder for Eval {
    fn set_input(&mut self, wire: usize, value: bool) {
        self.set(wire, value);
    }
}

// ---------------------------------------------------------------------------
// Small gadgets.
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

fn and_all<T: CircuitTrait>(b: &mut T, xs: &[usize]) -> usize {
    let mut v: Vec<usize> = xs.to_vec();
    if v.is_empty() {
        return b.one();
    }
    while v.len() > 1 {
        let mut n = Vec::with_capacity(v.len().div_ceil(2));
        for c in v.chunks(2) {
            n.push(if c.len() == 2 { b.and_wire(c[0], c[1]) } else { c[0] });
        }
        v = n;
    }
    v[0]
}

fn is_zero<T: CircuitTrait>(b: &mut T, xs: &[usize]) -> usize {
    let o = or_all(b, xs);
    not(b, o)
}

fn eq_const<T: CircuitTrait>(b: &mut T, x: &Fp, c: u32) -> usize {
    let bits: Vec<usize> = x
        .iter()
        .enumerate()
        .map(|(i, &w)| if (c >> i) & 1 == 1 { w } else { not(b, w) })
        .collect();
    and_all(b, &bits)
}

/// `x < p` for 31 input bits: `x ≥ p` iff bits 24..30 are all set and some
/// bit below 24 is.
fn canonical<T: CircuitTrait>(b: &mut T, x: &Fp) -> usize {
    let hi = and_all(b, &x[24..31]);
    let lo = or_all(b, &x[..24]);
    let ge = b.and_wire(hi, lo);
    not(b, ge)
}

fn ext_zero<T: CircuitTrait>(b: &mut T) -> Ext {
    core::array::from_fn(|_| koala::constant(b, 0))
}

fn ext_add<T: CircuitTrait>(b: &mut T, x: &Ext, y: &Ext) -> Ext {
    core::array::from_fn(|i| koala::add(b, &x[i], &y[i]))
}

fn ext_sub<T: CircuitTrait>(b: &mut T, x: &Ext, y: &Ext) -> Ext {
    core::array::from_fn(|i| koala::sub(b, &x[i], &y[i]))
}

/// The circuit twin of [`ext_inv`].
fn ext_inverse<T: CircuitTrait>(b: &mut T, a: &Ext) -> Ext {
    use koala::{add, mul, mul_const, square, sub};
    let [a0, a1, a2, a3] = a;
    let (sa0, sa1, sa2, sa3) = (square(b, a0), square(b, a1), square(b, a2), square(b, a3));
    let a0a2 = mul(b, a0, a2);
    let a1a3 = mul(b, a1, a3);
    let t = mul_const(b, &sa2, 3);
    let t = add(b, &sa0, &t);
    let u = mul_const(b, &a1a3, 6);
    let b0 = sub(b, &t, &u);
    let t = koala::double(b, &a0a2);
    let t = sub(b, &t, &sa1);
    let u = mul_const(b, &sa3, 3);
    let b1 = sub(b, &t, &u);
    let t = square(b, &b0);
    let u = square(b, &b1);
    let u = mul_const(b, &u, 3);
    let n = sub(b, &t, &u);
    let ninv = koala::inverse(b, &n);
    let zero = koala::constant(b, 0);
    let c0 = mul(b, &b0, &ninv);
    let t = mul(b, &b1, &ninv);
    let c1 = sub(b, &zero, &t);
    let t = mul(b, a0, &c0);
    let u = mul(b, a2, &c1);
    let u = mul_const(b, &u, 3);
    let r0 = add(b, &t, &u);
    let t = mul(b, a0, &c1);
    let u = mul(b, a2, &c0);
    let r2 = add(b, &t, &u);
    let t = mul(b, a1, &c0);
    let u = mul(b, a3, &c1);
    let u = mul_const(b, &u, 3);
    let t = add(b, &t, &u);
    let r1 = sub(b, &zero, &t);
    let t = mul(b, a1, &c1);
    let u = mul(b, a3, &c0);
    let t = add(b, &t, &u);
    let r3 = sub(b, &zero, &t);
    [r0, r1, r2, r3]
}

/// A ripple-carry `x + y` on equal-width words (one AND per full adder).
fn add_words<T: CircuitTrait>(b: &mut T, x: &[usize], y: &[usize]) -> Vec<usize> {
    let mut c = b.zero();
    let mut out = Vec::with_capacity(x.len());
    for (&p, &q) in x.iter().zip(y) {
        let pq = b.xor_wire(p, q);
        let s = b.xor_wire(pq, c);
        let pc = b.xor_wire(p, c);
        let qc = b.xor_wire(q, c);
        let t = b.and_wire(pc, qc);
        c = b.xor_wire(c, t);
        out.push(s);
    }
    out
}

fn const_word<T: CircuitTrait>(b: &mut T, v: usize, width: usize) -> Vec<usize> {
    (0..width).map(|i| if (v >> i) & 1 == 1 { b.one() } else { b.zero() }).collect()
}

// ---------------------------------------------------------------------------
// The translation.
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug)]
pub struct Options {
    pub dedup: bool,
    /// Stop after this many instructions (a prefix of the program).
    pub limit: Option<usize>,
    /// Compare every value written against the native run (evaluation only).
    pub check_writes: bool,
}

/// Gate counts per part of the verifier.
#[derive(Default, Debug, Clone)]
pub struct Profile {
    pub parts: Vec<(&'static str, usize, usize)>, // (name, non-free gates, instructions)
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
    pub hint_input_bits: usize,
    pub frontier_input_bits: usize,
    pub frontier_digests: Vec<(usize, usize, usize)>, // (depth, paths, fixed frontier)
    pub needed_digests: Vec<usize>,
    pub profile: Profile,
    /// (instruction, address) whose circuit value differs from the native run.
    pub mismatches: Vec<(usize, u32)>,
}

struct TreeState {
    tree: Tree,
    /// `(path, level)` -> routed fresh digest.
    fresh: Vec<[Fp; DIGEST]>,
    need: Vec<usize>,
    /// `same_parent[p][q][l]` and `differ[p][q][l]` for q < p.
    same_parent: Vec<Vec<Vec<usize>>>,
    differ: Vec<Vec<Vec<usize>>>,
    node: Vec<Vec<Option<[Fp; DIGEST]>>>,
    sib: Vec<Vec<Option<[Fp; DIGEST]>>>,
}

pub struct Translator<'a, T: ValuedBuilder + Probe> {
    b: &'a mut T,
    d: &'a Dump,
    native: &'a Native,
    witness: &'a [[u32; 4]],
    opts: Options,
    mem: Vec<Option<Vec<Fp>>>,
    ok: usize,
    ext_read: Vec<bool>,
    profile: Profile,
    /// sibling address -> (tree, path, level, limb)
    sib_of: HashMap<u32, (usize, usize, usize, usize)>,
    trees: Vec<TreeState>,
    tree_at: HashMap<usize, usize>,
    input_bits: usize,
    hint_input_bits: usize,
    frontier_input_bits: usize,
    frontier_values: Vec<Vec<[u32; DIGEST]>>,
    needed: Vec<usize>,
    /// Gates already attributed to routing inside the current instruction.
    nested: usize,
    pub mismatches: Vec<(usize, u32)>,
}

fn non_free<T: CircuitTrait>(b: &T) -> usize {
    let c = b.gate_counts();
    c.direct_and + c.direct_or
}

impl<'a, T: ValuedBuilder + Probe> Translator<'a, T> {
    pub fn new(b: &'a mut T, d: &'a Dump, native: &'a Native, witness: &'a [[u32; 4]], trees: &[Tree], opts: Options) -> Self {
        let mut ext_read = vec![false; d.total_memory];
        for ins in &d.instrs {
            match ins {
                Ins::ExtAlu { in1, in2, .. } => {
                    ext_read[*in1 as usize] = true;
                    ext_read[*in2 as usize] = true;
                }
                Ins::Ext2Felts { input, .. } => ext_read[*input as usize] = true,
                Ins::MemRead { addr, .. } => ext_read[*addr as usize] = true,
                _ => {}
            }
        }
        let one = b.one();
        let mut me = Self {
            b,
            d,
            native,
            witness,
            opts,
            mem: vec![None; d.total_memory],
            ok: one,
            ext_read,
            profile: Profile::default(),
            sib_of: HashMap::new(),
            trees: Vec::new(),
            tree_at: HashMap::new(),
            input_bits: 0,
            hint_input_bits: 0,
            frontier_input_bits: 0,
            frontier_values: Vec::new(),
            needed: Vec::new(),
            nested: 0,
            mismatches: Vec::new(),
        };
        if opts.dedup {
            for t in trees.iter().filter(|t| t.paths.len() > 1) {
                let ti = me.trees.len();
                for (p, path) in t.paths.iter().enumerate() {
                    for (l, lv) in path.iter().enumerate() {
                        for (i, &a) in lv.sib.iter().enumerate() {
                            me.sib_of.insert(a, (ti, p, l, i));
                        }
                    }
                }
                // The honest frontier: the sibling witnesses of the levels
                // that need one, in (path, level) order.
                let bits: Vec<Vec<bool>> =
                    t.paths.iter().map(|path| path.iter().map(|lv| native.mem[lv.bit as usize][0] == 1).collect()).collect();
                let need = needs(&bits);
                let mut vals = Vec::new();
                for (j, &n) in need.iter().enumerate() {
                    if n {
                        let lv = &t.paths[j / t.depth][j % t.depth];
                        vals.push(core::array::from_fn(|i| native.mem[lv.sib[i] as usize][0]));
                    }
                }
                me.needed.push(vals.len());
                me.frontier_values.push(vals);
                me.tree_at.insert(t.start, ti);
                let n = t.paths.len();
                me.trees.push(TreeState {
                    tree: t.clone(),
                    fresh: Vec::new(),
                    need: Vec::new(),
                    same_parent: Vec::new(),
                    differ: Vec::new(),
                    node: vec![vec![None; t.depth]; n],
                    sib: vec![vec![None; t.depth]; n],
                });
            }
        }
        me
    }

    fn input_felt(&mut self, v: u32) -> Fp {
        let wires: Fp = (0..BITS)
            .map(|i| {
                let w = self.b.fresh_one();
                self.b.set_input(w, (v >> i) & 1 == 1);
                w
            })
            .collect();
        self.input_bits += BITS;
        let c = canonical(self.b, &wires);
        self.check(c);
        wires
    }

    fn check(&mut self, c: usize) {
        self.ok = self.b.and_wire(self.ok, c);
    }

    fn felt(&mut self, a: u32) -> Fp {
        self.mem[a as usize].as_ref().unwrap_or_else(|| panic!("read of unwritten address {a}"))[0].clone()
    }

    fn ext(&mut self, a: u32) -> Ext {
        let v = self.mem[a as usize].as_ref().unwrap_or_else(|| panic!("read of unwritten address {a}")).clone();
        if v.len() == 4 {
            [v[0].clone(), v[1].clone(), v[2].clone(), v[3].clone()]
        } else {
            let z = koala::constant(self.b, 0);
            [v[0].clone(), z.clone(), z.clone(), z]
        }
    }

    fn write(&mut self, a: u32, v: Vec<Fp>) {
        self.mem[a as usize] = Some(v);
    }

    fn translate_select_in2(&mut self, a: u32) -> Fp {
        if let Some(&(t, p, l, limb)) = self.sib_of.get(&a) {
            if self.trees[t].sib[p][l].is_none() {
                self.route(t, p, l);
            }
            return self.trees[t].sib[p][l].as_ref().unwrap()[limb].clone();
        }
        self.felt(a)
    }

    /// The routing prologue of a tree: pair flags, need flags, the frontier
    /// inputs and the expansion network.
    fn prologue(&mut self, ti: usize) {
        let before = non_free(self.b);
        let tree = self.trees[ti].tree.clone();
        let (n, d) = (tree.paths.len(), tree.depth);
        let bits: Vec<Vec<usize>> = tree
            .paths
            .iter()
            .map(|path| {
                path.iter()
                    .map(|lv| {
                        let f = &self.mem[lv.bit as usize].as_ref().expect("index bit computed before the tree")[0];
                        assert!(f[1..].iter().all(|&w| w == 0), "index bit is a decomposition output");
                        f[0]
                    })
                    .collect()
            })
            .collect();
        // same_parent[p][q][l]: paths p and q agree on every bit above l.
        let mut same_parent = vec![Vec::new(); n];
        let mut differ = vec![Vec::new(); n];
        for p in 0..n {
            for q in 0..p {
                let mut sp = vec![0usize; d];
                let mut df = vec![0usize; d];
                let mut acc = self.b.one();
                for l in (0..d).rev() {
                    sp[l] = acc;
                    df[l] = self.b.xor_wire(bits[p][l], bits[q][l]);
                    let e = not(self.b, df[l]);
                    acc = self.b.and_wire(acc, e);
                }
                same_parent[p].push(sp);
                differ[p].push(df);
            }
        }
        let mut need = Vec::with_capacity(n * d);
        for p in 0..n {
            for l in 0..d {
                let shared: Vec<usize> = (0..p).map(|q| same_parent[p][q][l]).collect();
                let any = or_all(self.b, &shared);
                need.push(not(self.b, any));
            }
        }
        // The frontier digests: circuit inputs.
        let fmax = tree.frontier;
        let honest = self.frontier_values[ti].clone();
        let mut frontier: Vec<[Fp; DIGEST]> = Vec::with_capacity(fmax);
        for k in 0..fmax {
            let v = honest.get(k).copied().unwrap_or([0; DIGEST]);
            frontier.push(core::array::from_fn(|i| self.input_felt(v[i])));
        }
        self.frontier_input_bits += fmax * DIGEST * BITS;
        // Ranks and shifts.
        let total = n * d;
        let width = (usize::BITS - (total.max(2) - 1).leading_zeros()) as usize;
        let mut rank = const_word(self.b, 0, width);
        let mut occ = Vec::with_capacity(total);
        let mut shift: Vec<Vec<usize>> = Vec::with_capacity(total);
        for (j, &nd) in need.iter().enumerate() {
            // shift = j - rank = j + !rank + 1
            let neg: Vec<usize> = rank.iter().map(|&w| not(self.b, w)).collect();
            let jc = const_word(self.b, j + 1, width);
            shift.push(add_words(self.b, &jc, &neg));
            occ.push(nd);
            let mut inc = const_word(self.b, 0, width);
            inc[0] = nd;
            rank = add_words(self.b, &rank, &inc);
        }
        // Compaction on the metadata, LSB first; record the moves.
        let mut moves: Vec<Vec<usize>> = Vec::with_capacity(width);
        for k in 0..width {
            let step = 1usize << k;
            let mut nocc = Vec::with_capacity(total);
            let mut nshift = Vec::with_capacity(total);
            let mut mv = Vec::with_capacity(total);
            for x in 0..total {
                let src = x + step;
                let inc = if src < total { self.b.and_wire(occ[src], shift[src][k]) } else { self.b.zero() };
                let nk = not(self.b, shift[x][k]);
                let stay = self.b.and_wire(occ[x], nk);
                nocc.push(self.b.or_wire(inc, stay));
                nshift.push(if src < total { koala::mux_words(self.b, inc, &shift[x], &shift[src]) } else { shift[x].clone() });
                mv.push(inc);
            }
            occ = nocc;
            shift = nshift;
            moves.push(mv);
        }
        // Expansion of the frontier: the compaction run backwards.
        let zero = koala::constant(self.b, 0);
        let mut arr: Vec<[Fp; DIGEST]> = (0..total).map(|j| if j < fmax { frontier[j].clone() } else { core::array::from_fn(|_| zero.clone()) }).collect();
        for k in (0..width).rev() {
            let step = 1usize << k;
            let mut next = arr.clone();
            for z in step..total {
                let m = moves[k][z - step];
                next[z] = core::array::from_fn(|i| koala::mux_words(self.b, m, &arr[z][i], &arr[z - step][i]));
            }
            arr = next;
        }
        let st = &mut self.trees[ti];
        st.fresh = arr;
        st.need = need;
        st.same_parent = same_parent;
        st.differ = differ;
        let after = non_free(self.b);
        self.profile.add("merkle routing prologue", after - before);
    }

    /// The sibling of path `p` at level `l`: a fresh frontier digest, or the
    /// node or sibling of an earlier path with the same parent.
    fn route(&mut self, ti: usize, p: usize, l: usize) {
        let before = non_free(self.b);
        let lv = self.trees[ti].tree.paths[p][l].clone();
        let node: [Fp; DIGEST] = core::array::from_fn(|i| self.felt(lv.val[i]));
        self.trees[ti].node[p][l] = Some(node);
        let d = self.trees[ti].tree.depth;
        let fresh = self.trees[ti].fresh[p * d + l].clone();
        let need = self.trees[ti].need[p * d + l];
        let mut acc: Option<[Fp; DIGEST]> = None;
        for q in 0..p {
            let sp = self.trees[ti].same_parent[p][q][l];
            let df = self.trees[ti].differ[p][q][l];
            let take_node = self.b.and_wire(sp, df);
            let ndf = not(self.b, df);
            let take_sib = self.b.and_wire(sp, ndf);
            let qn = self.trees[ti].node[q][l].clone().unwrap();
            let qs = self.trees[ti].sib[q][l].clone().unwrap();
            let cand: [Fp; DIGEST] = core::array::from_fn(|i| {
                (0..BITS)
                    .map(|j| {
                        let a = self.b.and_wire(take_node, qn[i][j]);
                        let c = self.b.and_wire(take_sib, qs[i][j]);
                        self.b.or_wire(a, c)
                    })
                    .collect()
            });
            acc = Some(match acc {
                None => cand,
                Some(prev) => core::array::from_fn(|i| (0..BITS).map(|j| self.b.or_wire(prev[i][j], cand[i][j])).collect()),
            });
        }
        let sib = match acc {
            None => fresh,
            Some(derived) => core::array::from_fn(|i| koala::mux_words(self.b, need, &derived[i], &fresh[i])),
        };
        self.trees[ti].sib[p][l] = Some(sib);
        let after = non_free(self.b);
        self.profile.add("merkle sibling routing", after - before);
        self.nested += after - before;
    }

    pub fn run(mut self) -> Report {
        let d = self.d;
        let mut w = 0usize;
        for (k, ins) in d.instrs.iter().enumerate() {
            if self.opts.limit.is_some_and(|l| k >= l) {
                break;
            }
            if let Some(&ti) = self.tree_at.get(&k) {
                self.prologue(ti);
            }
            if k % 50_000 == 0 && std::env::var_os("ZIREN_PROGRESS").is_some() {
                eprintln!("  [{k}/{}] {} non-free gates so far", d.instrs.len(), non_free(self.b));
            }
            let before = non_free(self.b);
            let name: &'static str = match ins {
                Ins::BaseAlu { op, mult, out, in1, in2 } => {
                    let (op, mult) = (*op, *mult);
                    // Multiplicities count constrained reads only: a bit
                    // decomposition reads its input unconstrained, so a
                    // `mult = 0` result can still be read. Compute it.
                    if op == DIV_ASSERT || (op == DIV && mult == 0) {
                        if op == DIV {
                            "dead"
                        } else {
                            let x = self.felt(*in1);
                            let y = self.felt(*in2);
                            let zy = is_zero(self.b, &y);
                            let nzy = not(self.b, zy);
                            let zx = is_zero(self.b, &x);
                            let c = self.b.or_wire(nzy, zx);
                            self.check(c);
                            "base assert"
                        }
                    } else {
                        let x = self.felt(*in1);
                        let y = self.felt(*in2);
                        let (v, nm) = match op {
                            ADD => (koala::add(self.b, &x, &y), "base add/sub"),
                            SUB => (koala::sub(self.b, &x, &y), "base add/sub"),
                            MUL => (koala::mul(self.b, &x, &y), "base mul"),
                            _ => {
                                let zy = is_zero(self.b, &y);
                                let nzy = not(self.b, zy);
                                let zx = is_zero(self.b, &x);
                                let c = self.b.or_wire(nzy, zx);
                                self.check(c);
                                let iy = koala::inverse(self.b, &y);
                                let q = koala::mul(self.b, &x, &iy);
                                let one = koala::constant(self.b, 1);
                                (koala::mux_words(self.b, zy, &q, &one), "base div")
                            }
                        };
                        self.write(*out, vec![v]);
                        nm
                    }
                }
                Ins::ExtAlu { op, mult, out, in1, in2 } => {
                    let (op, mult) = (*op, *mult);
                    if op == DIV && mult == 0 {
                        "dead"
                    } else if op == DIV_ASSERT {
                        let x = self.ext(*in1);
                        let y = self.ext(*in2);
                        let yb: Vec<usize> = y.iter().flatten().copied().collect();
                        let xb: Vec<usize> = x.iter().flatten().copied().collect();
                        let zy = is_zero(self.b, &yb);
                        let nzy = not(self.b, zy);
                        let zx = is_zero(self.b, &xb);
                        let c = self.b.or_wire(nzy, zx);
                        self.check(c);
                        "ext assert"
                    } else {
                        let x = self.ext(*in1);
                        let y = self.ext(*in2);
                        let (v, nm) = match op {
                            ADD => (ext_add(self.b, &x, &y), "ext add/sub"),
                            SUB => (ext_sub(self.b, &x, &y), "ext add/sub"),
                            MUL => (koala::ext_mul(self.b, &x, &y), "ext mul"),
                            _ => {
                                let yb: Vec<usize> = y.iter().flatten().copied().collect();
                                let xb: Vec<usize> = x.iter().flatten().copied().collect();
                                let zy = is_zero(self.b, &yb);
                                let nzy = not(self.b, zy);
                                let zx = is_zero(self.b, &xb);
                                let c = self.b.or_wire(nzy, zx);
                                self.check(c);
                                let iy = ext_inverse(self.b, &y);
                                let q = koala::ext_mul(self.b, &x, &iy);
                                let mut one = ext_zero(self.b);
                                one[0] = koala::constant(self.b, 1);
                                let v: Ext = core::array::from_fn(|i| koala::mux_words(self.b, zy, &q[i], &one[i]));
                                (v, "ext div")
                            }
                        };
                        self.write(*out, v.to_vec());
                        nm
                    }
                }
                Ins::MemRead { addr, val } => {
                    let x = self.ext(*addr);
                    let cs: Vec<usize> = (0..4).map(|i| eq_const(self.b, &x[i], val[i])).collect();
                    let c = and_all(self.b, &cs);
                    self.check(c);
                    "constant check"
                }
                Ins::MemWrite { addr, val } => {
                    let v: Vec<Fp> = val.iter().map(|&c| koala::constant(self.b, c)).collect();
                    self.write(*addr, v);
                    "constants"
                }
                Ins::Poseidon2 { out, inp } => {
                    let mut s: [Fp; 16] = core::array::from_fn(|i| self.felt(inp[i]));
                    koala::permute_with(self.b, &mut s, &zc::EXTERNAL_INITIAL, &zc::INTERNAL, &zc::EXTERNAL_FINAL);
                    for i in 0..16 {
                        self.write(out[i], vec![s[i].clone()]);
                    }
                    "poseidon2"
                }
                Ins::Select { bit, out1, out2, in1, in2 } => {
                    let bv = self.felt(*bit);
                    let x = self.felt(*in1);
                    let y = self.translate_select_in2(*in2);
                    let boolean = bv[1..].iter().all(|&w| w == 0);
                    let (o1, o2) = if boolean {
                        (koala::mux_words(self.b, bv[0], &x, &y), koala::mux_words(self.b, bv[0], &y, &x))
                    } else {
                        let t = koala::sub(self.b, &y, &x);
                        let t = koala::mul(self.b, &bv, &t);
                        let o1 = koala::add(self.b, &x, &t);
                        let s = koala::add(self.b, &x, &y);
                        let o2 = koala::sub(self.b, &s, &o1);
                        (o1, o2)
                    };
                    self.write(*out1, vec![o1]);
                    self.write(*out2, vec![o2]);
                    "select"
                }
                Ins::HintBits { input, outs } => {
                    let v = self.felt(*input);
                    for (i, a) in outs.iter().enumerate() {
                        let mut f = koala::constant(self.b, 0);
                        if i < BITS {
                            f[0] = v[i];
                        }
                        self.write(*a, vec![f]);
                    }
                    "bit decomposition"
                }
                Ins::Print => "dead",
                Ins::Ext2Felts { input, outs } => {
                    let v = self.ext(*input);
                    for i in 0..4 {
                        self.write(outs[i], vec![v[i].clone()]);
                    }
                    "ext to felts"
                }
                Ins::CommitPv { addrs } => {
                    let mut cs = Vec::new();
                    for (i, a) in addrs.iter().enumerate() {
                        let x = self.felt(*a);
                        cs.push(eq_const(self.b, &x, d.public_values[i]));
                    }
                    let c = and_all(self.b, &cs);
                    self.check(c);
                    "public values"
                }
                Ins::Hint { outs } => {
                    for a in outs {
                        let v = self.witness[w];
                        w += 1;
                        if self.sib_of.contains_key(a) {
                            continue;
                        }
                        // A witness word is an extension element only where the
                        // program reads it as one and its layout position holds
                        // one: the `Witnessable` layout is fixed by the program,
                        // and a base-field word is written as `Block::from(f)`,
                        // upper limbs zero. Those limbs are fixed to zero here,
                        // which accepts a subset of what the AIR accepts and
                        // everything an honest prover writes.
                        let honest = self.d.witness[w - 1];
                        let limbs = if self.ext_read[*a as usize] && honest[1..] != [0, 0, 0] { 4 } else { 1 };
                        let f: Vec<Fp> = (0..limbs).map(|i| self.input_felt(v[i])).collect();
                        self.hint_input_bits += limbs * BITS;
                        self.write(*a, f);
                    }
                    "input canonicity"
                }
            };
            let after = non_free(self.b);
            let own = after - before - std::mem::take(&mut self.nested);
            if name != "dead" {
                self.profile.add(name, own);
            }
            if self.opts.check_writes {
                self.check_writes(k, ins);
            }
        }
        let report = Report {
            output: self.ok,
            input_bits: self.input_bits,
            hint_input_bits: self.hint_input_bits,
            frontier_input_bits: self.frontier_input_bits,
            frontier_digests: self.trees.iter().map(|t| (t.tree.depth, t.tree.paths.len(), t.tree.frontier)).collect(),
            needed_digests: self.needed.clone(),
            profile: self.profile.clone(),
            mismatches: self.mismatches.clone(),
        };
        report
    }

    fn check_writes(&mut self, k: usize, ins: &Ins) {
        let outs: Vec<u32> = match ins {
            Ins::BaseAlu { out, .. } | Ins::ExtAlu { out, .. } => vec![*out],
            Ins::Poseidon2 { out, .. } => out.to_vec(),
            Ins::Select { out1, out2, .. } => vec![*out1, *out2],
            Ins::HintBits { outs, .. } | Ins::Hint { outs } => outs.clone(),
            Ins::Ext2Felts { outs, .. } => outs.to_vec(),
            _ => vec![],
        };
        for a in outs {
            let Some(v) = self.mem[a as usize].clone() else { continue };
            for (i, limb) in v.iter().enumerate() {
                let got = self.read_value(limb);
                if got != self.native.mem[a as usize][i] {
                    self.mismatches.push((k, a));
                    break;
                }
            }
        }
    }

    fn read_value(&self, x: &Fp) -> u32 {
        x.iter().enumerate().fold(0u32, |acc, (i, &wire)| acc | (u32::from(self.b.probe(wire)) << i))
    }
}

/// Reading a wire's value; the counting builder has none.
pub trait Probe {
    fn probe(&self, wire: usize) -> bool;
}
impl Probe for Count {
    fn probe(&self, _: usize) -> bool {
        false
    }
}
impl Probe for Eval {
    fn probe(&self, wire: usize) -> bool {
        self.get(wire)
    }
}
impl Probe for garbled_snark_verifier::circuits::sect233k1::stream::Plan {
    fn probe(&self, _: usize) -> bool {
        false
    }
}
impl Probe for garbled_snark_verifier::circuits::sect233k1::stream::Streaming {
    fn probe(&self, wire: usize) -> bool {
        self.value(wire)
    }
}
