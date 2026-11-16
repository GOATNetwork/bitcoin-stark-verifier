//! KoalaBear arithmetic in a binary-stage tape (tape v3): the translated
//! circuit accepts honest values, rejects wrong results and non-canonical
//! operands, and publishes a KoalaBear-only input as 31 bits. A wrap node's
//! tape has no KoalaBear operation; a compose node's tape has them.

use whir_gc::binary_tape::{self, BTape, InputWidth, KbOp, Options, KB_PRIME};
use whir_gc::ziren::{Count, Eval};

/// A v3 tape writer for the operations these tests use.
#[derive(Default)]
struct Tape {
    ops: Vec<u8>,
    n: u64,
}
enum O {
    V(u32),
    C(u128),
}
impl Tape {
    fn opd(&mut self, o: O) {
        match o {
            O::V(v) => {
                self.ops.push(0);
                self.ops.extend(v.to_le_bytes());
            }
            O::C(c) => {
                self.ops.push(1);
                self.ops.extend(c.to_le_bytes());
            }
        }
    }
    fn input(&mut self, i: u64) {
        self.ops.push(0);
        self.ops.extend(i.to_le_bytes());
        self.n += 1;
    }
    fn add(&mut self, a: O, b: O) {
        self.ops.push(1);
        self.opd(a);
        self.opd(b);
        self.n += 1;
    }
    fn assert_eq(&mut self, a: O, b: O) {
        self.ops.push(4);
        self.opd(a);
        self.opd(b);
        self.n += 1;
    }
    fn kb(&mut self, k: KbOp, a: O, b: O) {
        self.ops.push(14);
        self.ops.push(match k {
            KbOp::Add => 0,
            KbOp::Sub => 1,
            KbOp::Mul => 2,
        });
        self.opd(a);
        self.opd(b);
        self.n += 1;
    }
    fn bytes(&self, inputs: &[u128], values: &[u128]) -> Vec<u8> {
        let mut out = b"ZTAP".to_vec();
        out.extend(3u32.to_le_bytes());
        out.extend(self.n.to_le_bytes());
        out.extend(&self.ops);
        out.extend((inputs.len() as u64).to_le_bytes());
        inputs.iter().for_each(|x| out.extend(x.to_le_bytes()));
        out.extend((values.len() as u64).to_le_bytes());
        values.iter().for_each(|x| out.extend(x.to_le_bytes()));
        out
    }
}

const A: u128 = 12_345;
const B: u128 = 0x7e00_1234;

/// `((a + b)·a - 5)^2`, then `a·(b + 0)` through a GF(2^128) addition whose
/// output is not canonical by construction, each asserted.
fn honest() -> BTape {
    let (a, b) = (A, B);
    let s = KbOp::Add.apply(a, b);
    let m = KbOp::Mul.apply(s, a);
    let d = KbOp::Sub.apply(m, 5);
    let q = KbOp::Mul.apply(d, d);
    let x = b; // b + 0 in GF(2^128)
    let y = KbOp::Mul.apply(a, x);
    let mut t = Tape::default();
    t.input(0); // v0
    t.input(1); // v1
    t.kb(KbOp::Add, O::V(0), O::V(1)); // v2
    t.kb(KbOp::Mul, O::V(2), O::V(0)); // v3
    t.kb(KbOp::Sub, O::V(3), O::C(5)); // v4
    t.kb(KbOp::Mul, O::V(4), O::V(4)); // v5
    t.assert_eq(O::V(5), O::C(q));
    t.input(2); // v6: read only through the binary-field addition
    t.add(O::V(6), O::C(0)); // v7
    t.kb(KbOp::Mul, O::V(0), O::V(7)); // v8
    t.assert_eq(O::V(8), O::C(y));
    let inputs = [a, b, b];
    let values = [a, b, s, m, d, q, b, x, y];
    binary_tape::parse(&t.bytes(&inputs, &values))
}

fn accepts(t: &BTape, inputs: &[u128]) -> bool {
    let mut b = Eval::default();
    let r = binary_tape::translate(&mut b, t, inputs, Options { check_values: false, limit: None });
    b.get(r.output)
}

#[test]
fn parses_v3_and_accepts_honest_values() {
    let t = honest();
    assert_eq!(t.ops.len(), 11);
    assert!(matches!(t.ops[2], binary_tape::TOp::Kb(KbOp::Add, ..)));
    let mut b = Eval::default();
    let r = binary_tape::translate(&mut b, &t, &t.inputs, Options { check_values: true, limit: None });
    assert!(r.mismatches.is_empty(), "values differ at {:?}", r.mismatches);
    assert!(b.get(r.output));
}

#[test]
fn koalabear_inputs_are_published_as_31_bits() {
    let t = honest();
    let w = binary_tape::input_widths(&t);
    assert_eq!(w, vec![InputWidth::Kb, InputWidth::Kb, InputWidth::Full]);
    let mut b = Count::default();
    let r = binary_tape::translate(&mut b, &t, &t.inputs, Options { check_values: false, limit: None });
    assert_eq!(r.inputs_by_width, [0, 0, 1, 2]);
    assert_eq!(r.input_bits, 2 * 31 + 128);
}

#[test]
fn rejects_wrong_results_and_non_canonical_operands() {
    let t = honest();
    // A wrong input value changes the asserted results.
    assert!(!accepts(&t, &[A + 1, B, B]));
    // a + p is the same residue in a non-canonical encoding that fits 31 bits.
    assert!(A + KB_PRIME < 1 << 31);
    assert!(!accepts(&t, &[A + KB_PRIME, B, B]));
    // A KoalaBear operand reached through a binary-field addition: a high bit
    // set, or a canonical-looking low part with the same residue plus p, is rejected.
    assert!(!accepts(&t, &[A, B, B | 1 << 100]));
    assert!(B + KB_PRIME >= 1 << 31);
    assert!(!accepts(&t, &[A, B, B + KB_PRIME]));
    // Only the honest input is accepted.
    assert!(accepts(&t, &[A, B, B]));
}

#[test]
fn koalabear_multiplication_gate_count() {
    let t = honest();
    let mut b = Count::default();
    let r = binary_tape::translate(&mut b, &t, &t.inputs, Options { check_values: false, limit: None });
    let (_, gates, ops) = *r.profile.parts.iter().find(|e| e.0 == "koalabear").expect("KoalaBear operations");
    eprintln!(
        "tape of {} ops: {} AND gates in total; {} KoalaBear operations hold {} non-free gates",
        t.ops.len(),
        b.and,
        ops,
        gates
    );
    assert_eq!(ops, 5);
}
