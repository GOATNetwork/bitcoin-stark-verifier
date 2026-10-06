//! Temporary (whir-gc measurement): the linear forms of its columns each
//! table's constraints and buses read, derived from the symbolic AIR, and how
//! many independent ones each trace has.

mod common;

use std::collections::{BTreeMap, HashMap};

use common::{prove_probes, Probe};
use p3_air::symbolic::{AirLayout, BaseEntry, BaseLeaf, SymbolicExpr, SymbolicExpression};
use p3_air::BaseAir;
use p3_binary_field::TowerLevel;
use p3_bus::{BusActivation, BusSymbolicBuilder};
use p3_field::{Field, PrimeCharacteristicRing};
use zkm_binary_recursion::config::{record_verification, Instance};
use zkm_binary_recursion::machine::program::Program;
use zkm_binary_recursion::machine::TapeMachine;
use zkm_binary_stark::{BinarySchedule, F};

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
enum Col {
    Main(usize),
    Prep(usize),
}

/// An affine form: column coefficients and a constant, as representations.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct Aff {
    lin: BTreeMap<Col, u128>,
    c: u128,
}

fn f(x: u128) -> F {
    F::from_repr(x)
}

impl Aff {
    fn constant(c: F) -> Self {
        Self { lin: BTreeMap::new(), c: c.to_repr() }
    }
    fn add(&mut self, other: &Self, s: F) {
        for (&col, &v) in &other.lin {
            let entry = self.lin.entry(col).or_insert(0);
            *entry = (f(*entry) + s * f(v)).to_repr();
            if *entry == 0 {
                self.lin.remove(&col);
            }
        }
        self.c = (f(self.c) + s * f(other.c)).to_repr();
    }
    fn scaled(&self, s: F) -> Self {
        let mut out = Self::default();
        out.add(self, s);
        out
    }
}

/// Sum of (product of atoms) times an affine form.
type Rep = BTreeMap<Vec<usize>, Aff>;

#[derive(Default)]
struct Ctx {
    atoms: HashMap<(Vec<(Col, u128)>, u128), usize>,
    externals: HashMap<String, usize>,
    forms: Vec<BTreeMap<Col, u128>>,
    next: usize,
}

impl Ctx {
    fn atom(&mut self, a: &Aff) -> usize {
        let (_, &first) = a.lin.iter().next().expect("an atom reads a column");
        let s = f(first).inverse();
        let n = a.scaled(s);
        let key = (n.lin.iter().map(|(&c, &v)| (c, v)).collect::<Vec<_>>(), n.c);
        if let Some(&id) = self.atoms.get(&key) {
            return id;
        }
        let id = self.next;
        self.next += 1;
        self.atoms.insert(key, id);
        self.forms.push(a.lin.clone());
        id
    }
    fn external(&mut self, name: String) -> usize {
        if let Some(&id) = self.externals.get(&name) {
            return id;
        }
        let id = self.next;
        self.next += 1;
        self.externals.insert(name, id);
        id
    }
    fn merge(into: &mut Rep, from: &Rep, s: F) {
        for (m, a) in from {
            let entry = into.entry(m.clone()).or_default();
            entry.add(a, s);
            if entry.lin.is_empty() && entry.c == 0 {
                into.remove(m);
            }
        }
    }
    fn as_constant(r: &Rep) -> Option<F> {
        match r.len() {
            0 => Some(F::ZERO),
            1 => {
                let (m, a) = r.iter().next().unwrap();
                (m.is_empty() && a.lin.is_empty()).then(|| f(a.c))
            }
            _ => None,
        }
    }
    fn rep(&mut self, e: &SymbolicExpression<F>, memo: &mut HashMap<usize, Rep>) -> Rep {
        let key = e as *const _ as usize;
        if let Some(r) = memo.get(&key) {
            return r.clone();
        }
        let r = match e {
            SymbolicExpr::Leaf(leaf) => match leaf {
                BaseLeaf::Variable(v) => {
                    let col = match v.entry {
                        BaseEntry::Main { offset: 0 } => Some(Col::Main(v.index)),
                        BaseEntry::Preprocessed { offset: 0 } => Some(Col::Prep(v.index)),
                        other => {
                            let id = self.external(format!("{other:?}/{}", v.index));
                            let mut r = Rep::new();
                            r.insert(vec![id], Aff::constant(F::ONE));
                            None.or_else(|| {
                                memo.insert(key, r.clone());
                                None::<Col>
                            });
                            return r;
                        }
                    };
                    let mut a = Aff::default();
                    a.lin.insert(col.unwrap(), 1);
                    let mut r = Rep::new();
                    r.insert(Vec::new(), a);
                    r
                }
                BaseLeaf::Constant(c) => {
                    let mut r = Rep::new();
                    if *c != F::ZERO {
                        r.insert(Vec::new(), Aff::constant(*c));
                    }
                    r
                }
                other => {
                    let id = self.external(format!("{other:?}"));
                    let mut r = Rep::new();
                    r.insert(vec![id], Aff::constant(F::ONE));
                    r
                }
            },
            SymbolicExpr::Add { x, y, .. } => {
                let mut r = self.rep(x, memo);
                let ry = self.rep(y, memo);
                Self::merge(&mut r, &ry, F::ONE);
                r
            }
            SymbolicExpr::Sub { x, y, .. } => {
                let mut r = self.rep(x, memo);
                let ry = self.rep(y, memo);
                Self::merge(&mut r, &ry, F::NEG_ONE);
                r
            }
            SymbolicExpr::Neg { x, .. } => {
                let mut r = Rep::new();
                let rx = self.rep(x, memo);
                Self::merge(&mut r, &rx, F::NEG_ONE);
                r
            }
            SymbolicExpr::Mul { x, y, .. } => {
                let rx = self.rep(x, memo);
                let ry = self.rep(y, memo);
                let mut r = Rep::new();
                if let Some(c) = Self::as_constant(&rx) {
                    Self::merge(&mut r, &ry, c);
                } else if let Some(c) = Self::as_constant(&ry) {
                    Self::merge(&mut r, &rx, c);
                } else {
                    for (ma, la) in &rx {
                        for (mb, lb) in &ry {
                            let mut m: Vec<usize> = ma.iter().chain(mb).copied().collect();
                            let rest = if la.lin.is_empty() {
                                lb.scaled(f(la.c))
                            } else if lb.lin.is_empty() {
                                la.scaled(f(lb.c))
                            } else {
                                // The thinner form becomes an atom; the wider stays linear.
                                let (atom, rest) =
                                    if la.lin.len() <= lb.lin.len() { (la, lb) } else { (lb, la) };
                                m.push(self.atom(atom));
                                rest.clone()
                            };
                            m.sort_unstable();
                            let mut term = Rep::new();
                            term.insert(m, rest);
                            Self::merge(&mut r, &term, F::ONE);
                        }
                    }
                }
                r
            }
        };
        memo.insert(key, r.clone());
        r
    }
    fn root(&mut self, e: &SymbolicExpression<F>, memo: &mut HashMap<usize, Rep>) {
        let r = self.rep(e, memo);
        for a in r.values() {
            if !a.lin.is_empty() {
                self.forms.push(a.lin.clone());
            }
        }
    }
}

/// Independent forms among `forms` over `width` columns.
fn rank(forms: &[Vec<(usize, F)>], width: usize) -> usize {
    let mut sorted: Vec<&Vec<(usize, F)>> = forms.iter().collect();
    sorted.sort_by_key(|form| form.len());
    let mut pivots: BTreeMap<usize, Vec<F>> = BTreeMap::new();
    for form in sorted {
        let mut v = vec![F::ZERO; width];
        for &(c, x) in form {
            v[c] += x;
        }
        for (&p, row) in &pivots {
            let x = v[p];
            if x != F::ZERO {
                for (vi, ri) in v.iter_mut().zip(row) {
                    *vi -= x * *ri;
                }
            }
        }
        if let Some(p) = v.iter().position(|x| *x != F::ZERO) {
            let s = v[p].inverse();
            let row: Vec<F> = v.iter().map(|x| *x * s).collect();
            // Keep earlier pivots reduced against the new one.
            for other in pivots.values_mut() {
                let x = other[p];
                if x != F::ZERO {
                    for (oi, ri) in other.iter_mut().zip(&row) {
                        *oi -= x * *ri;
                    }
                }
            }
            pivots.insert(p, row);
        }
    }
    pivots.len()
}

#[test]
#[ignore]
fn forms_census() {
    let probes = [Probe { groups: 16, log_height: 10 }];
    let (_, vk, proof) = prove_probes(&probes);
    let shapes: Vec<_> = probes.iter().map(Probe::shape).collect();
    let instances: Vec<Instance<'_, Probe>> = probes
        .iter()
        .map(|p| Instance { air: p, log_height: p.log_height, public_values: &[] })
        .collect();
    let schedule = BinarySchedule::default();
    let (verdict, tape) = record_verification(&instances, &shapes, &[], &schedule, &vk, &proof);
    verdict.expect("accepts");
    let machine = TapeMachine::new(Program::new(&tape, 0), &schedule).expect("machine");
    let (mut main_total, mut main_forms, mut prep_total, mut prep_forms, mut prep_varying, mut prep_varying_forms) =
        (0, 0, 0, 0, 0, 0);
    for air in machine.airs() {
        let builder = BusSymbolicBuilder::<F, F>::from_air(air, AirLayout::from_air::<F>(air));
        let mut ctx = Ctx::default();
        let mut memo = HashMap::new();
        // Memoised by address: every expression must outlive the walk.
        let constraints = builder.base_constraints();
        for c in &constraints {
            ctx.root(c, &mut memo);
        }
        for interaction in builder.interactions() {
            for field in &interaction.fields {
                ctx.root(field, &mut memo);
            }
            match &interaction.activation {
                BusActivation::Boolean(e) => ctx.root(e, &mut memo),
                other => panic!("activation {other:?}"),
            }
        }
        let main_width = BaseAir::<F>::width(air);
        let prep_width = BaseAir::<F>::preprocessed_width(air);
        let split = |forms: &[BTreeMap<Col, u128>], main: bool| -> Vec<Vec<(usize, F)>> {
            forms
                .iter()
                .map(|form| {
                    form.iter()
                        .filter_map(|(&col, &v)| match (col, main) {
                            (Col::Main(i), true) | (Col::Prep(i), false) => Some((i, f(v))),
                            _ => None,
                        })
                        .collect::<Vec<_>>()
                })
                .filter(|form| !form.is_empty())
                .collect()
        };
        let mf = split(&ctx.forms, true);
        let pf = split(&ctx.forms, false);
        let m_rank = rank(&mf, main_width);
        let p_rank = rank(&pf, prep_width.max(1));
        // Forms over the preprocessed columns that vary over the rows.
        let (varying, pv_rank) = BaseAir::<F>::preprocessed_trace(air).map_or((0, 0), |trace| {
            let w = trace.width;
            let rows = trace.values.len() / w;
            let varies: Vec<bool> = (0..w)
                .map(|c| (1..rows).any(|r| trace.values[r * w + c] != trace.values[c]))
                .collect();
            let restricted: Vec<Vec<(usize, F)>> = pf
                .iter()
                .map(|form| form.iter().copied().filter(|&(c, _)| varies[c]).collect::<Vec<_>>())
                .filter(|form| !form.is_empty())
                .collect();
            (varies.iter().filter(|&&v| v).count(), rank(&restricted, w))
        });
        println!(
            "{:>7}: main {main_width} columns -> {m_rank} forms ({} distinct); prep {prep_width} columns -> {p_rank} forms; varying prep {varying} columns -> {pv_rank} forms",
            air.name(),
            mf.len()
        );
        main_total += main_width;
        main_forms += m_rank;
        prep_total += prep_width;
        prep_forms += p_rank;
        prep_varying += varying;
        prep_varying_forms += pv_rank;
    }
    println!("total: main {main_total} -> {main_forms}; prep {prep_total} -> {prep_forms}; varying prep {prep_varying} -> {prep_varying_forms}");
}
