# Option B (whir-gc experiment): align each table of a stacked layout to its
# own power-of-two block, so a table is opened as one block and costs one
# reduction claim; and pad the narrow machine's Rounds preprocessed row to 128.
import sys, os
p3, ziren = sys.argv[1], sys.argv[2]
p = os.path.join(p3, "sumcheck/src/layout/plan.rs")
s = open(p).read()
start = s.index("pub(crate) fn plan_layout(shapes: &[LayoutShape]) -> (usize, Vec<TablePlacement>) {")
end = s.index("/// Plan the stacked layout of a set of committed table shapes.")
new = '''pub(crate) fn plan_layout(shapes: &[LayoutShape]) -> (usize, Vec<TablePlacement>) {
    // Sort indices by arity ascending; reverse-iterate to place largest first.
    let mut order = (0..shapes.len()).collect::<Vec<usize>>();
    order.sort_by_key(|&i| shapes[i].arity);

    // Start each table at a multiple of its own block, the next power of two
    // of its width in slots, so its columns form one aligned block and the
    // table is opened as a single claim. Gaps are zero slots.
    // Only a set of power-of-two widths is aligned; any other set keeps the
    // original contiguous layout (block 1: no rounding).
    let align = shapes.iter().all(|shape| shape.width.is_power_of_two());
    let mut offset = 0usize;
    let mut starts = Vec::with_capacity(shapes.len());
    for &table_idx in order.iter().rev() {
        let shape = &shapes[table_idx];
        let block = if align { shape.width.next_power_of_two() << shape.arity } else { 1 };
        offset = offset.div_ceil(block) * block;
        starts.push((table_idx, offset));
        offset += shape.width << shape.arity;
    }

    // Stacked arity: log2_ceil of the end of the last table.
    let k = log2_ceil_usize(offset.max(1));

    let placements = starts
        .into_iter()
        .map(|(table_idx, start)| {
            let shape = &shapes[table_idx];
            let slot_size = 1usize << shape.arity;
            let selectors = (0..shape.width)
                .map(|column| Selector::new(k - shape.arity, (start + column * slot_size) >> shape.arity))
                .collect();
            TablePlacement::new(table_idx, selectors)
        })
        .collect();

    (k, placements)
}

'''
s = s[:start] + new + s[end:]
open(p, "w").write(s)
r = os.path.join(ziren, "crates/binary-recursion/src/machine/rounds.rs")
t = open(r).read()
a = """    /// Zeros, which make the width a power of two.
    pub pad: T,
}"""
assert t.count(a) == 1, "rounds pad"
t = t.replace(a, """    /// Zeros, which make the width a power of two (128 with 26-bit ids).
    pub pad: [T; 63],
}""")
open(r, "w").write(t)
print("aligned layout and padded Rounds preprocessed row")
