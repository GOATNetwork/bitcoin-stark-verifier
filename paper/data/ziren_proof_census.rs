//! Census of a compressed Ziren proof: field elements per component, Merkle
//! openings, and the implied garbled-verifier input bits. Walks the serde
//! structure generically so it needs no type paths.
use std::collections::BTreeMap;
use zkm_sdk::ZKMProofWithPublicValues;

#[derive(Default, Clone, Copy)]
struct Acc { numbers: u64, arrays: u64 }

fn walk(v: &serde_json::Value, path: &mut Vec<String>, depth_limit: usize, acc: &mut BTreeMap<String, Acc>) {
    let key = path.iter().take(depth_limit).cloned().collect::<Vec<_>>().join("/");
    match v {
        serde_json::Value::Number(_) | serde_json::Value::Bool(_) => {
            // count at every prefix
            for d in 0..=path.len().min(depth_limit) {
                let k = path[..d].join("/");
                acc.entry(k).or_default().numbers += 1;
            }
        }
        serde_json::Value::String(_) | serde_json::Value::Null => {}
        serde_json::Value::Array(a) => {
            acc.entry(key).or_default().arrays += 1;
            for x in a { walk(x, path, depth_limit, acc); }
        }
        serde_json::Value::Object(o) => {
            for (k, x) in o {
                path.push(k.clone());
                walk(x, path, depth_limit, acc);
                path.pop();
            }
        }
    }
}

fn count_numbers(v: &serde_json::Value) -> u64 {
    match v {
        serde_json::Value::Number(_) | serde_json::Value::Bool(_) => 1,
        serde_json::Value::Array(a) => a.iter().map(count_numbers).sum(),
        serde_json::Value::Object(o) => o.values().map(count_numbers).sum(),
        _ => 0,
    }
}

fn main() {
    let path = std::env::args().nth(1).unwrap_or_else(|| "compressed-proof-with-pis.bin".into());
    let bytes = std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0);
    let proof = ZKMProofWithPublicValues::load(&path).expect("load");
    let v = serde_json::to_value(&proof.proof).expect("to json");
    let compressed = v.get("Compressed").expect("a compressed proof");
    let shard = compressed.get("proof").expect("proof");
    let vk = compressed.get("vk").expect("vk");
    let jsp = shard.get("jagged_shard_proof").expect("jsp");

    println!("file bytes: {bytes}");
    println!("vk numbers: {}", count_numbers(vk));
    println!("shard public_values numbers: {}", count_numbers(shard.get("public_values").unwrap()));
    println!("jagged_shard_proof numbers (all): {}", count_numbers(jsp));

    let mut acc = BTreeMap::new();
    let mut p = vec![];
    walk(jsp, &mut p, 3, &mut acc);
    println!("\n-- numbers per component (prefix depth <= 3) --");
    for (k, a) in &acc {
        if a.numbers > 0 { println!("{:<70} {:>10} numbers {:>8} arrays", if k.is_empty() { "(total)" } else { k }, a.numbers, a.arrays); }
    }

    // WHIR rounds: queries, leaf values, sibling digests.
    if let Some(ep) = jsp.get("evaluation_proof").map(|e| e.get("Bundle").unwrap_or(e)) {
        if let Some(wp) = ep.get("whir_proof").and_then(|w| if w.is_null() { None } else { Some(w) }) {
            let inner = wp.get("whir_proof").unwrap_or(wp);
            println!("\n-- WHIR --");
            if let Some(r) = inner.get("round_commitments").and_then(|x| x.as_array()) { println!("round_commitments: {}", r.len()); }
            if let Some(r) = inner.get("round_sumcheck_polys").and_then(|x| x.as_array()) {
                for (i, rr) in r.iter().enumerate() { println!("round {i}: sumcheck polys {} ({} numbers)", rr.as_array().map(|a| a.len()).unwrap_or(0), count_numbers(rr)); }
            }
            if let Some(r) = inner.get("round_ood_answers").and_then(|x| x.as_array()) {
                for (i, rr) in r.iter().enumerate() { println!("round {i}: ood answers {} numbers", count_numbers(rr)); }
            }
            if let Some(r) = inner.get("round_query_openings").and_then(|x| x.as_array()) {
                let mut total_sib = 0u64; let mut total_leafvals = 0u64; let mut total_leaves = 0u64;
                for (i, rr) in r.iter().enumerate() {
                    let leaves = rr.get("leaves").and_then(|x| x.as_array()).cloned().unwrap_or_default();
                    let mut sib = 0u64; let mut vals = 0u64; let mut depth = 0usize; let mut valw = 0usize;
                    for l in &leaves {
                        let pr = l.get("proof").and_then(|x| x.as_array()).cloned().unwrap_or_default();
                        depth = pr.len(); sib += pr.len() as u64;
                        let vv = l.get("values").and_then(|x| x.as_array()).cloned().unwrap_or_default();
                        valw = vv.iter().map(count_numbers).sum::<u64>() as usize; vals += valw as u64;
                    }
                    println!("round {i}: {} query leaves, depth {depth} siblings each ({sib} digests of 8), {valw} felts per leaf ({vals} felts)", leaves.len());
                    total_sib += sib; total_leafvals += vals; total_leaves += leaves.len() as u64;
                }
                println!("WHIR totals: {total_leaves} leaves, {total_sib} sibling digests ({} felts), {total_leafvals} leaf felts", total_sib * 8);
            }
            if let Some(fp) = inner.get("final_poly") { println!("final_poly numbers: {}", count_numbers(fp)); }
            if let Some(fp) = inner.get("final_sumcheck_polys") { println!("final_sumcheck_polys numbers: {}", count_numbers(fp)); }
            if let Some(be) = wp.get("batch_evaluations") { println!("batch_evaluations numbers: {}", count_numbers(be)); }
        }
    }
    if let Some(ch) = jsp.get("chip_heights").and_then(|x| x.as_object()) {
        println!("\n-- chips ({}) --", ch.len());
        for (k, h) in ch { println!("{k}: height {h}"); }
    }
    if let Some(ov) = jsp.get("opened_values").and_then(|x| x.get("chips")).and_then(|x| x.as_array()) {
        let mut main = 0u64; let mut prep = 0u64; let mut perm = 0u64; let mut quot = 0u64;
        for c in ov {
            main += count_numbers(c.get("main").unwrap());
            prep += count_numbers(c.get("preprocessed").unwrap());
            perm += count_numbers(c.get("permutation").unwrap());
            quot += count_numbers(c.get("quotient").unwrap());
        }
        println!("opened values: main {main} prep {prep} perm {perm} quotient {quot} (base felts; ext = 4 each)");
    }
    let total = count_numbers(shard);
    println!("\nGC input: {} base felts = {} bits at 31 bits each ({} bytes raw at 4 B)", total, total * 31, total * 4);
}
