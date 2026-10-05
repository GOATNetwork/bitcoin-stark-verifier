# Hook the GPU grinder into p3-binary-field's BinaryChallenger::grind (box copy only).
import sys, os
root = sys.argv[1]
p = os.path.join(root, "binary-field/src/challenger.rs")
s = open(p).read()
anchor = """        let witness = if let Some(pending) = blake3_pending(&self.inner) {"""
assert s.count(anchor) == 1
gpu = """        // GPU grinding (whir-gc experiment): the zkm_blake3_grind library finds a
        // candidate over the same Blake3 transcript, or declines (CPU below).
        if F::bits() >= u64::BITS as usize {
            if let Some(transcript) =
                (&self.inner as &dyn Any).downcast_ref::<HashChallenger<u8, Blake3, 32>>()
            {
                let pending = transcript.pending_input();
                let mut index = 0u64;
                // SAFETY: the library reads `len` bytes from `pending` and writes one u64.
                let declined = unsafe {
                    zkm_blake3_grind(pending.as_ptr(), pending.len(), bits as u32, &mut index)
                };
                if declined == 0 {
                    let witness = candidate::<F>(index);
                    assert!(self.check_witness(bits, witness), "GPU grind witness fails the CPU check");
                    return witness;
                }
            }
        }

"""
s = s.replace(anchor, gpu + anchor)
decl_anchor = "fn candidate<F: TowerLevel>(index: u64) -> F {"
assert s.count(decl_anchor) == 1
s = s.replace(decl_anchor, """unsafe extern "C" {
    /// GPU proof-of-work search (zkm_blake3_grind.cu): 0 and the candidate
    /// index in `out` when found, nonzero when it declines.
    fn zkm_blake3_grind(pending: *const u8, len: usize, bits: u32, out: *mut u64) -> i32;
}

""" + decl_anchor)
open(p, "w").write(s)
open(os.path.join(root, "binary-field/build.rs"), "w").write("""fn main() {
    // whir-gc experiment: link the GPU grinder from ZKM_GRIND_LIB_DIR.
    println!("cargo:rerun-if-env-changed=ZKM_GRIND_LIB_DIR");
    let dir = std::env::var("ZKM_GRIND_LIB_DIR").expect("ZKM_GRIND_LIB_DIR names the directory of libzkmgrind.so");
    println!("cargo:rustc-link-search=native={dir}");
    println!("cargo:rustc-link-lib=dylib=zkmgrind");
}
""")
print("patched", p)
