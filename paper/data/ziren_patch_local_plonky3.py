# Point every Plonky3 crate of Ziren's workspace at a local Plonky3 copy.
import sys, os, re, glob
ziren, p3 = sys.argv[1], sys.argv[2]
names = {}
for toml in glob.glob(os.path.join(p3, "*/Cargo.toml")):
    m = re.search(r'^\[package\][^\[]*?^name\s*=\s*"([^"]+)"', open(toml).read(), re.M | re.S)
    if m:
        names[m.group(1)] = os.path.dirname(toml)
p = os.path.join(ziren, "Cargo.toml")
s = open(p).read()
used = sorted(set(re.findall(r'^(p3-[a-z0-9-]+)\s*=\s*\{\s*git\s*=\s*"https://github.com/ProjectZKM/Plonky3"', s, re.M)))
assert '[patch."https://github.com/ProjectZKM/Plonky3"]' not in s
lines = ['', '[patch."https://github.com/ProjectZKM/Plonky3"]']
for n in sorted(names):
    lines.append(f'{n} = {{ path = "{names[n]}" }}')
open(p, "a").write("\n".join(lines) + "\n")
missing = [n for n in used if n not in names]
print(f"{len(used)} p3 deps in Ziren, {len(names)} crates in the copy, missing: {missing}")
