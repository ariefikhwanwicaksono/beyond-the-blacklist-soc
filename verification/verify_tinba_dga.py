"""Verify that the 1,000 DGA domains queried in the "tinba" capture are produced by the published Tinba DGA.

The reference implementation is J. Bader's tinba/dga.py (https://github.com/baderj/domain_generation_algorithms,
GPL-2.0). It is downloaded at run time from a pinned commit and imported unmodified -- it is NOT redistributed
in this repository.

That implementation only uses two values derived from the 16-byte seed: sum(seed[:16]) (through `& 0xFF`, so only
its value mod 256 matters) and seed[15]. The script therefore tries all 256 x 256 combinations, building for each a
seed string with those two properties, and checks which one regenerates the observed sequence from the hard-coded
first domain.

Usage: python3 verify_tinba_dga.py <path/to/zeek_out/tinba/dns.log>
Expected: exactly one combination (75, 106) reproduces 1000/1000 domains in order.
"""
import importlib.util
import sys
import tempfile
import urllib.request
from itertools import islice
from pathlib import Path

BADERJ_COMMIT = "6ab108e9304e54a18b9558d856c0d18107f5f8cd"
DGA_URL = f"https://raw.githubusercontent.com/baderj/domain_generation_algorithms/{BADERJ_COMMIT}/tinba/dga.py"


def load_baderj_dga():
    path = Path(tempfile.mkdtemp()) / "tinba_dga.py"
    urllib.request.urlretrieve(DGA_URL, path)
    spec = importlib.util.spec_from_file_location("tinba_dga", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod.dga


def observed_xyz_domains(dns_log):
    fields, seq, seen = None, [], set()
    for line in open(dns_log):
        if line.startswith("#fields"):
            fields = line.rstrip("\n").split("\t")[1:]
            continue
        if line.startswith("#"):
            continue
        q = line.rstrip("\n").split("\t")[fields.index("query")].lower()
        if q.endswith(".xyz") and q not in seen:
            seen.add(q)
            seq.append(q)
    return seq


def seed_for(seed_sum_mod256, last_byte):
    """16-char seed whose byte sum is congruent to seed_sum_mod256 and whose 16th byte is last_byte."""
    first = (seed_sum_mod256 - last_byte) % 256
    return chr(first) + "\x00" * 14 + chr(last_byte)


def main():
    seq = observed_xyz_domains(sys.argv[1])
    hard, observed = seq[0], seq[1:]
    print(f"unique .xyz domains in order: {len(seq)} (hard-coded first: {hard}, generated: {len(observed)})")
    dga = load_baderj_dga()

    first_hits = []
    for s in range(256):
        for t in range(256):
            gen = dga(seed_for(s, t), hard, ("xyz",), 1)
            next(gen)  # dga() yields the hard-coded domain first
            if next(gen) == observed[0]:
                first_hits.append((s, t))
    print("combinations reproducing the first generated domain:", first_hits)

    full = []
    for s, t in first_hits:
        gen = list(islice(dga(seed_for(s, t), hard, ("xyz",), len(observed)), 1, None))
        n_match = sum(a == b for a, b in zip(gen, observed))
        print(f"  (seed_sum mod 256={s}, seed[15]={t}): {n_match}/{len(observed)} in order")
        if n_match == len(observed):
            full.append((s, t))
    print("RESULT:", f"unique full match {full[0]}" if len(full) == 1 else f"{len(full)} full matches: {full}")


if __name__ == "__main__":
    main()
