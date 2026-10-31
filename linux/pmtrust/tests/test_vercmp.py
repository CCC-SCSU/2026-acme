#!/usr/bin/env python3
"""Cross-check pure-Python version comparison against the real tools on the
staging host (dpkg --compare-versions, rpm's lua rpm.vercmp, pacman's vercmp).
Usage: python3 tests/test_vercmp.py [apt|rpm|pacman ...]"""
import itertools
import os
import random
import shutil
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

BASE = ["1.0", "1.0-1", "1:1.0", "0:1.0", "1.0~rc1", "1.0~~", "1.0~", "1.0a", "1.0.1", "1.00", "1.0+b1",
        "2.38-1ubuntu6.3", "2.38-1ubuntu6", "2.38-1ubuntu6.10", "1.2.3-4.5", "1.2.3-4.5+deb12u1",
        "9.2", "10.1", "1.0-1.el9", "1.0-1.el9_4", "1.0-1.el9_4.1", "4.16.1.3-29.el9", "4.16.1.3-34.el9",
        "1.0^git1", "1.0^", "1.0.a", "a", "b", "1.0-1a", "1.0-1.1", "2:0.1", "1:9.9", "0.1-0",
        "6.0.2-6", "7.0.0-1", "7.0.0.r6.gc685ae6-2", "1.0-1_1", "1.0_1", "20240313-1", "0~20240313-1",
        "3.9.18-3.el9_4.6", "3.9.18-3.el9_4.10", "1.0rc1", "1.0.rc1", "1.0+", "1.0..1", "1.0-", "001.2"]


def pairs(n=400):
    random.seed(37)
    ps = list(itertools.combinations(BASE, 2))
    random.shuffle(ps)
    return ps[:n]


def sign(x):
    return (x > 0) - (x < 0)


def test_apt():
    from backends.apt import vercmp
    if not shutil.which("dpkg"):
        return "dpkg not on host; skipped"
    bad = 0
    ps = [(a, b) for a, b in pairs() if "_" not in a + b and "^" not in a + b and not a.endswith("-")
          and not b.endswith("-") and a[0].isdigit() and b[0].isdigit()]
    for a, b in ps:
        lt = subprocess.run(["dpkg", "--compare-versions", a, "lt", b]).returncode == 0
        eq = subprocess.run(["dpkg", "--compare-versions", a, "eq", b]).returncode == 0
        real = -1 if lt else 0 if eq else 1
        if real != sign(vercmp(a, b)):
            print(f"  apt mismatch {a} vs {b}: dpkg {real}, ours {vercmp(a, b)}")
            bad += 1
    return f"{len(ps)} pairs, {bad} mismatches"


def test_rpm():
    from backends.rpm import vercmp_evr
    if not shutil.which("rpm"):
        return "rpm not on host; skipped"
    # pmtrust only compares complete E:V-R triples from rpm headers; lua's
    # rpm.vercmp differs from rpmverCmp when exactly one side lacks a release.
    ps = [(a, b) for a, b in pairs(2000) if ("-" in a) == ("-" in b) and not a.endswith("-") and not b.endswith("-")]
    lua = "".join(f'print(rpm.vercmp("{a}","{b}") .. " ")' for a, b in ps)
    res = subprocess.run(["rpm", "--eval", "%{lua:" + lua + "}"], stdout=subprocess.PIPE, text=True).stdout.split()
    bad = 0
    for (a, b), r in zip(ps, res):
        if sign(int(r)) != sign(vercmp_evr(a, b)):
            print(f"  rpm mismatch {a} vs {b}: rpm {r}, ours {vercmp_evr(a, b)}")
            bad += 1
    return f"{len(ps)} pairs, {bad} mismatches"


def test_pacman():
    from backends.pacman import vercmp
    if not shutil.which("vercmp"):
        return "vercmp not on host; skipped"
    bad = 0
    ps = pairs()
    for a, b in ps:
        r = int(subprocess.run(["vercmp", a, b], stdout=subprocess.PIPE, text=True).stdout.strip())
        if sign(r) != sign(vercmp(a, b)):
            print(f"  pacman mismatch {a} vs {b}: vercmp {r}, ours {vercmp(a, b)}")
            bad += 1
    return f"{len(ps)} pairs, {bad} mismatches"


if __name__ == "__main__":
    which = sys.argv[1:] or ["apt", "rpm", "pacman"]
    fail = False
    for w in which:
        try:
            r = globals()[f"test_{w}"]()
        except ImportError as e:
            r = f"not built yet ({e})"
        print(f"{w}: {r}")
        fail |= "mismatches" in r and not r.endswith(" 0 mismatches")
    sys.exit(1 if fail else 0)
