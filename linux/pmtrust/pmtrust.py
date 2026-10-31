#!/usr/bin/env python3
"""pmtrust -- rebuild a possibly compromised package manager from a verified trust chain.

Purpose : CCDC (Acme LLC, team 37) offline workflow. The boxes are never trusted:
          they only run a static busybox to snapshot themselves and to carry out
          a precomputed plan. All verification, parsing and auditing happens on a
          TRUSTED STAGING HOST (a team laptop with internet access) using its own
          gpgv/openssl and keyrings you supply.
Hosts   : apt     daffy (.11 Debian), elmer (.77 Ubuntu 22.04), marvin (.199 Ubuntu 24.04), taz (.169 Debian 13)
          rpm     foghorn (.13 Rocky), sylvester (.69 Rocky)
          pacman  porky (.67 Arch)
          nix     ysam (.234 NixOS 25.05)        -- verify + store repair
          tce     roadrunner (.12 Tiny Core)     -- audit only (no signatures exist)
          pkg     tweety (.1 OPNsense)           -- audit only (router; a reset costs 100)
          Internal 192.168.220.Y, from outside 10.100.137.Y (team 37 NAT).
Run     : 1. python3 pmtrust.py agent --busybox /bin/busybox --out agent-build   (once)
          2. scp -r agent-build root@<box>:/root/pmtrust ; on the box:
             /root/pmtrust/bin/busybox sh /root/pmtrust/collect.sh ; scp the snapshot back
          3. python3 pmtrust.py plan --snapshot snap-<box>-*.tar.gz --keyring ... --expect-fpr ...
             (reads, verifies and audits; writes plan-<box>-<time>/ and a timestamped log)
          4. scp -r plan-<box>-* root@<box>:/root/pmtrust/ ; on the box:
             cd /root/pmtrust/plan-<box>-* && ./bin/busybox sh apply.sh        (dry run)
             ./bin/busybox sh apply.sh --apply
Revert  : on the box: ./bin/busybox sh apply.sh --rollback /var/lib/pmtrust/run-<time>
Exit    : 0 no critical findings, 2 critical findings, 1 fatal (verification failed / bad input)
"""
import argparse
import hashlib
import os
import shutil
import sys
import tempfile
from datetime import datetime, timezone

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

from core import net, audit_common                       # noqa: E402
from core.report import R, LOG, out, step, die, Fatal    # noqa: E402
from core.snapshot import Snapshot                        # noqa: E402
from core.vpkg import Payload                             # noqa: E402
from core.plan import Plan                                # noqa: E402
import backends                                           # noqa: E402


def is_static_elf(path):
    with open(path, "rb") as f:
        data = f.read()
    if data[:4] != b"\x7fELF" or data[4] != 2:
        return False, "not a 64-bit ELF file"
    if data[18:20] != b"\x3e\x00":
        return False, "not x86-64"
    import struct
    phoff = struct.unpack_from("<Q", data, 32)[0]
    phentsize, phnum = struct.unpack_from("<HH", data, 54)
    for i in range(phnum):
        ptype = struct.unpack_from("<I", data, phoff + i * phentsize)[0]
        if ptype == 3:   # PT_INTERP
            return False, "dynamically linked (has an ELF interpreter); it would load the box's libc"
    return True, "static x86-64 ELF"


def cmd_agent(args):
    od = os.path.abspath(args.out)
    if os.path.realpath(od) == os.path.realpath(os.path.join(HERE, "agent")):
        die(f"--out {args.out} is pmtrust's own agent/ source directory; pick another directory, "
            f"e.g. --out ../agent-build")
    os.makedirs(os.path.join(od, "bin"), exist_ok=True)
    ok, why = is_static_elf(args.busybox)
    if not ok:
        die(f"{args.busybox}: {why}. Use a static busybox (Debian/Ubuntu: busybox-static, /bin/busybox).")
    shutil.copy2(args.busybox, os.path.join(od, "bin", "busybox"))
    os.chmod(os.path.join(od, "bin", "busybox"), 0o755)
    for f in ("collect.sh", "apply.sh"):
        shutil.copy2(os.path.join(HERE, "agent", f), os.path.join(od, f))
        os.chmod(os.path.join(od, f), 0o755)
    lines = []
    for f in ("bin/busybox", "collect.sh", "apply.sh"):
        with open(os.path.join(od, f), "rb") as fh:
            lines.append(f"{hashlib.sha256(fh.read()).hexdigest()}  ./{f}")
    with open(os.path.join(od, "AGENT.sha256"), "w") as f:
        f.write("\n".join(lines) + "\n")
    out(f"agent written to {od} ({why})")
    for ln in lines:
        out("  " + ln)
    out(f"copy it to each Linux box:   scp -r {od} root@<box>:/root/pmtrust")
    out("then on the box:             /root/pmtrust/bin/busybox sh /root/pmtrust/collect.sh")
    out("tweety (FreeBSD):            scp collect.sh only; run it with /bin/sh")
    return 0


def cmd_plan(args):
    snap_path = os.path.abspath(args.snapshot)
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    workdir = os.path.abspath(args.workdir or tempfile.mkdtemp(prefix="pmtrust-", dir=args.tmp))
    os.makedirs(workdir, exist_ok=True)
    snap = Snapshot(snap_path, workdir)
    outdir = os.path.abspath(args.out or f"plan-{snap.host}-{ts}")
    if os.path.exists(outdir) and os.listdir(outdir):
        die(f"{outdir} exists and is not empty; choose another --out")
    os.makedirs(outdir, exist_ok=True)
    args.out = outdir
    LOG.open(os.path.join(outdir, f"pmtrust-plan-{snap.host}-{ts}.log"))
    out(f"pmtrust plan for {snap.host}; log: {LOG.path}")
    net.ALLOW_HTTP = args.allow_http
    net.CACHE_DIR = os.path.abspath(args.cache) if args.cache else None

    R.reset(f"pmtrust audit of {snap.host} (snapshot {snap.meta.get('date_utc')})")
    snap.sanity()
    if snap.os != "Linux" and args.backend not in (None, "freebsd-pkg"):
        die(f"snapshot is from {snap.os}")
    name = args.backend or backends.detect(snap)
    if not name:
        die("cannot detect the package manager from the snapshot; pass --backend")
    cls = backends.BACKENDS[name]
    out(f"backend: {name}")
    payload = Payload(os.path.join(outdir, "payload"))
    store = Payload(os.path.join(workdir, "store"))
    be = cls(args, snap, workdir, store)

    if cls.audit_only:
        be.audit()
        rep = R.rep
        with open(os.path.join(outdir, "report.txt"), "w") as f:
            f.write(rep.text())
        shutil.rmtree(os.path.join(outdir, "payload"), ignore_errors=True)
        return summary(rep, outdir, None, snap, audit_only=True)

    agent = args.agent or next((d for d in ("agent-build", "agent", os.path.join(HERE, "agent"))
                                if os.path.exists(os.path.join(d, "bin", "busybox"))), None)
    if not agent or not os.path.exists(os.path.join(agent, "bin", "busybox")):
        die("no agent directory with bin/busybox found; run 'pmtrust.py agent --out agent-build' first or pass --agent DIR")
    vpkgs = be.collect_verified()
    plan = Plan(snap, outdir, payload, be, store=store)
    step("Comparing the snapshot with the verified packages")
    be.pre_plan(plan, vpkgs)
    plan.compare_and_plan(vpkgs, restore_conffiles=args.restore_conffiles)
    be.post_compare(plan, vpkgs)
    step("Auditing for things a reinstall alone would not fix")
    audit_common.run(snap, vpkgs, plan, be, be.db_owned())
    be.injection_points(plan, vpkgs)
    plan.finalize_sh = be.finalize_script(plan)
    st = plan.stats
    R.info(f"compared {st['checked']} verified paths, {st['problems']} problems, {st['unchecked']} not hashed "
           f"in the snapshot (docs/locales/large files), {st['outside']} outside the collector's roots, "
           f"{st['upgrade_pkgs']} packages not at an exact version")
    rep = R.rep
    plan_id, shipped = plan.write(agent, rep.text())
    return summary(rep, outdir, plan, snap, plan_id=plan_id, shipped=shipped)


def summary(rep, outdir, plan, snap, audit_only=False, plan_id=None, shipped=()):
    out("\n" + "=" * 76)
    out(f"{rep.title}: {rep.count('CRIT')} critical, {rep.count('WARN')} warnings")
    for lvl, msg in rep.items:
        if lvl == "CRIT":
            out(f"  - {msg}")
    out(f"\nreport: {os.path.join(outdir, 'report.txt')}")
    out(f"log:    {LOG.path}")
    if audit_only:
        out("This backend is audit-only: no plan was written. Findings need a human decision.")
    else:
        n = len(plan.actions)
        out(f"plan:   {outdir}  ({n} actions, {len(plan.finalize_pkgs)} packages for finalize, "
            f"{plan.payload.count} payload files / {plan.payload.bytes // 1024} KiB)")
        out(f"plan id (apply.sh prints the same): {plan_id}")
        if plan.restarts:
            out("services the package scripts may restart during finalize:")
            for r in sorted(set(plan.restarts)):
                out(f"  {r}")
        if n == 0 and not plan.finalize_pkgs:
            out("Nothing to repair: every verified file matches. Ship the plan anyway to use --verify on the box.")
        out(f"next:   scp -r {outdir} root@<{snap.host}>:/root/pmtrust/ && "
            f"ssh root@<{snap.host}> 'cd /root/pmtrust/{os.path.basename(outdir)} && ./bin/busybox sh apply.sh'")
    out("Limits: signatures prove origin, not honesty (xz-utils would pass); a live kernel rootkit can lie "
        "to the collector; persistence outside package management (units, cron, keys, PAM) is not covered.")
    return 2 if rep.count("CRIT") else 0


def main(argv=None):
    ap = argparse.ArgumentParser(prog="pmtrust", description=__doc__.split("\n")[0],
                                 formatter_class=argparse.RawDescriptionHelpFormatter, epilog=__doc__)
    sub = ap.add_subparsers(dest="cmd", required=True)
    a = sub.add_parser("agent", help="build the on-box agent directory")
    a.add_argument("--busybox", default="/bin/busybox", help="static x86-64 busybox from the staging host")
    a.add_argument("--out", default="agent-build")
    p = sub.add_parser("plan", help="verify, audit a snapshot, and write a repair plan")
    p.add_argument("--snapshot", required=True)
    p.add_argument("--out", help="plan directory (default plan-<host>-<time>)")
    p.add_argument("--backend", choices=sorted(backends.BACKENDS))
    p.add_argument("--keyring", help="signing keyring from a trusted source (NOT the target)")
    p.add_argument("--expect-fpr", action="append", default=[], help="pinned signing key fingerprint (repeatable)")
    p.add_argument("--trust-keyring", action="store_true", help="accept any key in --keyring")
    p.add_argument("--arch")
    p.add_argument("--extra", action="append", default=[], help="extra package for the verified set")
    p.add_argument("--upgrade", action="store_true", help="use the newest versions instead of the installed ones")
    p.add_argument("--allow-downgrade", action="store_true")
    p.add_argument("--restore-conffiles", action="store_true",
                   help="replace modified config files with packaged defaults (backups kept)")
    p.add_argument("--allow-http", action="store_true", help="permit http:// mirrors (signatures still checked)")
    p.add_argument("--cache", help="content-addressed download cache directory")
    p.add_argument("--workdir")
    p.add_argument("--tmp", default="/var/tmp")
    p.add_argument("--agent", help="agent directory to copy apply.sh and busybox from (default: ./agent next "
                                   "to this script)")
    for cls in backends.BACKENDS.values():
        cls.add_args(p)
    args = ap.parse_args(argv)
    try:
        if args.cmd == "agent":
            return cmd_agent(args)
        return cmd_plan(args)
    except Fatal:
        return 1


if __name__ == "__main__":
    sys.exit(main())
