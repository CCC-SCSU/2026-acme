"""Tiny Core (tce) backend: roadrunner. AUDIT ONLY.

Tiny Core extensions (.tcz) ship with an .md5.txt over plain HTTP and NO
signatures, so there is no trust chain to rebuild. The best available check is
comparing extension hashes with a baseline you obtain separately (e.g. the
.md5.txt files fetched on the staging host from repo.tinycorelinux.net over
HTTPS, or hashes taken from the competition's pristine image) with
--tce-baseline. Everything here is reported for a human decision; nothing is
changed. Rebuilding means re-copying extensions from trusted media and
rebooting, which costs uptime on a scored box.
"""
import gzip
import os
import re

from core.report import R, die, step
from core.util import read_cpio
from .base import Backend

SUSPICIOUS = re.compile(r"(/dev/tcp|\bnc\b|ncat|socat|curl[^|]*\|\s*(ba)?sh|wget[^|]*\|\s*(ba)?sh|base64\s+-d|"
                        r"chmod\s+[0-7]*[46][0-7]{3}|chmod\s+u?\+s|authorized_keys|LD_PRELOAD|/tmp/\.|python\s+-c)")


class TceBackend(Backend):
    name = "tce"
    audit_only = True

    @staticmethod
    def detect(snap):
        return os.path.exists(os.path.join(snap.dir, "tcedir.txt")) or snap.lstat("etc/sysconfig/tcedir") is not None \
            or snap.lstat("usr/bin/tce-load") is not None

    @staticmethod
    def add_args(ap):
        g = ap.add_argument_group("tce (Tiny Core, audit only)")
        g.add_argument("--tce-baseline", action="append", default=[],
                       help="trusted md5 list(s): '<md5>  <name>.tcz' lines or a directory of *.tcz.md5.txt files")

    def _snapfile(self, name):
        p = os.path.join(self.snap.dir, name)
        return open(p, encoding="utf-8", errors="replace").read() if os.path.exists(p) else ""

    def load_baseline(self):
        base = {}
        for src in self.args.tce_baseline:
            files = [os.path.join(src, f) for f in os.listdir(src)] if os.path.isdir(src) else [src]
            for fn in files:
                for ln in open(fn, encoding="utf-8", errors="replace"):
                    m = re.match(r"\s*([0-9a-f]{32})\s+\*?(\S+\.(?:tcz|gz))\s*$", ln)
                    if m:
                        base[os.path.basename(m.group(2))] = m.group(1)
        return base

    def audit(self):
        snap = self.snap
        step("Tiny Core audit (no package signatures exist: detection only)")
        R.info("NOTE: Tiny Core extensions are not signed (md5 over HTTP); nothing here proves origin. "
               "Use --tce-baseline with hashes obtained independently of this box")
        tcedir = self._snapfile("tcedir.txt").strip()
        md5s = {}
        for ln in self._snapfile("tce-md5.txt").splitlines():
            if len(ln) > 34:
                md5s[os.path.basename(ln[32:].strip())] = ln[:32]
        local_md5 = {}
        p = os.path.join(snap.dir, "tce-files.cpio.gz")
        if os.path.exists(p):
            entries, _ = read_cpio(gzip.decompress(open(p, "rb").read()), "tce-files")
            for nm, mode, uid, gid, data, nlink, idx in entries:
                if nm and nm.endswith(".tcz.md5.txt"):
                    m = re.match(rb"([0-9a-f]{32})", data or b"")
                    if m:
                        local_md5[os.path.basename(nm)[:-8]] = m.group(1).decode()
                elif nm and os.path.basename(nm) in ("onboot.lst", "copy2fs.lst"):
                    lst = [x.strip() for x in data.decode("utf-8", "replace").splitlines() if x.strip()]
                    R.info(f"{nm}: {len(lst)} extensions loaded {'at boot' if 'onboot' in nm else 'into RAM'}")
        baseline = self.load_baseline()
        R.info(f"extension store {tcedir or '(not found)'}: {len(md5s)} .tcz files, baseline has {len(baseline)} entries")
        for name, h in sorted(md5s.items()):
            lm = local_md5.get(name)
            if lm and lm != h:
                R.crit(f"{name}: md5 {h} does not even match its own {name}.md5.txt ({lm}): modified extension")
            if baseline:
                if name not in baseline:
                    R.warn(f"{name}: not in the baseline (unknown or custom extension/image)")
                elif baseline[name] != h:
                    R.crit(f"{name}: md5 {h} differs from the baseline {baseline[name]}")
        # loop mounts: /tmp/tcloop/<ext> must be backed by <tcedir>/optional/<ext>.tcz
        loops = {}
        for ln in snap.loops.splitlines():
            dev, _, back = ln.partition("\t")
            loops["/dev/" + os.path.basename(dev)] = back.strip()
        for ln in snap.mounts.splitlines():
            f = ln.split()
            if len(f) >= 2 and f[1].startswith("/tmp/tcloop/"):
                ext = os.path.basename(f[1])
                back = loops.get(f[0], "")
                if f[0].startswith("/dev/loop") and not back.endswith(f"/{ext}.tcz"):
                    R.crit(f"{f[1]} is mounted from {f[0]} backed by {back or '?'}, not {ext}.tcz: swapped mount")
                elif not f[0].startswith("/dev/loop"):
                    R.crit(f"{f[1]} is mounted from {f[0]} ({f[2] if len(f) > 2 else '?'}), not a loop-mounted .tcz")
        # files in /usr/local that are not symlinks into an extension mount
        for d in ("usr/local/bin", "usr/local/sbin", "usr/local/lib"):
            for n in snap.listdir(d):
                e = snap.entries.get(f"{d}/{n}")
                if e is not None and e.kind == "f":
                    R.warn(f"/{d}/{n} is a real file, not a link into /tmp/tcloop (copy2fs extension, or planted)")
        # boot-time persistence
        for rel in ("opt/bootlocal.sh", "opt/bootsync.sh", "opt/shutdown.sh"):
            for ln in (snap.read(rel) or "").splitlines():
                s = ln.strip()
                if not s or s.startswith("#"):
                    continue
                (R.crit if SUSPICIOUS.search(s) else R.info)(f"/{rel} runs at boot as root: {s[:160]}")
        for ln in (snap.read("opt/.filetool.lst") or "").splitlines():
            s = ln.strip()
            if s and not s.startswith(("home", "opt")):
                R.warn(f"/opt/.filetool.lst persists {s} across reboots (restored from mydata.tgz)")
        for ln in self._snapfile("mydata-list.txt").splitlines():
            path = ln.split()[-1] if ln.split() else ""
            if re.match(r"(\./)?(usr/(local/)?s?bin|s?bin|etc/init\.d|etc/profile\.d|root/\.ssh|etc/sudoers|"
                        r"usr/local/tce\.installed|etc/ld\.so)", path):
                R.crit(f"mydata.tgz restores {path} at every boot (persistence in a system location)")
        mirror = (snap.read("opt/tcemirror") or "").strip()
        if mirror and "tinycorelinux.net" not in mirror:
            R.warn(f"/opt/tcemirror = {mirror}: tce-load downloads unsigned extensions from it")
        for n in snap.listdir("usr/local/tce.installed"):
            txt = snap.read(f"usr/local/tce.installed/{n}") or ""
            if txt.strip():
                (R.crit if SUSPICIOUS.search(txt) else R.info)(
                    f"/usr/local/tce.installed/{n} runs when the extension loads ({len(txt.splitlines())} lines)")
        cmd = self._snapfile("cmdline.txt").strip()
        if cmd:
            R.info(f"boot codes: {cmd[:200]}")
        R.info("roadrunner also runs Kubernetes: workloads, kubelet config and cluster RBAC are outside this tool")
