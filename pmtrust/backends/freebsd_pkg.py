"""FreeBSD pkg / OPNsense backend: tweety. AUDIT ONLY.

The router is the one box where a broken repair costs a 100-point reset, so
pmtrust only reports. Two trust chains exist on OPNsense: packages (pkg, signed
catalog checked against fingerprints) and the base system (opnsense-update
sets). This audit covers pkg's trust configuration, library/environment
injection, pkg's own file hashes (weak: same disk) and OPNsense persistence
spots. Re-verifying packages needs a trusted host with pkg and the OPNsense
fingerprints; on a confirmed compromise, export config.xml and reinstall from
verified media (or request the reset).
"""
import os
import re
import sqlite3
import tempfile

from core.report import R, step
from .base import Backend


class FreeBSDPkgBackend(Backend):
    name = "freebsd-pkg"
    audit_only = True

    @staticmethod
    def detect(snap):
        return snap.os == "FreeBSD"

    @staticmethod
    def add_args(ap):
        g = ap.add_argument_group("freebsd-pkg (OPNsense, audit only)")
        g.add_argument("--pkg-fingerprint", action="append", default=[],
                       help="expected trusted pkg fingerprint (sha256 hex, repeatable), from OPNsense out of band")

    def audit(self):
        snap = self.snap
        step("OPNsense/FreeBSD pkg audit (report only: a router reset costs 100 points)")
        # repository configuration
        confs = [f"etc/pkg/{n}" for n in snap.listdir("etc/pkg")] + \
                [f"usr/local/etc/pkg/repos/{n}" for n in snap.listdir("usr/local/etc/pkg/repos")]
        for rel in confs:
            txt = snap.read(rel) or ""
            for m in re.finditer(r'signature_type\s*:\s*"?(\w+)"?', txt, re.I):
                if m.group(1).lower() == "none":
                    R.crit(f"/{rel}: signature_type none: pkg accepts unsigned catalogs and packages")
            if re.search(r'url\s*:\s*"?http://', txt, re.I):
                R.info(f"/{rel}: plain-http repository URL (signatures still apply if enabled)")
            for m in re.finditer(r'fingerprints\s*:\s*"?([^",\n]+)', txt, re.I):
                path = m.group(1).strip()
                if path not in ("/usr/share/keys/pkg", "/usr/local/etc/pkg/fingerprints/OPNsense",
                                "${ABI_FILE}", "/usr/share/keys/pkgbase-%%VERSION_MAJOR%%"):
                    R.warn(f"/{rel}: non-default fingerprints directory {path}")
        pkgconf = snap.read("usr/local/etc/pkg.conf") or ""
        for key, lvl in (("PKG_ENV", R.crit), ("PLUGINS", R.crit), ("PLUGINS_DIR", R.crit), ("PKG_PLUGINS_DIR", R.crit),
                         ("REPOS_DIR", R.warn), ("ALIAS", R.info), ("SSH_ARGS", R.warn), ("FETCH_RESTRICT", R.info)):
            if re.search(rf"^\s*{key}\s*[:={{]", pkgconf, re.M):
                lvl(f"/usr/local/etc/pkg.conf sets {key} (changes how pkg runs or what it loads)")
        if re.search(r"LD_(PRELOAD|LIBRARY_PATH)", pkgconf):
            R.crit("/usr/local/etc/pkg.conf injects LD_PRELOAD/LD_LIBRARY_PATH into pkg")
        # fingerprints
        fps = []
        for d in ("usr/local/etc/pkg/fingerprints/OPNsense/trusted", "usr/share/keys/pkg/trusted"):
            for n in snap.listdir(d):
                m = re.search(r'fingerprint\s*:\s*"?([0-9a-f]{64})', snap.read(f"{d}/{n}") or "")
                if m:
                    fps.append((f"{d}/{n}", m.group(1)))
        expect = {f.lower() for f in self.args.pkg_fingerprint}
        for rel, fp in fps:
            if expect and fp not in expect:
                R.crit(f"/{rel}: trusted pkg fingerprint {fp} is not one you pinned")
            elif not expect:
                R.info(f"/{rel}: trusted fingerprint {fp} (compare with OPNsense's published value)")
        for d in ("usr/local/etc/pkg/fingerprints/OPNsense/revoked", "usr/share/keys/pkg/revoked"):
            for n in snap.listdir(d):
                R.info(f"/{d}/{n}: revoked fingerprint present")
        # library and environment injection
        for rel in ["etc/libmap.conf"] + [f"usr/local/etc/libmap.d/{n}" for n in snap.listdir("usr/local/etc/libmap.d")]:
            for ln in (snap.read(rel) or "").splitlines():
                s = ln.split("#", 1)[0].strip()
                if s and not s.startswith("include"):
                    (R.crit if re.search(r"lib(c|crypto|ssl|pthread|thr)\.so", s) else R.warn)(
                        f"/{rel}: library remap '{s[:100]}' (applies to every process the rule matches)")
        envf = ["etc/login.conf", "etc/rc.conf", "etc/rc.conf.local", "etc/profile", "root/.profile", "root/.cshrc",
                "root/.shrc"] + [f"etc/rc.conf.d/{n}" for n in snap.listdir("etc/rc.conf.d")]
        for rel in envf:
            if re.search(r"LD_(PRELOAD|LIBRARY_PATH|32_PRELOAD)", snap.read(rel) or ""):
                R.crit(f"/{rel} sets LD_PRELOAD/LD_LIBRARY_PATH")
        # pkg's own records (weak: same disk) vs the snapshot
        db = snap.read("var/db/pkg/local.sqlite", binary=True)
        owned = set()
        if db:
            tmp = tempfile.mkdtemp(prefix="pkgdb-", dir=self.workdir)
            with open(os.path.join(tmp, "local.sqlite"), "wb") as f:
                f.write(db)
            con = sqlite3.connect(os.path.join(tmp, "local.sqlite"))
            try:
                rows = con.execute("SELECT f.path, f.sha256, p.name FROM files f JOIN packages p ON p.id = f.package_id").fetchall()
            except sqlite3.Error as e:
                rows = []
                R.warn(f"cannot read pkg's local.sqlite: {e}")
            con.close()
            bad = 0
            for path, h, pkg in rows:
                owned.add(path.lstrip("/"))
                e = snap.lstat(path.lstrip("/"))
                if e is None or e.kind != "f" or not e.sha256 or not h:
                    continue
                want = h.split("$")[-1]
                if len(want) == 64 and want != e.sha256:
                    bad += 1
                    if path.startswith(("/usr/local/sbin", "/usr/local/bin", "/usr/local/lib", "/usr/local/libexec",
                                        "/usr/local/opnsense", "/usr/local/etc/rc")):
                        R.crit(f"{path} ({pkg}) differs from pkg's recorded sha256 (weak check: same disk)")
            R.info(f"pkg database: {len(rows)} files recorded, {bad} differ from the snapshot")
        # OPNsense persistence spots not owned by any package
        spots = ("usr/local/etc/rc.syshook.d/", "usr/local/etc/rc.d/", "usr/local/opnsense/service/conf/actions.d/",
                 "usr/local/etc/inc/plugins.inc.d/", "usr/local/etc/cron.d/", "usr/local/sbin/")
        for p, e in sorted(snap.entries.items()):
            if e.kind == "f" and p.startswith(spots) and p.count("/") <= 6 and owned and p not in owned:
                R.warn(f"/{p} is not owned by any package (runs as root via rc/configd/cron). Inspect")
        R.info("base system (/bin /sbin /usr/bin /lib /libexec) comes from OPNsense base sets, not pkg: not covered")
