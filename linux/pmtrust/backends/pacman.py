"""pacman backend (Arch Linux): porky.

Trust chain: every package has a detached OpenPGP signature. Arch uses a web of
trust: a packager key is valid when the pinned MASTER keys certified it (pacman
needs full validity: three marginal master signatures). The staging host's gpg
reproduces exactly that in a private GNUPGHOME built from archlinux-keyring.
Official sync databases are NOT signed, so pmtrust does not use them: it takes
the exact installed versions from the Arch Linux Archive (archive.archlinux.org),
where every package keeps its signature. File contents are checked against the
signed package's own .MTREE, never against the local db copy.

Finalize runs the now-verified pacman with --dbonly (no scriptlets; pacman >= 7
also skips hooks) after moving BOTH hook directories aside, because pacman 6
runs hooks even with --dbonly.
"""
import gzip
import os
import re
import shutil
import subprocess
import tempfile

from core import net
from core.report import R, die, step, out
from core.util import read_tar, sniff_decompress, sha256 as sha256hex
from core.vpkg import VPkg, VFile
from .base import Backend

MAX_PKG = 1024 * 1024 * 1024


# --------------------------------------------------------------------------
# alpm_pkg_vercmp (port of libalpm version.c)
# --------------------------------------------------------------------------
def _alpm_rpmvercmp(a, b):
    if a == b:
        return 0
    one = two = 0
    p1 = p2 = 0
    while one < len(a) and two < len(b):
        while one < len(a) and not (a[one].isascii() and a[one].isalnum()):
            one += 1
        while two < len(b) and not (b[two].isascii() and b[two].isalnum()):
            two += 1
        if not (one < len(a) and two < len(b)):
            break
        if (one - p1) != (two - p2):
            return -1 if (one - p1) < (two - p2) else 1
        s1, s2 = one, two
        if a[s1].isdigit():
            while s1 < len(a) and a[s1].isascii() and a[s1].isdigit():
                s1 += 1
            while s2 < len(b) and b[s2].isascii() and b[s2].isdigit():
                s2 += 1
            isnum = True
        else:
            while s1 < len(a) and a[s1].isascii() and a[s1].isalpha():
                s1 += 1
            while s2 < len(b) and b[s2].isascii() and b[s2].isalpha():
                s2 += 1
            isnum = False
        x, y = a[one:s1], b[two:s2]
        if not x:
            return -1
        if not y:
            return 1 if isnum else -1
        if isnum:
            x, y = x.lstrip("0"), y.lstrip("0")
            if len(x) != len(y):
                return 1 if len(x) > len(y) else -1
        if x != y:
            return -1 if x < y else 1
        one, two = s1, s2
        p1, p2 = one, two
    ra, rb = one >= len(a), two >= len(b)
    if ra and rb:
        return 0
    if (ra and not (two < len(b) and b[two].isalpha())) or (not ra and a[one].isalpha()):
        return -1
    return 1


def _parse_evr(s):
    i = 0
    while i < len(s) and s[i].isdigit():
        i += 1
    rest = s[i:]
    if rest.startswith(":"):
        epoch, ver = s[:i] or "0", rest[1:]
    else:
        epoch, ver = "0", s
    if "-" in ver[0:] and "-" in s[i:]:
        ver, _, rel = ver.rpartition("-")
    else:
        rel = None
    return epoch, ver, rel


def vercmp(a, b):
    if a == b:
        return 0
    ea, va, ra = _parse_evr(a)
    eb, vb, rb = _parse_evr(b)
    r = _alpm_rpmvercmp(ea, eb) or _alpm_rpmvercmp(va, vb)
    if not r and ra is not None and rb is not None:
        r = _alpm_rpmvercmp(ra, rb)
    return r


def parse_desc(text):
    """pacman desc/.PKGINFO-like %SECTION% blocks -> {SECTION: [lines]}"""
    out, key = {}, None
    for ln in text.splitlines():
        if ln.startswith("%") and ln.endswith("%") and len(ln) > 2:
            key = ln.strip("%")
            out[key] = []
        elif ln and key:
            out[key].append(ln)
        elif not ln:
            key = None
    return out


def parse_pkginfo(text):
    out = {}
    for ln in text.splitlines():
        if ln.startswith("#") or " = " not in ln:
            continue
        k, v = ln.split(" = ", 1)
        out.setdefault(k.strip(), []).append(v)
    return out


def parse_mtree(text):
    """libarchive mtree with /set defaults -> {path: attrs}"""
    defaults, out = {}, {}
    for ln in text.splitlines():
        ln = ln.strip()
        if not ln or ln.startswith("#"):
            continue
        parts = ln.split()
        if parts[0] == "/set":
            for kv in parts[1:]:
                k, _, v = kv.partition("=")
                defaults[k] = v
            continue
        if parts[0] == "/unset":
            for k in parts[1:]:
                defaults.pop(k, None)
            continue
        attrs = dict(defaults)
        for kv in parts[1:]:
            k, _, v = kv.partition("=")
            attrs[k] = v
        name = re.sub(r"\\([0-7]{3})", lambda m: chr(int(m.group(1), 8)), parts[0])
        out[name[2:] if name.startswith("./") else name] = attrs
    return out


class WotVerifier:
    """pacman-key semantics with the staging host's gpg in a private home."""

    def __init__(self, keyring, masters, workdir, trust_listed=False):
        self.gpg = shutil.which("gpg")
        if not self.gpg:
            die("gpg is required on the staging host for the pacman backend (web-of-trust check)")
        if os.path.isdir(keyring):
            kr = os.path.join(keyring, "archlinux.gpg")
            trusted_f = os.path.join(keyring, "archlinux-trusted")
            revoked_f = os.path.join(keyring, "archlinux-revoked")
        else:
            kr, trusted_f, revoked_f = keyring, keyring.replace(".gpg", "-trusted"), keyring.replace(".gpg", "-revoked")
        if not os.path.isfile(kr):
            die(f"{kr} not found (give --keyring the archlinux-keyring directory, e.g. /usr/share/pacman/keyrings "
                f"from verified Arch media)")
        listed = []
        if os.path.exists(trusted_f):
            listed = [ln.split(":")[0].upper() for ln in open(trusted_f) if ln.strip() and not ln.startswith("#")]
        masters = {m.upper() for m in masters}
        if not masters:
            if not trust_listed:
                die("pin the Arch master signing keys with --expect-fpr (cross-check them with "
                    "https://archlinux.org/master-keys/ through a second channel), or pass --trust-keyring "
                    "to accept the archlinux-trusted list in the keyring directory")
            masters = set(listed)
        unknown = masters - set(listed) if listed else set()
        if unknown:
            die(f"pinned keys are not master keys listed in archlinux-trusted: {', '.join(sorted(unknown))} "
                f"(pacman-key only gives trust to those; pin the master keys, not packager keys)")
        self.home = tempfile.mkdtemp(prefix="pacman-gnupg-", dir=workdir)
        os.chmod(self.home, 0o700)
        with open(os.path.join(self.home, "gpg.conf"), "w") as f:
            f.write("no-greeting\nno-permission-warning\nlock-never\ntrust-model pgp\nno-auto-key-retrieve\n")
        self._g("--import", kr)
        self._g("--quick-gen-key", "--passphrase", "", "pmtrust local master <pmtrust@localhost>",
                "ed25519", "sign", "never")
        ok = []
        for fpr in sorted(masters):
            if self._g("--quick-lsign-key", fpr, check=False).returncode == 0:
                ok.append(fpr)
            else:
                R.warn(f"master key {fpr} is not in the keyring")
        if not ok:
            die("none of the pinned master keys are in the keyring")
        trust = "".join(f"{fpr}:4:\n" for fpr in ok)          # marginal, as archlinux-trusted does
        self._g("--import-ownertrust", input=trust)
        if os.path.exists(revoked_f):
            for fpr in (ln.strip() for ln in open(revoked_f) if ln.strip() and not ln.startswith("#")):
                self._g("--batch", "--yes", "--delete-keys", fpr, check=False)
        self._g("--check-trustdb", check=False)
        self.masters = ok
        R.info(f"pacman web of trust: {len(ok)} pinned master keys, packager keys need 3 marginal certifications")

    def _g(self, *args, check=True, input=None):
        p = subprocess.run([self.gpg, "--homedir", self.home, "--batch", *args], input=input,
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                           env={"PATH": "/usr/bin:/bin", "LC_ALL": "C", "GNUPGHOME": self.home})
        if check and p.returncode != 0:
            die(f"gpg {' '.join(args[:2])} failed: {p.stderr.strip()[:300]}")
        return p

    def verify(self, data_path, sig_path, what):
        p = self._g("--status-fd", "1", "--verify", sig_path, data_path, check=False)
        st = p.stdout.split("\n")
        if any(f" {k} " in f" {ln} " for ln in st for k in ("BADSIG", "REVKEYSIG", "EXPKEYSIG", "ERRSIG")):
            die(f"{what}: signature is bad, revoked, expired or from an unknown key:\n{p.stdout}")
        valid = [ln.split()[2] for ln in st if ln.startswith("[GNUPG:] VALIDSIG")]
        trusted = any(ln.startswith(("[GNUPG:] TRUST_FULLY", "[GNUPG:] TRUST_ULTIMATE")) for ln in st)
        if not valid:
            die(f"{what}: no valid signature\n{p.stdout}")
        if not trusted:
            die(f"{what}: signed by {valid[0]}, which is not certified by enough pinned master keys "
                f"(pacman would refuse it too)")
        return valid[0]


class PacmanBackend(Backend):
    name = "pacman"
    lib_dirs = ("usr/lib",)

    @staticmethod
    def detect(snap):
        return bool(snap.listdir("var/lib/pacman/local"))

    @staticmethod
    def add_args(ap):
        g = ap.add_argument_group("pacman (Arch)")
        g.add_argument("--pacman-archive", default="https://archive.archlinux.org",
                       help="Arch Linux Archive base URL (exact installed versions), or a file:// copy")

    # -- target db as data ----------------------------------------------------
    def read_local(self):
        snap = self.snap
        self.local = {}
        self.owner = {}
        for d in snap.listdir("var/lib/pacman/local"):
            base = f"var/lib/pacman/local/{d}"
            desc = snap.read(f"{base}/desc")
            if not desc:
                continue
            dd = parse_desc(desc)
            name = (dd.get("NAME") or [""])[0]
            ver = (dd.get("VERSION") or [""])[0]
            if not name:
                continue
            files = parse_desc(snap.read(f"{base}/files") or "")
            dd["_files"] = files.get("FILES", [])
            dd["_backup"] = files.get("BACKUP", [])
            dd["_dir"] = base
            self.local[name] = dd
            for f in dd["_files"]:
                if not f.endswith("/"):
                    self.owner[f] = name
        if not self.local:
            die("no packages in /var/lib/pacman/local in the snapshot")

    def provides(self):
        prov = {}
        for name, dd in self.local.items():
            prov.setdefault(name, name)
            for p in dd.get("PROVIDES", []):
                prov.setdefault(re.split(r"[<>=]", p)[0], name)
        return prov

    def collect_verified(self):
        a = self.args
        self.read_local()
        self.wot = WotVerifier(a.keyring, a.expect_fpr, self.workdir, a.trust_keyring)
        osr = self.snap.os_release()
        R.info(f"target: {osr.get('PRETTY_NAME', '?')}, {len(self.local)} installed packages")
        if a.upgrade:
            die("--upgrade is not supported for Arch (partial upgrades are unsupported upstream); "
                "pmtrust reinstalls the exact installed versions from the archive")
        step("Resolving the core package set from the local database (selection only)")
        prov = self.provides()
        roots = {"pacman", "pacman-mirrorlist", "archlinux-keyring", "glibc", "gnupg", "gpgme", "libarchive",
                 "curl", "bash", "coreutils"} | set(a.extra)
        ext = ("etc/pacman.conf", "etc/pacman.d/", "usr/share/libalpm/", "etc/makepkg.conf")
        for f, o in self.owner.items():
            if f.startswith(ext):
                roots.add(o)
        roots = {r for r in roots if r in self.local}
        chosen, reason, queue = set(), {r: "core" for r in roots}, sorted(roots)
        while queue:
            n = queue.pop()
            if n in chosen:
                continue
            chosen.add(n)
            for dep in self.local[n].get("DEPENDS", []):
                d = prov.get(re.split(r"[<>=]", dep)[0])
                if d and d not in chosen:
                    reason.setdefault(d, f"dependency of {n}")
                    queue.append(d)
        out(f"\nVerified set: {len(chosen)} packages (exact installed versions from {a.pacman_archive})")
        step("Downloading packages from the archive and checking signatures (web of trust)")
        vpkgs = []
        first = ["glibc", "bash", "pacman"]
        for n in [x for x in first if x in chosen] + sorted(chosen - set(first)):
            vp = self.fetch_pkg(n, self.local[n])
            vp.meta["reason"] = reason.get(n, "")
            vpkgs.append(vp)
            out(f"  {n:32} {vp.version:28} {vp.meta['signer'][-16:]}  {reason.get(n)}")
        R.info(f"{len(vpkgs)} packages verified (signatures valid under the pinned master keys)")
        self.vpkgs = vpkgs
        return vpkgs

    def fetch_pkg(self, name, dd):
        ver = dd["VERSION"][0]
        arch = (dd.get("ARCH") or ["x86_64"])[0]
        base = net.join(self.args.pacman_archive, "packages", name[0], name)
        blob = sig = fn = None
        for ext in (".pkg.tar.zst", ".pkg.tar.xz"):
            fn = f"{name}-{ver}-{arch}{ext}"
            try:
                blob = net.fetch(f"{base}/{fn}", MAX_PKG, what=fn)
            except net.NotFound:
                continue
            try:
                sig = net.fetch(f"{base}/{fn}.sig", 64 * 1024, what=fn + ".sig")
            except net.NotFound:
                die(f"{fn}: no detached signature in the archive; refusing an unsigned package")
            break
        if blob is None:
            die(f"{name} {ver} ({arch}) not found in {self.args.pacman_archive} "
                f"(AUR/custom package or wrong --pacman-archive)")
        path = os.path.join(self.workdir, "pkgs", fn)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "wb") as f:
            f.write(blob)
        with open(path + ".sig", "wb") as f:
            f.write(sig)
        signer = self.wot.verify(path, path + ".sig", fn)
        vp = self.parse_pkg(blob, path, name, ver)
        vp.extra_blobs.append(path + ".sig")
        vp.meta["signer"] = signer
        vp.installed_version = ver
        vp.exact = True
        return vp

    def parse_pkg(self, blob, path, name, ver):
        what = os.path.basename(path)
        members = read_tar(sniff_decompress(blob), what)
        by = {m.path: m for m in members}
        if ".PKGINFO" not in by or ".MTREE" not in by:
            die(f"{what}: missing .PKGINFO or .MTREE")
        info = parse_pkginfo(by[".PKGINFO"].data.decode("utf-8", "replace"))
        if info.get("pkgname", [None])[0] != name or info.get("pkgver", [None])[0] != ver:
            die(f"{what}: signed .PKGINFO says {info.get('pkgname')} {info.get('pkgver')}, expected {name} {ver}")
        mtree = parse_mtree(gzip.decompress(by[".MTREE"].data).decode("utf-8", "replace"))
        vp = VPkg(name, ver, info.get("arch", ["?"])[0], blob_path=path)
        vp.conffiles = set(info.get("backup", []))
        if ".INSTALL" in by:
            vp.scripts["install"] = by[".INSTALL"].data
        users, groups = self.idmaps()
        for m in members:
            if m.path.startswith("."):
                continue
            mt = mtree.get(m.path)
            if mt is None:
                die(f"{what}: {m.path} is not listed in the signed .MTREE")
            uid = int(mt.get("uid", m.uid))
            gid = int(mt.get("gid", m.gid))
            mode = int(mt.get("mode", f"{m.mode:o}"), 8)
            if m.kind == "f":
                h = sha256hex(m.data)
                if mt.get("sha256digest") and mt["sha256digest"] != h:
                    die(f"{what}: {m.path} does not match its sha256 in .MTREE")
                vp.add(VFile(m.path, "f", mode, uid, gid, sha256=self.payload.put(m.data), size=len(m.data),
                             conffile=m.path in vp.conffiles))
            elif m.kind == "l":
                vp.add(VFile(m.path, "l", 0o777, uid, gid, link=m.link, conffile=m.path in vp.conffiles))
            elif m.kind == "d":
                vp.add(VFile(m.path, "d", mode, uid, gid))
        vp.meta["mtree_paths"] = set(p for p in mtree if not p.startswith("."))
        return vp

    def idmaps(self):
        return ({}, {})

    def db_owned(self):
        return {f.rstrip("/") for f in self.owner}

    def expected_dir_link(self, rel, link):
        return rel in ("bin", "sbin", "lib", "lib64", "usr/sbin", "usr/lib64") and link in (
            "usr/bin", "usr/lib", "bin", "lib", "/usr/bin", "/usr/lib")

    # -- plan -----------------------------------------------------------------------
    def pre_plan(self, plan, vpkgs):
        plan.phase = 0
        plan.backup_tree("var/lib/pacman/local", "pacman local database before finalize")
        plan.phase = 2

    def post_compare(self, plan, vpkgs):
        snap = self.snap
        for vp in vpkgs:
            d = self.local[vp.name]["_dir"]
            inst = vp.scripts.get("install")
            cur = snap.read(f"{d}/install", binary=True)
            if inst is not None and cur is not None and cur != inst:
                R.crit(f"/{d}/install differs from the signed package's .INSTALL (runs on the next "
                       f"upgrade/removal). finalize rewrites the database entry")
                plan.needs_finalize(vp)
            elif inst is None and cur is not None:
                R.crit(f"/{d}/install exists but the signed package has no .INSTALL. finalize rewrites it")
                plan.needs_finalize(vp)
            files = set(f.rstrip("/") for f in self.local[vp.name]["_files"])
            if files != {p.rstrip("/") for p in vp.meta["mtree_paths"]}:
                R.warn(f"/{d}/files differs from the signed file list; finalize rewrites it")
                plan.needs_finalize(vp)

    def injection_points(self, plan, vpkgs):
        snap = self.snap
        owned = {vf.path: vf for vp in vpkgs for vf in vp.files}
        plan.phase = 1
        conf = snap.read("etc/pacman.conf") or ""
        includes = ["etc/pacman.conf"]
        for ln in conf.splitlines():
            m = re.match(r"\s*Include\s*=\s*(\S+)", ln)
            if m:
                includes.append(m.group(1).lstrip("/"))
        verified_paths = set(owned)
        for rel in includes:
            section = "options"
            crit_before = R.count("CRIT")
            for ln in (snap.read(rel) or "").splitlines():
                s = ln.split("#", 1)[0].strip()
                if not s:
                    continue
                m = re.match(r"\[(.+)\]", s)
                if m:
                    section = m.group(1)
                    continue
                k, _, v = s.partition("=")
                k, v = k.strip(), v.strip()
                if k in ("SigLevel", "LocalFileSigLevel", "RemoteFileSigLevel"):
                    never = re.search(r"\b(Package)?(Never|TrustAll)\b", v)
                    optional = re.search(r"\bPackageOptional\b|(?<![A-Za-z])Optional\b", v)
                    if never or (optional and k != "LocalFileSigLevel"):
                        R.crit(f"/{rel} [{section}] {k} = {v}: weakens package signature checks")
                    elif optional:
                        R.info(f"/{rel}: LocalFileSigLevel = {v} (Arch default: local files need no signature)")
                elif k in ("XferCommand",):
                    R.crit(f"/{rel} [{section}] XferCommand = {v[:100]}: an external program downloads packages")
                elif k in ("HookDir", "DBPath", "RootDir", "GPGDir", "CacheDir"):
                    R.warn(f"/{rel} [{section}] {k} = {v}: non-default location for pacman {k}")
                elif k in ("NoUpgrade", "NoExtract"):
                    hits = [p for p in v.split() if any(re.fullmatch(p.replace("*", ".*"), q) for q in verified_paths)]
                    if hits:
                        R.crit(f"/{rel} {k} = {v}: stops pacman from replacing verified files ({', '.join(hits)[:100]})")
                elif k == "Server" and v.startswith("http://"):
                    R.info(f"/{rel}: plain-http mirror {v} (signatures still apply)")
            if R.count("CRIT") > crit_before:
                vf = owned.get(rel)
                if vf is not None and vf.kind == "f":
                    R.info(f"/{rel}: --apply restores the verified version (the modified one is kept in the backup)")
                    plan.put_file(rel, vf.sha256, vf.mode, vf.uid, vf.gid, "restore pacman config with weakened trust")
                else:
                    R.info(f"/{rel}: --apply quarantines it")
                    plan.quarantine(rel, "pacman config with weakened trust")
        for d in ("etc/pacman.d/hooks", "usr/share/libalpm/hooks", "usr/share/libalpm/scripts"):
            for n in snap.listdir(d):
                rel = f"{d}/{n}"
                vf = owned.get(rel)
                if vf is None:
                    R.crit(f"/{rel} is not shipped by any verified package: pacman runs hooks as root on every "
                           f"transaction. --apply quarantines it")
                    plan.quarantine(rel, "unverified pacman hook")
                elif vf.kind == "f" and snap.sha256(rel) not in (None, vf.sha256):
                    R.crit(f"/{rel} differs from the signed package. --apply restores it")
                    plan.put_file(rel, vf.sha256, vf.mode, vf.uid, vf.gid, "restore pacman hook")
        gpgconf = snap.read("etc/pacman.d/gnupg/gpg.conf") or ""
        if re.search(r"^\s*trust-model\s+always", gpgconf, re.M):
            R.crit("/etc/pacman.d/gnupg/gpg.conf sets trust-model always: every key in the keyring is trusted")
        for n in snap.listdir("usr/local/bin") + snap.listdir("usr/bin"):
            if n in ("pacman-static", "yay", "paru", "pikaur", "trizen"):
                R.info(f"{n} is installed: it can install packages outside this trust chain")
        plan.phase = 2

    def finalize_script(self, plan):
        pkgs = plan.finalize_pkgs
        if not pkgs:
            return ""
        files = " ".join("pkgs/" + os.path.basename(vp.blob_path) for vp in pkgs)
        want = " ".join(f"{vp.name}-{vp.version}" for vp in pkgs)
        pacman = "/" + plan.phys("usr/bin/pacman")
        conf = ("[options]\\nArchitecture = auto\\n"
                "# Packages were signature-checked on the staging host; their integrity here is\\n"
                "# checked by apply.sh against MANIFEST.sha256, so pacman does not re-check.\\n"
                "SigLevel = Never\\nLocalFileSigLevel = Never\\n")
        return f"""# pacman finalize, generated by pmtrust
PACMAN='{pacman}'
PAC_FILES='{files}'
PAC_WANT='{want}'
pm_needs_finalize() {{
    for p in $PAC_WANT; do [ -f "/var/lib/pacman/local/$p/desc" ] || return 0; done
    return 1
}}
pm_finalize() {{
    if [ -e /var/lib/pacman/db.lck ]; then crit "/var/lib/pacman/db.lck exists: another pacman is running or crashed; finalize skipped"; return 0; fi
    printf '{conf}' > "$WORK/pacman.conf"
    "$BB" mkdir -p "$WORK/nohooks"
    # pacman 6 runs hooks even with --dbonly: move both hook dirs aside for the run
    for h in /usr/share/libalpm/hooks /etc/pacman.d/hooks; do
        if [ -d "$h" ]; then "$BB" mv "$h" "$h.pmtrust-off" && record "MV${{TAB}}$h${{TAB}}$h.pmtrust-off"; fi
    done
    _args=""
    for f in $PAC_FILES; do _args="$_args $PLAN/$f"; done
    log "  $PACMAN -U --dbonly --noscriptlet --overwrite '*' ($(echo $PAC_FILES | "$BB" wc -w) packages), hooks moved aside"
    # shellcheck disable=SC2086
    "$BB" env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin LC_ALL=C HOME=/root "$PACMAN" -U --dbonly --noscriptlet \\
        --noconfirm --overwrite '*' --config "$WORK/pacman.conf" --root / --dbpath /var/lib/pacman/ \\
        --hookdir "$WORK/nohooks" --cachedir "$PLAN/pkgs" --logfile "$WORK/pacman.log" $_args >> "$LOG" 2>&1
    _rc=$?
    for h in /usr/share/libalpm/hooks /etc/pacman.d/hooks; do
        if [ -d "$h.pmtrust-off" ]; then "$BB" mv "$h.pmtrust-off" "$h"; fi
    done
    [ "$_rc" -eq 0 ] || crit "pacman exited with $_rc (see $LOG)"
    return 0
}}
"""
