"""apt / dpkg backend (Debian, Ubuntu): daffy, taz, elmer, marvin.

Trust chain: InRelease (clearsigned by pinned archive keys, verified with the
staging host's gpgv) -> SHA256 of Packages -> SHA256 of each .deb.
Reference implementation ported from reinstall-apt-trusted.py (v1).
"""
import os
import re
import string
import urllib.parse
from datetime import datetime, timedelta, timezone
from email.utils import parsedate_to_datetime

from core import net
from core.pgp import Trust
from core.report import R, die, step, out
from core.util import read_ar, read_tar, sniff_decompress, check_hash
from core.vpkg import VPkg, VFile
from .base import Backend, restart_hints

MAX_INDEX = 256 * 1024 * 1024
MAX_DEB = 512 * 1024 * 1024
SCRIPT_NAMES = ("preinst", "postinst", "prerm", "postrm", "config", "triggers")
CONTROL_DB = ("md5sums", "conffiles", "shlibs", "symbols", "templates")
KEYRING_PKGS = ("debian-archive-keyring", "ubuntu-keyring", "ubuntu-keyring-2018-archive",
                "ubuntu-keyring-2012-archive")
MERGED_USR = {"bin", "sbin", "lib", "lib32", "lib64", "libx32", "libo32"}
EXPECTED_DIR_LINKS = {"var/run": {"/run", "../run"}, "var/lock": {"/run/lock", "../run/lock"}}
for _d in MERGED_USR:
    EXPECTED_DIR_LINKS[_d] = {f"usr/{_d}", f"/usr/{_d}"}
RUNTIME_DIR_PERMS = {"var/cache/apt/archives/partial", "var/lib/apt/lists/partial"}


# --------------------------------------------------------------------------
# dpkg version comparison (port of verrevcmp), tested against dpkg
# --------------------------------------------------------------------------
def _order(c):
    if c.isdigit():
        return 0
    if c in string.ascii_letters:
        return ord(c)
    if c == "~":
        return -1
    return ord(c) + 256


def _verrevcmp(a, b):
    i = j = 0
    while i < len(a) or j < len(b):
        while (i < len(a) and not a[i].isdigit()) or (j < len(b) and not b[j].isdigit()):
            ac = _order(a[i]) if i < len(a) else 0
            bc = _order(b[j]) if j < len(b) else 0
            if ac != bc:
                return ac - bc
            i += 1
            j += 1
        while i < len(a) and a[i] == "0":
            i += 1
        while j < len(b) and b[j] == "0":
            j += 1
        first_diff = 0
        while i < len(a) and a[i].isdigit() and j < len(b) and b[j].isdigit():
            if not first_diff:
                first_diff = ord(a[i]) - ord(b[j])
            i += 1
            j += 1
        if i < len(a) and a[i].isdigit():
            return 1
        if j < len(b) and b[j].isdigit():
            return -1
        if first_diff:
            return first_diff
    return 0


def _split_version(v):
    epoch, rest = v.split(":", 1) if ":" in v else ("0", v)
    upstream, rev = rest.rsplit("-", 1) if "-" in rest else (rest, "")
    return int(epoch or 0), upstream, rev


def vercmp(a, b):
    ea, ua, ra = _split_version(a)
    eb, ub, rb = _split_version(b)
    if ea != eb:
        return -1 if ea < eb else 1
    r = _verrevcmp(ua, ub) or _verrevcmp(ra, rb)
    return (r > 0) - (r < 0)


def satisfies(ver, op, want):
    c = vercmp(ver, want)
    return {"<<": c < 0, "<=": c <= 0, "<": c <= 0, "=": c == 0, ">=": c >= 0, ">": c >= 0,
            ">>": c > 0}[op]


# --------------------------------------------------------------------------
# deb822 + relations
# --------------------------------------------------------------------------
def parse_deb822(text):
    paras, cur, key = [], {}, None
    for lineno, line in enumerate(text.splitlines(), 1):
        if not line.strip():
            if cur:
                paras.append(cur)
            cur, key = {}, None
            continue
        if line.startswith("#"):
            continue
        if line[0] in " \t":
            if key is None:
                raise ValueError(f"continuation line without a field at line {lineno}")
            cur[key] += "\n" + line.strip()
            continue
        if ":" not in line:
            raise ValueError(f"malformed line {lineno}: {line[:60]!r}")
        k, v = line.split(":", 1)
        key = k.strip()
        cur[key] = v.strip()
    if cur:
        paras.append(cur)
    return paras


_REL = re.compile(r"\s*([a-z0-9][a-z0-9+.-]*)(?::[a-z0-9-]+)?\s*(?:\(\s*(<<|<=|>=|>>|=|<|>)\s*([^)\s]+)\s*\))?")


def relations(field):
    """Yield clauses; each clause is a list of (name, op, version) alternatives."""
    for clause in field.split(","):
        alts = []
        for alt in clause.split("|"):
            m = _REL.match(alt)
            if m:
                alts.append((m.group(1), m.group(2), m.group(3)))
        if alts:
            yield alts


# --------------------------------------------------------------------------
# Repository metadata
# --------------------------------------------------------------------------
class Repo:
    def __init__(self, base, suite):
        self.base = base.rstrip("/")
        self.suite = suite
        self.tag = re.sub(r"[^A-Za-z0-9._-]", "_", f"{urllib.parse.urlsplit(base).netloc or 'local'}_{suite}")
        self.release = None
        self.date = None
        self.packages = {}


def _parse_date(s):
    d = parsedate_to_datetime(s)
    return d if d.tzinfo else d.replace(tzinfo=timezone.utc)


class AptBackend(Backend):
    name = "apt"
    lib_dirs = ("usr/lib", "lib")

    @staticmethod
    def detect(snap):
        return snap.read("var/lib/dpkg/status") is not None

    @staticmethod
    def add_args(ap):
        g = ap.add_argument_group("apt (Debian/Ubuntu)")
        g.add_argument("--repo", nargs=2, action="append", metavar=("URL", "SUITE"),
                       help="repository (repeatable); default from os-release")
        g.add_argument("--cross-check", nargs=2, action="append", default=[], metavar=("URL", "SUITE"),
                       help="second mirror whose Release date must agree (freeze detection)")
        g.add_argument("--components", default="main")
        g.add_argument("--max-age", type=int, default=120,
                       help="warn when an updates/security Release without Valid-Until is older (days)")

    # -- pipeline -------------------------------------------------------------
    def collect_verified(self):
        a = self.args
        self.trust = Trust(a.keyring, a.expect_fpr, a.trust_keyring, self.workdir)
        self.components = a.components.split(",")
        self.installed = self.read_status()
        self.arch = a.arch or next((ar for (n, ar) in self.installed if n == "dpkg"), None)
        if not self.arch:
            die("cannot determine the native architecture; pass --arch")
        triplet = {"amd64": "x86_64-linux-gnu", "i386": "i386-linux-gnu", "arm64": "aarch64-linux-gnu"}.get(self.arch)
        if triplet:
            self.lib_dirs = ("usr/lib", "lib", f"usr/lib/{triplet}")
        osr = self.snap.os_release()
        R.info(f"target: {osr.get('PRETTY_NAME', '?')}, arch {self.arch}, {len(self.installed)} installed packages")

        step("Fetching and verifying repository metadata")
        self.repos = []
        for i, (url, suite) in enumerate(a.repo or self.default_repos(osr)):
            repo = Repo(url, suite)
            try:
                self.load_repo(repo)
            except net.NotFound as e:
                if i == 0:
                    die(f"{url} {suite}: not found ({e})")
                R.warn(f"{url} {suite}: not found; skipping this repository")
                continue
            self.repos.append(repo)
        for url, suite in a.cross_check:
            primary = next((r for r in self.repos if r.suite == suite), None)
            if not primary:
                die(f"--cross-check {suite}: no matching repository suite")
            other = Repo(url, suite)
            self.load_repo(other, with_index=False)
            lag = other.date - primary.date
            if lag > timedelta(hours=6):
                die(f"{primary.tag} serves a Release {lag} older than {url}: possible freeze attack")
            R.info(f"cross-check {url} {suite}: dates agree within {abs(lag)}")

        step("Resolving the core package set from the signed indexes")
        chosen, reason = self.build_package_set()
        step("Downloading .debs and checking them against the signed index")
        vpkgs = []
        for name in self.lay_down_order(chosen):
            p, repo = chosen[name]
            vp = self.fetch_deb(p, repo)
            cur = self.inst(name)
            vp.installed_version = cur.get("Version") if cur else None
            vp.exact = vp.installed_version == vp.version
            vp.meta["reason"] = reason.get(name, "")
            vpkgs.append(vp)
        R.info(f"{len(vpkgs)} .debs verified against the signed index "
               f"({sum(1 for v in vpkgs if v.exact)} at the installed version)")
        self.vpkgs = vpkgs
        return vpkgs

    def default_repos(self, osr):
        distro, code = osr.get("ID"), osr.get("VERSION_CODENAME")
        if not code:
            die("cannot read VERSION_CODENAME from the target; pass --repo URL SUITE explicitly")
        if distro == "debian":
            return [("https://deb.debian.org/debian", code),
                    ("https://deb.debian.org/debian", f"{code}-updates"),
                    ("https://deb.debian.org/debian-security", f"{code}-security")]
        if distro == "ubuntu":
            if self.arch in ("amd64", "i386"):
                base, sec = "https://archive.ubuntu.com/ubuntu", "https://security.ubuntu.com/ubuntu"
            else:
                base = sec = "https://ports.ubuntu.com/ubuntu-ports"
            return [(base, code), (base, f"{code}-updates"), (sec, f"{code}-security")]
        die(f"unknown distribution {distro!r}; pass --repo URL SUITE explicitly")

    def load_repo(self, repo, with_index=True):
        raw = net.fetch(f"{repo.base}/dists/{repo.suite}/InRelease", 16 * 1024 * 1024)
        signed = self.trust.clearsigned(raw, repo.tag).decode("utf-8")
        paras = parse_deb822(signed)
        if len(paras) != 1:
            die(f"{repo.tag}: verified Release has {len(paras)} paragraphs, expected 1")
        rel = repo.release = paras[0]
        self.check_release(rel, repo)
        if not with_index:
            return
        signed_files = {}
        for line in rel.get("SHA256", "").splitlines():
            f = line.split()
            if len(f) == 3:
                signed_files[f[2]] = (f[0], int(f[1]))
        by_hash = rel.get("Acquire-By-Hash", "").lower() == "yes"
        for comp in self.components:
            for ext in (".xz", ".gz", ""):
                path = f"{comp}/binary-{self.arch}/Packages{ext}"
                if path in signed_files:
                    break
            else:
                die(f"{repo.tag}: signed Release lists no Packages index for {comp}/{self.arch}")
            sha, size = signed_files[path]
            urls = [f"{repo.base}/dists/{repo.suite}/{path}"]
            if by_hash:
                urls.insert(0, f"{repo.base}/dists/{repo.suite}/{os.path.dirname(path)}/by-hash/SHA256/{sha}")
            blob = None
            for url in urls:
                try:
                    blob = net.fetch(url, size, sha256=sha)
                    break
                except net.NotFound:
                    continue
            if blob is None:
                die(f"{repo.tag}: could not fetch {path}")
            check_hash(blob, sha, f"{repo.tag}/{path}", size=size)
            n = 0
            for p in parse_deb822(sniff_decompress(blob).decode("utf-8")):
                if p.get("Architecture") in (self.arch, "all") and "Package" in p:
                    repo.packages.setdefault(p["Package"], []).append(p)
                    n += 1
            R.info(f"{repo.tag}: {n} package entries from verified {path}")

    def check_release(self, rel, repo):
        names = {rel.get("Suite"), rel.get("Codename")}
        if repo.suite not in names:
            die(f"{repo.tag}: signed Release is for {sorted(n for n in names if n)}, not {repo.suite} "
                f"(suite substitution would let a mirror serve another release)")
        if self.arch not in rel.get("Architectures", "").split():
            die(f"{repo.tag}: architecture {self.arch} not listed in the signed Release")
        comps = {c.split("/")[-1] for c in rel.get("Components", "").split()}
        for c in self.components:
            if c not in comps:
                die(f"{repo.tag}: component {c} not listed in the signed Release")
        now = datetime.now(timezone.utc)
        repo.date = _parse_date(rel["Date"])
        if repo.date > now + timedelta(hours=1):
            die(f"{repo.tag}: Release Date {repo.date} is in the future; check this machine's clock")
        if "Valid-Until" in rel:
            vu = _parse_date(rel["Valid-Until"])
            if vu < now:
                die(f"{repo.tag}: Release expired at {vu} (stale or replayed metadata)")
            R.info(f"{repo.tag}: Release dated {repo.date:%Y-%m-%d}, valid until {vu:%Y-%m-%d}")
        else:
            age = (now - repo.date).days
            fresh = re.search(r"-(security|updates)$", repo.suite)
            msg = (f"{repo.tag}: Release has no Valid-Until (dated {repo.date:%Y-%m-%d}, {age} days old)")
            if fresh and age > self.args.max_age:
                R.warn(msg + "; a frozen mirror cannot be ruled out, use --cross-check")
            else:
                R.info(msg + ("" if fresh else "; release pockets are frozen by design"))

    # -- target db (as data) ----------------------------------------------------
    def read_status(self):
        txt = self.snap.read("var/lib/dpkg/status")
        if txt is None:
            die("no /var/lib/dpkg/status in the snapshot")
        installed = {}
        for p in parse_deb822(txt):
            if p.get("Status", "").endswith(" installed") and "Package" in p:
                installed[(p["Package"], p.get("Architecture", ""))] = p
        return installed

    def inst(self, name):
        return self.installed.get((name, self.arch)) or self.installed.get((name, "all"))

    def path_owner(self):
        if getattr(self, "_owner", None) is None:
            self._owner = {}
            for n in self.snap.listdir("var/lib/dpkg/info"):
                if n.endswith(".list"):
                    pkg = n[:-5].split(":")[0]
                    for ln in (self.snap.read(f"var/lib/dpkg/info/{n}") or "").splitlines():
                        if ln and ln != "/.":
                            self._owner[ln.lstrip("/")] = pkg
        return self._owner

    def _idmap(self, rel):
        out = {}
        for ln in (self.snap.read(rel) or "").splitlines():
            f = ln.split(":")
            if len(f) >= 3 and f[2].isdigit():
                out.setdefault(f[0], int(f[2]))
        return out

    @staticmethod
    def _script_adds_override(vp, owner, mode, path):
        for s in ("postinst", "preinst"):
            data = vp.scripts.get(s)
            if not data:
                continue
            txt = data[0].decode("utf-8", "replace")
            if path not in txt:
                continue
            for ln in txt.splitlines():
                if "dpkg-statoverride" in ln and "--add" in ln and re.search(rf"(^|\s){re.escape(mode)}(\s|$)", ln) \
                        and (owner in ln or "$" in ln):
                    return True
        return False

    def trigger_interested(self, names):
        """Packages with a trigger interest that `names` would activate. Read from
        the target's dpkg db (untrusted, used only to widen what gets verified)."""
        snap = self.snap
        files = [p for p, o in self.path_owner().items() if o in names]
        out = set()
        for ln in (snap.read("var/lib/dpkg/triggers/File") or "").splitlines():
            parts = ln.split()
            if len(parts) == 2:
                path = parts[0].strip("/")
                if any(f == path or f.startswith(path + "/") for f in files):
                    out.add(parts[1].split("/")[0].split(":")[0])
        named = set()
        for n in names:
            for key in (n, f"{n}:{self.arch}"):
                for ln in (snap.read(f"var/lib/dpkg/info/{key}.triggers") or "").splitlines():
                    f = ln.split()
                    if len(f) == 2 and f[0] in ("activate", "activate-noawait", "activate-await"):
                        named.add(f[1])
        for t in named:
            if "/" in t:
                continue
            for ln in (snap.read(f"var/lib/dpkg/triggers/{t}") or "").splitlines():
                if ln.strip():
                    out.add(ln.split()[0].split("/")[0].split(":")[0])
        return out

    def db_owned(self):
        owned = set(self.path_owner())
        # diverted files live at the divert-to path
        lines = (self.snap.read("var/lib/dpkg/diversions") or "").split("\n")
        for i in range(0, len(lines) - 2, 3):
            owned.add(lines[i + 1].lstrip("/"))
        return owned

    # -- package set ---------------------------------------------------------------
    def build_package_set(self):
        providers = {}
        for r in self.repos:
            for name, paras in r.packages.items():
                for p in paras:
                    for alts in relations(p.get("Provides", "")):
                        providers.setdefault(alts[0][0], set()).add(name)

        def candidates(name):
            out = []
            for r in self.repos:
                for p in r.packages.get(name, ()):
                    out.append((p, r))
            return out

        def latest(name):
            best = None
            for p, r in candidates(name):
                if best is None or vercmp(p["Version"], best[0]["Version"]) > 0:
                    best = (p, r)
            return best

        def pick_version(name):
            cur = self.inst(name)
            if cur and not self.args.upgrade:
                for p, r in candidates(name):
                    if p["Version"] == cur.get("Version"):
                        return (p, r)
            return latest(name)

        def concrete(name):
            if candidates(name):
                return name
            provs = sorted(providers.get(name, ()))
            return next((p for p in provs if self.inst(p)), None) or (provs[0] if provs else None)

        roots = {"dpkg", "apt", "gpgv"} | set(self.args.extra)
        # Every package that ships an apt/dpkg extension point is verified too, so
        # its hooks, transports and keys are checked against signed content.
        ext = ("etc/apt/apt.conf.d/", "etc/dpkg/dpkg.cfg.d/", "usr/lib/apt/methods/", "etc/apt/trusted.gpg.d/",
               "etc/apt/sources.list.d/", "usr/lib/apt/apt-helper", "usr/sbin/policy-rc.d")
        for path, owner in self.path_owner().items():
            if path.startswith(ext) and owner not in roots:
                if latest(owner):
                    roots.add(owner)
        for (name, a) in self.installed:
            if a not in (self.arch, "all"):
                continue
            c = latest(name)
            if not c:
                continue
            src = c[0].get("Source", name).split()[0]
            if src == "apt" or name in KEYRING_PKGS or c[0].get("Essential") == "yes" or \
                    name in ("sqv", "apt-transport-https", "debconf", "init-system-helpers"):
                roots.add(name)

        chosen, missing, reason = {}, [], {r: "core" for r in roots}
        for path, owner in self.path_owner().items():
            if owner in roots and path.startswith(ext):
                reason[owner] = f"ships /{path.rsplit('/', 1)[0]}/"

        queue = sorted(roots, reverse=True)
        while queue:
            popped = queue.pop()
            name = concrete(popped) or popped
            if name in chosen or name in missing:
                continue
            c = pick_version(name)
            if not c:
                missing.append(name)
                continue
            chosen[name] = c
            for field in ("Pre-Depends", "Depends"):
                for alts in relations(c[0].get(field, "")):
                    pick = next((n for n, _, _ in alts if self.inst(n)), None) or \
                        next((concrete(n) for n, _, _ in alts if self.inst(concrete(n) or "")), None) or \
                        next((concrete(n) for n, _, _ in alts if concrete(n) and latest(concrete(n))), None)
                    if pick is None:
                        R.warn(f"{name}: cannot resolve '{' | '.join(n for n, _, _ in alts)}' from the signed index")
                        continue
                    reason.setdefault(pick, f"dependency of {name}")
                    queue.append(pick)
        # Packages whose postinst dpkg would run as a trigger when verified files
        # change are verified too (file triggers and named triggers), to a fixpoint.
        for _ in range(10):
            extra = self.trigger_interested(set(chosen)) - set(chosen) - set(missing)
            self.uninstalled_interest = getattr(self, "uninstalled_interest", set()) | \
                {n for n in extra if not self.inst(n)}
            extra = {n for n in extra if self.inst(n) and latest(n)}
            if not extra:
                break
            for n in sorted(extra):
                reason.setdefault(n, "trigger interest in verified files")
                queue.append(n)
            while queue:
                popped = queue.pop()
                name = concrete(popped) or popped
                if name in chosen or name in missing:
                    continue
                c = pick_version(name)
                if not c:
                    missing.append(name)
                    continue
                chosen[name] = c
                for field in ("Pre-Depends", "Depends"):
                    for alts in relations(c[0].get(field, "")):
                        pick = next((n for n, _, _ in alts if self.inst(n)), None) or \
                            next((concrete(n) for n, _, _ in alts if concrete(n) and latest(concrete(n))), None)
                        if pick:
                            reason.setdefault(pick, f"dependency of {name}")
                            queue.append(pick)
        if missing:
            die("not available from the verified repositories: " + ", ".join(sorted(missing)) +
                "\n(installed from a third-party source, renamed, or the wrong --repo/--components)")

        # Versioned dependencies inside the chosen set must hold; an installed
        # version kept for an exact audit may be too old for an upgraded package.
        for _ in range(20):
            bumped = False
            for name, (p, r) in list(chosen.items()):
                for field in ("Pre-Depends", "Depends"):
                    for alts in relations(p.get(field, "")):
                        ok, fix = False, None
                        for n, op, v in alts:
                            n2 = n if n in chosen else concrete(n)
                            if n2 in chosen:
                                if not op or satisfies(chosen[n2][0]["Version"], op, v):
                                    ok = True
                                    break
                                lt = latest(n2)
                                if lt and satisfies(lt[0]["Version"], op, v) and fix is None:
                                    fix = (n2, lt)
                            elif self.inst(n) and (not op or satisfies(self.inst(n)["Version"], op, v)):
                                ok = True
                                break
                        if not ok and fix:
                            chosen[fix[0]] = fix[1]
                            reason[fix[0]] = f"upgraded to satisfy {name} ({field})"
                            bumped = True
            if not bumped:
                break

        downgrades = []
        for name, (p, r) in sorted(chosen.items()):
            cur = self.inst(name)
            if cur and vercmp(cur["Version"], p["Version"]) > 0:
                downgrades.append(f"{name}: installed {cur['Version']} > archive {p['Version']}")
        if downgrades:
            msg = ("installed versions newer than anything in the signed archive (possible version hijack by "
                   "another repo, or the wrong suite):\n  " + "\n  ".join(downgrades))
            if not self.args.allow_downgrade:
                die(msg + "\nRerun with --allow-downgrade to replace them with the archive versions.")
            R.warn(msg)
        out(f"\nVerified set: {len(chosen)} packages")
        for name, (p, r) in sorted(chosen.items()):
            cur = self.inst(name)
            out(f"  {name:32} {(cur or {}).get('Version', '-'):>26} -> {p['Version']:26} [{r.suite}] "
                f"{reason.get(name)}")
        return chosen, reason

    @staticmethod
    def lay_down_order(chosen):
        first = ["libc6", "libc-bin", "dpkg", "tar", "dash", "bash", "coreutils", "libzstd1", "liblzma5",
                 "zlib1g", "libbz2-1.0", "libselinux1", "libpcre2-8-0", "libmd0", "libacl1"]
        return [n for n in first if n in chosen] + sorted(n for n in chosen if n not in first)

    # -- .deb ---------------------------------------------------------------------
    def fetch_deb(self, para, repo):
        fn = para["Filename"]
        if fn.startswith("/") or ".." in fn.split("/"):
            die(f"suspicious Filename in signed index: {fn}")
        size = int(para["Size"])
        if size > MAX_DEB:
            die(f"{fn}: larger than {MAX_DEB} bytes")
        blob = net.fetch(f"{repo.base}/{fn}", size, sha256=para["SHA256"].lower(), what=fn)
        check_hash(blob, para["SHA256"], fn, size=size)
        path = os.path.join(self.workdir, "debs", os.path.basename(fn))
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "wb") as f:
            f.write(blob)
        return self.parse_deb(para, blob, path)

    def parse_deb(self, para, blob, path):
        what = os.path.basename(path)
        members = read_ar(blob, what)
        if not members or members[0][0] != "debian-binary" or not members[0][1].startswith(b"2."):
            die(f"{what}: missing or unsupported debian-binary member")
        ctl = [m for m in members if m[0].startswith("control.tar")]
        dat = [m for m in members if m[0].startswith("data.tar")]
        if len(ctl) != 1 or len(dat) != 1:
            die(f"{what}: expected exactly one control and one data member")
        control = {m.path: m for m in read_tar(sniff_decompress(ctl[0][1]), what)}
        if "control" not in control:
            die(f"{what}: no control file")
        cf = parse_deb822(control["control"].data.decode("utf-8"))[0]
        if (cf.get("Package"), cf.get("Version"), cf.get("Architecture")) != \
                (para["Package"], para["Version"], para["Architecture"]):
            die(f"{what}: control file does not match the signed index entry")
        multiarch = para.get("Multi-Arch", "no")
        dbname = f"{para['Package']}:{para['Architecture']}" if multiarch == "same" else para["Package"]
        vp = VPkg(para["Package"], para["Version"], para["Architecture"], blob_path=path, dbkey=dbname)
        vp.meta["para"] = para
        if "conffiles" in control:
            for line in control["conffiles"].data.decode("utf-8").splitlines():
                if line.strip() and not line.startswith("remove-on-upgrade"):
                    vp.conffiles.add(line.split()[0].lstrip("/"))
        for s in SCRIPT_NAMES:
            if s in control:
                vp.scripts[s] = (control[s].data, control[s].mode)
        vp.meta["control"] = {k: control[k].data for k in CONTROL_DB if k in control and control[k].kind == "f"}
        listing = ["/."]
        for m in read_tar(sniff_decompress(dat[0][1]), what):
            listing.append("/" + m.path)
            if m.kind == "f":
                h = self.payload.put(m.data)
                vp.add(VFile(m.path, "f", m.mode, m.uid, m.gid, sha256=h, size=len(m.data),
                             conffile=m.path in vp.conffiles))
            elif m.kind == "l":
                vp.add(VFile(m.path, "l", 0o777, m.uid, m.gid, link=m.link, conffile=m.path in vp.conffiles))
            elif m.kind == "d":
                vp.add(VFile(m.path, "d", m.mode, m.uid, m.gid))
        vp.meta["list"] = listing
        return vp

    # -- semantics hooks ------------------------------------------------------------
    def expected_dir_link(self, rel, link):
        return link in EXPECTED_DIR_LINKS.get(rel, ())

    def runtime_dir_perm(self, rel):
        return rel in RUNTIME_DIR_PERMS

    def skip_compare(self, vp, vf):
        return vf.conffile and vf.path.startswith("etc/dpkg/")   # handled as critical in injection_points

    def known_lib_dir(self, path):
        return bool(re.match(r"(usr/)?lib(32|64|x32)?(/[a-z0-9_]+-linux-gnu[a-z]*)?$", path))

    # -- plan ---------------------------------------------------------------------
    def pre_plan(self, plan, vpkgs):
        plan.phase = 0
        plan.backup_tree("var/lib/dpkg", "dpkg database before finalize")
        plan.backup_tree("etc/ld.so.cache", "loader cache (libc postinst runs ldconfig)")
        plan.backup_tree("var/cache/debconf", "debconf database (maintainer scripts update it)")
        plan.backup_tree("var/cache/ldconfig", "ldconfig aux cache")
        plan.phase = 1
        self.plan_db_rewrites(plan, vpkgs)
        plan.phase = 2

    def plan_db_rewrites(self, plan, vpkgs):
        snap = self.snap
        owners = {}
        for vp in vpkgs:
            for vf in vp.files:
                if vf.kind != "d":
                    owners.setdefault(vf.path, set()).add(vp.name)
        # Diversions: dpkg matches the literal package path and never diverts the
        # holder package's own copy. Directory diversions (usrmerge's /lib ->
        # /lib.usr-is-merged) are how merged-/usr protects its symlinks.
        div_rel = "var/lib/dpkg/diversions"
        lines = (snap.read(div_rel) or "").split("\n")
        keep, removed = [], []
        for i in range(0, len(lines) - 2, 3):
            frm, to, pkg = lines[i:i + 3]
            hit = owners.get(frm.lstrip("/"), set()) - {pkg}
            if hit:
                holder = "a local admin (no package)" if pkg == ":" else pkg
                R.crit(f"dpkg diversion {frm} -> {to} by {holder} covers a file shipped by "
                       f"{', '.join(sorted(hit))}; dpkg would write the real file to {to}. --apply removes it.")
                removed.append((frm, to))
                for vp in vpkgs:
                    if vp.name in hit:
                        plan.needs_finalize(vp)
                continue
            keep.extend([frm, to, pkg])
        if removed:
            e = snap.stat(div_rel)
            plan.put_bytes(div_rel, ("\n".join(keep) + "\n").encode() if keep else b"",
                           0o644, 0, 0, "remove diversions covering verified files")
            for frm, to in removed:
                if not owners.get(to.lstrip("/")):
                    plan.quarantine(to.lstrip("/"), f"orphaned divert target of {frm}")
        so_rel = "var/lib/dpkg/statoverride"
        by_phys = {}
        for vp in vpkgs:
            for vf in vp.files:
                by_phys.setdefault(plan.phys(vf.path), []).append((vp, vf))
        users = self._idmap("etc/passwd")
        groups = self._idmap("etc/group")
        keep_so, drop = [], False
        for ln in (snap.read(so_rel) or "").splitlines():
            f = ln.split()
            if len(f) != 4:
                keep_so.append(ln)
                continue
            hits = by_phys.get(snap.resolve(f[3].lstrip("/")), [])
            if not hits:
                keep_so.append(ln)
                continue
            owner, group, mode, path = f
            legit = [(vp, vf) for vp, vf in hits if self._script_adds_override(vp, owner, mode, path)]
            if legit:
                # dpkg applies the override when it unpacks: expect it on disk.
                uid = users.get(owner.lstrip("#"), int(owner[1:]) if owner.startswith("#") else None)
                gid = groups.get(group.lstrip("#"), int(group[1:]) if group.startswith("#") else None)
                for _, vf in legit:
                    if uid is not None and gid is not None:
                        vf.mode, vf.uid, vf.gid = int(mode, 8), uid, gid
                R.info(f"dpkg stat-override '{ln}' is set by {legit[0][0].name}'s own maintainer script")
                keep_so.append(ln)
                continue
            R.crit(f"dpkg stat-override '{ln}' changes owner/mode of a verified file and no verified maintainer "
                   f"script sets it (classic setuid persistence). --apply removes it.")
            drop = True
        if drop:
            plan.put_bytes(so_rel, ("\n".join(keep_so) + "\n").encode() if keep_so else b"",
                           0o644, 0, 0, "remove stat-overrides on verified files")
        # dpkg reads its own conffiles on every run.
        for vp in vpkgs:
            for vf in vp.files:
                if vf.conffile and vf.path.startswith("etc/dpkg/") and vf.kind == "f":
                    cur = snap.sha256(vf.path)
                    if cur is not None and cur != vf.sha256:
                        R.crit(f"/{vf.path} differs from the verified dpkg default; dpkg reads it on every "
                               f"run. --apply restores it (original kept in the backup).")
                        plan.put_file(vf.path, vf.sha256, vf.mode, vf.uid, vf.gid, "restore dpkg config")

    def post_compare(self, plan, vpkgs):
        """Maintainer scripts and dpkg's per-package control files."""
        snap = self.snap
        plan.phase = 3
        for vp in vpkgs:
            base = f"var/lib/dpkg/info/{vp.dbkey}"
            changed = False
            for s in SCRIPT_NAMES:
                rel = f"{base}.{s}"
                cur = snap.read(rel, binary=True)
                new = vp.scripts.get(s)
                if new is not None and cur != new[0]:
                    if vp.installed_version is not None:
                        state = "missing" if cur is None else "differs from the verified package"
                        if vp.exact or cur is None:
                            R.crit(f"maintainer script /{rel} {state}")
                        else:
                            R.info(f"/{rel}: replaced with the verified {vp.version} copy before upgrade "
                                   f"(dpkg would otherwise run the unverifiable {vp.installed_version} script)")
                    mode = new[1] if s != "triggers" else 0o644
                    plan.put_bytes(rel, new[0], mode or 0o755, 0, 0, f"verified {s} of {vp.name}")
                    changed = True
                elif new is None and snap.lstat(plan.phys(rel)) is not None:
                    if vp.exact:
                        R.crit(f"maintainer script /{rel} is present but not in the verified package")
                    plan.quarantine(rel, f"{s} not in verified {vp.name}")
                    changed = True
            if vp.installed_version is not None:
                for c, data in vp.meta["control"].items():
                    cur = snap.read(f"{base}.{c}", binary=True)
                    if cur is not None and cur != data and vp.exact:
                        level = R.crit if c == "md5sums" else R.warn
                        level(f"/{base}.{c} differs from the verified package"
                              + (" (hides changes from debsums/dpkg --verify)" if c == "md5sums" else ""))
                        changed = True
                cur_list = snap.read(f"{base}.list")
                if vp.exact and cur_list is not None and set(cur_list.splitlines()) != set(vp.meta["list"]):
                    R.warn(f"/{base}.list differs from the verified file list; finalize rewrites it")
                    changed = True
            if changed:
                plan.needs_finalize(vp)
        plan.phase = 2

    def injection_points(self, plan, vpkgs):
        snap = self.snap
        owned = {vf.path for vp in vpkgs for vf in vp.files}
        content = {vf.path: vf.sha256 for vp in vpkgs for vf in vp.files if vf.kind == "f"}
        plan.phase = 1
        for name in snap.listdir("etc/dpkg/dpkg.cfg.d"):
            rel = f"etc/dpkg/dpkg.cfg.d/{name}"
            if rel in owned:
                continue
            txt = snap.read(rel) or ""
            risky = re.search(r"^\s*(force-|instdir|admindir|root|path-include|path-exclude|status-logger|"
                              r"pre-invoke|post-invoke|log)", txt, re.M)
            (R.crit if risky else R.warn)(
                f"/{rel} is not shipped by any verified package and injects options into every dpkg run"
                f"{' (contains risky options)' if risky else ''}. --apply quarantines it.")
            plan.quarantine(rel, "dpkg option injection")
        pol = "usr/sbin/policy-rc.d"
        if snap.lstat(plan.phys(pol)) is not None and pol not in owned:
            R.crit(f"/{pol} exists: it runs as root whenever a maintainer script starts or stops a service. "
                   f"--apply quarantines it (finalize uses its own temporary copy).")
            plan.quarantine(pol, "service-policy hook")
        # trigger interests: other packages' postinst runs when verified files change
        verified_names = {vp.name for vp in vpkgs}
        interested = {}
        for ln in (snap.read("var/lib/dpkg/triggers/File") or "").splitlines():
            parts = ln.split()
            if len(parts) != 2:
                continue
            path, pkg = parts[0].lstrip("/"), parts[1].split("/")[0].split(":")[0]
            if pkg in verified_names:
                continue
            if any(p == path or p.startswith(path + "/") for p in owned):
                interested.setdefault(pkg, set()).add("/" + path)
        for pkg in sorted(getattr(self, "uninstalled_interest", ())):
            R.warn(f"/var/lib/dpkg/triggers has an interest registered for {pkg}, which is not installed "
                   f"(stale or planted entry); inspect /var/lib/dpkg/triggers/File")
        for pkg, paths in sorted(interested.items()):
            R.warn(f"trigger interest: postinst of {pkg} (not verified) runs when {', '.join(sorted(paths))[:120]} "
                   f"changes. finalize defers it (--no-triggers); inspect /var/lib/dpkg/info/{pkg}*.postinst "
                   f"before the next apt run")
        # apt trust configuration
        if snap.lstat("etc/apt/trusted.gpg"):
            R.warn("/etc/apt/trusted.gpg exists: every key in it can sign for every repository.")
        for name in snap.listdir("etc/apt/trusted.gpg.d"):
            rel = f"etc/apt/trusted.gpg.d/{name}"
            if rel not in owned:
                R.crit(f"/{rel} is not shipped by any verified package and is trusted for ALL repositories. "
                       f"--apply quarantines it (use signed-by for third-party repos instead)")
                plan.quarantine(rel, "unverified globally trusted apt key")
            elif snap.sha256(rel) not in (None, content.get(rel)):
                R.crit(f"/{rel} differs from the verified keyring package (extra or replaced archive key)")

        def check_source(rel, uri, opts):
            for k in ("trusted", "allow-insecure", "allow-weak", "allow-downgrade-to-insecure"):
                if opts.get(k, "").lower() == "yes":
                    R.crit(f"/{rel}: {uri} sets {k}=yes, which disables or weakens signature checks. "
                           f"--apply quarantines the file")
                    plan.quarantine(rel, f"{k}=yes source")
            if uri.startswith("http://") and "signed-by" not in opts:
                R.info(f"/{rel}: {uri} has no signed-by, so any globally trusted key can sign for it")

        for rel in ["etc/apt/sources.list"] + [f"etc/apt/sources.list.d/{n}"
                                               for n in snap.listdir("etc/apt/sources.list.d")]:
            txt = snap.read(rel)
            if not txt:
                continue
            if rel.endswith(".sources"):
                try:
                    paras = parse_deb822(txt)
                except ValueError:
                    R.warn(f"/{rel}: could not parse")
                    continue
                for p in paras:
                    low = {k.lower(): v for k, v in p.items()}
                    if low.get("enabled", "yes").lower() != "no":
                        check_source(rel, low.get("uris", "?"), low)
            elif rel.endswith(".list"):
                for ln in txt.splitlines():
                    ln = ln.split("#", 1)[0].strip()
                    if not re.match(r"deb(-src)?\s", ln):
                        continue
                    m = re.match(r"deb(?:-src)?\s+\[([^\]]*)\]\s+(\S+)", ln)
                    opts = {}
                    if m:
                        for kv in m.group(1).split():
                            k, _, v = kv.partition("=")
                            opts[k.lower()] = v
                        uri = m.group(2)
                    else:
                        uri = ln.split()[1] if len(ln.split()) > 1 else "?"
                    check_source(rel, uri, opts)

        hook = re.compile(r"(Pre|Post)-Invoke|Pre-Install-Pkgs|Post-Invoke-Success|Pre-Invoke-Success", re.I)
        weaken = re.compile(r"AllowUnauthenticated|AllowInsecureRepositories|AllowWeakRepositories|"
                            r"AllowDowngradeToInsecureRepositories|Check-Valid-Until|Check-Date|"
                            r"Verify-Peer|Verify-Host|Dir::|\bDir\s*\{|TrustedParts|\bTrusted\b|"
                            r"Signed-By|APT::Key|gpgv|Methods", re.I)
        for rel in ["etc/apt/apt.conf"] + [f"etc/apt/apt.conf.d/{n}" for n in snap.listdir("etc/apt/apt.conf.d")]:
            data = snap.read(rel, binary=True)
            if data is None:
                continue
            vsha = content.get(rel)
            if vsha and snap.sha256(rel) == vsha:
                continue                      # identical to the signed package
            ref = set()
            if vsha:                          # modified conffile: only new lines are suspicious
                ref = {x.strip() for x in self.payload.get(vsha).decode("utf-8", "replace").splitlines()}
            where = "modified conffile" if vsha else "not shipped by any verified package"
            text = data.decode("utf-8", "replace")
            has_hook = bool(hook.search(text))
            bad = False
            for ln in text.splitlines():
                s = ln.strip()
                if not s or s.startswith(("//", "#")) or s in ref or s in ("{", "}", "};"):
                    continue
                if has_hook:
                    R.crit(f"/{rel} ({where}): new line in an apt hook configuration (runs as root on apt "
                           f"runs): {s[:120]}")
                    bad = True
                elif weaken.search(s):
                    R.crit(f"/{rel} ({where}): weakens or redirects apt's trust settings: {s[:120]}")
                    bad = True
            if bad and vsha:
                vf = next(vf for vp in vpkgs for vf in vp.files if vf.path == rel)
                plan.put_file(rel, vsha, vf.mode, vf.uid, vf.gid, "restore apt config with injected lines")
                R.info(f"/{rel}: --apply restores the verified version (the modified one is kept in the backup)")
            elif bad:
                plan.quarantine(rel, "apt hook/trust injection")
                R.info(f"/{rel}: --apply quarantines it")
        for rel in ["etc/apt/preferences"] + [f"etc/apt/preferences.d/{n}" for n in snap.listdir("etc/apt/preferences.d")]:
            for m in re.finditer(r"^Pin-Priority:\s*(-?\d+)", snap.read(rel) or "", re.M | re.I):
                if int(m.group(1)) >= 1000:
                    R.warn(f"/{rel}: Pin-Priority {m.group(1)} lets that source replace or downgrade packages")
        for name in snap.listdir("usr/lib/apt/methods"):
            rel = f"usr/lib/apt/methods/{name}"
            if plan.phys(rel) not in {plan.phys(p) for p in owned}:
                R.crit(f"/{rel} is an apt transport not shipped by any verified package; apt runs it as root "
                       f"for matching URIs. --apply quarantines it.")
                plan.quarantine(rel, "rogue apt transport")
        plan.phase = 2

    def finalize_script(self, plan):
        pkgs = plan.finalize_pkgs
        if not pkgs:
            return ""
        flags = ["--force-confdef", "--force-confnew" if self.args.restore_conffiles else "--force-confold",
                 "--no-triggers"]
        if self.args.allow_downgrade:
            flags.append("--force-downgrade")
        want = " ".join(f"{vp.dbkey}={vp.version}" for vp in pkgs)
        debs = " ".join("pkgs/" + os.path.basename(vp.blob_path) for vp in pkgs)
        names = " ".join(vp.name for vp in self.vpkgs)
        plan.restarts.extend(restart_hints([(f"{vp.name}.{s}", d[0]) for vp in pkgs for s, d in vp.scripts.items()
                                            if s in ("postinst", "preinst", "prerm")]))
        dpkg = "/" + plan.phys("usr/bin/dpkg")
        return f"""# apt/dpkg finalize, generated by pmtrust
APT_WANT='{want}'
APT_DEBS='{debs}'
APT_VERIFIED=' {names} '
DPKG='{dpkg}'

pm_needs_finalize() {{
    "$BB" awk -v want="$APT_WANT" '
        BEGIN {{ n = split(want, w, " "); for (i = 1; i <= n; i++) {{ split(w[i], kv, "="); need[kv[1]] = kv[2] }} }}
        function check() {{ k = p; if (!(k in need)) k = p ":" a;
                           if ((k in need) && s ~ / installed$/ && v == need[k]) ok[k] = 1; p = a = v = s = "" }}
        /^Package:/ {{ p = $2 }} /^Architecture:/ {{ a = $2 }} /^Version:/ {{ v = $2 }} /^Status:/ {{ s = $0 }}
        /^$/ {{ check() }}
        END {{ check(); bad = 0; for (k in need) if (!(k in ok)) bad++; exit(bad ? 0 : 1) }}
    ' /var/lib/dpkg/status
}}

pm_finalize() {{
    _pol=/usr/sbin/policy-rc.d
    _ours=0
    if ! exists "$_pol"; then
        printf '#!/bin/sh\\n# pmtrust: block service restarts during finalize\\nexit 101\\n' > "$_pol"
        "$BB" chmod 755 "$_pol"; record "RM${{TAB}}$_pol${{TAB}}ABSENT"; _ours=1
    fi
    _args=""
    for d in $APT_DEBS; do _args="$_args $PLAN/$d"; done
    log "  $DPKG --install {' '.join(flags)} ($(echo $APT_DEBS | "$BB" wc -w) packages)"
    # shellcheck disable=SC2086
    "$BB" env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin LC_ALL=C HOME=/root DEBIAN_FRONTEND=noninteractive \\
        DEBCONF_NONINTERACTIVE_SEEN=true "$DPKG" --install {' '.join(flags)} $_args >> "$LOG" 2>&1
    _rc=$?
    [ "$_rc" -eq 0 ] || crit "dpkg exited with $_rc (see $LOG); verified files are in place, run 'dpkg --configure -a' after inspecting"
    # Run pending triggers only for verified packages; others stay pending.
    _pend=$("$BB" awk -v ok="$APT_VERIFIED" '/^Package:/{{p=$2}} /^Status:.*triggers-(pending|awaited)/{{ if (index(ok, " " p " ")) print p }}' /var/lib/dpkg/status | "$BB" sort -u)
    if [ -n "$_pend" ]; then
        log "  $DPKG --triggers-only $(echo $_pend)"
        # shellcheck disable=SC2086
        "$BB" env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin LC_ALL=C HOME=/root DEBIAN_FRONTEND=noninteractive \\
            "$DPKG" --triggers-only $_pend >> "$LOG" 2>&1 || warn "dpkg --triggers-only failed (see $LOG)"
    fi
    _left=$("$BB" awk '/^Package:/{{p=$2}} /^Status:.*triggers-(pending|awaited)/{{print p}}' /var/lib/dpkg/status | "$BB" sort -u)
    [ -n "$_left" ] && warn "triggers still pending for unverified packages (run on the next apt/dpkg run; inspect their postinst first): $(echo $_left)"
    [ "$_ours" = 1 ] && "$BB" rm -f "$_pol"
    return 0
}}
"""
