"""rpm / dnf backend (Rocky, RHEL-like): foghorn, sylvester.

Trust chain: each package's header carries an OpenPGP signature (RSAHEADER,
checked with the STAGING host's gpgv against pinned keys) over the header
bytes; the signed header holds the payload digest and every file's digest.
repomd.xml is often unsigned on Rocky (repo_gpgcheck=0), so package selection
uses it only as an index: every package is still checked by its own signature
and by the checksum in primary.xml.

The rpmdb (sqlite) is read as data in pure Python. The old-script trap is
handled at finalize: rpm -U --replacepkgs with --nopreun --nopostun --notriggers,
so neither the old (unverified) scriptlets in the rpmdb nor other packages'
triggers run.
"""
import gzip
import io
import os
import re
import shutil
import sqlite3
import struct
import tempfile
import xml.etree.ElementTree as ET
from datetime import datetime, timezone

from core import net
from core.pgp import Trust
from core.report import R, die, step, out
from core.util import read_cpio, sniff_decompress, check_hash, sha256 as sha256hex
from core.vpkg import VPkg, VFile
from .base import Backend

HDR_MAGIC = b"\x8e\xad\xe8\x01\x00\x00\x00\x00"
LEAD_MAGIC = b"\xed\xab\xee\xdb"
MAX_RPM = 1024 * 1024 * 1024
T = dict(NAME=1000, VERSION=1001, RELEASE=1002, EPOCH=1003, ARCH=1022, SOURCERPM=1044,
         PREIN=1023, POSTIN=1024, PREUN=1025, POSTUN=1026, PREINPROG=1085, POSTINPROG=1086,
         PREUNPROG=1087, POSTUNPROG=1088, PRETRANS=1151, POSTTRANS=1152, TRIGGERSCRIPTS=1065,
         FILETRIGGERSCRIPTS=5066, TRANSFILETRIGGERSCRIPTS=5076, OLDFILENAMES=1027, FILESIZES=1028,
         FILEMODES=1030, FILEDIGESTS=1035, FILELINKTOS=1036, FILEFLAGS=1037, FILEUSERNAME=1039,
         FILEGROUPNAME=1040, PROVIDENAME=1047, REQUIREFLAGS=1048, REQUIRENAME=1049, REQUIREVERSION=1050,
         DIRINDEXES=1116, BASENAMES=1117, DIRNAMES=1118, PAYLOADCOMPRESSOR=1125, LONGFILESIZES=5008,
         FILECAPS=5010, FILEDIGESTALGO=5011, PAYLOADDIGEST=5092, PAYLOADDIGESTALGO=5093,
         TRIGGERNAME=1066, FILETRIGGERNAME=5069, TRANSFILETRIGGERNAME=5079)
SIG_RSA, SIG_DSA, SIG_SHA256, SIG_PGP, SIG_GPG = 268, 267, 273, 1002, 1005
SCRIPT_TAGS = ("PREIN", "POSTIN", "PREUN", "POSTUN", "PRETRANS", "POSTTRANS", "TRIGGERSCRIPTS",
               "FILETRIGGERSCRIPTS", "TRANSFILETRIGGERSCRIPTS", "PREINPROG", "POSTINPROG",
               "PREUNPROG", "POSTUNPROG")
RPMFILE_CONFIG, RPMFILE_GHOST = 1, 64
DIGEST_ALGO = {1: "md5", 2: "sha1", 8: "sha256", 9: "sha384", 10: "sha512"}


# --------------------------------------------------------------------------
# rpmvercmp (port of rpm's rpmvercmp.c) and EVR comparison
# --------------------------------------------------------------------------
def _alnum(c):
    return c.isascii() and c.isalnum()


def rpmvercmp(a, b):
    if a == b:
        return 0
    i = j = 0
    while i < len(a) or j < len(b):
        while i < len(a) and not _alnum(a[i]) and a[i] not in "~^":
            i += 1
        while j < len(b) and not _alnum(b[j]) and b[j] not in "~^":
            j += 1
        ca = a[i] if i < len(a) else ""
        cb = b[j] if j < len(b) else ""
        if ca == "~" or cb == "~":
            if ca != "~":
                return 1
            if cb != "~":
                return -1
            i += 1
            j += 1
            continue
        if ca == "^" or cb == "^":
            if not ca:
                return -1
            if not cb:
                return 1
            if ca != "^":
                return 1
            if cb != "^":
                return -1
            i += 1
            j += 1
            continue
        if not (ca and cb):
            break
        si, sj = i, j
        if ca.isascii() and ca.isdigit():
            while i < len(a) and a[i].isascii() and a[i].isdigit():
                i += 1
            while j < len(b) and b[j].isascii() and b[j].isdigit():
                j += 1
            isnum = True
        else:
            while i < len(a) and a[i].isascii() and a[i].isalpha():
                i += 1
            while j < len(b) and b[j].isascii() and b[j].isalpha():
                j += 1
            isnum = False
        s1, s2 = a[si:i], b[sj:j]
        if not s1:
            return -1
        if not s2:
            return 1 if isnum else -1
        if isnum:
            s1, s2 = s1.lstrip("0"), s2.lstrip("0")
            if len(s1) != len(s2):
                return 1 if len(s1) > len(s2) else -1
        if s1 != s2:
            return -1 if s1 < s2 else 1
    ra, rb = i >= len(a), j >= len(b)
    if ra and rb:
        return 0
    return -1 if ra else 1


def parse_evr(s):
    e, _, rest = s.partition(":") if ":" in s and s.split(":", 1)[0].isdigit() else ("0", "", s)
    v, _, r = rest.rpartition("-") if "-" in rest else (rest, "", "")
    return e or "0", v, r


def vercmp_evr(a, b):
    ea, va, ra = parse_evr(a)
    eb, vb, rb = parse_evr(b)
    rc = rpmvercmp(ea, eb) or rpmvercmp(va, vb)
    if not rc and ra and rb:
        rc = rpmvercmp(ra, rb)
    return rc


def evr(e, v, r):
    return f"{e}:{v}-{r}" if e not in (None, "", "0", 0) else f"{v}-{r}"


# --------------------------------------------------------------------------
# rpm header format
# --------------------------------------------------------------------------
def parse_header(buf, off, magic=True, what="header"):
    start = off
    if magic:
        if buf[off:off + 8] != HDR_MAGIC:
            die(f"{what}: bad header magic")
        off += 8
    if len(buf) < off + 8:
        die(f"{what}: truncated header")
    il, dl = struct.unpack(">II", buf[off:off + 8])
    if il > 200000 or dl > 512 * 1024 * 1024:
        die(f"{what}: implausible header size")
    off += 8
    ents = buf[off:off + 16 * il]
    data = buf[off + 16 * il:off + 16 * il + dl]
    if len(data) != dl or len(ents) != 16 * il:
        die(f"{what}: truncated header data")
    tags = {}
    for k in range(il):
        tag, typ, o, cnt = struct.unpack(">iIiI", ents[16 * k:16 * k + 16])
        if o < 0 or o > dl:
            die(f"{what}: bad offset for tag {tag}")
        if typ == 6:
            tags[tag] = data[o:data.index(b"\0", o)].decode("utf-8", "replace")
        elif typ in (8, 9):
            vals, p = [], o
            for _ in range(cnt):
                e = data.index(b"\0", p)
                vals.append(data[p:e].decode("utf-8", "replace"))
                p = e + 1
            tags[tag] = vals
        elif typ == 4:
            tags[tag] = list(struct.unpack(f">{cnt}I", data[o:o + 4 * cnt]))
        elif typ == 3:
            tags[tag] = list(struct.unpack(f">{cnt}H", data[o:o + 2 * cnt]))
        elif typ == 5:
            tags[tag] = list(struct.unpack(f">{cnt}Q", data[o:o + 8 * cnt]))
        elif typ in (1, 2):
            tags[tag] = list(data[o:o + cnt])
        elif typ == 7:
            tags[tag] = bytes(data[o:o + cnt])
    end = off + 16 * il + dl
    return tags, end, bytes(buf[start:end])


def first(tags, name, default=None):
    v = tags.get(T[name], default)
    if isinstance(v, list):
        return v[0] if v else default
    return v


def file_paths(tags):
    if T["BASENAMES"] in tags:
        dirs = tags.get(T["DIRNAMES"], [])
        return [dirs[i] + b for i, b in zip(tags.get(T["DIRINDEXES"], []), tags[T["BASENAMES"]])]
    return list(tags.get(T["OLDFILENAMES"], []))


def nevra(tags):
    e = first(tags, "EPOCH")
    return f"{first(tags, 'NAME')}-{evr(e, first(tags, 'VERSION'), first(tags, 'RELEASE'))}.{first(tags, 'ARCH')}"


def scripts_of(tags):
    out = {}
    for n in SCRIPT_TAGS:
        v = tags.get(T[n])
        if v is not None:
            out[n] = repr(v).encode()
    return out


class RpmBackend(Backend):
    name = "rpm"
    lib_dirs = ("usr/lib64", "usr/lib", "lib64")

    @staticmethod
    def detect(snap):
        return any(snap.read(p, binary=True) is not None for p in
                   ("var/lib/rpm/rpmdb.sqlite", "usr/lib/sysimage/rpm/rpmdb.sqlite", "var/lib/rpm/Packages"))

    @staticmethod
    def add_args(ap):
        g = ap.add_argument_group("rpm/dnf (Rocky)")
        g.add_argument("--rpm-repo", action="append", default=[], metavar="URL",
                       help="repository base URL with repodata/ (repeatable; file:// for a mounted DVD ISO). "
                            "Default: Rocky BaseOS + AppStream for the target's release, plus the vault")
        g.add_argument("--require-signed-metadata", action="store_true",
                       help="refuse repositories without a valid repomd.xml.asc")

    # -- target db as data ---------------------------------------------------
    def read_rpmdb(self):
        snap = self.snap
        for d in ("usr/lib/sysimage/rpm", "var/lib/rpm"):
            if snap.read(f"{d}/rpmdb.sqlite", binary=True) is not None:
                self.dbpath = "/" + snap.resolve(d)
                tmp = tempfile.mkdtemp(prefix="rpmdb-", dir=self.workdir)
                for suf in ("", "-wal", "-shm"):
                    data = snap.read(f"{d}/rpmdb.sqlite{suf}", binary=True)
                    if data is not None:
                        with open(os.path.join(tmp, f"rpmdb.sqlite{suf}"), "wb") as f:
                            f.write(data)
                con = sqlite3.connect(os.path.join(tmp, "rpmdb.sqlite"))
                rows = con.execute("SELECT hnum, blob FROM Packages").fetchall()
                con.close()
                hdrs = [parse_header(blob, 0, magic=False, what=f"rpmdb #{h}")[0] for h, blob in rows]
                R.info(f"rpmdb {self.dbpath}/rpmdb.sqlite: {len(hdrs)} headers")
                return hdrs
        if snap.read("var/lib/rpm/Packages", binary=True) is not None:
            die("BerkeleyDB rpmdb (EL8 or older) is not supported by the pure-Python reader; "
                "this backend targets Rocky 9/10 (sqlite rpmdb)")
        die("no rpmdb found in the snapshot")

    # -- repositories -----------------------------------------------------------
    def default_repos(self, osr):
        if osr.get("ID") not in ("rocky",):
            die(f"no default repositories for {osr.get('ID')!r}; pass --rpm-repo URL (repeatable)")
        ver = osr.get("VERSION_ID", "")
        major = ver.split(".")[0]
        arch = self.arch
        urls = [f"https://dl.rockylinux.org/pub/rocky/{major}/{r}/{arch}/os" for r in ("BaseOS", "AppStream")]
        if "." in ver:
            urls += [f"https://dl.rockylinux.org/vault/rocky/{ver}/{r}/{arch}/os" for r in ("BaseOS", "AppStream")]
        return urls

    def load_repo(self, base):
        tag = re.sub(r"[^A-Za-z0-9._-]", "_", base.split("://", 1)[-1])[-60:]
        try:
            repomd = net.fetch(net.join(base, "repodata/repomd.xml"), 16 * 1024 * 1024)
        except net.NotFound:
            return None
        try:
            asc = net.fetch(net.join(base, "repodata/repomd.xml.asc"), 1024 * 1024)
        except net.NotFound:
            asc = None
        if asc is not None:
            self.trust.detached(repomd, asc, f"{tag}/repomd.xml")
        elif self.args.require_signed_metadata:
            die(f"{tag}: repomd.xml is not signed and --require-signed-metadata was given")
        else:
            R.info(f"{tag}: repomd.xml is unsigned (normal for Rocky); packages are still verified one by one "
                   f"by their own signatures")
        root = ET.fromstring(repomd)
        ns = {"r": "http://linux.duke.edu/metadata/repo"}
        prim = None
        for d in root.findall("r:data", ns):
            if d.get("type") == "primary":
                prim = d
        if prim is None:
            die(f"{tag}: no primary metadata in repomd.xml")
        ck = prim.find("r:checksum", ns)
        href = prim.find("r:location", ns).get("href")
        size = prim.find("r:size", ns)
        if ck is None or ck.get("type") != "sha256":
            die(f"{tag}: primary metadata has no sha256 checksum")
        blob = net.fetch(net.join(base, href), int(size.text) if size is not None else 512 * 1024 * 1024,
                         sha256=ck.text.strip())
        check_hash(blob, ck.text.strip(), f"{tag}/{href}")
        ts = root.find("r:revision", ns)
        pkgs = self.parse_primary(sniff_decompress(blob), base)
        R.info(f"{tag}: {len(pkgs)} packages in primary metadata"
               + (f" (revision {ts.text})" if ts is not None else ""))
        return pkgs

    @staticmethod
    def parse_primary(xmlbytes, base):
        C = "{http://linux.duke.edu/metadata/common}"
        RP = "{http://linux.duke.edu/metadata/rpm}"
        out = []
        for ev, el in ET.iterparse(io.BytesIO(xmlbytes), events=("end",)):
            if el.tag != C + "package":
                continue
            v = el.find(C + "version")
            ck = el.find(C + "checksum")
            fmt = el.find(C + "format")
            p = {"name": el.findtext(C + "name"), "arch": el.findtext(C + "arch"),
                 "epoch": v.get("epoch", "0"), "ver": v.get("ver"), "rel": v.get("rel"),
                 "sha256": ck.text.strip() if ck is not None and ck.get("type") == "sha256" else None,
                 "href": el.find(C + "location").get("href"), "size": int(el.find(C + "size").get("package")),
                 "base": base, "provides": [], "requires": [], "files": [],
                 "sourcerpm": fmt.findtext(RP + "sourcerpm") if fmt is not None else ""}
            if fmt is not None:
                for kind in ("provides", "requires"):
                    sect = fmt.find(RP + kind)
                    if sect is not None:
                        for e in sect.findall(RP + "entry"):
                            p[kind].append((e.get("name"), e.get("flags"),
                                            evr(e.get("epoch"), e.get("ver"), e.get("rel")) if e.get("ver") else None))
                p["files"] = [f.text for f in fmt.findall(C + "file") if f.text]
            p["evr"] = evr(p["epoch"], p["ver"], p["rel"])
            out.append(p)
            el.clear()
        return out

    # -- pipeline ----------------------------------------------------------------
    def collect_verified(self):
        a = self.args
        self.trust = Trust(a.keyring, a.expect_fpr, a.trust_keyring, self.workdir)
        hdrs = self.read_rpmdb()
        self.installed = {}
        self.inst_provides = {}
        self.gpg_pubkeys = []
        self.inst_files = {}
        for h in hdrs:
            name = first(h, "NAME")
            if name == "gpg-pubkey":
                self.gpg_pubkeys.append(f"{first(h, 'VERSION')}-{first(h, 'RELEASE')}")
                continue
            self.installed.setdefault(name, []).append(h)
            for prov in h.get(T["PROVIDENAME"], []):
                self.inst_provides.setdefault(prov, set()).add(name)
            for p in file_paths(h):
                self.inst_files[p.lstrip("/")] = name
        self.inst_phys = {self.snap.resolve(p): o for p, o in self.inst_files.items()}
        osr = self.snap.os_release()
        archs = {first(h, "ARCH") for hs in self.installed.values() for h in hs}
        self.arch = a.arch or ("x86_64" if "x86_64" in archs else sorted(archs - {"noarch"})[0])
        R.info(f"target: {osr.get('PRETTY_NAME', '?')}, arch {self.arch}, "
               f"{sum(len(v) for v in self.installed.values())} installed packages")

        step("Fetching repository metadata")
        self.repo_pkgs = []
        for i, base in enumerate(a.rpm_repo or self.default_repos(osr)):
            pk = self.load_repo(base)
            if pk is None:
                (die if i == 0 else R.info)(f"{base}: no repodata (skipped)")
                continue
            self.repo_pkgs.extend(p for p in pk if p["arch"] in (self.arch, "noarch"))
        step("Resolving the core package set")
        chosen, reason = self.build_set()
        step("Downloading packages and verifying each header signature")
        vpkgs = []
        for name in self.order(chosen):
            p = chosen[name]
            vp = self.fetch_rpm(p)
            cur = self.inst_evr(name)
            vp.installed_version = cur
            vp.exact = cur == p["evr"]
            vp.meta["reason"] = reason.get(name, "")
            vpkgs.append(vp)
        R.info(f"{len(vpkgs)} packages verified ({sum(1 for v in vpkgs if v.exact)} at the installed version)")
        self.vpkgs = vpkgs
        return vpkgs

    def inst_evr(self, name):
        hs = self.installed.get(name)
        if not hs:
            return None
        h = hs[0]
        return evr(first(h, "EPOCH"), first(h, "VERSION"), first(h, "RELEASE"))

    def build_set(self):
        by_name, provides, files = {}, {}, {}
        for p in self.repo_pkgs:
            by_name.setdefault(p["name"], []).append(p)
            for n, _, _ in p["provides"]:
                provides.setdefault(n, set()).add(p["name"])
            for f in p["files"]:
                files.setdefault(f, set()).add(p["name"])

        def latest(name):
            c = by_name.get(name)
            if not c:
                return None
            best = c[0]
            for p in c[1:]:
                if vercmp_evr(p["evr"], best["evr"]) > 0:
                    best = p
            return best

        def pick(name):
            cur = self.inst_evr(name)
            if cur and not self.args.upgrade:
                for p in by_name.get(name, ()):
                    if p["evr"] == cur:
                        return p
            return latest(name)

        roots = {"rpm", "rpm-libs", "dnf", "python3-dnf", "libdnf", "gnupg2", "glibc", "bash"} | set(self.args.extra)
        src_pat = re.compile(r"^(rpm|dnf|dnf-plugins-core|libdnf|libdnf5|dnf5|librepo|libsolv|libcomps|python3\.\d+|"
                             r"python3|glibc|gnupg2|gpgme|rocky-release|rocky-repos|rocky-gpg-keys|yum)-[0-9]")
        ext = ("etc/yum.repos.d/", "etc/dnf/", "etc/rpm/", "usr/lib/rpm/macros.d/", "usr/lib64/rpm-plugins/",
               "etc/pki/rpm-gpg/", "usr/lib/rpm/")
        for name, hs in self.installed.items():
            src = first(hs[0], "SOURCERPM") or ""
            if src_pat.match(src) or name.endswith(("-release", "-repos", "-gpg-keys")) or \
                    name.startswith("rpm-plugin-"):
                roots.add(name)
        for path, owner in self.inst_files.items():
            if path.startswith(ext) or re.match(r"usr/lib(64)?/python3\.\d+/site-packages/dnf-plugins/", path):
                roots.add(owner)
        roots = {r for r in roots if r in self.installed or r in self.args.extra}

        chosen, reason, missing, optional = {}, {r: "core" for r in roots}, [], set()
        queue = sorted(roots, reverse=True)
        while True:
            while queue:
                name = queue.pop()
                if name in chosen or name in missing:
                    continue
                p = pick(name)
                if not p:
                    missing.append(name)
                    continue
                chosen[name] = p
                for req, flags, ver in p["requires"]:
                    if req.startswith(("rpmlib(", "config(")) or req in chosen:
                        continue
                    cands = set(by_name) & {req} or provides.get(req, set()) | files.get(req, set())
                    inst = self.inst_provides.get(req, set()) & set(self.installed)
                    if req.startswith("/"):
                        # file requires: match through the target's merged-/usr symlinks
                        phys = self.snap.resolve(req.lstrip("/"))
                        for f, owners in files.items():
                            if self.snap.resolve(f.lstrip("/")) == phys:
                                cands = cands | owners
                        if phys in self.inst_phys:
                            inst = inst | {self.inst_phys[phys]}
                    prov = (cands & inst) or (cands & set(chosen)) or cands or inst
                    if not prov:
                        R.warn(f"{name}: cannot resolve requirement {req} from the repositories")
                        continue
                    n = sorted(prov)[0]
                    reason.setdefault(n, f"required by {name}")
                    queue.append(n)
            # Packages whose triggers / (trans)file triggers fire when the chosen
            # packages change: their scriptlets would run, so verify them too.
            chosen_files = [f for f, o in self.inst_files.items() if o in chosen]
            for n, hs in self.installed.items():
                if n in chosen or n in missing:
                    continue
                h = hs[0]
                hit = set(h.get(T["TRIGGERNAME"], [])) & set(chosen)
                for pre in h.get(T["FILETRIGGERNAME"], []) + h.get(T["TRANSFILETRIGGERNAME"], []):
                    pre = pre.strip("/")
                    if any(f == pre or f.startswith(pre + "/") for f in chosen_files):
                        hit.add("/" + pre)
                if hit:
                    reason[n] = f"trigger on {', '.join(sorted(hit))[:60]}"
                    optional.add(n)
                    queue.append(n)
            if not queue:
                break
        for n in sorted(set(missing) & optional):
            R.warn(f"{n} has a trigger on verified packages but is not in the repositories: its scriptlets "
                   f"cannot be verified (finalize does not run triggers; inspect it before the next dnf run)")
        missing = [m for m in missing if m not in optional]
        if missing:
            die("not available from the repositories: " + ", ".join(sorted(missing)) +
                "\n(third-party packages, a different release, or pass --rpm-repo)")
        downgrades = []
        for name, p in chosen.items():
            cur = self.inst_evr(name)
            if cur and vercmp_evr(cur, p["evr"]) > 0:
                downgrades.append(f"{name}: installed {cur} > repository {p['evr']}")
        if downgrades and not self.args.allow_downgrade:
            die("installed versions newer than the repositories (wrong release, or a version hijack):\n  "
                + "\n  ".join(downgrades) + "\nPass --allow-downgrade to replace them.")
        out(f"\nVerified set: {len(chosen)} packages")
        for name in sorted(chosen):
            out(f"  {name:32} {self.inst_evr(name) or '-':>28} -> {chosen[name]['evr']:28} {reason.get(name)}")
        return chosen, reason

    @staticmethod
    def order(chosen):
        first_ = ["glibc", "glibc-common", "bash", "rpm-libs", "rpm"]
        return [n for n in first_ if n in chosen] + sorted(n for n in chosen if n not in first_)

    # -- rpm files ------------------------------------------------------------------
    def fetch_rpm(self, p):
        href = p["href"]
        if href.startswith("/") or ".." in href.split("/"):
            die(f"suspicious location in primary metadata: {href}")
        if p["size"] > MAX_RPM:
            die(f"{href}: too large")
        blob = net.fetch(net.join(p["base"], href), p["size"], sha256=p["sha256"], what=href)
        if p["sha256"]:
            check_hash(blob, p["sha256"], href, size=p["size"])
        path = os.path.join(self.workdir, "rpms", os.path.basename(href))
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "wb") as f:
            f.write(blob)
        return self.parse_rpm(blob, path, p)

    def parse_rpm(self, blob, path, p=None):
        what = os.path.basename(path)
        if blob[:4] != LEAD_MAGIC:
            die(f"{what}: not an rpm (bad lead)")
        sig, send, _ = parse_header(blob, 96, True, f"{what} signature")
        send += (8 - ((send - 96) % 8)) % 8
        hdr, hend, hbytes = parse_header(blob, send, True, f"{what} header")
        payload = blob[hend:]
        # 1. the header signature (only gpgv output is trusted)
        sigpkt = sig.get(SIG_RSA) or sig.get(SIG_DSA)
        if sigpkt:
            self.trust.detached(hbytes, sigpkt, what, quiet=True)
        else:
            legacy = sig.get(SIG_GPG) or sig.get(SIG_PGP)
            if not legacy:
                die(f"{what}: package is not signed")
            self.trust.detached(hbytes + payload, legacy, what, quiet=True)
        if SIG_SHA256 in sig and sig[SIG_SHA256] != sha256hex(hbytes):
            die(f"{what}: header SHA256 in the signature header does not match")
        # 2. payload digest from the SIGNED header
        pd = hdr.get(T["PAYLOADDIGEST"])
        algo = DIGEST_ALGO.get(first(hdr, "PAYLOADDIGESTALGO", 8), "sha256")
        if pd:
            check_hash(payload, pd[0], f"{what} payload", algo=algo)
        elif not (sig.get(SIG_GPG) or sig.get(SIG_PGP)):
            die(f"{what}: no payload digest in the signed header and no legacy whole-package signature")
        name = first(hdr, "NAME")
        if p and (name, evr(first(hdr, "EPOCH"), first(hdr, "VERSION"), first(hdr, "RELEASE")), first(hdr, "ARCH")) \
                != (p["name"], p["evr"], p["arch"]):
            die(f"{what}: signed header does not match the repository entry")
        vp = VPkg(name, evr(first(hdr, "EPOCH"), first(hdr, "VERSION"), first(hdr, "RELEASE")),
                  first(hdr, "ARCH"), blob_path=path)
        vp.meta["nevra"] = nevra(hdr)
        vp.meta["scripts"] = scripts_of(hdr)
        vp.meta["digests"] = hdr.get(T["FILEDIGESTS"], [])
        vp.meta["requires"] = hdr.get(T["REQUIRENAME"], [])
        # 3. file contents from the payload, bound to the signed per-file digests
        falgo = DIGEST_ALGO.get(first(hdr, "FILEDIGESTALGO", 1), "md5")
        content = {}
        entries, _ = read_cpio(sniff_decompress(payload), what)
        import hashlib
        for nm, mode, uid, gid, data, nlink, idx in entries:
            if nm is None:
                die(f"{what}: stripped cpio payloads (files over 4 GiB) are not supported")
            if data:
                content[hashlib.new(falgo, data).hexdigest()] = data
        users, groups = self.idmaps()
        paths = file_paths(hdr)
        modes = hdr.get(T["FILEMODES"], [])
        digests = hdr.get(T["FILEDIGESTS"], [])
        links = hdr.get(T["FILELINKTOS"], [])
        flags = hdr.get(T["FILEFLAGS"], [0] * len(paths))
        unames = hdr.get(T["FILEUSERNAME"], [])
        gnames = hdr.get(T["FILEGROUPNAME"], [])
        caps = hdr.get(T["FILECAPS"], [])
        for i, fp in enumerate(paths):
            rel = fp.lstrip("/")
            mode = modes[i]
            fl = flags[i] if i < len(flags) else 0
            if fl & RPMFILE_GHOST:
                continue
            uid = users.get(unames[i] if i < len(unames) else "root", None)
            gid = groups.get(gnames[i] if i < len(gnames) else "root", None)
            if uid is None or gid is None:
                R.warn(f"{name}: /{rel} owner {unames[i]}:{gnames[i]} unknown on the target; using root")
                uid, gid = uid or 0, gid or 0
            if i < len(caps) and caps[i]:
                vp.meta.setdefault("caps", []).append(f"/{rel} ({caps[i]})")
            ftype = mode & 0o170000
            if ftype == 0o040000:
                vp.add(VFile(rel, "d", mode & 0o7777, uid, gid))
            elif ftype == 0o120000:
                vp.add(VFile(rel, "l", 0o777, uid, gid, link=links[i], conffile=bool(fl & RPMFILE_CONFIG)))
            elif ftype == 0o100000:
                dg = digests[i] if i < len(digests) else ""
                data = content.get(dg)
                if data is None:
                    if dg == hashlib.new(falgo, b"").hexdigest():
                        data = b""
                    else:
                        die(f"{what}: payload has no content matching the signed digest of /{rel}")
                h = self.payload.put(data)
                vp.add(VFile(rel, "f", mode & 0o7777, uid, gid, sha256=h, size=len(data),
                             conffile=bool(fl & RPMFILE_CONFIG)))
                if fl & RPMFILE_CONFIG:
                    vp.conffiles.add(rel)
        if falgo in ("md5", "sha1"):
            R.warn(f"{name}: file digests use {falgo}; content binding is weaker than sha256")
        return vp

    def idmaps(self):
        if not hasattr(self, "_ids"):
            def m(rel):
                out = {}
                for ln in (self.snap.read(rel) or "").splitlines():
                    f = ln.split(":")
                    if len(f) >= 3 and f[2].isdigit():
                        out.setdefault(f[0], int(f[2]))
                return out
            self._ids = (m("etc/passwd"), m("etc/group"))
        return self._ids

    def db_owned(self):
        return set(self.inst_files)

    # -- plan -----------------------------------------------------------------------
    def pre_plan(self, plan, vpkgs):
        plan.phase = 0
        plan.backup_tree(self.dbpath.lstrip("/"), "rpmdb before finalize")
        plan.phase = 2

    def post_compare(self, plan, vpkgs):
        """Installed headers in the rpmdb vs the verified headers (same NEVRA)."""
        for vp in vpkgs:
            if not vp.exact:
                continue
            h = next((h for h in self.installed.get(vp.name, []) if nevra(h) == vp.meta["nevra"]), None)
            if h is None:
                continue
            bad = []
            if scripts_of(h) != vp.meta["scripts"]:
                bad.append("scriptlets (would run on the next erase/upgrade)")
            if h.get(T["FILEDIGESTS"], []) != vp.meta["digests"]:
                bad.append("file digests (hides changes from rpm -V)")
            if bad:
                R.crit(f"rpmdb entry for {vp.meta['nevra']} differs from the signed header: {', '.join(bad)}. "
                       f"finalize rewrites it (old scriptlets are not run)")
                plan.needs_finalize(vp)

    def injection_points(self, plan, vpkgs):
        snap = self.snap
        owned = {vf.path: vf for vp in vpkgs for vf in vp.files}
        plan.phase = 1

        def unowned_or_modified(rel):
            vf = owned.get(rel)
            if vf is None:
                return "not shipped by any verified package"
            if vf.kind == "f" and snap.sha256(rel) not in (None, vf.sha256):
                return "modified"
            return None

        def handle(rel, why, msg):
            vf = owned.get(rel)
            if why == "modified" and vf is not None:
                R.crit(f"/{rel} ({why}): {msg}. --apply restores the verified version")
                plan.put_file(rel, vf.sha256, vf.mode, vf.uid, vf.gid, msg)
            else:
                R.crit(f"/{rel} ({why}): {msg}. --apply quarantines it")
                plan.quarantine(rel, msg)

        # rpm macros: evaluated by every rpm run (scriptlet paths, dbpath, netsharedpath ...)
        for d in ("etc/rpm", "usr/lib/rpm/macros.d"):
            for n in snap.listdir(d):
                rel = f"{d}/{n}"
                e = snap.stat(rel)
                if e is None or e.kind != "f":
                    continue
                why = unowned_or_modified(rel)
                if why:
                    handle(rel, why, "rpm macro file read by every rpm/dnf run")
        for rel in ("usr/lib/rpm/macros", "usr/lib/rpm/rpmrc", "etc/rpmrc", "root/.rpmmacros", "root/.rpmrc"):
            if snap.stat(rel) is not None:
                why = unowned_or_modified(rel)
                if why:
                    handle(rel, why, "rpm configuration read by every rpm run")
        for d in ("usr/lib64/rpm-plugins", "usr/lib/rpm-plugins"):
            for n in snap.listdir(d):
                rel = f"{d}/{n}"
                if rel not in owned:
                    handle(rel, "not shipped by any verified package", "rpm plugin loaded into every transaction")
        # Python start-up hooks run inside dnf
        for top in ("usr/lib", "usr/lib64", "usr/local/lib", "usr/local/lib64"):
            for py in snap.listdir(top):
                if not re.match(r"python3(\.\d+)?$", py):
                    continue
                for sub in ("", "/site-packages"):
                    d = f"{top}/{py}{sub}"
                    for n in snap.listdir(d):
                        if n.endswith(".pth") or n in ("sitecustomize.py", "usercustomize.py"):
                            rel = f"{d}/{n}"
                            why = unowned_or_modified(rel)
                            if why:
                                handle(rel, why, "Python start-up hook executed inside dnf")
                    pd = f"{top}/{py}/site-packages/dnf-plugins"
                    for n in snap.listdir(pd) if sub else ():
                        rel = f"{pd}/{n}"
                        if n.endswith(".py") and rel not in owned:
                            handle(rel, "not shipped by any verified package", "dnf plugin loaded by every dnf run")
        # repository and dnf configuration (report only, except outright disabled checks)
        for rel in ["etc/dnf/dnf.conf", "etc/yum.conf"] + \
                [f"etc/yum.repos.d/{n}" for n in snap.listdir("etc/yum.repos.d") if n.endswith(".repo")]:
            txt = snap.read(rel)
            if not txt:
                continue
            section, enabled = "main", {}
            bad = False
            for ln in txt.splitlines():
                s = ln.split("#", 1)[0].strip()
                m = re.match(r"\[(.+)\]", s)
                if m:
                    section = m.group(1)
                    continue
                k, _, v = s.partition("=")
                k, v = k.strip().lower(), v.strip().lower()
                if k == "enabled":
                    enabled[section] = v
                if k in ("gpgcheck", "pkg_gpgcheck") and v in ("0", "false", "no"):
                    R.crit(f"/{rel} [{section}]: gpgcheck=0 disables package signature checks")
                    bad = True
                elif k == "sslverify" and v in ("0", "false", "no"):
                    R.crit(f"/{rel} [{section}]: sslverify=0")
                    bad = True
                elif k in ("pluginpath", "pluginconfpath", "reposdir", "installroot", "persistdir"):
                    R.crit(f"/{rel} [{section}]: {k} redirects where dnf loads code/config from: {s[:100]}")
                    bad = True
                elif k == "localpkg_gpgcheck" and v in ("0", "false", "no") and section == "main":
                    R.info(f"/{rel}: localpkg_gpgcheck=0 (default on EL): local rpm files are not signature-checked")
                elif k == "baseurl" and v.startswith("http://"):
                    R.info(f"/{rel} [{section}]: plain-http baseurl")
            if bad:
                why = unowned_or_modified(rel)
                if why:
                    handle(rel, why, "dnf/repo configuration that disables or redirects trust checks")
        for n in snap.listdir("etc/pki/rpm-gpg"):
            rel = f"etc/pki/rpm-gpg/{n}"
            why = unowned_or_modified(rel)
            if why:
                R.warn(f"/{rel} ({why}): a key file repos can reference with gpgkey=")
        if self.gpg_pubkeys:
            R.info(f"keys imported in the rpmdb (gpg-pubkey): {', '.join(self.gpg_pubkeys)}; compare with your pins")
            pins = {f[-8:].lower() for f in self.trust.expect}
            extra = [k for k in self.gpg_pubkeys if k.split("-")[0].lower() not in pins]
            if extra and pins:
                R.warn(f"rpmdb trusts keys that are not pinned: {', '.join(extra)} (rpm -e gpg-pubkey-<id> removes one)")
        caps = [c for vp in vpkgs for c in vp.meta.get("caps", [])]
        if caps:
            R.info(f"files with capabilities (restored by rpm at finalize, not by the lay-down): {', '.join(caps)[:300]}")
        plan.phase = 2

    def finalize_script(self, plan):
        pkgs = plan.finalize_pkgs
        if not pkgs:
            return ""
        files = " ".join("pkgs/" + os.path.basename(vp.blob_path) for vp in pkgs)
        nevras = " ".join(vp.meta["nevra"] for vp in pkgs)
        rpm = "/" + plan.phys("usr/bin/rpm")
        plan.restarts.append("rpm scriptlets (%post of verified packages) run; %preun/%postun and triggers do not")
        return f"""# rpm finalize, generated by pmtrust
RPM='{rpm}'
RPM_DBPATH='{self.dbpath}'
RPM_FILES='{files}'
RPM_NEVRAS='{nevras}'
_rpm() {{
    "$BB" env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin LC_ALL=C HOME=/root "$RPM" --dbpath "$RPM_DBPATH" "$@"
}}
pm_needs_finalize() {{
    # shellcheck disable=SC2086
    ! _rpm -q --quiet $RPM_NEVRAS
}}
pm_finalize() {{
    _args=""
    for f in $RPM_FILES; do _args="$_args $PLAN/$f"; done
    log "  $RPM -U --replacepkgs --replacefiles --oldpackage --nopreun --nopostun --notriggers ($(echo $RPM_FILES | "$BB" wc -w) packages)"
    # Old %preun/%postun live in the (untrusted) rpmdb: never run them. Triggers
    # belong to other, unverified packages: never run them either.
    # shellcheck disable=SC2086
    _rpm -U --replacepkgs --replacefiles --oldpackage --nopreun --nopostun --notriggers \\
        --define "_pkgverify_level digest" $_args >> "$LOG" 2>&1
    _rc=$?
    [ "$_rc" -eq 0 ] || crit "rpm exited with $_rc (see $LOG); verified files are in place but the rpmdb may be incomplete"
    return 0
}}
"""
