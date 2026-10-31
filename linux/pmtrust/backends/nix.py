"""nix backend (NixOS): ysam.

Model: the store is content addressed. For every store path in the closure of
the system's `nix` package (plus --nix-path extras), pmtrust fetches the
binary cache's .narinfo, verifies its ed25519 signature against a key you pin
with --nix-trusted-key (staging host's openssl), checks that the target's nix
db records the same NAR hash, downloads the NAR (FileHash + NarHash checked),
unpacks it in pure Python and compares every file with the snapshot.

`nix-store --verify --check-contents` compares against the db on the same disk,
so it is a corruption check, not a tamper check. `--repair` would refetch from
whatever substituters the (possibly tampered) nix.conf lists. pmtrust repairs
the store files directly from the verified NARs; rebuilding the system from a
reviewed configuration.nix remains the real fix.

Two collection rounds are needed: the first snapshot does not hash /nix/store.
`pmtrust plan` writes need-hashes.txt; run collect.sh --hash-list with it.
"""
import base64
import hashlib
import os
import re
import sqlite3
import subprocess
import tempfile

from core import net
from core.report import R, die, step, out
from core.util import sniff_decompress
from core.vpkg import VPkg, VFile
from .base import Backend

NIX32 = "0123456789abcdfghijklmnpqrsvwxyz"
STORE_RE = re.compile(r"^/nix/store/([0-9a-df-np-sv-z]{32})-([^/]+)$")


def nix32_encode(h):
    n = (len(h) * 8 - 1) // 5 + 1
    out = []
    for i in range(n - 1, -1, -1):
        b = i * 5
        j, k = b // 8, b % 8
        c = h[j] >> k
        if j + 1 < len(h):
            c |= h[j + 1] << (8 - k)
        out.append(NIX32[c & 0x1F])
    return "".join(out)


def nix32_decode(s, nbytes):
    v = 0
    for i, ch in enumerate(reversed(s)):
        v |= NIX32.index(ch) << (5 * i)
    return v.to_bytes(nbytes, "little")


def norm_hash(h):
    """'sha256:<nix32|hex|base64>' -> hex digest"""
    algo, _, val = h.partition(":")
    if algo != "sha256":
        die(f"unsupported hash {h[:20]}")
    if len(val) == 64 and all(c in "0123456789abcdef" for c in val):
        return val
    if len(val) == 52:
        return nix32_decode(val, 32).hex()
    return base64.b64decode(val + "=" * (-len(val) % 4)).hex()


def parse_nar(data, prefix, what):
    """NAR -> list of (relpath, kind, executable, bytes|linktarget)"""
    off = 0

    def s():
        nonlocal off
        n = int.from_bytes(data[off:off + 8], "little")
        v = data[off + 8:off + 8 + n]
        off += 8 + n + (-n % 8)
        if off > len(data):
            die(f"{what}: truncated NAR")
        return v

    def expect(tok):
        got = s()
        if got != tok:
            die(f"{what}: bad NAR token {got[:20]!r}, expected {tok!r}")

    out = []

    def node(path):
        expect(b"(")
        expect(b"type")
        t = s()
        if t == b"regular":
            nxt = s()
            exe = False
            if nxt == b"executable":
                expect(b"")
                exe = True
                nxt = s()
            if nxt != b"contents":
                die(f"{what}: bad NAR regular node")
            out.append((path, "f", exe, s()))
            expect(b")")
        elif t == b"symlink":
            expect(b"target")
            out.append((path, "l", False, s().decode("utf-8", "surrogateescape")))
            expect(b")")
        elif t == b"directory":
            out.append((path, "d", False, None))
            while True:
                tok = s()
                if tok == b")":
                    break
                if tok != b"entry":
                    die(f"{what}: bad NAR directory")
                expect(b"(")
                expect(b"name")
                name = s().decode("utf-8", "surrogateescape")
                if name in ("", ".", "..") or "/" in name:
                    die(f"{what}: bad NAR entry name {name!r}")
                expect(b"node")
                node(f"{path}/{name}")
                expect(b")")
        else:
            die(f"{what}: unknown NAR node type {t!r}")

    expect(b"nix-archive-1")
    node(prefix)
    return out


class NixBackend(Backend):
    name = "nix"
    bin_dirs = ()
    lib_dirs = ()

    @staticmethod
    def detect(snap):
        return snap.read("nix/var/nix/db/db.sqlite", binary=True) is not None

    @staticmethod
    def add_args(ap):
        g = ap.add_argument_group("nix (NixOS)")
        g.add_argument("--nix-cache", default="https://cache.nixos.org", help="binary cache URL (or file://)")
        g.add_argument("--nix-trusted-key", action="append", default=[], metavar="NAME:BASE64",
                       help="binary cache signing key you trust (repeatable). Get cache.nixos.org's from the "
                            "NixOS manual / a trusted NixOS install, cross-checked out of band")
        g.add_argument("--nix-path", action="append", default=[], help="extra store path to verify (repeatable)")

    def read_db(self):
        tmp = tempfile.mkdtemp(prefix="nixdb-", dir=self.workdir)
        for suf in ("", "-wal", "-shm"):
            data = self.snap.read(f"nix/var/nix/db/db.sqlite{suf}", binary=True)
            if data is not None:
                with open(os.path.join(tmp, f"db.sqlite{suf}"), "wb") as f:
                    f.write(data)
        con = sqlite3.connect(os.path.join(tmp, "db.sqlite"))
        rows = con.execute("SELECT id, path, hash, narSize FROM ValidPaths").fetchall()
        refs = con.execute("SELECT referrer, reference FROM Refs").fetchall()
        con.close()
        self.paths = {p: {"id": i, "hash": h, "narSize": n} for i, p, h, n in rows}
        byid = {i: p for i, p, h, n in rows}
        self.refs = {}
        for a, b in refs:
            if a in byid and b in byid:
                self.refs.setdefault(byid[a], set()).add(byid[b])
        R.info(f"nix db: {len(self.paths)} valid store paths")

    def closure(self, roots):
        seen, stack = set(), list(roots)
        while stack:
            p = stack.pop()
            if p in seen:
                continue
            seen.add(p)
            stack.extend(self.refs.get(p, ()))
        return seen

    def collect_verified(self):
        a = self.args
        if not a.nix_trusted_key:
            die("pin the binary cache key with --nix-trusted-key NAME:BASE64 (e.g. cache.nixos.org-1:..., from a "
                "source you trust; never from the target's nix.conf)")
        self.keys = {}
        for k in a.nix_trusted_key:
            name, _, b64 = k.partition(":")
            raw = base64.b64decode(b64)
            if len(raw) != 32:
                die(f"--nix-trusted-key {name}: not a 32-byte ed25519 public key")
            self.keys[name] = raw
        self.read_db()
        cur = self.snap.lstat("run/current-system")
        system = cur.link if cur is not None and cur.link else None
        nix_paths = [p for p in self.paths if re.match(r"^/nix/store/[a-z0-9]{32}-nix-\d", p)]
        if system and system in self.paths:
            sysc = self.closure([system])
            nix_paths = [p for p in nix_paths if p in sysc] or nix_paths
            R.info(f"current system: {system}")
        roots = set(nix_paths) | set(a.nix_path)
        if not roots:
            die("no nix store path found in the db; pass --nix-path")
        core = sorted(self.closure(roots))
        out(f"\nVerified set: {len(core)} store paths (closure of {', '.join(sorted(os.path.basename(r) for r in roots))})")
        need = [p for p in core if self.snap.lstat(p.lstrip("/")) is None]
        if need:
            hl = os.path.join(self.args.out or ".", "need-hashes.txt")
            with open(hl, "w") as f:
                f.write("\n".join(need) + "\n")
            die(f"the snapshot does not include {len(need)} store paths. Copy {hl} to the box and run:\n"
                f"  bin/busybox sh collect.sh --hash-list need-hashes.txt\nthen plan again with the new snapshot.")
        step(f"Fetching signed narinfo files from {a.nix_cache}")
        vpkgs = []
        for p in core:
            vpkgs.append(self.verify_path(p))
        R.info(f"{len(vpkgs)} store paths verified against signed narinfo files")
        self.vpkgs = vpkgs
        return vpkgs

    def verify_sig(self, fingerprint, sigs, what):
        for sig in sigs:
            name, _, b64 = sig.partition(":")
            if name not in self.keys:
                continue
            raw = base64.b64decode(b64)
            d = tempfile.mkdtemp(prefix="ed25519-", dir=self.workdir)
            der = bytes.fromhex("302a300506032b6570032100") + self.keys[name]
            for fn, data in (("pub.der", der), ("msg", fingerprint.encode()), ("sig", raw)):
                with open(os.path.join(d, fn), "wb") as f:
                    f.write(data)
            p = subprocess.run(["openssl", "pkeyutl", "-verify", "-pubin", "-inkey", f"{d}/pub.der", "-keyform", "DER",
                                "-rawin", "-in", f"{d}/msg", "-sigfile", f"{d}/sig"],
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            if p.returncode == 0 and "Signature Verified Successfully" in p.stdout:
                return name
            die(f"{what}: signature by {name} does NOT verify")
        die(f"{what}: no signature by a pinned key (signed by: {', '.join(s.split(':')[0] for s in sigs) or 'nobody'})")

    def verify_path(self, path):
        m = STORE_RE.match(path)
        if not m:
            die(f"not a store path: {path}")
        hp = m.group(1)
        raw = net.fetch(net.join(self.args.nix_cache, f"{hp}.narinfo"), 1024 * 1024)
        info, sigs = {}, []
        for ln in raw.decode("utf-8").splitlines():
            k, _, v = ln.partition(": ")
            if k == "Sig":
                sigs.append(v)
            elif k:
                info[k] = v
        if info.get("StorePath") != path:
            die(f"{hp}.narinfo is for {info.get('StorePath')}, not {path}")
        refs = sorted(f"/nix/store/{r}" for r in info.get("References", "").split())
        fp = f"1;{path};{info['NarHash']};{info['NarSize']};{','.join(refs)}"
        signer = self.verify_sig(fp, sigs, f"{hp}.narinfo")
        narhex = norm_hash(info["NarHash"])
        dbhash = self.paths.get(path, {}).get("hash")
        if dbhash and norm_hash(dbhash) != narhex:
            R.crit(f"nix db records a different NAR hash for {path} than the signed narinfo "
                   f"(db tampered to hide modified store contents)")
        url = info["URL"]
        if url.startswith("/") or ".." in url.split("/"):
            die(f"{hp}.narinfo: suspicious URL {url}")
        blob = net.fetch(net.join(self.args.nix_cache, url), int(info.get("FileSize", 0) or 2 ** 31),
                         what=os.path.basename(url))
        if "FileHash" in info and hashlib.sha256(blob).hexdigest() != norm_hash(info["FileHash"]):
            die(f"{url}: FileHash does not match the signed narinfo")
        nar = sniff_decompress(blob) if info.get("Compression", "none") != "none" else blob
        if hashlib.sha256(nar).hexdigest() != narhex or len(nar) != int(info["NarSize"]):
            die(f"{url}: NAR does not match the signed NarHash/NarSize")
        vp = VPkg(os.path.basename(path), info["NarHash"], "nix")
        vp.installed_version = info["NarHash"]
        vp.exact = True
        vp.meta["signer"] = signer
        for rel, kind, exe, payload in parse_nar(nar, path.lstrip("/"), url):
            if kind == "f":
                vp.add(VFile(rel, "f", 0o555 if exe else 0o444, 0, 0, sha256=self.payload.put(payload),
                             size=len(payload)))
            elif kind == "l":
                vp.add(VFile(rel, "l", 0o777, 0, 0, link=payload))
            else:
                vp.add(VFile(rel, "d", 0o555, 0, 0))
        return vp

    def db_owned(self):
        return set()

    def runtime_dir_perm(self, rel):
        return False

    def post_compare(self, plan, vpkgs):
        plan.finalize_pkgs = []          # no database repair: store paths keep their db entries

    def injection_points(self, plan, vpkgs):
        snap = self.snap
        trusted = set(self.keys)
        confs = ["etc/nix/nix.conf", "etc/nix/nix.custom.conf", "root/.config/nix/nix.conf"]
        for rel in confs:
            txt = snap.read(rel)
            if txt is None:
                continue
            for ln in txt.splitlines():
                s = ln.split("#", 1)[0].strip()
                if not s:
                    continue
                if s.startswith(("include ", "!include ")):
                    R.warn(f"/{rel}: {s} pulls in more nix settings; review that file")
                    continue
                k, _, v = s.partition("=")
                k, v = k.strip(), v.strip()
                base = k[6:] if k.startswith("extra-") else k
                if base == "require-sigs" and v == "false":
                    R.crit(f"/{rel}: require-sigs = false lets any substituter serve unsigned store paths")
                elif base == "trusted-public-keys":
                    extra = [x for x in v.split() if x.split(":")[0] not in trusted]
                    if extra:
                        R.crit(f"/{rel}: {k} trusts keys you did not pin: {' '.join(extra)[:160]}")
                elif base in ("post-build-hook", "plugin-files", "pre-build-hook", "diff-hook"):
                    R.crit(f"/{rel}: {k} = {v[:120]} runs code inside nix/nix-daemon")
                elif base == "allow-unsafe-native-code-during-evaluation" and v == "true":
                    R.crit(f"/{rel}: {k} = true")
                elif base == "substituters":
                    other = [x for x in v.split() if x.rstrip("/") != "https://cache.nixos.org"]
                    if other:
                        R.warn(f"/{rel}: {k} adds substituters: {' '.join(other)[:160]}")
                elif base == "trusted-users":
                    other = [x for x in v.split() if x not in ("root", "@wheel")]
                    if other or "@wheel" in v.split():
                        R.warn(f"/{rel}: trusted-users = {v} (these users can import unsigned store paths)")
                elif base == "sandbox" and v == "false":
                    R.warn(f"/{rel}: sandbox = false")
                elif base in ("extra-sandbox-paths", "sandbox-paths", "builders", "netrc-file"):
                    R.warn(f"/{rel}: {k} = {v[:120]}")
        for rel in ("etc/environment", "etc/profile", "root/.profile", "root/.bashrc"):
            txt = snap.read(rel) or ""
            if re.search(r"\bNIX_CONFIG\b|\bNIX_REMOTE\b", txt):
                R.crit(f"/{rel} sets NIX_CONFIG/NIX_REMOTE (overrides nix.conf for every nix run)")
        for n in snap.listdir("etc/nixos"):
            if n.endswith(".nix"):
                R.info(f"/etc/nixos/{n}: review nix.settings, substituters, overlays and "
                       f"systemd.services.nix-daemon before the next nixos-rebuild")

    def finalize_script(self, plan):
        # The store is mounted read-only on NixOS: remount it for the repair only.
        return """# nix: no package-database repair; store files are replaced directly
pm_needs_finalize() { return 1; }
pm_finalize() { :; }
pm_prepare() {
    if "$BB" grep -q ' /nix/store [^ ]* ro[, ]' /proc/mounts 2>/dev/null; then
        "$BB" mount -o remount,rw,bind /nix/store && { log "  remounted /nix/store read-write for the repair"; NIX_RO=1; }
    fi
}
pm_cleanup() {
    if [ "${NIX_RO:-0}" = 1 ]; then "$BB" mount -o remount,ro,bind /nix/store && log "  /nix/store read-only again"; fi
}
"""
