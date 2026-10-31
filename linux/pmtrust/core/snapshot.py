"""The target as data: a snapshot taken on the box by agent/collect.sh.

All paths are relative to the target root without a leading slash ("usr/bin/ls").
Symlinks are resolved as if chrooted, so an absolute link on the target never
points the audit at the staging host.
"""
import gzip
import os
import stat
import tarfile

from .report import die, R
from .util import read_cpio

S_FMT = {stat.S_IFREG: "f", stat.S_IFDIR: "d", stat.S_IFLNK: "l"}


class Entry:
    __slots__ = ("kind", "mode", "uid", "gid", "size", "sha256", "link")

    def __init__(self, kind, mode, uid, gid, size):
        self.kind, self.mode, self.uid, self.gid, self.size = kind, mode, uid, gid, size
        self.sha256 = None
        self.link = None

    def __repr__(self):
        return f"<{self.kind} {oct(self.mode)} {self.uid}:{self.gid} {self.sha256 or self.link or ''}>"


def _rel(p):
    return p.lstrip("/")


class Snapshot:
    def __init__(self, tarpath, workdir):
        self.path = tarpath
        dest = os.path.join(workdir, "snapshot")
        os.makedirs(dest, exist_ok=True)
        try:
            with tarfile.open(tarpath, "r:gz") as tf:
                tf.extractall(dest, filter="data")
        except (tarfile.TarError, OSError) as e:
            die(f"cannot read snapshot {tarpath}: {e}")
        subs = [d for d in os.listdir(dest) if d.startswith("snap-")]
        if len(subs) != 1:
            die(f"{tarpath}: expected one snap-* directory, found {subs}")
        self.dir = os.path.join(dest, subs[0])
        self.meta = self._kv("meta.txt")
        self.os = self.meta.get("os", "Linux")
        self.host = self.meta.get("hostname", "unknown")
        self.entries = {}
        self.children = {}
        self.files = {}
        self.weird = []
        self._load_fs()
        self.files = self._load_cpio("files.cpio.gz")
        self.deref = self._load_cpio("deref.cpio.gz")    # symlinked configs, content of their target
        self.mounts = self._text("mounts.txt") or ""
        self.roots = [r.strip("/") for r in self.meta.get("roots", "").split() if r.strip("/")]
        self.loops = self._text("loops.txt") or ""

    # -- loading ---------------------------------------------------------
    def _text(self, name):
        p = os.path.join(self.dir, name)
        if not os.path.exists(p):
            return None
        with open(p, "rb") as f:
            return f.read().decode("utf-8", "surrogateescape")

    def _kv(self, name):
        out = {}
        for line in (self._text(name) or "").splitlines():
            if "=" in line:
                k, v = line.split("=", 1)
                out[k.strip()] = v.strip()
        return out

    def _load_cpio(self, name):
        p = os.path.join(self.dir, name)
        if not os.path.exists(p):
            return {}
        with open(p, "rb") as f:
            raw = gzip.decompress(f.read())
        files = {}
        entries, _ = read_cpio(raw, name)
        for nm, mode, uid, gid, data, nlink, idx in entries:
            if nm is None:
                break
            if stat.S_ISREG(mode):
                files[_rel(nm)] = data
        return files

    def _load_fs(self):
        for line in (self._text("fs.txt") or "").splitlines():
            parts = line.split(" ", 4)
            if len(parts) != 5 or not parts[4].startswith("/"):
                continue
            try:
                raw_mode = int(parts[0], 16)
                uid, gid, size = int(parts[1]), int(parts[2]), int(parts[3])
            except ValueError:
                continue
            kind = S_FMT.get(stat.S_IFMT(raw_mode), "o")
            rel = _rel(parts[4])
            if not rel:
                continue
            self.entries[rel] = Entry(kind, raw_mode & 0o7777, uid, gid, size)
        for line in (self._text("links.txt") or "").splitlines():
            if "\t" in line:                       # FreeBSD: path<TAB>target
                p, t = line.split("\t", 1)
            elif line.startswith("'") and "' -> '" in line and line.endswith("'"):
                p, t = line[1:-1].split("' -> '", 1)   # busybox %N
            else:
                continue
            e = self.entries.get(_rel(p))
            if e is not None and e.kind == "l":
                e.link = t
        for line in (self._text("sha256.txt") or "").splitlines():
            if len(line) < 66:
                continue
            h, p = line[:64], line[64:].lstrip(" ")
            if p.startswith("*"):
                p = p[1:]
            e = self.entries.get(_rel(p))
            if e is not None and e.kind == "f":
                e.sha256 = h.lower()
        weird = os.path.join(self.dir, "weird.bin")
        if os.path.exists(weird):
            with open(weird, "rb") as f:
                self.weird = [w.decode("utf-8", "replace") for w in f.read().split(b"\0") if w]
        for rel in self.entries:
            parent, _, name = rel.rpartition("/")
            self.children.setdefault(parent, set()).add(name)
        if not self.entries:
            die(f"{self.path}: snapshot has no file listing")

    # -- queries ---------------------------------------------------------
    def covered(self, rel):
        """True if the collector walked the directory that would contain rel.
        Paths outside its roots (/proc, /var/log, /home ...) are unknown, not missing."""
        rel = _rel(rel)
        return any(rel == r or rel.startswith(r + "/") for r in self.roots)

    def lstat(self, rel):
        return self.entries.get(_rel(rel))

    def resolve(self, rel, follow_last=True):
        """Resolve rel inside the target root, as if chrooted."""
        queue = [p for p in _rel(rel).split("/") if p not in ("", ".")]
        cur, hops = [], 0
        while queue:
            part = queue.pop(0)
            if part == "..":
                if cur:
                    cur.pop()
                continue
            if not queue and not follow_last:
                cur.append(part)
                break
            e = self.entries.get("/".join(cur + [part]))
            if e is not None and e.kind == "l" and e.link is not None:
                hops += 1
                if hops > 40:
                    return "/".join(cur + [part] + queue)
                if e.link.startswith("/"):
                    cur = []
                queue = [p for p in e.link.split("/") if p not in ("", ".")] + queue
                continue
            cur.append(part)
        return "/".join(cur)

    def resolve_parent(self, rel):
        """Physical path of rel with every parent component resolved, last kept."""
        rel = _rel(rel)
        parent, _, name = rel.rpartition("/")
        rp = self.resolve(parent, follow_last=True) if parent else ""
        return f"{rp}/{name}" if rp else name

    def stat(self, rel):
        return self.entries.get(self.resolve(rel))

    def exists(self, rel):
        return self.resolve_parent(rel) in self.entries

    def read(self, rel, binary=False):
        data = self.files.get(self.resolve(rel))
        if data is None:
            data = self.deref.get(_rel(rel))
        if data is None:
            return None
        return data if binary else data.decode("utf-8", "replace")

    def listdir(self, rel):
        return sorted(self.children.get(self.resolve(rel), ()))

    def sha256(self, rel):
        e = self.stat(rel)
        return e.sha256 if e is not None and e.kind == "f" else None

    def os_release(self):
        txt = self.read("etc/os-release") or self.read("usr/lib/os-release") or ""
        out = {}
        for line in txt.splitlines():
            if "=" in line and not line.startswith("#"):
                k, v = line.split("=", 1)
                out[k.strip()] = v.strip().strip('"')
        return out

    def sanity(self):
        if self.weird:
            for w in self.weird[:20]:
                R.warn(f"file name containing a newline: {w!r} (suspicious; inspect manually)")
        try:
            uid = self.meta.get("uname", "")
        except Exception:
            uid = ""
        hashed = sum(1 for e in self.entries.values() if e.kind == "f" and e.sha256)
        files = sum(1 for e in self.entries.values() if e.kind == "f")
        R.info(f"snapshot {os.path.basename(self.path)}: host {self.host}, taken {self.meta.get('date_utc')}, "
               f"{len(self.entries)} entries, {hashed}/{files} files hashed, {len(self.files)} files copied")
        return uid
