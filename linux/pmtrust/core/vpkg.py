"""Uniform model of a VERIFIED package, independent of the package format.

Backends turn a downloaded, hash- and signature-checked package into a VPkg.
The core compares VPkg files with the snapshot and plans the repair from them,
so backends never deal with the target's disk layout.
"""
import hashlib
import os


class VFile:
    __slots__ = ("path", "kind", "mode", "uid", "gid", "sha256", "size", "link", "conffile", "pkg")

    def __init__(self, path, kind, mode, uid, gid, sha256=None, size=0, link=None, conffile=False, pkg=None):
        self.path, self.kind, self.mode, self.uid, self.gid = path, kind, mode, uid, gid
        self.sha256, self.size, self.link, self.conffile, self.pkg = sha256, size, link, conffile, pkg


class VPkg:
    def __init__(self, name, version, arch, blob_path=None, dbkey=None):
        self.name, self.version, self.arch = name, version, arch
        self.blob_path = blob_path          # verified package file, shipped for finalize
        self.extra_blobs = []               # e.g. detached signatures
        self.dbkey = dbkey or name
        self.files = []                     # list[VFile]
        self.scripts = {}                   # name -> bytes (maintainer scripts / scriptlets)
        self.conffiles = set()
        self.meta = {}
        self.installed_version = None       # version on the target, if any
        self.exact = False                  # verified version == installed version

    def add(self, vf):
        vf.pkg = self.name
        self.files.append(vf)


class Payload:
    """Content-addressed store of verified file contents (payload/<aa>/<sha256>)."""

    def __init__(self, root):
        self.root = root
        os.makedirs(root, exist_ok=True)
        self.count = 0
        self.bytes = 0

    def put(self, data):
        h = hashlib.sha256(data).hexdigest()
        p = os.path.join(self.root, h[:2], h)
        if not os.path.exists(p):
            os.makedirs(os.path.dirname(p), exist_ok=True)
            with open(p + ".tmp", "wb") as f:
                f.write(data)
            os.replace(p + ".tmp", p)
            self.count += 1
            self.bytes += len(data)
        return h

    def has(self, h):
        return os.path.exists(os.path.join(self.root, h[:2], h))

    def get(self, h):
        with open(os.path.join(self.root, h[:2], h), "rb") as f:
            return f.read()
