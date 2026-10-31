"""Format helpers shared by backends: decompression, ar/tar/cpio readers, hashing.

Everything here parses untrusted bytes in-process. Nothing shells out to the
target; the only external fallback is the HOST's zstd binary for Python < 3.14.
"""
import bz2
import gzip
import hashlib
import io
import lzma
import os
import shutil
import subprocess
import tarfile

from .report import die


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def check_hash(data, expect_hex, what, algo="sha256", size=None):
    if size is not None and len(data) != size:
        die(f"{what}: size {len(data)} does not match signed size {size}")
    h = hashlib.new(algo, data).hexdigest()
    if h != expect_hex.lower():
        die(f"{what}: {algo} does not match the signed value")


def zstd_decompress(blob):
    try:
        from compression import zstd  # Python 3.14+
        return zstd.decompress(blob)
    except ImportError:
        pass
    try:
        import zstandard  # python3-zstandard on the staging host
        return zstandard.ZstdDecompressor().decompressobj().decompress(blob)
    except ImportError:
        pass
    exe = shutil.which("zstd")
    if not exe:
        die("reading zstd data needs Python 3.14+, python3-zstandard, or the zstd binary on the staging host")
    return subprocess.run([exe, "-dc"], input=blob, stdout=subprocess.PIPE, check=True).stdout


def sniff_decompress(blob, what="data"):
    """Decompress by magic bytes (names on untrusted data can lie)."""
    if blob[:6] == b"\xfd7zXZ\x00":
        return lzma.decompress(blob)
    if blob[:2] == b"\x1f\x8b":
        return gzip.decompress(blob)
    if blob[:3] == b"BZh":
        return bz2.decompress(blob)
    if blob[:4] == b"\x28\xb5\x2f\xfd":
        return zstd_decompress(blob)
    if blob[:1] == b"\x5d" and len(blob) > 13:  # legacy lzma_alone
        try:
            return lzma.decompress(blob, format=lzma.FORMAT_ALONE)
        except lzma.LZMAError:
            pass
    return blob


def norm_rel(path, what="path"):
    """Normalize an archive member path to a relative path without '.' parts.
    Rejects '..' so nothing can point outside the target root."""
    parts = [p for p in path.split("/") if p not in ("", ".")]
    if ".." in parts:
        die(f"{what}: path traversal in member {path!r}")
    return "/".join(parts)


def read_ar(blob, what):
    if not blob.startswith(b"!<arch>\n"):
        die(f"{what}: not an ar archive")
    off, members = 8, []
    while off < len(blob):
        hdr = blob[off:off + 60]
        if len(hdr) < 60 or hdr[58:60] != b"`\n":
            die(f"{what}: corrupt ar header")
        name = hdr[:16].decode("ascii").strip().rstrip("/")
        size = int(hdr[48:58].decode("ascii").strip())
        body = blob[off + 60:off + 60 + size]
        if len(body) != size:
            die(f"{what}: truncated member {name}")
        members.append((name, body))
        off += 60 + size + (size & 1)
    return members


class Member:
    """Uniform archive member: kind f(ile) d(ir) l(ink) h(ardlink) o(ther)."""
    __slots__ = ("path", "kind", "mode", "uid", "gid", "data", "link", "uname", "gname")

    def __init__(self, path, kind, mode, uid=0, gid=0, data=None, link=None, uname=None, gname=None):
        self.path, self.kind, self.mode = path, kind, mode
        self.uid, self.gid, self.data, self.link = uid, gid, data, link
        self.uname, self.gname = uname, gname


def read_tar(raw, what):
    out = []
    with tarfile.open(fileobj=io.BytesIO(raw), mode="r:") as tf:
        for ti in tf.getmembers():
            rel = norm_rel(ti.name, what)
            if not rel:
                continue
            if ti.isfile():
                fobj = tf.extractfile(ti)
                out.append(Member(rel, "f", ti.mode & 0o7777, ti.uid, ti.gid, fobj.read() if fobj else b"",
                                  uname=ti.uname, gname=ti.gname))
            elif ti.islnk():
                out.append(Member(rel, "h", ti.mode & 0o7777, ti.uid, ti.gid, None,
                                  link=norm_rel(ti.linkname, what), uname=ti.uname, gname=ti.gname))
            elif ti.issym():
                out.append(Member(rel, "l", 0o777, ti.uid, ti.gid, None, link=ti.linkname,
                                  uname=ti.uname, gname=ti.gname))
            elif ti.isdir():
                out.append(Member(rel, "d", ti.mode & 0o7777, ti.uid, ti.gid, uname=ti.uname, gname=ti.gname))
            else:
                out.append(Member(rel, "o", ti.mode & 0o7777, ti.uid, ti.gid))
    # Resolve hard links to the content of their target (same verified bytes).
    by_path = {m.path: m for m in out if m.kind == "f"}
    for m in out:
        if m.kind == "h":
            tgt = by_path.get(m.link)
            if tgt is None:
                die(f"{what}: hard link {m.path} -> {m.link} has no target")
            m.kind, m.data = "f", tgt.data
    return out


def read_cpio(raw, what):
    """newc / crc cpio (070701/070702), and rpm's stripped variant (07070X) by index."""
    out, off = [], 0
    while off + 6 <= len(raw):
        magic = raw[off:off + 6]
        if magic in (b"070701", b"070702"):
            h = raw[off:off + 110]
            if len(h) < 110:
                die(f"{what}: truncated cpio header")
            f = [int(h[6 + 8 * i:14 + 8 * i], 16) for i in range(13)]
            mode, uid, gid, nlink, mtime, size = f[1], f[2], f[3], f[4], f[5], f[6]
            namesize = f[11]
            name = raw[off + 110:off + 110 + namesize - 1].decode("utf-8", "surrogateescape")
            off = (off + 110 + namesize + 3) & ~3
            data = raw[off:off + size]
            off = (off + size + 3) & ~3
            if name == "TRAILER!!!":
                break
            out.append((name, mode, uid, gid, data, nlink, None))
        elif magic == b"07070X":
            h = raw[off:off + 14]
            idx = int(h[6:14], 16)
            off = (off + 14 + 3) & ~3
            out.append((None, None, None, None, None, None, idx))
            # stripped entries carry no size; caller must supply sizes from the header
            return out, off
        else:
            die(f"{what}: bad cpio magic at offset {off}")
    return out, off


def dearmor(data):
    """ASCII-armored OpenPGP -> binary packets (for gpgv --keyring)."""
    import base64
    text = data.decode("ascii", "replace")
    if "-----BEGIN PGP" not in text:
        return data
    blobs = []
    for block in text.split("-----BEGIN PGP")[1:]:
        body = block.split("\n\n", 1)[1] if "\n\n" in block else block.split("\r\n\r\n", 1)[1]
        body = body.split("-----END PGP", 1)[0]
        lines = [ln.strip() for ln in body.splitlines() if ln.strip() and not ln.startswith("=")]
        blobs.append(base64.b64decode("".join(lines)))
    return b"".join(blobs)


def write_file(path, data, mode=0o644):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as f:
        f.write(data)
    os.chmod(path, mode)
