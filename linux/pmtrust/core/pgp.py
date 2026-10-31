"""OpenPGP verification with the STAGING host's gpgv against a user-supplied
keyring and pinned fingerprints. Only gpgv's status output and its --output
(the verified bytes) are trusted; the input file itself is never parsed for
content after verification.
"""
import os
import re
import shutil
import subprocess
import tempfile

from .report import die, R
from .util import dearmor

WEAK_HASH_ALGOS = {1: "MD5", 2: "SHA1", 3: "RIPEMD160"}


class Trust:
    def __init__(self, keyring, expect_fpr, trust_any, workdir, gpgv=None, label="keyring"):
        self.gpgv = gpgv or shutil.which("gpgv")
        if not self.gpgv:
            die("gpgv not found on the staging host")
        if not keyring:
            die(f"--{label} is required (an archive keyring obtained out of band, not from the target)")
        keyring = os.path.realpath(keyring)
        if not os.path.isfile(keyring):
            die(f"{label} {keyring} not found")
        with open(keyring, "rb") as f:
            raw = f.read()
        self.keyring = os.path.join(workdir, f"{label}.gpg")
        with open(self.keyring, "wb") as f:
            f.write(dearmor(raw))
        self.expect = {re.sub(r"\s", "", x).upper() for x in (expect_fpr or [])}
        for x in self.expect:
            if not re.fullmatch(r"[0-9A-F]{40}|[0-9A-F]{64}", x):
                die(f"--expect-fpr {x} is not a full v4/v5 fingerprint")
        if not self.expect and not trust_any:
            die("pin the signing keys with --expect-fpr (cross-check them through a second channel), "
                "or pass --trust-keyring to accept any key in the keyring")
        self.workdir = workdir

    def _run(self, args, tag):
        home = tempfile.mkdtemp(prefix="gnupghome-", dir=self.workdir)
        proc = subprocess.run([self.gpgv, "--homedir", home, "--keyring", self.keyring,
                               "--status-fd", "1"] + args,
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                              env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"})
        shutil.rmtree(home, ignore_errors=True)
        good, accepted = set(), []
        for line in proc.stdout.splitlines():
            f = line.split()
            if len(f) < 3 or f[0] != "[GNUPG:]":
                continue
            kw = f[1]
            if kw in ("BADSIG", "REVKEYSIG"):
                die(f"{tag}: gpgv reported {kw} for key {f[2]}; not trustworthy")
            if kw == "GOODSIG":
                good.add(f[2].upper()[-16:])
            elif kw == "VALIDSIG" and len(f) >= 11:
                fpr = f[2].upper()
                primary = f[11].upper() if len(f) > 11 else fpr
                if fpr[-16:] not in good:
                    R.warn(f"{tag}: ignoring signature by {fpr} (expired or revoked key)")
                    continue
                algo = int(f[9])
                if algo in WEAK_HASH_ALGOS:
                    R.warn(f"{tag}: ignoring signature by {primary} that uses {WEAK_HASH_ALGOS[algo]}")
                    continue
                if self.expect and not ({fpr, primary} & self.expect):
                    R.info(f"{tag}: valid signature by {primary} is not pinned; not counted")
                    continue
                accepted.append(primary)
        if not accepted:
            die(f"{tag}: no acceptable signature.\n{proc.stdout}{proc.stderr}")
        return sorted(set(accepted))

    def clearsigned(self, raw, tag):
        """Verify a cleartext-signed file; return the signed text from gpgv --output."""
        check_clearsign_structure(raw, tag)
        d = tempfile.mkdtemp(prefix="clearsign-", dir=self.workdir)
        src, outp = os.path.join(d, "in"), os.path.join(d, "out")
        with open(src, "wb") as f:
            f.write(raw)
        fprs = self._run(["--output", outp, src], tag)
        if not os.path.exists(outp):
            die(f"{tag}: gpgv produced no verified output")
        with open(outp, "rb") as f:
            signed = f.read()
        shutil.rmtree(d, ignore_errors=True)
        R.info(f"{tag}: signature verified ({', '.join(fprs)})")
        return signed

    def detached(self, data, sig, tag, quiet=False):
        d = tempfile.mkdtemp(prefix="detached-", dir=self.workdir)
        dp, sp = os.path.join(d, "data"), os.path.join(d, "data.sig")
        with open(dp, "wb") as f:
            f.write(data)
        with open(sp, "wb") as f:
            f.write(dearmor(sig))
        fprs = self._run([sp, dp], tag)
        shutil.rmtree(d, ignore_errors=True)
        if not quiet:
            R.info(f"{tag}: signature verified ({', '.join(fprs)})")
        return fprs


def check_clearsign_structure(raw, tag):
    try:
        lines = raw.decode("utf-8").splitlines()
    except UnicodeDecodeError:
        die(f"{tag}: not valid UTF-8")
    markers = {"-----BEGIN PGP SIGNED MESSAGE-----": 0,
               "-----BEGIN PGP SIGNATURE-----": 0,
               "-----END PGP SIGNATURE-----": 0}
    for ln in lines:
        if ln in markers:
            markers[ln] += 1
    if not lines or lines[0] != "-----BEGIN PGP SIGNED MESSAGE-----" or \
            any(n != 1 for n in markers.values()):
        die(f"{tag}: not exactly one cleartext-signed block; refusing to parse it")
    tail = [ln for ln in lines[lines.index("-----END PGP SIGNATURE-----") + 1:] if ln.strip()]
    if tail:
        die(f"{tag}: data after the signature block; refusing to parse it")
