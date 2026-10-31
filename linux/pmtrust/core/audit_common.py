"""Checks that apply to every Linux package manager: things a reinstall alone
would not fix. Everything works on the snapshot; nothing runs on the box.

Only /etc/ld.so.preload is changed by --apply (quarantined), because it
injects code into the package manager itself. Everything else is report-only
and needs a human decision.
"""
import re

from .report import R

SHADOW_BIN_DIRS = ("usr/local/sbin", "usr/local/bin", "root/bin", "root/.local/bin")
ENV_FILES = ("etc/environment", "etc/profile", "etc/bash.bashrc", "etc/bashrc", "etc/security/pam_env.conf",
             "root/.bashrc", "root/.profile", "root/.bash_profile", "root/.zshrc", "etc/sudoers",
             "etc/zsh/zshenv", "etc/zshenv")


def run(snap, vpkgs, plan, backend, db_owned):
    """db_owned: set of paths (no leading slash) the target's own package db
    claims. It is attacker-writable, so the unowned scan is labelled weak."""
    verified = {}
    for vp in vpkgs:
        for vf in vp.files:
            verified[vf.path] = vf
    ver_phys = {plan.phys(p) for p in verified}

    # Library preloading subverts every dynamically linked process, including
    # the package manager that finalize is about to run.
    pre = snap.read("etc/ld.so.preload")
    if pre and any(ln.strip() and not ln.lstrip().startswith("#") for ln in pre.splitlines()):
        libs = [ln.strip() for ln in pre.splitlines() if ln.strip() and not ln.lstrip().startswith("#")]
        R.crit(f"/etc/ld.so.preload is active ({', '.join(libs)[:200]}): it injects libraries into every "
               f"process, including the package manager. --apply quarantines it.")
        plan.quarantine("etc/ld.so.preload", "library preload")
        for lib in libs:
            if snap.exists(lib.lstrip("/")):
                R.crit(f"preloaded library {lib} exists on the target; it is quarantined with the preload file")
                plan.quarantine(lib.lstrip("/"), "preloaded library")
    elif snap.lstat("etc/ld.so.preload") and not pre:
        R.warn("/etc/ld.so.preload exists but could not be read from the snapshot")

    # Binaries earlier in root's PATH than the verified ones.
    bin_names = {}
    for p in verified:
        d, _, n = p.rpartition("/")
        if d in backend.bin_dirs and verified[p].kind in "fl":
            bin_names[n] = p
    for d in SHADOW_BIN_DIRS:
        for n in snap.listdir(d):
            if n in bin_names and plan.phys(f"{d}/{n}") not in ver_phys:
                R.crit(f"/{d}/{n} shadows the verified /{bin_names[n]} earlier in PATH. Not touched; "
                       f"inspect and remove it.")

    # Libraries that the dynamic loader could find before the verified ones.
    lib_names = {p.rpartition("/")[2] for p in verified if re.search(r"\.so(\.|$)", p)}
    ver_lib_dirs = {plan.phys(p).rpartition("/")[0] for p in verified if re.search(r"\.so(\.|$)", p)}
    search = {"usr/local/lib", "usr/local/lib64"}
    conf = ["etc/ld.so.conf"] + [f"etc/ld.so.conf.d/{n}" for n in snap.listdir("etc/ld.so.conf.d")]
    for rel in conf:
        for ln in (snap.read(rel) or "").splitlines():
            ln = ln.split("#", 1)[0].strip()
            if not ln or ln.startswith("include"):
                continue
            hp = snap.resolve(ln.lstrip("/"))
            if hp not in ver_lib_dirs and not ln.startswith("/usr/local") and not backend.known_lib_dir(hp):
                R.warn(f"/{rel} adds library search directory {ln}")
            search.add(hp)
    for top in sorted(search):
        if top in ver_lib_dirs:
            continue
        prefix = top + "/"
        for path, e in snap.entries.items():
            if e.kind == "f" and path.startswith(prefix) and path.count("/") - top.count("/") <= 3:
                if path.rpartition("/")[2] in lib_names and path not in ver_phys:
                    R.crit(f"/{path} has the name of a verified library but lives in a loader search "
                           f"directory outside the verified location; the loader may pick it first. Not touched.")

    # Environment-based injection (report only).
    env_files = list(ENV_FILES)
    env_files += [f"etc/profile.d/{n}" for n in snap.listdir("etc/profile.d")]
    env_files += [f"etc/sudoers.d/{n}" for n in snap.listdir("etc/sudoers.d")]
    for rel in env_files:
        txt = snap.read(rel)
        if txt and re.search(r"\bLD_(PRELOAD|LIBRARY_PATH|AUDIT)\b", txt):
            R.crit(f"/{rel} sets or preserves LD_PRELOAD/LD_LIBRARY_PATH/LD_AUDIT. Not touched.")

    # Files in binary and library directories that no package claims. The
    # package database is on the attacker's disk, so this finds leftovers and
    # sloppy implants, not careful ones.
    owned = {snap.resolve_parent(p) for p in db_owned} | ver_phys
    scan_dirs = set(backend.bin_dirs) | set(backend.lib_dirs)
    seen = set()
    unowned = []
    for d in sorted(scan_dirs):
        hd = snap.resolve(d)
        if hd in seen or snap.entries.get(hd) is None:
            continue
        seen.add(hd)
        for n in snap.listdir(hd):
            p = f"{hd}/{n}"
            e = snap.entries.get(p)
            if e is None or e.kind != "f" or p in owned:
                continue
            if d in backend.lib_dirs and ".so" not in n:
                continue
            unowned.append((p, e))
    for p, e in unowned:
        extra = " (SETUID/SETGID)" if e.mode & 0o6000 else ""
        R.warn(f"/{p} is not owned by any package{extra}; leftover implant or locally built file. "
               f"Inspect (weak check: the owner lists are on the target's disk).")

    # Setuid/setgid files nobody owns, anywhere in the scanned roots.
    for p, e in snap.entries.items():
        if e.kind == "f" and e.mode & 0o6000 and p not in owned and p not in {u[0] for u in unowned}:
            if p.startswith(("usr/", "bin/", "sbin/", "lib", "opt/", "root/", "etc/")):
                R.warn(f"/{p} is setuid/setgid ({e.mode:o}) and not owned by any package. Inspect.")

    # World-writable files in binary directories.
    for d in sorted(seen):
        for n in snap.listdir(d):
            e = snap.entries.get(f"{d}/{n}")
            if e is not None and e.kind == "f" and e.mode & 0o002:
                R.crit(f"/{d}/{n} is world-writable; anyone can replace a program root runs")
