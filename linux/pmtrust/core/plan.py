"""Compare verified packages with the snapshot and write the repair plan.

The plan directory is everything the box needs, and it is self-contained:

  apply.sh          generic POSIX applier (run with the bundled busybox)
  bin/busybox       static busybox from the agent directory
  plan.env          backend, host, creation time, snapshot hash
  actions.tsv       ordered actions (Q quarantine, F file, L symlink, D directory, T back up a tree)
  verify.tsv        post-conditions for every verified file (also used by --verify)
  finalize.sh       backend fragment: runs the now-verified package manager to fix its database
  payload/aa/<sha>  verified file contents, content addressed
  pkgs/             verified package files for finalize
  report.txt        the staging-side audit report
  MANIFEST.sha256   checked by apply.sh before it does anything

Actions only change what the snapshot shows as different from the verified
packages, so a plan built from a clean (or already repaired) box is empty.
"""
import hashlib
import os
import shutil
import stat
from datetime import datetime, timezone

from .report import R, die, out
from .snapshot import Entry

UNHASHED_PREFIXES = ("usr/share/doc/", "usr/share/man/", "usr/share/info/", "usr/share/locale/",
                     "usr/share/help/", "usr/share/icons/", "usr/lib/firmware/", "usr/lib/modules/",
                     "lib/modules/", "lib/firmware/", "usr/src/", "boot/")


def _bad_name(p):
    return any(c in p for c in "\t\n\r")


class Plan:
    def __init__(self, snap, outdir, payload, backend, store=None):
        self.snap, self.outdir, self.payload, self.backend = snap, outdir, payload, backend
        self.store = store or payload      # all verified contents; payload = only what the box needs
        self.actions = []
        self.verify = {}
        self.overlay = {}          # physical rel -> Entry | None, the planned post-repair state
        self.quarantined = set()
        self.finalize_pkgs = []    # VPkg objects whose package file finalize must install
        self.finalize_sh = ""
        self.restarts = []
        self.notes = []
        self.stats = {"checked": 0, "problems": 0, "unchecked": 0, "upgrade_pkgs": 0, "outside": 0}
        # Actions run in phases: 0 tree backups, 1 quarantine + db rewrites,
        # 2 directories/files (libc and the package manager first), 3 scripts.
        self.phase = 2
        self._seq = 0

    # -- path handling ----------------------------------------------------
    def _lookup(self, rel):
        if rel in self.overlay:
            return self.overlay[rel]
        return self.snap.entries.get(rel)

    def resolve(self, rel, follow_last=True):
        queue = [p for p in rel.strip("/").split("/") if p not in ("", ".")]
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
            e = self._lookup("/".join(cur + [part]))
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

    def phys(self, rel):
        rel = rel.strip("/")
        parent, _, name = rel.rpartition("/")
        rp = self.resolve(parent) if parent else ""
        return f"{rp}/{name}" if rp else name

    def _old(self, p):
        e = self.snap.entries.get(p)
        if e is None:
            return "-"
        if e.kind == "f":
            return f"f:{e.sha256 or '?'}"
        if e.kind == "l":
            return f"l:{e.link}"
        return e.kind

    def _add(self, *fields):
        if any(_bad_name(str(x)) for x in fields):
            R.crit(f"refusing to plan an action on a path with control characters: {fields[1]!r}")
            return
        op = fields[0]
        phase = 0 if op == "T" else min(self.phase, 1) if op == "Q" else self.phase
        self._seq += 1
        self.actions.append((phase, self._seq, tuple(str(x) for x in fields)))

    # -- actions ----------------------------------------------------------
    def quarantine(self, rel, why, follow_parent=True):
        p = self.phys(rel) if follow_parent else rel.strip("/")
        if p in self.quarantined:
            return
        if self._lookup(p) is None:
            return
        self.quarantined.add(p)
        self.overlay[p] = None
        self._add("Q", "/" + p, self._old(p), why)

    def put_file(self, rel, sha, mode, uid, gid, why):
        p = self.phys(rel)
        if not self.payload.has(sha):
            if not self.store.has(sha):
                die(f"internal: verified content for /{rel} missing")
            self.payload.put(self.store.get(sha))
        self._add("F", "/" + p, sha, f"{mode & 0o7777:o}", uid, gid, self._old(p), why)
        e = Entry("f", mode & 0o7777, uid, gid, 0)
        e.sha256 = sha
        self.overlay[p] = e

    def put_bytes(self, rel, data, mode, uid, gid, why):
        self.put_file(rel, self.payload.put(data), mode, uid, gid, why)

    def put_link(self, rel, target, uid, gid, why):
        p = self.phys(rel)
        self._add("L", "/" + p, target, uid, gid, self._old(p), why)
        e = Entry("l", 0o777, uid, gid, 0)
        e.link = target
        self.overlay[p] = e

    def ensure_dir(self, rel, mode, uid, gid, why):
        p = self.phys(rel)
        self._add("D", "/" + p, f"{mode & 0o7777:o}", uid, gid, self._old(p), why)
        self.overlay[p] = Entry("d", mode & 0o7777, uid, gid, 0)

    def backup_tree(self, rel, why):
        """Back up a file or tree before finalize (apply.sh skips it if absent)."""
        self._add("T", "/" + self.resolve(rel), why)

    def expect(self, rel, kind, value, mode, uid, gid, level, pkg):
        """Post-condition for --verify: level C = critical if wrong, W = warning (conffiles)."""
        p = self.phys(rel)
        if _bad_name(p) or _bad_name(str(value)):
            return
        self.verify[p] = (kind, value, f"{mode & 0o7777:o}", uid, gid, level, pkg)

    def needs_finalize(self, vpkg):
        if vpkg not in self.finalize_pkgs:
            self.finalize_pkgs.append(vpkg)

    # -- comparison -------------------------------------------------------
    def compare_and_plan(self, vpkgs, restore_conffiles=False):
        """Compare every verified file with the snapshot; plan replacements."""
        b = self.backend
        for vp in vpkgs:
            changed = False
            if not vp.exact:
                self.stats["upgrade_pkgs"] += 1
                if vp.installed_version is None:
                    R.info(f"{vp.name} {vp.version} is not installed; finalize will install it")
                else:
                    R.info(f"{vp.name}: installed {vp.installed_version} is not in the signed repositories; "
                           f"its files cannot be compared and are replaced with verified {vp.version}")
            for vf in vp.files:
                if _bad_name(vf.path):
                    R.crit(f"{vp.name}: verified package contains a path with control characters: {vf.path!r}")
                    continue
                r = self._one(vp, vf, restore_conffiles)
                changed = changed or r
            if changed or not vp.exact:
                self.needs_finalize(vp)

    def _one(self, vp, vf, restore_conffiles):
        b = self.backend
        p = self.phys(vf.path)
        e = self._lookup(p)
        exact = vp.exact
        if e is None and not self.snap.covered(p):
            self.stats["outside"] += 1      # not walked by the collector: unknown, not missing
            return False
        if vf.kind == "d":
            if e is None:
                if exact:
                    R.warn(f"directory /{vf.path} ({vp.name}) is missing")
                self.ensure_dir(vf.path, vf.mode, vf.uid, vf.gid, f"{vp.name}: missing directory")
                return True
            if e.kind == "l":
                if b.expected_dir_link(vf.path, e.link):
                    return False
                R.crit(f"/{vf.path} ({vp.name}) is a directory in the verified package but a symlink to "
                       f"{e.link} on the target; files would be written through it")
                self.quarantine(vf.path, "directory replaced by symlink", follow_parent=True)
                self.ensure_dir(vf.path, vf.mode, vf.uid, vf.gid, "restore directory")
                return True
            if e.kind != "d":
                R.crit(f"/{vf.path} ({vp.name}) should be a directory but is a {e.kind}")
                self.quarantine(vf.path, "not a directory")
                self.ensure_dir(vf.path, vf.mode, vf.uid, vf.gid, "restore directory")
                return True
            self.stats["checked"] += 1
            if (e.mode, e.uid) != (vf.mode, vf.uid):
                msg = (f"/{vf.path} ({vp.name}): directory mode/owner {e.mode:o} {e.uid} != packaged "
                       f"{vf.mode:o} {vf.uid}")
                if e.mode & 0o002 and not e.mode & 0o1000:
                    R.crit(msg + " (world-writable without sticky bit)")
                elif e.uid != 0 and vf.uid == 0 and not b.runtime_dir_perm(vf.path):
                    R.crit(msg + " (non-root owner can replace files inside it)")
                elif b.runtime_dir_perm(vf.path):
                    R.info(msg + " (expected: changed at runtime)")
                    return False
                elif not (e.mode & ~vf.mode & 0o7777) and e.uid == vf.uid:
                    R.info(msg + " (tighter than packaged; harmless)")
                    return False
                elif exact:
                    R.warn(msg)
                    return False
                else:
                    return False
                self.stats["problems"] += 1
                self.ensure_dir(vf.path, vf.mode, vf.uid, vf.gid, "dangerous directory permissions")
                return True
            return False

        # files and symlinks
        level = "W" if vf.conffile else "C"
        if vf.kind == "l":
            self.expect(vf.path, "l", vf.link, 0o777, vf.uid, vf.gid, level, vp.name)
        elif vf.kind == "f":
            self.expect(vf.path, "f", vf.sha256, vf.mode, vf.uid, vf.gid, level, vp.name)
        if b.skip_compare(vp, vf):
            return False
        problem = None
        if e is None:
            if vf.conffile:
                return False        # deleted conffiles are a legitimate admin choice
            problem = "missing"
        elif vf.kind == "l":
            if e.kind != "l" or e.link != vf.link:
                problem = f"symlink differs (expected -> {vf.link})"
        elif vf.kind == "f":
            if e.kind != "f":
                problem = f"is a {e.kind}, not a regular file"
            elif e.sha256 is None:
                self.stats["unchecked"] += 1
                if not exact and not vf.path.startswith(UNHASHED_PREFIXES):
                    problem = "not hashed in the snapshot"
                else:
                    return False
            elif e.sha256 != vf.sha256:
                problem = "content differs"
            elif (e.mode, e.uid, e.gid) != (vf.mode, vf.uid, vf.gid):
                problem = (f"mode/owner {e.mode:o} {e.uid}:{e.gid} != packaged "
                           f"{vf.mode:o} {vf.uid}:{vf.gid}")
        else:
            return False
        self.stats["checked"] += 1
        if not problem:
            return False
        if exact:
            if vf.conffile:
                R.warn(f"conffile /{vf.path} ({vp.name}): {problem}"
                       + ("" if restore_conffiles else " (kept; --restore-conffiles replaces it)"))
            else:
                R.crit(f"/{vf.path} ({vp.name}): {problem}")
                self.stats["problems"] += 1
        if vf.conffile and not restore_conffiles and e is not None:
            return False
        if e is not None and e.kind == "d":
            self.quarantine(vf.path, "directory where a file belongs")
        if vf.kind == "l":
            self.put_link(vf.path, vf.link, vf.uid, vf.gid, f"{vp.name}: {problem}")
        else:
            self.put_file(vf.path, vf.sha256, vf.mode, vf.uid, vf.gid, f"{vp.name}: {problem}")
        return True

    # -- output -----------------------------------------------------------
    def write(self, agent_dir, report_text, extra_env=None):
        od = self.outdir
        if not self.finalize_pkgs and all(a[2][0] == "T" for a in self.actions):
            self.actions = []            # nothing to repair: no backups needed either
        os.makedirs(od, exist_ok=True)
        os.makedirs(os.path.join(od, "pkgs"), exist_ok=True)
        os.makedirs(os.path.join(od, "bin"), exist_ok=True)
        shutil.copy2(os.path.join(agent_dir, "apply.sh"), os.path.join(od, "apply.sh"))
        bb = os.path.join(agent_dir, "bin", "busybox")
        if os.path.exists(bb):
            shutil.copy2(bb, os.path.join(od, "bin", "busybox"))
        else:
            R.warn(f"{bb} not found: copy a static busybox to {od}/bin/busybox before using the plan")
        shipped = []
        for vp in self.finalize_pkgs:
            for blob in [vp.blob_path] + vp.extra_blobs:
                if blob:
                    dst = os.path.join(od, "pkgs", os.path.basename(blob))
                    shutil.copy2(blob, dst)
                    shipped.append(os.path.basename(blob))
        with open(os.path.join(od, "actions.tsv"), "w") as f:
            for _, _, a in sorted(self.actions):
                f.write("\t".join(a) + "\n")
        with open(os.path.join(od, "verify.tsv"), "w") as f:
            for p in sorted(self.verify):
                kind, value, mode, uid, gid, level, pkg = self.verify[p]
                f.write(f"{kind}\t/{p}\t{value}\t{mode}\t{uid}\t{gid}\t{level}\t{pkg}\n")
        with open(os.path.join(od, "finalize.sh"), "w") as f:
            f.write(self.finalize_sh or "pm_needs_finalize() { return 1; }\npm_finalize() { :; }\n")
        with open(os.path.join(od, "report.txt"), "w") as f:
            f.write(report_text)
        snap_sha = hashlib.sha256(open(self.snap.path, "rb").read()).hexdigest()
        env = {
            "PLAN_VERSION": "2",
            "BACKEND": self.backend.name,
            "HOST": self.snap.host,
            "CREATED": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "CREATED_EPOCH": str(int(datetime.now(timezone.utc).timestamp())),
            "SNAPSHOT_SHA256": snap_sha,
            "SNAPSHOT_DATE": self.snap.meta.get("date_utc", "?"),
            "ACTIONS": str(len(self.actions)),
            "FINALIZE_PKGS": " ".join(vp.name for vp in self.finalize_pkgs),
            "RESTARTS": " ".join(sorted(set(self.restarts))),
        }
        env.update(extra_env or {})
        with open(os.path.join(od, "plan.env"), "w") as f:
            for k, v in env.items():
                safe = str(v).replace("'", "")
                f.write(f"{k}='{safe}'\n")
        manifest = []
        for dirpath, dirnames, files in os.walk(od):
            dirnames.sort()
            for fn in sorted(files):
                full = os.path.join(dirpath, fn)
                rel = os.path.relpath(full, od)
                if rel == "MANIFEST.sha256" or (rel.startswith("pmtrust-plan-") and rel.endswith(".log")):
                    continue        # the staging log keeps growing; it is evidence, not plan input
                with open(full, "rb") as fh:
                    manifest.append(f"{hashlib.sha256(fh.read()).hexdigest()}  ./{rel}")
        with open(os.path.join(od, "MANIFEST.sha256"), "w") as f:
            f.write("\n".join(manifest) + "\n")
        with open(os.path.join(od, "MANIFEST.sha256"), "rb") as f:
            plan_id = hashlib.sha256(f.read()).hexdigest()
        os.chmod(os.path.join(od, "apply.sh"), 0o755)
        return plan_id, shipped
