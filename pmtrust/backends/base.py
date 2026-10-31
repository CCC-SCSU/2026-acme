"""Backend interface. A backend owns facts about one package manager; the core
owns the flow, comparison, planning and reporting."""


class Backend:
    name = "base"
    audit_only = False
    bin_dirs = ("bin", "sbin", "usr/bin", "usr/sbin")
    lib_dirs = ()

    def __init__(self, args, snap, workdir, payload):
        self.args, self.snap, self.workdir, self.payload = args, snap, workdir, payload

    # -- detection / CLI ---------------------------------------------------
    @staticmethod
    def detect(snap):
        return False

    @staticmethod
    def add_args(ap):
        pass

    # -- pipeline ----------------------------------------------------------
    def collect_verified(self):
        """Read the target db as data, verify metadata, choose the core set,
        download + verify + unpack. Return list[VPkg] in lay-down order."""
        raise NotImplementedError

    def db_owned(self):
        """Paths the target's (untrusted) package db claims; for the weak unowned scan."""
        return set()

    def pre_plan(self, plan, vpkgs):
        """Actions that must precede file lay-down (tree backups, db rewrites)."""

    def post_compare(self, plan, vpkgs):
        """Package-manager database repairs (maintainer scripts etc.)."""

    def injection_points(self, plan, vpkgs):
        pass

    def finalize_script(self, plan):
        return ""

    # -- semantics hooks used by the core comparison ------------------------
    def expected_dir_link(self, rel, link):
        return False

    def runtime_dir_perm(self, rel):
        return False

    def skip_compare(self, vp, vf):
        return False

    def known_lib_dir(self, path):
        return False


def restart_hints(scripts):
    """Services a set of maintainer scripts may restart (best effort, for the report)."""
    import re
    out = set()
    for name, data in scripts:
        txt = data.decode("utf-8", "replace") if isinstance(data, bytes) else data
        for m in re.finditer(r"\b(?:invoke-rc\.d|service)\s+(?:--\S+\s+)*([A-Za-z0-9@._-]+)\s+(?:re)?start", txt):
            out.add(f"{m.group(1)} (via {name}, blocked by policy-rc.d)")
        for m in re.finditer(r"\bdeb-systemd-invoke\s+(?:--\S+\s+)*(?:try-)?restart\s+([A-Za-z0-9@._$-]+)", txt):
            out.add(f"{m.group(1)} (via {name}, blocked by policy-rc.d)")
        for m in re.finditer(r"\bsystemctl\s+(?:--\S+\s+)*(daemon-reexec|try-restart|restart|reload-or-restart|"
                             r"try-reload-or-restart)[ \t]*([A-Za-z0-9@._$-]*)", txt):
            out.add(f"{m.group(2) or 'systemd'} {m.group(1)} (direct systemctl in {name}; NOT blocked)")
    return sorted(out)
