"""Reporting: CRIT/WARN/INFO findings, a timestamped log file, exit codes.

Exit codes used by pmtrust: 0 = no critical findings, 2 = critical findings,
1 = fatal error (verification failure, bad input). A failed verification is
always fatal: the tool never continues on partially trusted data.
"""
import sys
from datetime import datetime, timezone


class _Log:
    def __init__(self):
        self.fh = None
        self.path = None

    def open(self, path):
        self.path = path
        self.fh = open(path, "a", buffering=1, encoding="utf-8")

    def write(self, text):
        if not self.fh:
            return
        ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        for line in str(text).splitlines() or [""]:
            self.fh.write(f"{ts} {line}\n")


LOG = _Log()


def out(msg=""):
    print(msg, file=sys.stderr)
    LOG.write(msg)


class Fatal(Exception):
    pass


def die(msg):
    out(f"\n[FATAL] {msg}")
    raise Fatal(msg)


def step(msg):
    out(f"\n==> {msg}")


class Report:
    def __init__(self, title):
        self.title = title
        self.items = []

    def add(self, level, msg):
        self.items.append((level, msg))
        out(f"[{level}] {msg}")

    def crit(self, msg):
        self.add("CRIT", msg)

    def warn(self, msg):
        self.add("WARN", msg)

    def info(self, msg):
        self.add("INFO", msg)

    def count(self, level):
        return sum(1 for lvl, _ in self.items if lvl == level)

    def text(self):
        lines = [f"# {self.title}: {self.count('CRIT')} critical, {self.count('WARN')} warnings"]
        for level in ("CRIT", "WARN", "INFO"):
            for lvl, msg in self.items:
                if lvl == level:
                    lines.append(f"[{lvl}] {msg}")
        return "\n".join(lines) + "\n"


class _Current:
    """Module-level handle so backends can write `R.crit(...)` without plumbing."""

    def __init__(self):
        self.rep = Report("audit")

    def __getattr__(self, name):
        return getattr(self.rep, name)

    def reset(self, title):
        self.rep = Report(title)
        return self.rep


R = _Current()
