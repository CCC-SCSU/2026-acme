from .apt import AptBackend

BACKENDS = {"apt": AptBackend}

try:
    from .rpm import RpmBackend
    BACKENDS["rpm"] = RpmBackend
except ImportError:      # pragma: no cover - optional while developing
    pass
try:
    from .pacman import PacmanBackend
    BACKENDS["pacman"] = PacmanBackend
except ImportError:      # pragma: no cover
    pass
try:
    from .nix import NixBackend
    BACKENDS["nix"] = NixBackend
except ImportError:      # pragma: no cover
    pass
try:
    from .tce import TceBackend
    BACKENDS["tce"] = TceBackend
except ImportError:      # pragma: no cover
    pass
try:
    from .freebsd_pkg import FreeBSDPkgBackend
    BACKENDS["freebsd-pkg"] = FreeBSDPkgBackend
except ImportError:      # pragma: no cover
    pass


def detect(snap):
    for name, cls in BACKENDS.items():
        if cls.detect(snap):
            return name
    return None
