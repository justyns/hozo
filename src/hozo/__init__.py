"""Hozo: run risky/dev tools in named, composable sandboxes.

A Python library with a thin CLI on top; import the public names below directly from
``hozo``. ``SandboxRunner.run`` is the only part with side effects.
"""

from importlib.metadata import PackageNotFoundError, version

from .audit import AuditReport, render_profile, render_report, run_audit
from .backend import Backend, SandboxResult, get_backend
from .bwrap import BubblewrapBackend, build_bwrap_argv
from .errors import HozoError, MergeConflictError, ProfileError
from .executor import SandboxRunner
from .explain import explain_policy
from .policy import ResolvedPolicy, SandboxRequest, resolve_policy
from .profiles import Bind
from .seatbelt import SeatbeltBackend, build_seatbelt_profile


def run(request, **kwargs) -> SandboxResult:
    """Convenience wrapper: ``SandboxRunner().run(request, **kwargs)``."""
    return SandboxRunner().run(request, **kwargs)


def check_available() -> bool:
    """True if this platform's sandbox runtime (bwrap / sandbox-exec) is installed."""
    return get_backend().is_available()


try:
    __version__ = version("hozo")
except PackageNotFoundError:  # running from a source tree that isn't installed
    __version__ = "0.0.0"

__all__ = [
    "Bind",
    "SandboxRequest",
    "ResolvedPolicy",
    "SandboxResult",
    "SandboxRunner",
    "Backend",
    "BubblewrapBackend",
    "SeatbeltBackend",
    "get_backend",
    "resolve_policy",
    "build_bwrap_argv",
    "build_seatbelt_profile",
    "explain_policy",
    "check_available",
    "run",
    "run_audit",
    "render_report",
    "render_profile",
    "AuditReport",
    "HozoError",
    "ProfileError",
    "MergeConflictError",
    "__version__",
]
