"""Hozo: run risky/dev tools in named, composable bubblewrap sandboxes.

A Python library with a thin CLI on top; import the public names below directly from
``hozo``. ``SandboxRunner.run`` is the only part with side effects.
"""

from .backend import Backend, SandboxResult, get_backend
from .bwrap import BubblewrapBackend, build_bwrap_argv, check_available
from .errors import HozoError, MergeConflictError, ProfileError
from .executor import SandboxRunner
from .explain import explain_policy
from .policy import ResolvedPolicy, SandboxRequest, resolve_policy
from .profiles import Bind


def run(request, **kwargs) -> SandboxResult:
    """Convenience wrapper: ``SandboxRunner().run(request, **kwargs)``."""
    return SandboxRunner().run(request, **kwargs)


__version__ = "0.1.0"

__all__ = [
    "Bind",
    "SandboxRequest",
    "ResolvedPolicy",
    "SandboxResult",
    "SandboxRunner",
    "Backend",
    "BubblewrapBackend",
    "get_backend",
    "resolve_policy",
    "build_bwrap_argv",
    "explain_policy",
    "check_available",
    "run",
    "HozoError",
    "ProfileError",
    "MergeConflictError",
    "__version__",
]
