"""Sandbox backend base class and selection.

A ``Backend`` translates a ``ResolvedPolicy`` into a runtime-specific invocation and runs
it. Concrete backends live in their own modules (``bwrap.py``, ``seatbelt.py``);
``get_backend`` is a plain in-code factory, not plugin discovery.

How that invocation is *shaped* is the backend's business alone — an argv for bwrap, an
SBPL profile for Seatbelt — so callers ask for ``describe()`` rather than reaching for a
renderer of their own.
"""

from __future__ import annotations

import platform
import subprocess
from abc import ABC, abstractmethod
from dataclasses import dataclass

from .errors import HozoError
from .policy import ResolvedPolicy

_PLATFORM_BACKENDS = {"Linux": "bwrap", "Darwin": "seatbelt"}


@dataclass
class SandboxResult:
    returncode: int
    stdout: str | None
    stderr: str | None
    policy: ResolvedPolicy
    argv: list[str]
    backend: str


class Backend(ABC):
    """A sandbox runtime. Subclasses translate a policy into an invocation and execute it."""

    name: str

    @abstractmethod
    def is_available(self) -> bool:
        """True if the runtime binary is installed."""

    @abstractmethod
    def describe(self, policy: ResolvedPolicy) -> str:
        """Render what this backend would run, for ``explain`` (pure; no execution)."""

    @abstractmethod
    def run(self, policy: ResolvedPolicy, *, environ=None, capture: bool = False) -> SandboxResult:
        """Execute the policy and return the result."""

    def _spawn(
        self,
        argv: list[str],
        env: dict[str, str],
        policy: ResolvedPolicy,
        *,
        capture: bool,
        cwd: str | None = None,
        pass_fds: tuple[int, ...] = (),
    ) -> SandboxResult:
        """Run the built invocation. ``env`` is the child's whole process environment (not
        passed as runtime flags), so values stay out of the world-readable cmdline.
        ``pass_fds`` keeps those descriptors open at the same numbers in the child."""
        extra = {"capture_output": True, "text": True} if capture else {}
        proc = subprocess.run(argv, env=env, cwd=cwd, pass_fds=pass_fds, **extra)
        return SandboxResult(proc.returncode, proc.stdout, proc.stderr, policy, argv, self.name)


def get_backend(name: str | None = None) -> Backend:
    if name is None:
        system = platform.system()
        name = _PLATFORM_BACKENDS.get(system)
        if name is None:
            supported = ", ".join(f"{os} ({backend})" for os, backend in _PLATFORM_BACKENDS.items())
            raise HozoError(f"unsupported platform {system!r}; hozo supports {supported}")
    # Imported lazily: both backend modules import this one, so a top-level import cycles.
    if name == "bwrap":
        from .bwrap import BubblewrapBackend

        return BubblewrapBackend()
    if name == "seatbelt":
        from .seatbelt import SeatbeltBackend

        return SeatbeltBackend()
    raise HozoError(f"unknown backend {name!r}; available: {', '.join(_PLATFORM_BACKENDS.values())}")
