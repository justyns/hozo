"""Backend base class and platform-aware selection."""

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
    name: str

    @abstractmethod
    def is_available(self) -> bool:
        pass

    @abstractmethod
    def describe(self, policy: ResolvedPolicy) -> str:
        """Render what this backend would run, for ``explain`` (pure; no execution)."""

    @abstractmethod
    def run(self, policy: ResolvedPolicy, *, environ=None, capture: bool = False) -> SandboxResult:
        pass

    def exec(self, policy: ResolvedPolicy, *, environ=None) -> int:
        """Seatbelt overrides this to replace the process."""
        return self.run(policy, environ=environ).returncode

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
        """``env`` is the child's whole environment, kept out of the argv so values never reach the
        world-readable cmdline."""
        extra = {"capture_output": True, "text": True} if capture else {}
        proc = subprocess.run(argv, env=env, cwd=cwd, pass_fds=pass_fds, **extra)
        return SandboxResult(proc.returncode, proc.stdout, proc.stderr, policy, argv, self.name)


def get_backend(name: str | None = None) -> Backend:
    if name is None:
        system = platform.system()
        name = _PLATFORM_BACKENDS.get(system)
        if name is None:
            supported = ", ".join(f"{system_name} ({backend})" for system_name, backend in _PLATFORM_BACKENDS.items())
            raise HozoError(f"unsupported platform {system!r}; hozo supports {supported}")
    # Lazy imports avoid a cycle, since bwrap.py and seatbelt.py import this module.
    if name == "bwrap":
        from .bwrap import BubblewrapBackend

        return BubblewrapBackend()
    if name == "seatbelt":
        from .seatbelt import SeatbeltBackend

        return SeatbeltBackend()
    raise HozoError(f"unknown backend {name!r}; available: {', '.join(_PLATFORM_BACKENDS.values())}")
