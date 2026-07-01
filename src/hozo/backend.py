"""Sandbox backend base class and selection.

A ``Backend`` translates a ``ResolvedPolicy`` into runtime-specific argv and runs it.
Concrete backends live in their own modules (``bwrap.py``); ``get_backend`` is a plain
in-code factory, not plugin discovery.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass

from .errors import HozoError
from .policy import ResolvedPolicy


@dataclass
class SandboxResult:
    returncode: int
    stdout: str | None
    stderr: str | None
    policy: ResolvedPolicy
    argv: list[str]
    backend: str


class Backend(ABC):
    """A sandbox runtime. Subclasses translate policy -> argv and execute it."""

    name: str

    @abstractmethod
    def is_available(self) -> bool:
        """True if the runtime binary is installed."""

    @abstractmethod
    def build_argv(self, policy: ResolvedPolicy, *, proxy=None) -> list[str]:
        """Translate a policy into the runtime's argv (pure; no execution)."""

    @abstractmethod
    def run(self, policy: ResolvedPolicy, *, environ=None, capture: bool = False) -> SandboxResult:
        """Execute the policy and return the result."""


def get_backend(name: str = "bwrap") -> Backend:
    if name == "bwrap":
        from .bwrap import BubblewrapBackend

        return BubblewrapBackend()
    raise HozoError(f"unknown backend {name!r}; available: bwrap")
