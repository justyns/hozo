"""Orchestrate a run: resolve the request into a policy, then hand it to the backend."""

from __future__ import annotations

from .backend import Backend, SandboxResult, get_backend
from .errors import HozoError
from .policy import ResolvedPolicy, SandboxRequest, resolve_policy


class SandboxRunner:
    def __init__(self, backend: Backend | None = None):
        self.backend = backend or get_backend()

    def run(
        self,
        request_or_policy: SandboxRequest | ResolvedPolicy,
        *,
        capture: bool = False,
        environ: dict[str, str] | None = None,
    ) -> SandboxResult:
        if isinstance(request_or_policy, ResolvedPolicy):
            policy = request_or_policy
        else:
            policy = resolve_policy(request_or_policy)

        if not self.backend.is_available():
            raise HozoError(f"backend {self.backend.name!r} not available — install it. Hozo will not run unsandboxed.")

        return self.backend.run(policy, environ=environ, capture=capture)
