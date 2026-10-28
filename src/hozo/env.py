"""Build the sandbox environment as an explicit dict."""

from __future__ import annotations

import fnmatch
import os

from .paths import SCRATCH_PLACEHOLDER
from .proxy import proxy_env


def matches_any(name: str, patterns: list[str]) -> bool:
    return any(fnmatch.fnmatchcase(name, pat) for pat in patterns)


def _build_path(prepend: list[str], base: str) -> str:
    dirs: list[str] = []
    for group in (prepend, base.split(":") if base else []):
        for entry in group:
            if entry and entry not in dirs:
                dirs.append(entry)
    return ":".join(dirs)


def build_env(
    policy,
    environ: dict[str, str] | None = None,
    *,
    proxy_port: int | None = None,
    scratch: str | None = None,
) -> dict[str, str]:
    """``proxy_port`` is the sandbox-side port of the egress proxy, and its HTTP(S)_PROXY vars
    override ``env.set``. ``scratch`` is the per-run temp dir substituted for ``{scratch}``."""
    environ = os.environ if environ is None else environ

    env: dict[str, str] = {}
    for key, value in environ.items():
        if not policy.clear_env or matches_any(key, policy.env_allow):
            env[key] = value

    for key, value in policy.env_set.items():
        env[key] = value.replace(SCRATCH_PLACEHOLDER, scratch) if scratch else value
    if proxy_port is not None:
        env.update(proxy_env(proxy_port))

    new_path = _build_path(policy.prepend_path, env.get("PATH", ""))
    if new_path:
        env["PATH"] = new_path

    return env
