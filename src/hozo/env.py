"""Build the sandbox environment as an explicit dict

Start from the host env filtered by the allow globs (or everything, when ``clear_env`` is
false), apply explicit ``set`` values, point HTTP(S)_PROXY at the egress proxy when there
is one, then prepend to PATH. Backends hand the result to the child as its process
environment, so values never land in a world-readable cmdline.
"""

from __future__ import annotations

import fnmatch
import os

from .paths import SCRATCH_PLACEHOLDER
from .proxy import proxy_env


def _matches(name: str, patterns: list[str]) -> bool:
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
    """``proxy_port`` (when set) is the loopback port the sandbox reaches the egress proxy
    on; it adds the HTTP(S)_PROXY vars, which win over a profile's own ``env.set``.
    ``scratch`` is the backend's per-run temp dir, substituted for ``{scratch}``."""
    environ = os.environ if environ is None else environ

    env: dict[str, str] = {}
    for key, value in environ.items():
        if not policy.clear_env or _matches(key, policy.env_allow):
            env[key] = value

    for key, value in policy.env_set.items():
        env[key] = value.replace(SCRATCH_PLACEHOLDER, scratch) if scratch else value
    if proxy_port is not None:
        env.update(proxy_env(proxy_port))

    new_path = _build_path(policy.prepend_path, env.get("PATH", ""))
    if new_path:
        env["PATH"] = new_path

    return env
