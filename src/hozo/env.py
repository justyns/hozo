"""Build the sandbox environment as an explicit dict

Start from the host env filtered by the allow globs (or everything, when ``clear_env`` is
false), apply explicit ``set`` values, then prepend to PATH.
"""

from __future__ import annotations

import fnmatch
import os


def _matches(name: str, patterns: list[str]) -> bool:
    return any(fnmatch.fnmatchcase(name, pat) for pat in patterns)


def _build_path(prepend: list[str], base: str) -> str:
    dirs: list[str] = []
    for group in (prepend, base.split(":") if base else []):
        for entry in group:
            if entry and entry not in dirs:
                dirs.append(entry)
    return ":".join(dirs)


def build_env(policy, environ: dict[str, str] | None = None) -> dict[str, str]:
    environ = os.environ if environ is None else environ

    env: dict[str, str] = {}
    for key, value in environ.items():
        if not policy.clear_env or _matches(key, policy.env_allow):
            env[key] = value

    env.update(policy.env_set)

    new_path = _build_path(policy.prepend_path, env.get("PATH", ""))
    if new_path:
        env["PATH"] = new_path

    return env
