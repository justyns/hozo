"""Build the sandbox environment as an explicit dict

Start from the host env filtered by the allow globs (or everything, when ``clear_env`` is
false), apply explicit ``set`` values, point HTTP(S)_PROXY at the egress proxy when there
is one, then prepend to PATH. Backends hand the result to the child as its process
environment, so values never land in a world-readable cmdline.
"""

from __future__ import annotations

import fnmatch
import os
import shlex
import subprocess

from .errors import HozoError
from .paths import SCRATCH_PLACEHOLDER
from .proxy import proxy_env

_COMMAND_TIMEOUT = 60.0
_SETUP_HINT = " It must print the credential on stdout; see `hozo profile show <name>`."


def resolve_env_commands(policy) -> dict[str, str]:
    """Run each ``env.set_from_command`` argv on the host."""
    values: dict[str, str] = {}
    for name, argv in policy.env_set_from_command.items():
        shown = shlex.join(argv)
        try:
            proc = subprocess.run(
                argv,
                capture_output=True,
                text=True,
                encoding="utf-8",
                stdin=subprocess.DEVNULL,
                timeout=_COMMAND_TIMEOUT,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise HozoError(f"env.set_from_command {name}: {shown}: {exc}.{_SETUP_HINT}") from exc
        if proc.returncode != 0:
            why = proc.stderr.strip().splitlines()[-1][:200] if proc.stderr.strip() else ""
            raise HozoError(
                f"env.set_from_command {name}: {shown} exited {proc.returncode}"
                f"{': ' + why if why else ''}.{_SETUP_HINT}"
            )
        # This is probably okay, but would cause problems if there's leading/trailing whitespace in the actual value
        value = proc.stdout.strip()
        if not value:
            raise HozoError(f"env.set_from_command {name}: {shown} produced no output.{_SETUP_HINT}")
        values[name] = value
    return values


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
    from_command: dict[str, str] | None = None,
) -> dict[str, str]:
    """``proxy_port`` (when set) is the loopback port the sandbox reaches the egress proxy
    on; it adds the HTTP(S)_PROXY vars, which win over a profile's own ``env.set``.
    ``scratch`` is the backend's per-run temp dir, substituted for ``{scratch}``.
    ``from_command`` holds values a backend already resolved; ``explain`` passes none."""
    environ = os.environ if environ is None else environ

    env: dict[str, str] = {}
    for key, value in environ.items():
        if not policy.clear_env or _matches(key, policy.env_allow):
            env[key] = value

    for key, value in policy.env_set.items():
        env[key] = value.replace(SCRATCH_PLACEHOLDER, scratch) if scratch else value
    env.update(from_command or {})
    if proxy_port is not None:
        env.update(proxy_env(proxy_port))

    new_path = _build_path(policy.prepend_path, env.get("PATH", ""))
    if new_path:
        env["PATH"] = new_path

    return env
