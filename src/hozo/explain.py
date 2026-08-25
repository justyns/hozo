"""Human-readable audit of a ResolvedPolicy.

Lists the backend, profiles, network, home, binds, writable host paths, the env var
*names* the sandbox runs with, the command, and finally the backend's own rendering of
what it would run. Env values never appear, so explain output is always safe to paste.

Nothing here is backend-specific: the tail comes from ``Backend.describe``.
"""

from __future__ import annotations

import shlex

from .backend import Backend, get_backend
from .env import build_env
from .policy import ResolvedPolicy


def explain_policy(
    policy: ResolvedPolicy,
    *,
    environ: dict[str, str] | None = None,
    backend: Backend | None = None,
) -> str:
    backend = backend or get_backend()

    lines = [
        f"Backend:  {backend.name}",
        "Profiles: " + (", ".join(policy.profiles_applied) or "(none)"),
    ]

    if policy.network_mode == "proxy":
        hosts = ", ".join(policy.proxy_allow_hosts) or "(none — nothing reachable)"
        lines.append(f"Network:  proxy (allow: {hosts})")
    else:
        lines.append(f"Network:  {policy.network_mode}")

    if policy.home:
        lines.append(f"Home:     {policy.home}")

    lines.append(f"Workdir:  {policy.cwd}")

    lines.append("Binds:")
    for bind in policy.binds:
        optional = " (optional)" if bind.optional else ""
        lines.append(f"  {bind.mode:2}  {bind.source}{optional}")
    writable = [bind.source for bind in policy.binds if bind.mode == "rw"]
    lines.append("Writable host paths: " + (", ".join(writable) or "(none)"))

    # Names only, so the placeholder port stands in for the per-run one.
    proxy_port = 0 if policy.network_mode == "proxy" else None
    env_names = sorted(
        set(build_env(policy, environ=environ, proxy_port=proxy_port)) | set(policy.env_set_from_command)
    )
    lines.append("Env:      " + (", ".join(env_names) or "(none)"))

    if policy.env_set_from_command:
        lines.append("Runs on HOST before the sandbox (output becomes the value, never shown):")
        for name, argv in sorted(policy.env_set_from_command.items()):
            lines.append(f"  {name} = {shlex.join(argv)}")

    lines.append("Command:  " + (shlex.join(policy.command) if policy.command else "(none)"))

    return "\n".join(lines) + "\n\n" + backend.describe(policy)
