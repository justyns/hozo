"""Human-readable audit of a ResolvedPolicy.

Lists the backend, profiles, network, home, binds, writable host paths, the env var
*names* the sandbox runs with, the command, and the full runtime argv. Env values
never appear (they aren't in the argv), so explain output is always safe to paste.
"""

from __future__ import annotations

import shlex

from .backend import Backend
from .bwrap import BubblewrapBackend, build_sandbox_env
from .policy import ResolvedPolicy
from .proxy import ProxyMount


def explain_policy(
    policy: ResolvedPolicy,
    *,
    environ: dict[str, str] | None = None,
    backend: Backend | None = None,
) -> str:
    backend = backend or BubblewrapBackend()

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
        lines.append(f"Home:     {policy.home} (ephemeral)")

    lines.append(f"Workdir:  {policy.cwd}")

    lines.append("Binds:")
    for bind in policy.binds:
        optional = " (optional)" if bind.optional else ""
        lines.append(f"  {bind.mode:2}  {bind.source}{optional}")
    writable = [bind.source for bind in policy.binds if bind.mode == "rw"]
    lines.append("Writable host paths: " + (", ".join(writable) or "(none)"))

    env_names = sorted(build_sandbox_env(policy, environ=environ, proxy=(policy.network_mode == "proxy")))
    lines.append("Env:      " + (", ".join(env_names) or "(none)"))

    lines.append("Command:  " + (shlex.join(policy.command) if policy.command else "(none)"))

    proxy = ProxyMount("<host-proxy.sock>", "<bridge.py>") if policy.network_mode == "proxy" else None
    argv = backend.build_argv(policy, proxy=proxy)
    return "\n".join(lines) + f"\n\n{backend.name} argv:\n  {shlex.join(argv)}"
