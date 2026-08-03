"""The bubblewrap backend: render a ResolvedPolicy into a ``bwrap`` argv and run it.

``build_bwrap_argv`` is the pure renderer; ``BubblewrapBackend`` executes it (and manages
the egress proxy for proxy mode). The env is built by ``build_sandbox_env`` and handed to
bwrap as its process environment rather than via ``--setenv``, so env values never land in
the world-readable ``/proc/PID/cmdline``. The system mounts (/usr, certs, /etc/*) are
ordinary ``base`` binds; only the host-specific merged-/usr symlinks and ``--proc``/``--dev``
stay here.
"""

from __future__ import annotations

import functools
import logging
import os
import shlex
import shutil
import subprocess
import tempfile
from datetime import date
from pathlib import Path

from .backend import Backend, SandboxResult
from .env import build_env
from .paths import state_dir
from .policy import ResolvedPolicy
from .profiles import Bind
from .proxy import (
    BRIDGE_PORT,
    BRIDGE_SCRIPT_TARGET,
    PROXY_SOCKET_TARGET,
    BackgroundProxy,
    ProxyMount,
    bridge_script_path,
)

# Top-level dirs that are symlinks into /usr on merged-/usr distros (Arch/EndeavourOS).
_MERGED_USR_LINKS = ("/bin", "/sbin", "/lib", "/lib64")


def check_available() -> bool:
    # Not cached: bwrap can be installed/removed during a long-lived library process.
    return shutil.which("bwrap") is not None


def build_bwrap_argv(policy: ResolvedPolicy, *, proxy: ProxyMount | None = None) -> list[str]:
    use_proxy = proxy is not None and policy.network_mode == "proxy"

    argv = [
        "bwrap",
        "--die-with-parent",
        "--unshare-pid",
        "--unshare-ipc",
        "--unshare-uts",
        "--unshare-cgroup-try",
    ]
    if policy.network_mode in ("none", "proxy"):
        argv += ["--unshare-net"]

    argv += list(_merged_usr_links())
    if policy.proc:
        argv += ["--proc", "/proc"]
    if policy.dev:
        argv += ["--dev", "/dev"]

    if policy.home:
        argv += ["--dir", policy.home]

    for path in policy.tmpfs:
        argv += ["--tmpfs", path]

    for bind in policy.binds:
        argv += [_bind_flag(bind), bind.source, bind.source]

    if use_proxy:
        argv += ["--ro-bind", proxy.socket_path, PROXY_SOCKET_TARGET]
        argv += ["--ro-bind", proxy.script_path, BRIDGE_SCRIPT_TARGET]

    argv += ["--chdir", policy.cwd]
    if use_proxy:
        # Start the in-sandbox TCP->UDS bridge, then exec the real command.
        bridge = f"python3 {BRIDGE_SCRIPT_TARGET} {PROXY_SOCKET_TARGET} {BRIDGE_PORT}"
        argv += ["sh", "-c", f"{bridge} & sleep 0.2; exec {shlex.join(policy.command)}"]
    else:
        argv += policy.command
    return argv


def build_sandbox_env(
    policy: ResolvedPolicy, *, environ: dict[str, str] | None = None, proxy: bool = False
) -> dict[str, str]:
    """The environment the sandboxed command runs with. Handed to bwrap as its process
    env (no ``--clearenv``), so the values never appear in the cmdline."""
    env = build_env(policy, environ=environ)
    if proxy:
        env.update(_proxy_env())
    return env


def _proxy_env() -> dict[str, str]:
    url = f"http://127.0.0.1:{BRIDGE_PORT}"
    no_proxy = "localhost,127.0.0.1,::1"
    return {
        "HTTP_PROXY": url,
        "HTTPS_PROXY": url,
        "http_proxy": url,
        "https_proxy": url,
        "NO_PROXY": no_proxy,
        "no_proxy": no_proxy,
    }


@functools.cache
def _merged_usr_links() -> tuple[str, ...]:
    """Recreate the host's top-level /usr symlinks (/bin, /lib, ...), or bind them on a
    non-merged-/usr distro. Host-specific, so it stays here rather than in base.yaml.
    Targets aren't uniform (/sbin -> usr/bin, /lib64 -> usr/lib), so read each one."""
    args: list[str] = []
    for link in _MERGED_USR_LINKS:
        if os.path.islink(link):
            args += ["--symlink", os.readlink(link), link]
        elif os.path.isdir(link):
            args += ["--ro-bind", link, link]
    return tuple(args)


def _bind_flag(bind: Bind) -> str:
    if bind.mode == "rw":
        return "--bind-try" if bind.optional else "--bind"
    return "--ro-bind-try" if bind.optional else "--ro-bind"


class BubblewrapBackend(Backend):
    """bubblewrap (bwrap)."""

    name = "bwrap"

    def is_available(self) -> bool:
        return check_available()

    def build_argv(self, policy: ResolvedPolicy, *, proxy=None) -> list[str]:
        return build_bwrap_argv(policy, proxy=proxy)

    def run(self, policy: ResolvedPolicy, *, environ=None, capture: bool = False) -> SandboxResult:
        if policy.network_mode == "proxy":
            return self._run_with_proxy(policy, environ, capture)
        argv = self.build_argv(policy)
        env = build_sandbox_env(policy, environ=environ)
        return self._spawn(argv, env, policy, capture)

    def _spawn(self, argv: list[str], env: dict, policy: ResolvedPolicy, capture: bool) -> SandboxResult:
        # The env is bwrap's process environment (not --setenv args), so values stay out
        # of the world-readable /proc/PID/cmdline; env= fully replaces the operator's env.
        if capture:
            proc = subprocess.run(argv, env=env, capture_output=True, text=True)
            return SandboxResult(proc.returncode, proc.stdout, proc.stderr, policy, argv, self.name)
        proc = subprocess.run(argv, env=env)
        return SandboxResult(proc.returncode, None, None, policy, argv, self.name)

    def _run_with_proxy(self, policy: ResolvedPolicy, environ, capture: bool) -> SandboxResult:
        base = state_dir() / "proxy"
        logs = base / "logs"
        logs.mkdir(parents=True, exist_ok=True)
        workdir = Path(tempfile.mkdtemp(dir=str(base)))
        socket_path = workdir / "proxy.sock"

        handler = _attach_proxy_log(logs)
        try:
            with BackgroundProxy(socket_path, policy.proxy_allow_hosts):
                argv = self.build_argv(policy, proxy=ProxyMount(str(socket_path), bridge_script_path()))
                env = build_sandbox_env(policy, environ=environ, proxy=True)
                return self._spawn(argv, env, policy, capture)
        finally:
            logging.getLogger("hozo.proxy").removeHandler(handler)
            handler.close()
            shutil.rmtree(workdir, ignore_errors=True)


def _attach_proxy_log(logs_dir: Path) -> logging.Handler:
    handler = logging.FileHandler(logs_dir / f"{date.today().isoformat()}.log")
    handler.setFormatter(logging.Formatter("%(asctime)s %(message)s"))
    log = logging.getLogger("hozo.proxy")
    log.setLevel(logging.INFO)
    log.addHandler(handler)
    return handler
