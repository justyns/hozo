"""Render a ResolvedPolicy as a ``bwrap`` argv and run it."""

from __future__ import annotations

import functools
import logging
import os
import shlex
import shutil
import tempfile
from contextlib import ExitStack, contextmanager
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
    logger,
)
from .seccomp import build_seccomp_filter, host_arch

# Top-level dirs that are symlinks into /usr on merged-/usr distros (Arch/EndeavourOS).
_MERGED_USR_LINKS = ("/bin", "/sbin", "/lib", "/lib64")

# Stand-ins for `explain`. The socket, script and seccomp fd exist only during a run.
_EXPLAIN_MOUNT = ProxyMount("<host-proxy.sock>", "<bridge.py>")
_EXPLAIN_SECCOMP_FD = "<seccomp-fd>"

# Backs the {scratch} placeholder.
SCRATCH_DIR = "/tmp/hozo-scratch"


def check_available() -> bool:
    # Not cached: bwrap can be installed/removed during a long-lived library process.
    return shutil.which("bwrap") is not None


def build_bwrap_argv(
    policy: ResolvedPolicy, *, proxy: ProxyMount | None = None, seccomp_fd: int | str | None = None
) -> list[str]:
    use_proxy = proxy is not None

    argv = [
        "bwrap",
        "--die-with-parent",
        "--unshare-pid",
        "--unshare-ipc",
        "--unshare-uts",
        "--unshare-cgroup-try",
    ]
    if seccomp_fd is not None:
        argv += ["--seccomp", str(seccomp_fd)]
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

    # After the tmpfs/bind ops, so neither mounts over it.
    argv += ["--dir", SCRATCH_DIR]

    if use_proxy:
        argv += ["--ro-bind", proxy.socket_path, PROXY_SOCKET_TARGET]
        argv += ["--ro-bind", proxy.script_path, BRIDGE_SCRIPT_TARGET]

    argv += ["--chdir", policy.cwd]
    if use_proxy:
        # bridge.py exits once the port listens. '&&' waits for it and skips the command if the
        # bridge failed.
        bridge = f"python3 {BRIDGE_SCRIPT_TARGET} {PROXY_SOCKET_TARGET} {BRIDGE_PORT}"
        argv += ["sh", "-c", f"{bridge} && exec {shlex.join(policy.command)}"]
    else:
        argv += policy.command
    return argv


@functools.cache
def _merged_usr_links() -> tuple[str, ...]:
    """Recreate the host's /bin, /lib, ... symlinks, or bind them where /usr is not merged.
    Targets differ (/sbin -> usr/bin, /lib64 -> usr/lib), so each is read."""
    args: list[str] = []
    for link in _MERGED_USR_LINKS:
        if os.path.islink(link):
            args += ["--symlink", os.readlink(link), link]
        elif os.path.isdir(link):
            args += ["--ro-bind", link, link]
    return tuple(args)


def _describe_syscalls(policy: ResolvedPolicy, *, filtered: bool) -> list[str]:
    if not policy.syscall_deny:
        return []
    denied = ", ".join(sorted(policy.syscall_deny))
    if filtered:
        return [f"Syscalls: deny -> {policy.syscall_action} ({denied})"]
    return [f"Syscalls: NOT FILTERED, no syscall table for {host_arch()}; requested: {denied}"]


def _bind_flag(bind: Bind) -> str:
    if bind.mode == "rw":
        return "--bind-try" if bind.optional else "--bind"
    return "--ro-bind-try" if bind.optional else "--ro-bind"


class BubblewrapBackend(Backend):
    name = "bwrap"

    def is_available(self) -> bool:
        return check_available()

    def describe(self, policy: ResolvedPolicy) -> str:
        mount = _EXPLAIN_MOUNT if policy.network_mode == "proxy" else None
        # Compile what run() would, so explain cannot claim a filter that will not load.
        program = build_seccomp_filter(policy)
        argv = build_bwrap_argv(policy, proxy=mount, seccomp_fd=_EXPLAIN_SECCOMP_FD if program else None)
        lines = _describe_syscalls(policy, filtered=program is not None)
        lines.append(f"{self.name} argv:\n  " + shlex.join(argv))
        return "\n".join(lines)

    def run(self, policy: ResolvedPolicy, *, environ=None, capture: bool = False) -> SandboxResult:
        with ExitStack() as stack:
            mount = stack.enter_context(_proxy(policy)) if policy.network_mode == "proxy" else None
            program = build_seccomp_filter(policy)
            seccomp_fd = stack.enter_context(_seccomp_fd(program)) if program else None
            argv = build_bwrap_argv(policy, proxy=mount, seccomp_fd=seccomp_fd)
            env = build_env(policy, environ=environ, proxy_port=BRIDGE_PORT if mount else None, scratch=SCRATCH_DIR)
            pass_fds = () if seccomp_fd is None else (seccomp_fd,)
            return self._spawn(argv, env, policy, capture=capture, pass_fds=pass_fds)


@contextmanager
def _seccomp_fd(program: bytes):
    """A temp file rather than a pipe, which deadlocks on a filter larger than the pipe buffer."""
    with tempfile.TemporaryFile() as handle:
        handle.write(program)
        handle.flush()
        handle.seek(0)
        yield handle.fileno()


@contextmanager
def _proxy(policy: ResolvedPolicy):
    """Run the egress proxy on a per-run socket, logging it to a dated file meanwhile."""
    base = state_dir() / "proxy"
    logs = base / "logs"
    logs.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=base, ignore_cleanup_errors=True) as workdir:
        handler = logging.FileHandler(logs / f"{date.today().isoformat()}.log")
        handler.setFormatter(logging.Formatter("%(asctime)s %(message)s"))
        logger.setLevel(logging.INFO)
        logger.addHandler(handler)
        socket_path = Path(workdir) / "proxy.sock"
        try:
            with BackgroundProxy(socket_path, policy.proxy_allow_hosts):
                yield ProxyMount(str(socket_path), str(Path(__file__).with_name("bridge.py")))
        finally:
            logger.removeHandler(handler)
            handler.close()
