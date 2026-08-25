"""The bubblewrap backend: render a ResolvedPolicy into a ``bwrap`` argv and run it.

``build_bwrap_argv`` is the pure renderer; ``BubblewrapBackend`` executes it (and manages
the egress proxy for proxy mode). The env is handed to bwrap as its process environment
rather than via ``--setenv``, so env values never land in the world-readable
``/proc/PID/cmdline``. The system mounts (/usr, certs, /etc/*) are ordinary ``base`` binds;
only the host-specific merged-/usr symlinks and ``--proc``/``--dev`` stay here.
"""

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
from .env import build_env, resolve_env_commands
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
from .seccomp import build_seccomp_filter, host_arch

# Top-level dirs that are symlinks into /usr on merged-/usr distros (Arch/EndeavourOS).
_MERGED_USR_LINKS = ("/bin", "/sbin", "/lib", "/lib64")

# Stand-in paths for `explain`: the real socket and script are per-run temporaries.
_EXPLAIN_MOUNT = ProxyMount("<host-proxy.sock>", "<bridge.py>")
# Likewise the seccomp fd, which only exists for the duration of a run.
_EXPLAIN_SECCOMP_FD = "<seccomp-fd>"

# The in-sandbox per-run temp dir behind the {scratch} placeholder.
SCRATCH_DIR = "/tmp/hozo-scratch"


def check_available() -> bool:
    # Not cached: bwrap can be installed/removed during a long-lived library process.
    return shutil.which("bwrap") is not None


def build_bwrap_argv(
    policy: ResolvedPolicy, *, proxy: ProxyMount | None = None, seccomp_fd: str | None = None
) -> list[str]:
    use_proxy = proxy is not None and policy.network_mode == "proxy"

    argv = [
        "bwrap",
        "--die-with-parent",
        "--unshare-pid",
        "--unshare-ipc",
        "--unshare-uts",
        "--unshare-cgroup-try",
    ]
    if seccomp_fd is not None:
        argv += ["--seccomp", seccomp_fd]
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
        # Start the in-sandbox TCP->UDS bridge, then exec the real command. The bridge
        # backgrounds itself once it is listening, so '&&' is both the wait and the guard:
        # the command runs only after egress works, and not at all if it doesn't.
        bridge = f"python3 {BRIDGE_SCRIPT_TARGET} {PROXY_SOCKET_TARGET} {BRIDGE_PORT}"
        argv += ["sh", "-c", f"{bridge} && exec {shlex.join(policy.command)}"]
    else:
        argv += policy.command
    return argv


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


def _describe_syscalls(policy: ResolvedPolicy, *, filtered: bool) -> list[str]:
    """Reported here, not in ``explain``'s backend-neutral header: Seatbelt cannot filter
    syscalls, and neither can an arch with no table."""
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
    """bubblewrap (bwrap)."""

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
        # Before the ExitStack: fail closed before a proxy socket or temp dir exists.
        from_command = resolve_env_commands(policy)
        with ExitStack() as stack:
            mount = None
            if policy.network_mode == "proxy":
                socket_path = stack.enter_context(_proxy_workspace())
                stack.enter_context(BackgroundProxy(socket_path, policy.proxy_allow_hosts))
                mount = ProxyMount(str(socket_path), bridge_script_path())

            program = build_seccomp_filter(policy)
            seccomp_fd = stack.enter_context(_seccomp_fd(program)) if program else None
            pass_fds = () if seccomp_fd is None else (seccomp_fd,)

            argv = build_bwrap_argv(policy, proxy=mount, seccomp_fd=None if seccomp_fd is None else str(seccomp_fd))
            env = build_env(
                policy,
                environ=environ,
                proxy_port=BRIDGE_PORT if mount else None,
                scratch=SCRATCH_DIR,
                from_command=from_command,
            )
            return self._spawn(argv, env, policy, capture=capture, pass_fds=pass_fds)


@contextmanager
def _seccomp_fd(program: bytes):
    """The compiled cBPF on an inherited fd. A temp file rather than a pipe, since a filter
    larger than the pipe buffer would deadlock. bwrap reads from the current offset."""
    with tempfile.TemporaryFile() as handle:
        handle.write(program)
        handle.flush()
        handle.seek(0)
        yield handle.fileno()


@contextmanager
def _proxy_workspace():
    """A per-run scratch dir for the proxy socket, with the proxy logger writing to a dated
    file for the lifetime of the run. Yields the socket path."""
    base = state_dir() / "proxy"
    logs = base / "logs"
    logs.mkdir(parents=True, exist_ok=True)
    workdir = Path(tempfile.mkdtemp(dir=str(base)))

    handler = logging.FileHandler(logs / f"{date.today().isoformat()}.log")
    handler.setFormatter(logging.Formatter("%(asctime)s %(message)s"))
    log = logging.getLogger("hozo.proxy")
    log.setLevel(logging.INFO)
    log.addHandler(handler)
    try:
        yield workdir / "proxy.sock"
    finally:
        log.removeHandler(handler)
        handler.close()
        shutil.rmtree(workdir, ignore_errors=True)
