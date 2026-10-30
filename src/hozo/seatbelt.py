"""Render a ResolvedPolicy as an SBPL profile and run it under ``sandbox-exec``."""

from __future__ import annotations

import os
import shutil
import signal
import stat
import tempfile
import textwrap
import time
import traceback
from contextlib import ExitStack
from dataclasses import replace
from pathlib import Path
from typing import NoReturn

from .backend import Backend, SandboxResult
from .env import build_env
from .errors import HozoError, ProfileError
from .policy import ResolvedPolicy
from .profiles import Bind
from .proxy import BackgroundProxy

SANDBOX_EXEC = "/usr/bin/sandbox-exec"

# Stand-in for `explain`. The real scratch dir exists only during a run.
_EXPLAIN_SCRATCH = "<per-run-scratch>"

# system.sb supplies dyld, the shared cache, mach services and /dev nodes, and tracks macOS
# releases. Keep it imported. The rules below hold hozo's policy.
_HEADER = """\
(version 1)
(deny default)
(import "system.sb")
(allow process-fork)
(allow process-exec*)
(allow signal (target same-sandbox))
(allow file-read-metadata)
; Running a binary needs file-map-executable as well as file-read*. Homebrew is /opt/homebrew
; on arm64, /usr/local on x86_64.
(allow file-read* file-map-executable
  (subpath "/usr")
  (subpath "/bin")
  (subpath "/sbin")
  (subpath "/System")
  (subpath "/opt/homebrew")
  (subpath "/usr/local")
  ; /usr/bin/git and friends are xcrun shims into the developer dir.
  (subpath "/Library/Developer/CommandLineTools")
  (regex #"^/Applications/Xcode[^/]*\\.app/"))
(allow file-read*
  (subpath "/private/etc")
  (subpath "/Library/Apple")
  ; xcodebuild's license check.
  (literal "/Library/Preferences/com.apple.dt.Xcode.plist"))
(allow file*
  (subpath "/dev/fd")
  (literal "/dev/null")
  (literal "/dev/zero")
  (literal "/dev/random")
  (literal "/dev/urandom")
  (literal "/dev/tty")
  (literal "/dev/stdin")
  (literal "/dev/stdout")
  (literal "/dev/stderr")
  (literal "/dev/dtracehelper")
  ; Interactive stdio is /dev/ttysNNN. tcsetattr and TIOCGWINSZ need file-ioctl on it, and
  ; /dev/ptmx allocates ptys.
  (literal "/dev/ptmx")
  (regex #"^/dev/ttys[0-9]+$"))"""

# `network*` does not cover DNS, which goes over mach IPC to mDNSResponder and opendirectoryd.
# Mirrors Chromium's network.sb.
_HOST_NETWORK = """\
(allow network-outbound)
(allow network-inbound)
(allow network-bind (local ip "*:*"))
(allow system-socket)
(allow mach-lookup
  (global-name "com.apple.mDNSResponder")
  (global-name "com.apple.SystemConfiguration.DNSConfiguration")
  (global-name "com.apple.SystemConfiguration.configd")
  (global-name "com.apple.networkd"))
(allow file-read*
  (literal "/private/etc/hosts")
  (literal "/private/etc/resolv.conf")
  (literal "/private/var/run/resolv.conf"))"""


# For OAuth callbacks and dev servers, proxy mode only. macOS loopback is shared with the host.
_LOOPBACK_LISTEN = """\
(allow network-bind (local ip "localhost:*"))
(allow network-inbound (local ip "localhost:*"))"""


def _q(path: str) -> str:
    """Quote a path as an SBPL string literal."""
    return '"' + path.replace("\\", "\\\\").replace('"', '\\"') + '"'


def _is_socket(path: str) -> bool:
    try:
        return stat.S_ISSOCK(os.stat(path).st_mode)
    except OSError:
        return False


def _subpaths(op: str, paths: list[str]) -> str:
    body = "\n".join(f"  (subpath {_q(p)})" for p in paths)
    return f"(allow {op}\n{body})"


def _network_block(mode: str, proxy_port: int | None) -> str:
    if mode == "host":
        return _HOST_NETWORK
    if mode == "proxy":
        if proxy_port is None:
            # The explain view. run() passes the port, and without one no egress rule is emitted.
            egress = "; network: proxy, egress only to the loopback proxy port (set per run)"
        else:
            egress = f'(allow network-outbound (remote tcp "localhost:{proxy_port}"))'
        return f"{egress}\n{_LOOPBACK_LISTEN}"
    return "; network: none (default-deny)"


def build_seatbelt_profile(policy: ResolvedPolicy, *, proxy_port: int | None = None) -> str:
    """Render a policy as SBPL. Bind sources must already be canonicalized. rw grants include
    file-map-executable so venv and node_modules binaries run."""
    if policy.tmpfs:
        raise ProfileError(
            f"tmpfs is not supported on macOS: {', '.join(sorted(policy.tmpfs))}. "
            "Use $TMPDIR, which hozo points at a per-run scratch dir."
        )

    ro = sorted({b.source for b in policy.binds if b.mode == "ro"})
    rw = sorted({b.source for b in policy.binds if b.mode == "rw"})

    blocks = [_HEADER]
    if ro:
        blocks.append(_subpaths("file-read* file-map-executable", ro))
    if rw:
        blocks.append(_subpaths("file-read* file-write* file-map-executable", rw))
    # A file grant does not cover connect() on a unix socket.
    sockets = sorted({b.source for b in policy.binds if _is_socket(b.source)})
    if sockets:
        body = "\n".join(f"  (remote unix-socket (path-literal {_q(p)}))" for p in sockets)
        blocks.append(f"(allow network-outbound\n{body})")
    blocks.append(_network_block(policy.network_mode, proxy_port))
    return "\n".join(blocks) + "\n"


def check_available() -> bool:
    return shutil.which("sandbox-exec") is not None


class SeatbeltBackend(Backend):
    name = "seatbelt"

    def is_available(self) -> bool:
        return check_available()

    def describe(self, policy: ResolvedPolicy) -> str:
        # Canonicalize before adding the stand-in; realpath would resolve it against the cwd.
        profile = build_seatbelt_profile(_with_scratch(_canonicalize(policy), _EXPLAIN_SCRATCH))
        return f"{self.name} profile:\n" + textwrap.indent(profile, "  ")

    def run(self, policy: ResolvedPolicy, *, environ=None, capture: bool = False) -> SandboxResult:
        with ExitStack() as stack:
            scratch = stack.enter_context(tempfile.TemporaryDirectory(prefix="hozo-", ignore_cleanup_errors=True))
            port = None
            if policy.network_mode == "proxy":
                port = stack.enter_context(BackgroundProxy(0, policy.proxy_allow_hosts)).port
            profile_dir = stack.enter_context(tempfile.TemporaryDirectory(prefix="hozo-sb-"))
            argv, env = _invocation(policy, environ, scratch, profile_dir, port)
            return self._spawn(argv, env, policy, capture=capture, cwd=policy.cwd)

    def exec(self, policy: ResolvedPolicy, *, environ=None) -> NoReturn:
        """sandbox-exec has no die-with-parent, so replace this process with it. A SIGKILL to
        the caller's pid then reaches the command."""
        scratch = tempfile.mkdtemp(prefix="hozo-")
        profile_dir = tempfile.mkdtemp(prefix="hozo-sb-")
        port = _start_helper(policy, [scratch, profile_dir])
        argv, env = _invocation(policy, environ, scratch, profile_dir, port)
        os.chdir(policy.cwd)
        # Python starts with these ignored, and execve keeps SIG_IGN.
        signal.signal(signal.SIGPIPE, signal.SIG_DFL)
        signal.signal(signal.SIGXFSZ, signal.SIG_DFL)
        os.execve(SANDBOX_EXEC, argv, env)


def _invocation(
    policy: ResolvedPolicy, environ, scratch: str, profile_dir: str, port: int | None
) -> tuple[list[str], dict[str, str]]:
    env = build_env(policy, environ=environ, proxy_port=port, scratch=scratch)
    env["TMPDIR"] = scratch  # The host's /var/folders TMPDIR is scrubbed.
    profile = build_seatbelt_profile(_canonicalize(_with_scratch(policy, scratch)), proxy_port=port)
    # Written to its own dir, not to the sandbox-visible scratch.
    profile_path = Path(profile_dir) / "policy.sb"
    profile_path.write_text(profile)
    return [SANDBOX_EXEC, "-f", str(profile_path), *policy.command], env


def _start_helper(policy: ResolvedPolicy, cleanup: list[str]) -> int | None:
    """Fork a helper that serves the proxy and removes ``cleanup`` once it is reparented,
    which means the exec'd command exited. Returns the proxy port, if any."""
    read_fd, write_fd = os.pipe()
    parent = os.getpid()
    if os.fork() == 0:
        os.close(read_fd)
        status = 1
        try:
            os.setsid()  # keep a terminal's Ctrl-C off the helper
            with ExitStack() as stack:
                port = None
                if policy.network_mode == "proxy":
                    port = stack.enter_context(BackgroundProxy(0, policy.proxy_allow_hosts)).port
                # Let the caller's stdio close when the command exits.
                devnull = os.open(os.devnull, os.O_RDWR)
                for fd in (0, 1, 2):
                    os.dup2(devnull, fd)
                os.write(write_fd, f"{port or 0}\n".encode())
                os.close(write_fd)
                while os.getppid() == parent:
                    time.sleep(0.1)
            status = 0
        except Exception:
            traceback.print_exc()
        finally:
            for path in cleanup:
                shutil.rmtree(path, ignore_errors=True)
            os._exit(status)

    os.close(write_fd)
    with os.fdopen(read_fd) as handshake:
        reply = handshake.readline().strip()
    if not reply:
        raise HozoError("hozo helper failed to start")
    return int(reply) or None


def _with_scratch(policy: ResolvedPolicy, scratch: str) -> ResolvedPolicy:
    return replace(policy, binds=[*policy.binds, Bind(source=scratch, mode="rw")])


def _canonicalize(policy: ResolvedPolicy) -> ResolvedPolicy:
    """Seatbelt matches symlink-resolved paths, so /tmp/x must appear as /private/tmp/x."""
    return replace(policy, binds=[replace(b, source=os.path.realpath(b.source)) for b in policy.binds])
