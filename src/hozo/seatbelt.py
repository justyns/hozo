"""The macOS Seatbelt backend: render a ResolvedPolicy into an SBPL profile and run it
under ``sandbox-exec``.

``build_seatbelt_profile`` is the pure renderer (policy -> SBPL text); ``SeatbeltBackend``
canonicalizes paths, mints a throwaway ``TMPDIR``, writes the profile to a temp file, and
runs ``sandbox-exec -f <profile> -- <command>``. Isolation is filter-based, not namespace
based: unbound paths are simply denied, so ``$HOME`` stays the real home path and only the
explicitly-bound subpaths under it are reachable.

Three facts drive the profile:
  * dylibs need ``file-read*`` AND ``file-map-executable``; a plain read grant is not
    enough to run a binary.
  * file rules match the symlink-resolved path, so every bind source is ``realpath``'d to
    its ``/private/...`` form before it lands in a rule.
  * interactive stdio is ``/dev/ttysNNN``, not ``/dev/tty``, and ``file-ioctl`` matches
    that path; without a rule for it ``tcsetattr`` and ``TIOCGWINSZ`` are denied.
SBPL cannot filter egress by hostname (the host token is only ``localhost`` or ``*``), so
host allowlisting stays in the proxy; proxy mode just pins egress to its loopback port.
"""

from __future__ import annotations

import os
import shutil
import tempfile
import textwrap
from contextlib import ExitStack
from dataclasses import replace
from pathlib import Path

from .backend import Backend, SandboxResult
from .env import build_env
from .errors import ProfileError
from .policy import ResolvedPolicy
from .profiles import Bind
from .proxy import BackgroundProxy

SANDBOX_EXEC = "/usr/bin/sandbox-exec"

# Stand-in path for `explain`: the real scratch dir is a per-run temporary.
_EXPLAIN_SCRATCH = "<per-run-scratch>"

# Apple's own base profile supplies the platform plumbing — dyld and the shared cache, the
# mach services and /dev nodes every process needs — and tracks OS changes so this file
# doesn't have to. Hand-vendoring that set instead looked more robust and wasn't: the
# vendored version couldn't start /bin/echo on macOS 26. Keep the split as: system.sb owns
# the platform, the rules below own hozo's policy.
_HEADER = """\
(version 1)
(deny default)
(import "system.sb")
(allow process-fork)
(allow process-exec*)
(allow signal (target same-sandbox))
(allow file-read-metadata)
; Where executables and their libraries live; Homebrew's prefix differs by arch.
(allow file-read* file-map-executable
  (subpath "/usr")
  (subpath "/bin")
  (subpath "/sbin")
  (subpath "/System")
  (subpath "/opt/homebrew")
  (subpath "/usr/local"))
(allow file-read*
  (subpath "/private/etc")
  (subpath "/Library/Apple"))
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
  ; The controlling terminal and pty allocation.
  (literal "/dev/ptmx")
  (regex #"^/dev/ttys[0-9]+$"))"""

# Full network + working DNS. `network*` alone does NOT cover name resolution, which goes
# through mach IPC to mDNSResponder/opendirectoryd. Mirrors Chromium's network.sb.
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


# For OAuth callbacks and dev servers. No outbound grant, and proxy mode only: macOS
# loopback is shared with the host, so `network: none` keeps offering no socket at all.
_LOOPBACK_LISTEN = """\
(allow network-bind (local ip "localhost:*"))
(allow network-inbound (local ip "localhost:*"))"""


def _q(path: str) -> str:
    """Quote a path as an SBPL string literal, escaping backslash and double-quote."""
    return '"' + path.replace("\\", "\\\\").replace('"', '\\"') + '"'


def _subpaths(op: str, paths: list[str]) -> str:
    body = "\n".join(f"  (subpath {_q(p)})" for p in paths)
    return f"(allow {op}\n{body})"


def _network_block(mode: str, proxy_port: int | None) -> str:
    if mode == "host":
        return _HOST_NETWORK
    if mode == "proxy":
        if proxy_port is None:
            # Static/explain view; run() injects the real loopback port. Emitting no allow
            # rule here also fails closed if this profile is used without a bound port.
            egress = "; network: proxy — egress limited to the loopback proxy (port injected per run)"
        else:
            egress = f'(allow network-outbound (remote tcp "localhost:{proxy_port}"))'
        return f"{egress}\n{_LOOPBACK_LISTEN}"
    return "; network: none (default-deny)"


def build_seatbelt_profile(policy: ResolvedPolicy, *, proxy_port: int | None = None) -> str:
    """Render a policy into an SBPL profile string (pure; paths are used verbatim, so the
    caller canonicalizes them first). rw grants include read + write + map-executable so a
    project's own binaries (venv, node_modules/.bin) can run.

    Raises ``ProfileError`` for policy this backend cannot express: currently ``tmpfs:``.
    """
    if policy.tmpfs:
        raise ProfileError(
            f"tmpfs: is not supported by the seatbelt backend. Granting {', '.join(sorted(policy.tmpfs))} "
            "would expose the real host path read-write rather than hide it. Use TMPDIR, which "
            "hozo points at a per-run scratch dir."
        )

    ro = sorted({b.source for b in policy.binds if b.mode == "ro"})
    rw = sorted({b.source for b in policy.binds if b.mode == "rw"})

    blocks = [_HEADER]
    if ro:
        blocks.append(_subpaths("file-read* file-map-executable", ro))
    if rw:
        blocks.append(_subpaths("file-read* file-write* file-map-executable", rw))
    blocks.append(_network_block(policy.network_mode, proxy_port))
    return "\n".join(blocks) + "\n"


def check_available() -> bool:
    return shutil.which("sandbox-exec") is not None


class SeatbeltBackend(Backend):
    """macOS Seatbelt (sandbox-exec)."""

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

            env = build_env(policy, environ=environ, proxy_port=port, scratch=scratch)
            env["TMPDIR"] = scratch  # isolated per-run temp; the real /var/folders TMPDIR is scrubbed
            profile = build_seatbelt_profile(_canonicalize(_with_scratch(policy, scratch)), proxy_port=port)

            # Written to its own dir, not to the sandbox-visible scratch.
            profile_dir = stack.enter_context(tempfile.TemporaryDirectory(prefix="hozo-sb-"))
            profile_path = Path(profile_dir) / "policy.sb"
            profile_path.write_text(profile)

            argv = [SANDBOX_EXEC, "-f", str(profile_path), *policy.command]
            return self._spawn(argv, env, policy, capture=capture, cwd=policy.cwd)


def _with_scratch(policy: ResolvedPolicy, scratch: str) -> ResolvedPolicy:
    """Add the per-run scratch as an rw bind so it gets realpath'd and shows up in explain."""
    return replace(policy, binds=[*policy.binds, Bind(source=scratch, mode="rw")])


def _canonicalize(policy: ResolvedPolicy) -> ResolvedPolicy:
    """realpath every bind source to its /private/... form — Seatbelt matches rules against
    the symlink-resolved path, so /tmp/x must be written as /private/tmp/x."""
    return replace(policy, binds=[replace(b, source=os.path.realpath(b.source)) for b in policy.binds])
