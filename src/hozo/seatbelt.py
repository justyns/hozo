"""The macOS Seatbelt backend: render a ResolvedPolicy into an SBPL profile and run it
under ``sandbox-exec``.

``build_seatbelt_profile`` is the pure renderer (policy -> SBPL text); ``SeatbeltBackend``
canonicalizes paths, mints a throwaway ``TMPDIR``, writes the profile to a temp file, and
runs ``sandbox-exec -f <profile> -- <command>``. Isolation is filter-based, not namespace
based: unbound paths are simply denied, so ``$HOME`` stays the real home path and only the
explicitly-bound subpaths under it are reachable.

Two facts drive the profile (both cost real projects a bug):
  * dylibs and the dyld shared cache need ``file-read*`` AND ``file-map-executable`` — the
    latter is a distinct operation. The cache lives in the OS cryptex on Ventura+ .
  * Seatbelt matches file rules against the symlink-resolved path, so every bind source is
    ``realpath``'d to its ``/private/...`` form before it lands in a rule.
SBPL cannot filter egress by hostname (the host token is only ``localhost`` or ``*``), so
host allowlisting stays in the proxy; proxy mode just pins egress to its loopback port.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
from dataclasses import replace

from .backend import Backend, SandboxResult
from .env import build_env
from .policy import ResolvedPolicy
from .proxy import BackgroundProxy

SANDBOX_EXEC = "/usr/bin/sandbox-exec"

# The "nothing runs without these" grants, vendored rather than (import "system.sb") — the
# bundled profile can fail to compile across releases. Mirrors bwrap's _merged_usr_links().
_HEADER = """\
(version 1)
(deny default)
(allow process-fork)
(allow process-exec*)
(allow sysctl-read)
(allow signal (target same-sandbox))
(allow file-read-metadata)
(allow file-read* file-map-executable
  (subpath "/usr/lib")
  (subpath "/usr/bin")
  (subpath "/usr/sbin")
  (subpath "/bin")
  (subpath "/sbin")
  (subpath "/System/Library/dyld")
  (subpath "/System/Cryptexes/OS")
  (subpath "/System/Cryptexes/App")
  (subpath "/System/Volumes/Preboot/Cryptexes/OS")
  (subpath "/System/Volumes/Preboot/Cryptexes/App/System")
  (subpath "/opt/homebrew")
  (subpath "/usr/local"))
(allow file-read*
  (subpath "/System/Library/Frameworks")
  (subpath "/System/Library/PrivateFrameworks")
  (subpath "/usr/share")
  (subpath "/private/etc")
  (subpath "/Library/Apple")
  (subpath "/private/var/db/timezone"))
(allow mach-lookup
  (global-name "com.apple.system.opendirectoryd.libinfo")
  (global-name "com.apple.system.opendirectoryd.membership")
  (global-name "com.apple.system.notification_center")
  (global-name "com.apple.logd")
  (global-name "com.apple.system.logger")
  (global-name "com.apple.CoreServices.coreservicesd")
  (global-name "com.apple.bsd.dirhelper")
  (global-name "com.apple.SecurityServer")
  (global-name "com.apple.trustd.agent"))
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
  (literal "/dev/dtracehelper"))"""

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
            return "; network: proxy — egress limited to the loopback proxy (port injected per run)"
        return f'(allow network-outbound (remote tcp "localhost:{proxy_port}"))'
    return "; network: none (default-deny)"


def build_seatbelt_profile(
    policy: ResolvedPolicy, *, proxy_port: int | None = None, writable_scratch: tuple[str, ...] = ()
) -> str:
    """Render a policy into an SBPL profile string (pure; paths are used verbatim, so the
    caller canonicalizes them first). rw grants include read + write + map-executable so a
    project's own binaries (venv, node_modules/.bin) can run."""
    ro = sorted({b.source for b in policy.binds if b.mode == "ro"})
    rw = sorted({b.source for b in policy.binds if b.mode == "rw"} | set(policy.tmpfs) | set(writable_scratch))

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

    def build_argv(self, policy: ResolvedPolicy, *, proxy=None) -> list[str]:
        # Inspection form (used by explain): inline the profile via -p. run() writes the
        # profile to a file (-f) and injects the runtime TMPDIR/proxy port.
        return [SANDBOX_EXEC, "-p", build_seatbelt_profile(policy), *policy.command]

    def run(self, policy: ResolvedPolicy, *, environ=None, capture: bool = False) -> SandboxResult:
        canon = _canonicalize(policy)
        scratch = tempfile.mkdtemp(prefix="hozo-")
        try:
            if policy.network_mode == "proxy":
                with BackgroundProxy(allowed_hosts=policy.proxy_allow_hosts, tcp_port=0) as bp:
                    env = _sandbox_env(policy, environ, scratch, proxy_port=bp.port)
                    profile = build_seatbelt_profile(canon, proxy_port=bp.port, writable_scratch=(scratch,))
                    return self._spawn(profile, policy, env, capture)
            env = _sandbox_env(policy, environ, scratch, proxy_port=None)
            profile = build_seatbelt_profile(canon, writable_scratch=(scratch,))
            return self._spawn(profile, policy, env, capture)
        finally:
            shutil.rmtree(scratch, ignore_errors=True)

    def _spawn(self, profile: str, policy: ResolvedPolicy, env: dict, capture: bool) -> SandboxResult:
        with tempfile.NamedTemporaryFile("w", suffix=".sb", delete=False) as fh:
            fh.write(profile)
            profile_path = fh.name
        argv = [SANDBOX_EXEC, "-f", profile_path, *policy.command]
        try:
            if capture:
                proc = subprocess.run(argv, env=env, cwd=policy.cwd, capture_output=True, text=True)
                return SandboxResult(proc.returncode, proc.stdout, proc.stderr, policy, argv, self.name)
            proc = subprocess.run(argv, env=env, cwd=policy.cwd)
            return SandboxResult(proc.returncode, None, None, policy, argv, self.name)
        finally:
            os.unlink(profile_path)


def _canonicalize(policy: ResolvedPolicy) -> ResolvedPolicy:
    """realpath every bind source and tmpfs path to its /private/... form — Seatbelt matches
    rules against the symlink-resolved path, so /tmp/x must be written as /private/tmp/x."""
    binds = [replace(b, source=os.path.realpath(b.source)) for b in policy.binds]
    tmpfs = [os.path.realpath(p) for p in policy.tmpfs]
    return replace(policy, binds=binds, tmpfs=tmpfs)


def _sandbox_env(policy, environ, scratch: str, *, proxy_port: int | None) -> dict[str, str]:
    env = build_env(policy, environ=environ)
    env["TMPDIR"] = scratch  # isolated per-run temp; the real /var/folders TMPDIR is scrubbed
    if proxy_port is not None:
        url = f"http://127.0.0.1:{proxy_port}"  # numeric so the client never resolves DNS
        no_proxy = "localhost,127.0.0.1,::1"
        env.update(
            HTTP_PROXY=url, HTTPS_PROXY=url, http_proxy=url, https_proxy=url, NO_PROXY=no_proxy, no_proxy=no_proxy
        )
    return env
