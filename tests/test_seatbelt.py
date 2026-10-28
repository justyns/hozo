import os
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest
from conftest import policy_with_base, proxy_up, wait_until

import hozo
from hozo import cli, seatbelt
from hozo.errors import ProfileError
from hozo.policy import SandboxRequest, resolve_policy
from hozo.profiles import Bind


def _macos_policy(tmp_path, **kw):
    # The Linux default base sets tmpfs:, which the renderer rejects.
    return policy_with_base("base-macos", tmp_path, **kw)


def _profile(tmp_path, **kw):
    return seatbelt.build_seatbelt_profile(_macos_policy(tmp_path, **kw))


def _bare(binds):
    # No base and no project bind, so only the given binds appear in the profile.
    policy = policy_with_base(None, Path("/proj"), command=["x"], bind_project=False, binds=binds)
    return seatbelt.build_seatbelt_profile(policy)


def test_profile_denies_by_default(tmp_path):
    assert _profile(tmp_path).startswith("(version 1)\n(deny default)")


def test_system_essentials_present(tmp_path):
    prof = _profile(tmp_path)
    assert "(allow process-exec*)" in prof
    # dylibs need file-read* AND the distinct file-map-executable op
    assert "file-map-executable" in prof
    # Apple's base profile owns the platform plumbing (dyld, the shared cache, mach services)
    assert '(import "system.sb")' in prof
    assert '(subpath "/usr")' in prof


def test_profile_grants_the_controlling_tty(tmp_path):
    # Without these, file-ioctl on the tty is denied and raw mode fails.
    prof = _profile(tmp_path)
    assert r'(regex #"^/dev/ttys[0-9]+$")' in prof
    assert '(literal "/dev/ptmx")' in prof


def test_ro_and_rw_binds_land_in_the_right_blocks():
    prof = _bare([Bind(source="/opt/ro", mode="ro"), Bind(source="/opt/rw", mode="rw")])
    ro_section = prof.split("(allow file-read* file-write*")[0]  # everything before the rw block
    assert '(subpath "/opt/ro")' in ro_section  # read-only path in the read block
    assert '(subpath "/opt/rw")' not in ro_section  # writable path is *not* in the read block
    assert '(subpath "/opt/rw")' in prof  # ...it's in the rw block


def test_tmpfs_is_rejected(tmp_path):
    # Granting it would expose the real host path.
    p = _macos_policy(tmp_path)
    p.tmpfs = ["/tmp"]
    with pytest.raises(ProfileError, match="tmpfs"):
        seatbelt.build_seatbelt_profile(p)


def test_rw_binds_are_writable(tmp_path):
    prof = _profile(tmp_path, binds=[Bind(source="/var/scratch", mode="rw")])
    rw_block = prof.split("(allow file-read* file-write*", 1)[1]
    assert '(subpath "/var/scratch")' in rw_block


def test_network_none_has_no_egress(tmp_path):
    prof = _profile(tmp_path, network="none")
    assert "network-outbound" not in prof
    assert "network-bind" not in prof  # not even a loopback listener
    assert "network: none" in prof


def test_network_host_allows_network_and_dns(tmp_path):
    prof = _profile(tmp_path, network="host")
    assert "(allow network-outbound)" in prof
    assert "com.apple.mDNSResponder" in prof  # DNS isn't covered by network*


def test_proxy_mode_pins_egress_to_loopback_port(tmp_path):
    p = _macos_policy(tmp_path, profiles=["proxy"])
    prof = seatbelt.build_seatbelt_profile(p, proxy_port=45678)
    assert '(allow network-outbound (remote tcp "localhost:45678"))' in prof


def test_proxy_mode_allows_a_loopback_listener(tmp_path):
    p = _macos_policy(tmp_path, profiles=["proxy"])
    for prof in (seatbelt.build_seatbelt_profile(p, proxy_port=45678), seatbelt.build_seatbelt_profile(p)):
        assert '(allow network-bind (local ip "localhost:*"))' in prof
        assert '(allow network-inbound (local ip "localhost:*"))' in prof


def test_proxy_mode_without_port_fails_closed(tmp_path):
    p = _macos_policy(tmp_path, profiles=["proxy"])
    assert "network-outbound" not in seatbelt.build_seatbelt_profile(p)  # no port -> no egress rule


def test_paths_are_sbpl_escaped():
    prof = _bare([Bind(source='/weird/"quote"', mode="ro")])
    assert r"/weird/\"quote\"" in prof  # embedded quotes escaped, not breaking the literal


def test_canonicalize_resolves_symlinks(tmp_path):
    real = tmp_path / "real"
    real.mkdir()
    link = tmp_path / "link"
    link.symlink_to(real)
    p = resolve_policy(
        SandboxRequest(
            command=["x"],
            project=str(tmp_path),
            no_base=True,
            bind_project=False,
            binds=[Bind(source=str(link), mode="ro")],
        )
    )
    assert seatbelt._canonicalize(p).binds[0].source == str(real)


def test_describe_renders_the_profile(tmp_path):
    p = _macos_policy(tmp_path, command=["echo", "hi"])
    text = seatbelt.SeatbeltBackend().describe(p)
    assert text.startswith("seatbelt profile:") and "(deny default)" in text


def test_describe_reports_the_per_run_scratch(tmp_path):
    # run() grants this, so explain must not under-report it.
    text = seatbelt.SeatbeltBackend().describe(_macos_policy(tmp_path))
    rw_block = text.split("(allow file-read* file-write*", 1)[1]
    assert seatbelt._EXPLAIN_SCRATCH in rw_block


def test_explain_with_seatbelt_renders_profile(tmp_path):
    p = _macos_policy(tmp_path)
    text = hozo.explain_policy(p, backend=seatbelt.SeatbeltBackend(), environ={})
    assert "seatbelt profile:" in text and "(deny default)" in text


class _ExecError(Exception):
    pass


def test_cli_run_replaces_the_process_with_sandbox_exec(tmp_path, monkeypatch):
    monkeypatch.setattr("platform.system", lambda: "Darwin")
    monkeypatch.setattr(seatbelt, "check_available", lambda: True)
    monkeypatch.setattr(seatbelt, "_start_helper", lambda policy, cleanup: None)
    # A regression to the run-as-a-child path then returns 0 instead of reaching execve.
    monkeypatch.setattr("subprocess.run", lambda *a, **kw: subprocess.CompletedProcess(a, 0))
    calls, resets = [], []
    monkeypatch.setattr(signal, "signal", lambda sig, handler: resets.append((sig, handler)))

    def fake_execve(path, argv, env):
        calls.append((path, argv, env, os.getcwd()))
        raise _ExecError

    monkeypatch.setattr(os, "execve", fake_execve)
    monkeypatch.chdir(tmp_path)
    with pytest.raises(_ExecError):
        cli.main(["--", "echo", "hi"])

    path, argv, env, cwd = calls[0]
    assert path == argv[0] == seatbelt.SANDBOX_EXEC
    assert argv[1] == "-f" and Path(argv[2]).read_text().startswith("(version 1)")
    assert argv[3:] == ["echo", "hi"]
    assert cwd == str(tmp_path)
    assert os.path.realpath(env["TMPDIR"]) in Path(argv[2]).read_text()
    assert resets == [(signal.SIGPIPE, signal.SIG_DFL), (signal.SIGXFSZ, signal.SIG_DFL)]
    for leftover in (env["TMPDIR"], os.path.dirname(argv[2])):  # the mocked-out helper's job
        shutil.rmtree(leftover)


_HELPER_HOST = """
import sys, time
from hozo import seatbelt
from hozo.policy import ResolvedPolicy
print(seatbelt._start_helper(ResolvedPolicy(network_mode="proxy"), [sys.argv[1]]), flush=True)
time.sleep(60)
"""


def test_helper_serves_the_proxy_until_its_parent_is_killed(tmp_path):
    # The helper's parent stands in for the exec'd command; plain POSIX, so Linux runs it too.
    scratch = tmp_path / "scratch"
    scratch.mkdir()
    host = subprocess.Popen([sys.executable, "-c", _HELPER_HOST, str(scratch)], stdout=subprocess.PIPE, text=True)
    port = int(host.stdout.readline())
    assert proxy_up(port) and scratch.exists()

    host.kill()
    host.wait()
    assert wait_until(lambda: not scratch.exists())
    assert wait_until(lambda: not proxy_up(port))


_FAILING_HELPER_HOST = """
import sys
from hozo import seatbelt
from hozo.policy import ResolvedPolicy
def fail(*args):
    raise RuntimeError("proxy start failed")
seatbelt.BackgroundProxy = fail
seatbelt._start_helper(ResolvedPolicy(network_mode="proxy"), [sys.argv[1]])
"""


def test_helper_start_failure_reaches_the_callers_stderr(tmp_path):
    scratch = tmp_path / "scratch"
    scratch.mkdir()
    host = subprocess.run([sys.executable, "-c", _FAILING_HELPER_HOST, str(scratch)], capture_output=True, text=True)
    assert "RuntimeError: proxy start failed" in host.stderr
    assert "hozo helper failed to start" in host.stderr
    assert not scratch.exists()


def test_socket_binds_allow_connecting_to_that_socket(tmp_path):
    sock_path = os.path.join(tempfile.mkdtemp(prefix="hz-"), "s")  # short: sun_path caps at 104 on macOS
    server = socket.socket(socket.AF_UNIX)
    server.bind(sock_path)
    prof = _bare([Bind(source=sock_path, mode="ro"), Bind(source=str(tmp_path), mode="ro")])
    server.close()
    shutil.rmtree(os.path.dirname(sock_path))
    rule = f'(allow network-outbound\n  (remote unix-socket (path-literal "{sock_path}")))'
    assert rule in prof
    assert prof.count("unix-socket") == 1  # the plain directory bind gets no socket rule
