import os
import platform

import pytest

from hozo import bwrap
from hozo.env import build_env
from hozo.policy import SandboxRequest, resolve_policy
from hozo.proxy import BRIDGE_PORT, ProxyMount

# The renderer is Linux-only, and these assertions expect the Linux `base` profile
# (macOS resolves `base-macos`, which binds no system paths of its own).
pytestmark = pytest.mark.skipif(platform.system() != "Linux", reason="bwrap renderer is Linux-only")


def _has_seq(argv, seq):
    n = len(seq)
    return any(argv[i : i + n] == seq for i in range(len(argv) - n + 1))


def _argv(tmp_path, **req_kw):
    req_kw.setdefault("command", ["true"])
    req_kw.setdefault("project", str(tmp_path))
    return bwrap.build_bwrap_argv(resolve_policy(SandboxRequest(**req_kw)))


def test_argv_is_list_starting_bwrap_ending_command(tmp_path):
    argv = _argv(tmp_path)
    assert isinstance(argv, list)
    assert argv[0] == "bwrap"
    assert argv[-1] == "true"


def test_network_none_unshares_net(tmp_path):
    assert "--unshare-net" in _argv(tmp_path, network="none")


def test_network_host_keeps_net(tmp_path):
    assert "--unshare-net" not in _argv(tmp_path, network="host")


def test_project_bound_in_place_and_chdir(tmp_path):
    argv = _argv(tmp_path)
    assert _has_seq(argv, ["--bind", str(tmp_path), str(tmp_path)])
    assert _has_seq(argv, ["--chdir", str(tmp_path)])


def test_usr_bind_and_merged_usr(tmp_path):
    argv = _argv(tmp_path)
    assert _has_seq(argv, ["--ro-bind", "/usr", "/usr"])
    if os.path.islink("/bin"):
        assert "--symlink" in argv


def test_scratch_dir_created_after_the_tmpfs(tmp_path):
    argv = _argv(tmp_path)
    assert _has_seq(argv, ["--dir", bwrap.SCRATCH_DIR])
    assert argv.index(bwrap.SCRATCH_DIR) > argv.index("--tmpfs")  # a tmpfs would mount over it


def test_no_env_flags_in_argv(tmp_path):
    # env is bwrap's process environment, not --setenv args, so it never hits the cmdline
    argv = _argv(tmp_path)
    assert "--setenv" not in argv and "--clearenv" not in argv


def test_sandbox_env_scrubs_secrets_keeps_allowed(tmp_path):
    policy = resolve_policy(SandboxRequest(command=["true"], project=str(tmp_path)))
    env = build_env(policy, environ={"ANTHROPIC_API_KEY": "sekret", "TERM": "xterm"})
    assert "ANTHROPIC_API_KEY" not in env  # not in the allowlist -> never copied
    assert env["TERM"] == "xterm"
    assert env["HOME"] == os.path.expanduser("~")


def test_check_available_returns_bool():
    assert isinstance(bwrap.check_available(), bool)


def test_proxy_mode_renders_bridge_binds_and_wrapper(tmp_path):
    policy = resolve_policy(SandboxRequest(command=["curl", "x"], project=str(tmp_path), profiles=["proxy"]))
    argv = bwrap.build_bwrap_argv(policy, proxy=ProxyMount("/h/proxy.sock", "/h/bridge.py"))
    assert "--unshare-net" in argv
    assert _has_seq(argv, ["--ro-bind", "/h/proxy.sock", "/run/hozo-proxy.sock"])
    assert _has_seq(argv, ["--ro-bind", "/h/bridge.py", "/run/hozo-bridge.py"])
    assert argv[-3:-1] == ["sh", "-c"]
    assert f"python3 /run/hozo-bridge.py /run/hozo-proxy.sock {BRIDGE_PORT}" in argv[-1]
    assert "exec curl x" in argv[-1]


def test_proxy_env_points_at_the_bridge_port(tmp_path):
    policy = resolve_policy(SandboxRequest(command=["x"], project=str(tmp_path), profiles=["proxy"]))
    env = build_env(policy, environ={}, proxy_port=BRIDGE_PORT)
    assert env["HTTP_PROXY"] == f"http://127.0.0.1:{BRIDGE_PORT}"
    assert env["NO_PROXY"] == "localhost,127.0.0.1,::1"


def test_proxy_mount_ignored_when_not_proxy(tmp_path):
    policy = resolve_policy(SandboxRequest(command=["true"], project=str(tmp_path), network="none"))
    argv = bwrap.build_bwrap_argv(policy, proxy=ProxyMount("/h/s", "/h/b"))
    assert "/run/hozo-proxy.sock" not in argv
