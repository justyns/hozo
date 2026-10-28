import os
import subprocess

import pytest
from conftest import HOZO_CLI

import hozo
from hozo import cli
from hozo.env import build_env
from hozo.policy import resolve_policy


def test_bare_prints_usage(capsys):
    assert cli.main([]) == 0
    assert "hozo" in capsys.readouterr().out


def test_version_flag(capsys):
    assert cli.main(["--version"]) == 0
    assert capsys.readouterr().out.strip() == hozo.__version__


def _run(args, **kw):
    return subprocess.run([*HOZO_CLI, *args], capture_output=True, text=True, **kw)


def test_version_after_the_separator_belongs_to_the_command():
    res = _run(["+untrusted", "--", "echo", "--version"])
    assert res.returncode == 0
    assert res.stdout.strip() != hozo.__version__


def test_profile_list(capsys):
    assert cli.main(["profile", "list"]) == 0
    out = capsys.readouterr().out
    assert "base" in out and "untrusted" in out


def test_explain_verb(capsys):
    assert cli.main(["explain", "+untrusted", "--", "echo", "hi"]) == 0
    out = capsys.readouterr().out
    assert "Workdir:" in out and "Backend:" in out


def test_run_missing_command_errors():
    assert cli.main(["run", "+untrusted"]) == 2


def test_unknown_option_errors():
    assert cli.main(["--frobnicate", "--", "true"]) == 2


needs_sandbox = pytest.mark.skipif(not hozo.check_available(), reason="no sandbox runtime installed")


@needs_sandbox
def test_run_success_returncode(tmp_path):
    # project defaults to cwd; mounted in place
    assert (
        _run(["+untrusted", "--", "sh", "-c", f'test "$(pwd)" = {os.path.realpath(tmp_path)}'], cwd=tmp_path).returncode
        == 0
    )


@needs_sandbox
def test_run_failure_returncode(tmp_path):
    assert _run(["+untrusted", "--", "false"], cwd=tmp_path).returncode == 1


def test_value_option_missing_value_errors():
    assert cli.main(["--network", "--no-base", "+untrusted", "--", "true"]) == 2


def test_allow_flags_grant_net_and_paths(capsys):
    rc = cli.main(["explain", "--allow-net=a.com", "--allow-read=/etc/hosts", "--allow-write=/tmp/x", "--", "true"])
    out = capsys.readouterr().out
    assert rc == 0
    assert "Network:  proxy (allow: a.com)" in out
    assert "/etc/hosts" in out and "/tmp/x" in out


def test_allow_read_requires_paths():
    assert cli.main(["--allow-read", "--", "true"]) == 2


def test_allow_env_passes_named_vars_through(capsys, monkeypatch):
    monkeypatch.setenv("HOZO_TEST_GRANTED", "1")
    monkeypatch.setenv("HOZO_TEST_OTHER", "1")
    assert cli.main(["explain", "--allow-env=HOZO_TEST_GRANTED", "--", "true"]) == 0
    env_line = next(line for line in capsys.readouterr().out.splitlines() if line.startswith("Env:"))
    assert "HOZO_TEST_GRANTED" in env_line and "HOZO_TEST_OTHER" not in env_line


def test_allow_env_keeps_the_host_value_over_defaults(monkeypatch):
    monkeypatch.setenv("PATH", "/opt/tool/bin:/usr/bin")
    monkeypatch.setenv("XDG_CACHE_HOME", "/host/cache")
    request, _ = cli._parse_flags(["--allow-env=PATH,XDG_CACHE_HOME"])
    env = build_env(resolve_policy(request))
    assert env["PATH"] == "/opt/tool/bin:/usr/bin"
    assert env["XDG_CACHE_HOME"] == "/host/cache"
