import pytest

import hozo
from hozo import cli


def test_bare_prints_usage(capsys):
    assert cli.main([]) == 0
    assert "hozo" in capsys.readouterr().out


def test_profile_list(capsys):
    assert cli.main(["profile", "list"]) == 0
    out = capsys.readouterr().out
    assert "base" in out and "untrusted" in out


def test_explain_verb(capsys):
    assert cli.main(["explain", "+untrusted", "--", "echo", "hi"]) == 0
    out = capsys.readouterr().out
    assert "/work" in out and "bwrap" in out


def test_run_missing_command_errors():
    assert cli.main(["run", "+untrusted"]) == 2


def test_unknown_option_errors():
    assert cli.main(["--frobnicate", "--", "true"]) == 2


needs_bwrap = pytest.mark.skipif(not hozo.check_available(), reason="bwrap not installed")


@needs_bwrap
def test_run_success_returncode(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    assert cli.main(["+untrusted", "--", "sh", "-c", 'test "$(pwd)" = /work']) == 0


@needs_bwrap
def test_run_failure_returncode(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    assert cli.main(["+untrusted", "--", "false"]) == 1


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
