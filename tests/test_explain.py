from hozo import explain
from hozo.policy import SandboxRequest, resolve_policy


def test_explain_lists_sections(tmp_path):
    p = resolve_policy(SandboxRequest(command=["echo", "hi"], project=str(tmp_path)))
    text = explain.explain_policy(p, environ={"TERM": "xterm"})
    assert "Profiles:" in text and "base" in text
    assert "Network:" in text
    assert "/work" in text
    assert "Env:" in text and "HOME" in text
    assert "bwrap" in text


def test_explain_redacts_env_values(tmp_path):
    p = resolve_policy(SandboxRequest(command=["true"], project=str(tmp_path)))
    text = explain.explain_policy(p, environ={"TERM": "sentinel-value"})
    assert "sentinel-value" not in text  # value redacted
    assert "TERM" in text  # name still shown


def test_writable_shows_host_source(tmp_path):
    p = resolve_policy(SandboxRequest(command=["true"], project=str(tmp_path)))
    assert f"Writable host paths: {tmp_path}" in explain.explain_policy(p, environ={})


def test_command_setenv_not_redacted(tmp_path):
    p = resolve_policy(SandboxRequest(command=["tool", "--setenv", "K", "V"], project=str(tmp_path)))
    argv = next(
        line for line in explain.explain_policy(p, environ={}).splitlines() if line.strip().startswith("bwrap --")
    )
    assert "tool --setenv K V" in argv
