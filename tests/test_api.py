import pytest

import hozo


def test_public_symbols_importable():
    for name in (
        "SandboxRequest",
        "ResolvedPolicy",
        "SandboxResult",
        "SandboxRunner",
        "resolve_policy",
        "build_bwrap_argv",
        "explain_policy",
        "HozoError",
    ):
        assert hasattr(hozo, name)


def test_programmatic_request_without_yaml(tmp_path):
    # No on-disk profiles: built-ins resolve via importlib.resources.
    req = hozo.SandboxRequest(command=["true"], project=str(tmp_path), profiles=[], network="none")
    policy = hozo.resolve_policy(req)
    assert policy.network_mode == "none"
    assert hozo.build_bwrap_argv(policy)[0] == "bwrap"
    assert str(tmp_path) in hozo.explain_policy(policy, environ={})


def test_inline_overrides_beat_profiles(tmp_path):
    req = hozo.SandboxRequest(command=["true"], project=str(tmp_path), profiles=["untrusted"], network="host")
    assert hozo.resolve_policy(req).network_mode == "host"


def test_run_returns_result(tmp_path):
    if not hozo.check_available():
        pytest.skip("no sandbox runtime installed")
    res = hozo.run(
        hozo.SandboxRequest(command=["sh", "-c", "echo hi"], project=str(tmp_path)),
        capture=True,
    )
    assert res.returncode == 0
    assert "hi" in res.stdout
