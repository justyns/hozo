import pytest

from hozo.policy import SandboxRequest, resolve_policy


@pytest.fixture(autouse=True)
def _isolate_dirs(monkeypatch, tmp_path, tmp_path_factory):
    """Point HOME and all XDG dirs at temp dirs so tests never touch the real ~/.config,
    ~/.local, etc. HOME lives in its own temp subtree, separate from tmp_path (which tests
    use as the project dir)."""
    monkeypatch.setenv("HOME", str(tmp_path_factory.mktemp("home")))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "data"))
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path / "cache"))


def policy_with_base(base, tmp_path, *, profiles=(), **kw):
    """Resolve against a named base instead of the platform default, which resolve_policy
    picks from platform.system(). Pass base=None for no base at all."""
    kw.setdefault("command", ["true"])
    kw.setdefault("project", str(tmp_path))
    layers = [*([base] if base else []), *profiles]
    return resolve_policy(SandboxRequest(no_base=True, profiles=layers, **kw))
