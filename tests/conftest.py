import pytest


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
