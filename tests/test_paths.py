from pathlib import Path

import pytest

from hozo import paths
from hozo.errors import HozoError


def test_xdg_dirs_respect_env(monkeypatch, tmp_path):
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "cfg"))
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    assert paths.config_dir() == tmp_path / "cfg" / "hozo"
    assert paths.state_dir() == tmp_path / "state" / "hozo"


def test_xdg_dirs_default_to_home(monkeypatch):
    for var in ("XDG_CONFIG_HOME", "XDG_STATE_HOME"):
        monkeypatch.delenv(var, raising=False)
    assert paths.config_dir() == Path.home() / ".config" / "hozo"
    assert paths.state_dir() == Path.home() / ".local" / "state" / "hozo"


def test_profiles_dir(monkeypatch, tmp_path):
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
    assert paths.profiles_dir() == tmp_path / "hozo" / "profiles"


def test_expand_project_and_home():
    assert paths.expand_path("{project}/sub", project=Path("/repo")) == "/repo/sub"
    assert paths.expand_path("{home}/.cache") == str(Path.home() / ".cache")


def test_expand_tilde():
    assert paths.expand_path("~/x") == str(Path.home() / "x")


def test_expand_project_missing_raises():
    with pytest.raises(HozoError):
        paths.expand_path("{project}/x")
