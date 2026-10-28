import pytest
from conftest import policy_with_base

from hozo import profiles
from hozo.errors import ProfileError
from hozo.paths import profiles_dir
from hozo.profiles import Bind


def test_load_builtin_base():
    p = profiles.load_profile("base")
    assert p.name == "base"
    assert p.clear_env is True
    assert p.home == "{home}"
    assert "LC_*" in p.env_allow  # small allowlist; no deny list needed
    assert p.network_mode is None  # base intentionally leaves network unset


def test_builtin_untrusted_sets_none():
    assert profiles.load_profile("untrusted").network_mode == "none"


def test_builtin_names_present():
    assert {"base", "untrusted", "node", "python"} <= set(profiles.builtin_names())


def test_node_has_optional_rw_cache_bind():
    p = profiles.load_profile("node")
    assert any(b.optional and b.mode == "rw" for b in p.binds)


def test_user_override_wins():
    pdir = profiles_dir()
    pdir.mkdir(parents=True, exist_ok=True)
    (pdir / "base.yaml").write_text("name: base\ndescription: custom\n")
    assert profiles.load_profile("base").description == "custom"
    assert profiles.available_profiles()["base"] == "user"


def test_missing_profile_raises():
    with pytest.raises(ProfileError):
        profiles.load_profile("does-not-exist")


def test_compose_profiles_present():
    assert {"proxy", "node", "python", "claude"} <= set(profiles.builtin_names())


def test_proxy_profile_allows_nothing_by_default():
    p = profiles.load_profile("proxy")
    assert p.network_mode == "proxy"
    assert p.proxy_allow_hosts == []  # deny-all until a profile/flag grants hosts


def test_node_leaves_network_unset():
    assert profiles.load_profile("node").network_mode is None


def test_claude_profile_allows_anthropic():
    p = profiles.load_profile("claude")
    assert p.network_mode == "proxy"
    assert "api.anthropic.com" in p.proxy_allow_hosts


def test_bad_proxy_port_raises():
    with pytest.raises(ProfileError):
        profiles.parse_profile({"name": "x", "proxy": {"allow_hosts": ["api.example.com:https"]}}, "<t>")


def test_bad_network_mode_raises():
    with pytest.raises(ProfileError):
        profiles.parse_profile({"name": "x", "network": {"mode": "wifi"}}, "<test>")


def test_bind_source_must_be_absolute():
    with pytest.raises(ProfileError):
        profiles.parse_profile({"name": "x", "binds": [{"source": "rel"}]}, "<test>")


def test_invalid_yaml_raises():
    pdir = profiles_dir()
    pdir.mkdir(parents=True, exist_ok=True)
    (pdir / "broken.yaml").write_text("{ broken")
    with pytest.raises(ProfileError):
        profiles.load_profile("broken")


def test_ssh_grants_no_network_or_hosts():
    assert "ssh" in profiles.builtin_names()
    p = profiles.load_profile("ssh")
    assert p.network_mode is None
    assert p.proxy_allow_hosts == []


def test_ssh_agent_forwards_only_the_agent_socket(tmp_path, monkeypatch):
    assert "ssh-agent" in profiles.builtin_names()
    sock = str(tmp_path / "agent.sock")
    monkeypatch.setenv("SSH_AUTH_SOCK", sock)
    p = policy_with_base(None, tmp_path, profiles=["ssh-agent"], bind_project=False)
    assert p.binds == [Bind(source=sock, mode="ro", optional=True)]
    assert p.env_allow == ["SSH_AUTH_SOCK"]


def test_ssh_agent_without_an_agent_binds_nothing(tmp_path, monkeypatch):
    monkeypatch.delenv("SSH_AUTH_SOCK", raising=False)
    p = policy_with_base(None, tmp_path, profiles=["ssh-agent"], bind_project=False)
    assert p.binds == []


def test_optional_request_bind_with_an_empty_source_binds_nothing(tmp_path, monkeypatch):
    monkeypatch.delenv("SSH_AUTH_SOCK", raising=False)
    bind = Bind(source="{ssh_auth_sock}", mode="ro", optional=True)
    p = policy_with_base(None, tmp_path, bind_project=False, binds=[bind])
    assert p.binds == []
