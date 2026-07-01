from pathlib import Path

import pytest

from hozo import policy
from hozo.errors import MergeConflictError
from hozo.paths import profiles_dir
from hozo.policy import SandboxRequest


@pytest.fixture
def make_profile():
    pdir = profiles_dir()
    pdir.mkdir(parents=True, exist_ok=True)

    def _make(name, body=""):
        (pdir / f"{name}.yaml").write_text(f"name: {name}\n{body}")

    return _make


def test_base_only(tmp_path):
    p = policy.resolve_policy(SandboxRequest(command=["echo", "hi"], project=str(tmp_path)))
    assert p.network_mode == "none"
    assert p.clear_env is True
    assert p.home == str(Path.home())
    assert "LC_*" in p.env_allow  # deny-all + small allowlist scrubs secrets
    assert p.command == ["echo", "hi"]
    work = [b for b in p.binds if b.target == "/work"]
    assert work and work[0].source == str(tmp_path) and work[0].mode == "rw"


def test_no_project_bind(tmp_path):
    p = policy.resolve_policy(SandboxRequest(command=["x"], project=str(tmp_path), bind_project=False))
    assert all(b.target != "/work" for b in p.binds)


@pytest.mark.parametrize(
    "names,expected",
    [
        (["p_unset", "p_proxy"], "proxy"),
        (["p_none", "p_proxy"], "none"),
        (["p_proxy"], "proxy"),
        (["p_unset"], "none"),
    ],
)
def test_network_truth_table(make_profile, names, expected):
    make_profile("p_unset")
    make_profile("p_none", "network:\n  mode: none\n")
    make_profile("p_proxy", "network:\n  mode: proxy\n")
    p = policy.resolve_policy(SandboxRequest(command=["x"], profiles=names))
    assert p.network_mode == expected


def test_network_request_override(make_profile):
    make_profile("p_none", "network:\n  mode: none\n")
    p = policy.resolve_policy(SandboxRequest(command=["x"], profiles=["p_none"], network="host"))
    assert p.network_mode == "host"


def test_bind_conflict_raises(make_profile):
    make_profile("a", "binds:\n  - {source: /x, target: /t}\n")
    make_profile("b", "binds:\n  - {source: /y, target: /t}\n")
    with pytest.raises(MergeConflictError):
        policy.resolve_policy(SandboxRequest(command=["x"], profiles=["a", "b"]))


def test_bind_conflict_override(make_profile):
    make_profile("a", "binds:\n  - {source: /x, target: /t}\n")
    make_profile("b", "binds:\n  - {source: /y, target: /t}\n")
    p = policy.resolve_policy(SandboxRequest(command=["x"], profiles=["a", "b"], override=True))
    assert [b for b in p.binds if b.target == "/t"][0].source == "/y"


def test_env_set_conflict_raises(make_profile):
    make_profile("a", "env:\n  set: {FOO: '1'}\n")
    make_profile("b", "env:\n  set: {FOO: '2'}\n")
    with pytest.raises(MergeConflictError):
        policy.resolve_policy(SandboxRequest(command=["x"], profiles=["a", "b"]))


def test_inline_env_wins(make_profile):
    make_profile("a", "env:\n  set: {FOO: '1'}\n")
    p = policy.resolve_policy(SandboxRequest(command=["x"], profiles=["a"], env={"FOO": "2"}))
    assert p.env_set["FOO"] == "2"


def test_no_base_skips_base(make_profile):
    make_profile("p_unset")
    p = policy.resolve_policy(SandboxRequest(command=["x"], profiles=["p_unset"], no_base=True))
    assert p.home is None


def test_allow_hosts_union(make_profile):
    make_profile("a", "proxy:\n  allow_hosts: [a.com]\n")
    p = policy.resolve_policy(SandboxRequest(command=["x"], profiles=["a"], allow_hosts=["b.com"]))
    assert set(p.proxy_allow_hosts) == {"a.com", "b.com"}


def test_node_plus_proxy_composition():
    p = policy.resolve_policy(SandboxRequest(command=["npm", "i"], profiles=["node", "proxy"]))
    assert p.network_mode == "proxy"  # node unset, proxy explicit -> proxy
    assert "registry.npmjs.org" in p.proxy_allow_hosts  # node's host unioned in


def test_relative_project_absolutized(monkeypatch, tmp_path):
    sub = tmp_path / "proj"
    sub.mkdir()
    monkeypatch.chdir(sub)
    p = policy.resolve_policy(SandboxRequest(command=["true"], project=".."))
    assert next(b for b in p.binds if b.target == "/work").source == str(tmp_path)


def test_required_bind_wins_over_optional(make_profile):
    make_profile("opt", "binds:\n  - {source: /srv, target: /srv, optional: true}\n")
    make_profile("req", "binds:\n  - {source: /srv, target: /srv, optional: false}\n")
    p = policy.resolve_policy(SandboxRequest(command=["x"], profiles=["opt", "req"]))
    assert next(b for b in p.binds if b.target == "/srv").optional is False


def test_clear_env_false_honored(make_profile):
    make_profile("hostenv", "process:\n  clear_env: false\n")
    assert policy.resolve_policy(SandboxRequest(command=["x"], profiles=["hostenv"])).clear_env is False


def test_cwd_project_mounts_in_place(make_profile):
    make_profile("inplace", 'process: {cwd: "{project}"}\n')
    p = policy.resolve_policy(SandboxRequest(command=["x"], project="/home/u/proj", profiles=["inplace"]))
    assert p.cwd == "/home/u/proj"
    work = [b for b in p.binds if b.target == "/home/u/proj"][0]
    assert work.source == "/home/u/proj" and work.mode == "rw"


def test_home_placeholder_and_identity(make_profile):
    import getpass
    from pathlib import Path

    make_profile("realhome", 'home: "{home}"\nbinds:\n  - {source: "{home}/.foo", target: "{home}/.foo", mode: rw}\n')
    p = policy.resolve_policy(SandboxRequest(command=["x"], profiles=["realhome"]))
    home = str(Path.home())
    assert p.home == home
    assert p.env_set["HOME"] == home  # HOME follows the sandbox home
    assert p.env_set["USER"] == getpass.getuser()  # real user by default
    foo = [b for b in p.binds if b.target == f"{home}/.foo"][0]
    assert foo.source == f"{home}/.foo"  # same path inside and out
