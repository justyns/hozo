from hozo import env
from hozo.policy import ResolvedPolicy


def make_policy(**kw):
    defaults = dict(
        command=[],
        profiles_applied=[],
        network_mode="none",
        clear_env=True,
        cwd="/work",
        home=None,
        binds=[],
        tmpfs=[],
        env_allow=[],
        env_set={},
        prepend_path=[],
        proc=True,
        dev=True,
        proxy_allow_hosts=[],
    )
    defaults.update(kw)
    return ResolvedPolicy(**defaults)


def test_allow_globs_copy_lc_only():
    p = make_policy(env_allow=["TERM", "LC_*"])
    out = env.build_env(p, environ={"TERM": "xterm", "LC_ALL": "C", "SECRET": "x"})
    assert out == {"TERM": "xterm", "LC_ALL": "C"}


def test_set_overrides_and_path_order():
    p = make_policy(env_set={"HOME": "/home/u", "PATH": "/usr/bin:/bin"}, prepend_path=["/opt/a"])
    out = env.build_env(p, environ={})
    assert out["HOME"] == "/home/u"
    assert out["PATH"] == "/opt/a:/usr/bin:/bin"


def test_scratch_substituted_by_the_backend():
    p = make_policy(env_set={"T": "{scratch}/claude"})
    assert env.build_env(p, environ={}, scratch="/run/x")["T"] == "/run/x/claude"
    assert env.build_env(p, environ={})["T"] == "{scratch}/claude"  # explain: no run, no dir


def test_clear_env_false_copies_all():
    p = make_policy(clear_env=False)
    out = env.build_env(p, environ={"FOO": "1", "SECRET": "x"})
    assert out == {"FOO": "1", "SECRET": "x"}


def test_path_dedup():
    p = make_policy(env_set={"PATH": "/usr/bin"}, prepend_path=["/usr/bin", "/opt"])
    out = env.build_env(p, environ={})
    assert out["PATH"] == "/usr/bin:/opt"
