"""``env.set_from_command``: a host argv whose stdout becomes an env var in the sandbox.

One file per field, following the ``syscalls:`` precedent in test_seccomp.py.
"""

import platform
import shlex

import pytest
from conftest import policy_with_base

import hozo
from hozo import env, explain, profiles
from hozo.errors import HozoError, MergeConflictError, ProfileError
from hozo.policy import ResolvedPolicy, SandboxRequest, resolve_policy

SENTINEL = "hozo-sentinel-4f2a9c"
needs_sandbox = pytest.mark.skipif(not hozo.check_available(), reason="no sandbox runtime installed")


def _parse(body):
    return profiles.parse_profile({"name": "x", "env": {"set_from_command": body}}, "test")


# --- parse ---------------------------------------------------------------------------


def test_argv_is_parsed_verbatim():
    p = _parse({"TOK": ["security", "find-generic-password", "-w"]})
    assert p.env_set_from_command == {"TOK": ["security", "find-generic-password", "-w"]}


def test_a_shell_string_is_rejected():
    """AGENTS.md hard rule: hozo never executes shell strings."""
    with pytest.raises(ProfileError, match="never a shell string"):
        _parse({"TOK": "security -w | cut -c1-5"})


def test_an_empty_argv_is_rejected():
    with pytest.raises(ProfileError, match="non-empty"):
        _parse({"TOK": []})


def test_non_strings_are_rejected_rather_than_coerced():
    with pytest.raises(ProfileError):
        _parse({"TOK": ["echo", 7]})


def test_a_platform_mapping_picks_the_host_branch():
    p = _parse({"TOK": {"macos": ["security", "x"], "linux": ["secret-tool", "y"]}})
    expected = "security" if platform.system() == "Darwin" else "secret-tool"
    assert p.env_set_from_command["TOK"][0] == expected


def test_a_platform_mapping_that_omits_this_host_is_skipped():
    """Naming some platforms and not this one is an explicit 'nothing to do here', which is
    different from an entry that is missing outright."""
    other = "linux" if platform.system() == "Darwin" else "macos"
    assert _parse({"TOK": {other: ["echo", "hi"]}}).env_set_from_command == {}


def test_an_unknown_platform_key_is_rejected():
    with pytest.raises(ProfileError, match="unknown platform"):
        _parse({"TOK": {"freebsd": ["echo", "hi"]}})


def test_a_platform_branch_is_still_validated_as_argv():
    here = "macos" if platform.system() == "Darwin" else "linux"
    with pytest.raises(ProfileError, match="never a shell string"):
        _parse({"TOK": {here: "secret-tool lookup foo bar"}})


# --- the env override ----------------------------------------------------------------
# The one place a command may be a string: shlex.split, exec'd directly, no shell.


def _spec(monkeypatch, value, env=None):
    for name, val in (env or {}).items():
        monkeypatch.setenv(name, val)
    return _parse({"TOK": value})


def test_the_env_var_replaces_the_default(monkeypatch):
    p = _spec(
        monkeypatch,
        {"env": "HOZO_TEST_CMD", "default": ["echo", "default"]},
        {"HOZO_TEST_CMD": "op read op://Private/x/y"},
    )
    assert p.env_set_from_command["TOK"] == ["op", "read", "op://Private/x/y"]


def test_an_unset_or_empty_env_var_falls_back_to_the_default(monkeypatch):
    monkeypatch.delenv("HOZO_TEST_CMD", raising=False)
    spec = {"env": "HOZO_TEST_CMD", "default": ["echo", "default"]}
    assert _parse({"TOK": spec}).env_set_from_command["TOK"] == ["echo", "default"]
    monkeypatch.setenv("HOZO_TEST_CMD", "   ")
    assert _parse({"TOK": spec}).env_set_from_command["TOK"] == ["echo", "default"]


def test_an_override_quotes_are_respected(monkeypatch):
    p = _spec(monkeypatch, {"env": "HOZO_TEST_CMD", "default": ["x"]}, {"HOZO_TEST_CMD": "op read 'a b/c'"})
    assert p.env_set_from_command["TOK"] == ["op", "read", "a b/c"]


def test_a_shell_substitution_in_the_override_is_rejected(monkeypatch):
    with pytest.raises(ProfileError, match="shell substitution"):
        _spec(monkeypatch, {"env": "HOZO_TEST_CMD", "default": ["x"]}, {"HOZO_TEST_CMD": "pass show hozo/$USER"})


def test_an_unbalanced_quote_in_the_override_is_rejected(monkeypatch):
    with pytest.raises(ProfileError, match="cannot parse"):
        _spec(monkeypatch, {"env": "HOZO_TEST_CMD", "default": ["x"]}, {"HOZO_TEST_CMD": "op read 'unclosed"})


def test_an_entry_with_no_default_needs_the_env_var(monkeypatch):
    monkeypatch.delenv("HOZO_TEST_CMD", raising=False)
    with pytest.raises(ProfileError, match="must be set"):
        _parse({"TOK": {"env": "HOZO_TEST_CMD"}})


def test_unknown_keys_beside_env_are_rejected():
    with pytest.raises(ProfileError, match="unknown key"):
        _parse({"TOK": {"env": "HOZO_TEST_CMD", "defualt": ["x"]}})


def test_the_claude_profile_reads_one_stored_token_on_this_platform(monkeypatch):
    """The delenv matters: the profile tells users to export this, so without it the suite
    fails for anyone who followed the setup."""
    monkeypatch.delenv("HOZO_CMD_CLAUDE_TOKEN", raising=False)
    p = profiles.load_profile("claude")
    argv = p.env_set_from_command["CLAUDE_CODE_OAUTH_TOKEN"]
    assert argv[0] == ("security" if platform.system() == "Darwin" else "secret-tool")
    # By service alone: both stores match a subset, so no account value to agree on.
    assert "hozo-claude" in argv


# --- merge / resolve -----------------------------------------------------------------


def test_placeholders_expand_per_argv_element(tmp_path, make_profile):
    make_profile("cmd", 'env:\n  set_from_command:\n    TOK: [id, "-u", "{user}"]\n')
    p = policy_with_base(None, tmp_path, profiles=["cmd"])
    import getpass

    assert p.env_set_from_command["TOK"] == ["id", "-u", getpass.getuser()]


def test_scratch_is_rejected_in_a_host_command(tmp_path, make_profile):
    """{scratch} is a sandbox-internal path; a command running on the host cannot mean it."""
    make_profile("cmd", 'env:\n  set_from_command:\n    TOK: [cat, "{scratch}/x"]\n')
    with pytest.raises(HozoError, match="scratch"):
        policy_with_base(None, tmp_path, profiles=["cmd"])


def test_conflicting_commands_across_layers_raise(tmp_path, make_profile):
    make_profile("a", "env:\n  set_from_command:\n    TOK: [echo, one]\n")
    make_profile("b", "env:\n  set_from_command:\n    TOK: [echo, two]\n")
    with pytest.raises(MergeConflictError, match="conflicting commands"):
        policy_with_base(None, tmp_path, profiles=["a", "b"])


def test_identical_commands_across_layers_merge_quietly(tmp_path, make_profile):
    make_profile("a", "env:\n  set_from_command:\n    TOK: [echo, same]\n")
    make_profile("b", "env:\n  set_from_command:\n    TOK: [echo, same]\n")
    p = policy_with_base(None, tmp_path, profiles=["a", "b"])
    assert p.env_set_from_command == {"TOK": ["echo", "same"]}


def test_the_same_var_set_two_ways_raises(tmp_path, make_profile):
    make_profile("a", "env:\n  set:\n    TOK: static\n")
    make_profile("b", "env:\n  set_from_command:\n    TOK: [echo, dynamic]\n")
    with pytest.raises(MergeConflictError, match="both env.set and env.set_from_command"):
        policy_with_base(None, tmp_path, profiles=["a", "b"])


def test_inline_request_env_wins_over_a_command(tmp_path, make_profile):
    """The library escape hatch: a caller supplying the value skips the host command."""
    make_profile("cmd", "env:\n  set_from_command:\n    TOK: [echo, from-command]\n")
    p = resolve_policy(
        SandboxRequest(command=["true"], project=str(tmp_path), no_base=True, profiles=["cmd"], env={"TOK": "inline"})
    )
    assert p.env_set_from_command == {}
    assert p.env_set["TOK"] == "inline"


def test_the_resolved_policy_holds_the_recipe_not_the_value(tmp_path, make_profile):
    """ResolvedPolicy rides along in SandboxResult, so a value here would land in every
    repr, traceback with locals, and consumer log."""
    make_profile("cmd", f"env:\n  set_from_command:\n    TOK: [echo, {SENTINEL}]\n")
    p = policy_with_base(None, tmp_path, profiles=["cmd"])
    assert p.env_set_from_command == {"TOK": ["echo", SENTINEL]}
    assert "TOK" not in p.env_set  # nothing was executed, so there is no value to carry


# --- build_env / execution -----------------------------------------------------------


def test_build_env_invents_no_value_when_the_backend_supplies_none():
    """Fail closed: a caller that forgets from_command must get nothing, not a plausible
    literal the child would use as a credential."""
    p = ResolvedPolicy(env_set_from_command={"TOK": ["false"]})
    assert "TOK" not in env.build_env(p, environ={})


def test_build_env_uses_a_resolved_value_when_given():
    p = ResolvedPolicy(env_set_from_command={"TOK": ["irrelevant"]})
    assert env.build_env(p, environ={}, from_command={"TOK": SENTINEL})["TOK"] == SENTINEL


def test_a_command_beats_a_static_set_for_the_same_key():
    p = ResolvedPolicy(env_set={"TOK": "static"}, env_set_from_command={"TOK": ["irrelevant"]})
    assert env.build_env(p, environ={}, from_command={"TOK": SENTINEL})["TOK"] == SENTINEL


def test_stdout_is_stripped():
    p = ResolvedPolicy(env_set_from_command={"TOK": ["/bin/echo", f"  {SENTINEL}  "]})
    assert env.resolve_env_commands(p) == {"TOK": SENTINEL}


def test_a_failing_command_fails_the_run():
    p = ResolvedPolicy(env_set_from_command={"TOK": ["/bin/sh", "-c", "exit 3"]})
    with pytest.raises(HozoError, match="exited 3"):
        env.resolve_env_commands(p)


def test_empty_output_fails_the_run():
    """A silently-unset credential surfaces later as a confusing auth error, not this one."""
    p = ResolvedPolicy(env_set_from_command={"TOK": ["/bin/sh", "-c", "exit 0"]})
    with pytest.raises(HozoError, match="no output"):
        env.resolve_env_commands(p)


def test_a_missing_binary_fails_the_run():
    p = ResolvedPolicy(env_set_from_command={"TOK": ["/nonexistent/hozo-not-a-binary"]})
    with pytest.raises(HozoError):
        env.resolve_env_commands(p)


def test_the_error_never_echoes_stdout():
    """The secret travels on stdout by contract, so stdout must never reach the message. The
    secret is assembled from two argv pieces so it is never a contiguous substring of the
    command, which the error does legitimately quote."""
    secret = "hozo-leaked-secret"
    script = 'printf "%s%s\\n" "$1" "$2"; echo "keyring unavailable" >&2; exit 1'
    p = ResolvedPolicy(env_set_from_command={"TOK": ["/bin/sh", "-c", script, "_", "hozo-leaked", "-secret"]})
    with pytest.raises(HozoError) as exc:
        env.resolve_env_commands(p)
    assert secret not in str(exc.value)


def test_the_error_surfaces_stderr_so_setup_is_diagnosable():
    """Deliberately the other way from stdout: without it, a first-time failure is a bare
    exit code and you cannot tell "keyring not running" from "item not stored"."""
    p = ResolvedPolicy(env_set_from_command={"TOK": ["/bin/sh", "-c", 'echo "keyring unavailable" >&2; exit 1']})
    with pytest.raises(HozoError, match="keyring unavailable"):
        env.resolve_env_commands(p)


def test_the_resolved_value_never_lands_on_the_policy():
    """Stashing the value on the policy would put it in SandboxResult.policy, and so in
    every repr. Built from two argv pieces so the argv itself is not a match."""
    p = ResolvedPolicy(
        env_set_from_command={"TOK": ["/bin/sh", "-c", 'printf "%s%s" "$1" "$2"', "_", "hozo-leaked", "-secret"]}
    )
    assert env.resolve_env_commands(p) == {"TOK": "hozo-leaked-secret"}
    assert "hozo-leaked-secret" not in repr(p)


def test_every_entry_is_resolved_not_just_the_first():
    p = ResolvedPolicy(env_set_from_command={"A": ["/bin/echo", "one"], "B": ["/bin/echo", "two"]})
    assert env.resolve_env_commands(p) == {"A": "one", "B": "two"}
    assert env.build_env(p, environ={}, from_command={"A": "one", "B": "two"}) == {"A": "one", "B": "two"}


def test_a_hanging_command_times_out(monkeypatch):
    """Without the timeout a helper waiting on a prompt hangs the run forever -- and stdin is
    already closed, so nothing can ever answer it."""
    monkeypatch.setattr(env, "_COMMAND_TIMEOUT", 0.2)
    p = ResolvedPolicy(env_set_from_command={"TOK": ["/bin/sleep", "5"]})
    with pytest.raises(HozoError):
        env.resolve_env_commands(p)


# --- explain -------------------------------------------------------------------------


def test_explain_shows_the_command_but_never_a_value(tmp_path, make_profile):
    """The sentinel is printed, not named in the argv, so its absence is assertable."""
    make_profile("cmd", f"env:\n  set_from_command:\n    TOK: [/bin/echo, {SENTINEL}]\n")
    p = policy_with_base(None, tmp_path, profiles=["cmd"])
    text = explain.explain_policy(p, environ={})
    assert "Runs on HOST" in text
    assert "TOK" in text
    assert "/bin/echo" in text  # the argv is shown, so the field stays auditable


def test_explain_never_executes_the_command(tmp_path, make_profile, monkeypatch):
    """explain calls build_env to list names, so execution there would make inspecting a
    profile run it. Popen, not run, since run is built on it."""

    def boom(*a, **kw):
        raise AssertionError("explain must never run a host command")

    monkeypatch.setattr(env.subprocess, "Popen", boom)
    make_profile("cmd", "env:\n  set_from_command:\n    TOK: [/bin/echo, hi]\n")
    p = policy_with_base(None, tmp_path, profiles=["cmd"])
    assert "TOK" in explain.explain_policy(p, environ={})


# --- end to end ----------------------------------------------------------------------


@needs_sandbox
def test_the_value_reaches_the_child(tmp_path, make_profile):
    """Secret built from two argv pieces, so the absence assertions below are real."""
    cmd = '[/bin/sh, -c, \'printf "%s%s" "$1" "$2"\', _, hozo-leaked, -secret]'
    make_profile("cmd", f"env:\n  allow: [PATH]\n  set_from_command:\n    TOK: {cmd}\n")
    res = hozo.run(
        hozo.SandboxRequest(
            command=["/bin/sh", "-c", 'echo "$TOK"'],
            project=str(tmp_path),
            profiles=["cmd"],
        ),
        capture=True,
    )
    assert res.stdout.strip() == "hozo-leaked-secret"
    # The only place a real value and a real SandboxResult coexist.
    assert "hozo-leaked-secret" not in shlex.join(res.argv)  # never in /proc/PID/cmdline
    assert "hozo-leaked-secret" not in repr(res.policy)


@needs_sandbox
def test_a_failing_credential_command_stops_the_run(tmp_path, make_profile):
    make_profile("cmd", 'env:\n  set_from_command:\n    TOK: [/bin/sh, -c, "exit 1"]\n')
    with pytest.raises(HozoError):
        hozo.run(
            hozo.SandboxRequest(command=["/bin/echo", "hi"], project=str(tmp_path), profiles=["cmd"]),
            capture=True,
        )
