import os
import platform
import shutil
import tempfile
import textwrap
from collections import Counter
from dataclasses import replace
from pathlib import Path

import pytest
import yaml
from conftest import policy_with_base

import hozo
from hozo import audit, cli
from hozo.audit import FileAccess
from hozo.paths import profiles_dir
from hozo.policy import SandboxRequest, resolve_policy
from hozo.profiles import Bind, load_profile, parse_profile

needs_strace = pytest.mark.skipif(
    not (hozo.check_available() and shutil.which("strace") and platform.system() == "Linux"),
    reason="needs a sandbox runtime and strace",
)


def _ro(path):
    return FileAccess(path, "ro")


def _rw(path):
    return FileAccess(path, "rw")


def _policy(tmp_path, **kw):
    # These assert against base's grants: /usr ro, the /etc/* files, proc + dev.
    return policy_with_base("base", tmp_path, **kw)


# --- parse_strace -----------------------------------------------------------------


def test_read_and_write_are_told_apart_by_open_flags():
    text = textwrap.dedent("""\
        1  openat(AT_FDCWD, "/etc/hosts", O_RDONLY|O_CLOEXEC) = 3
        1  openat(AT_FDCWD, "/home/u/.npmrc", O_WRONLY|O_CREAT|O_TRUNC, 0666) = 4
    """)
    assert audit.parse_strace(text) == [_ro("/etc/hosts"), _rw("/home/u/.npmrc")]


def test_failed_write_is_still_recorded():
    text = '1  openat(AT_FDCWD, "/home/u/.npm/x", O_WRONLY|O_CREAT, 0666) = -1 EROFS (Read-only file system)\n'
    assert audit.parse_strace(text) == [_rw("/home/u/.npm/x")]


def test_missing_file_is_recorded_as_a_read():
    text = '1  stat("/home/u/.config/tool", 0x7ffd) = -1 ENOENT (No such file or directory)\n'
    assert audit.parse_strace(text) == [_ro("/home/u/.config/tool")]


def test_rename_records_both_operands():
    assert audit.parse_strace('1  rename("/a/x", "/b/y") = 0\n') == [_rw("/a/x"), _rw("/b/y")]


def test_execve_argv_is_not_mistaken_for_file_access():
    text = '1  execve("/usr/bin/cat", ["cat", "/etc/shadow"], 0x7ffd) = 0\n'
    assert audit.parse_strace(text) == [_ro("/usr/bin/cat")]


def test_noise_lines_are_skipped():
    text = textwrap.dedent("""\
        1  <... openat resumed>) = 3
        1  +++ exited with 0 +++
        1  --- SIGCHLD {si_signo=SIGCHLD} ---
        1  close(3) = 0
        1  openat(AT_FDCWD, "/etc/hosts", O_RDONLY) = 3
    """)
    assert audit.parse_strace(text) == [_ro("/etc/hosts")]


def test_unfinished_line_still_yields_its_path():
    text = '1  openat(AT_FDCWD, "/etc/hosts", O_RDONLY <unfinished ...>\n'
    assert audit.parse_strace(text) == [_ro("/etc/hosts")]


# --- classification ---------------------------------------------------------------


def test_paths_the_policy_already_grants_are_dropped(tmp_path):
    policy = _policy(tmp_path)  # base binds /usr ro, project rw
    found = [_ro("/usr/lib/libc.so.6"), _ro("/home/u/.npmrc")]
    assert audit.denied(found, policy) == [_ro("/home/u/.npmrc")]


def test_write_to_a_readonly_bind_is_still_a_finding(tmp_path):
    assert audit.denied([_rw("/usr/lib/x")], _policy(tmp_path)) == [_rw("/usr/lib/x")]


def test_proc_and_dev_count_as_granted_without_a_bind(tmp_path):
    policy = _policy(tmp_path)
    assert policy.proc and policy.dev  # guard: the premise of this test
    assert audit.denied([_ro("/proc/self/maps"), _ro("/dev/null")], policy) == []


def test_ignored_prefixes_are_dropped(tmp_path):
    assert audit.denied([_rw("/scratch/trace.log")], _policy(tmp_path), ignore=("/scratch",)) == []


# --- rollup -----------------------------------------------------------------------


def test_files_collapse_onto_their_directory():
    found = Counter([_ro("/home/u/.cache/node/a"), _ro("/home/u/.cache/node/b")])
    assert audit.group(found) == {_ro("/home/u/.cache/node"): 2}


def test_existing_directory_is_not_collapsed(tmp_path):
    assert audit.group(Counter([_ro(str(tmp_path))])) == {_ro(str(tmp_path)): 1}


@pytest.mark.parametrize(
    "target,expected",
    [
        ("/home/u/.npmrc", "/home/u/.npmrc"),  # would otherwise grant all of $HOME
        ("/etc/foo.conf", "/etc/foo.conf"),  # would otherwise grant all of /etc
        ("/home/u/.npm/x", "/home/u/.npm"),  # a dotdir is a sensible grant
        ("/home/u/.cache/node/a/b", "/home/u/.cache/node/a"),
    ],
)
def test_rollup_never_suggests_a_grant_broader_than_a_dotdir(target, expected):
    assert audit.group(Counter([_ro(target)])) == {_ro(expected): 1}


def test_counts_survive_the_rollup():
    assert audit.group(Counter({_ro("/home/u/.cache/node/a"): 5_000_000})) == {_ro("/home/u/.cache/node"): 5_000_000}


# --- the insecure profile ---------------------------------------------------------


@pytest.mark.skipif(
    platform.system() != "Linux",
    reason="macOS ships /etc and /var as symlinks into /private",
)
def test_insecure_profile_lists_no_symlinked_top_level_dir():
    for bind in load_profile("insecure").binds:
        assert not os.path.islink(bind.source), f"{bind.source} is a symlink"


def test_insecure_grants_the_real_home_read_only(tmp_path):
    policy = resolve_policy(SandboxRequest(command=["x"], project=str(tmp_path), profiles=["insecure"]))
    home = [b for b in policy.binds if b.source == "/home"]
    assert home and home[0].mode == "ro"
    assert "*:*" in policy.proxy_allow_hosts  # matches every host and port in the proxy


# --- request widening -------------------------------------------------------------


def test_audit_forces_proxy_even_under_untrusted(tmp_path):
    request = SandboxRequest(command=["x"], project=str(tmp_path), profiles=["untrusted"])
    assert resolve_policy(request).network_mode == "none"  # guard: the premise
    assert resolve_policy(audit.widen(request)).network_mode == "proxy"


def test_widen_does_not_alias_the_caller(tmp_path):
    """replace() passes untouched fields by reference, so widen must copy the mutable ones."""
    request = SandboxRequest(command=["x"], project=str(tmp_path), profiles=["untrusted"], binds=[])
    audit.widen(request).binds.append(Bind(source="/x", mode="rw"))
    assert request.profiles == ["untrusted"] and request.binds == []


# --- rendering --------------------------------------------------------------------


def _report(*files, hosts=()):
    report = audit.AuditReport(command=["npm", "install"], returncode=0)
    report.files.update(files)
    report.hosts.update(hosts)
    return report


def test_generated_profile_is_a_valid_profile():
    report = _report(_ro("/home/u/.npmrc"), _rw("/home/u/.npm"), hosts=["registry.npmjs.org:443"])
    profile = parse_profile(yaml.safe_load(audit.render_profile(report, "audit-npm")), "<generated>")
    assert profile.name == "audit-npm"
    assert {(b.source, b.mode) for b in profile.binds} == {("/home/u/.npmrc", "ro"), ("/home/u/.npm", "rw")}
    assert profile.proxy_allow_hosts == ["registry.npmjs.org"]  # bare host == ports 80/443


def test_a_path_both_read_and_written_is_granted_once_as_rw():
    report = _report(_ro("/home/u/.npm"), _rw("/home/u/.npm"))
    binds = [line for line in audit.render_profile(report, "n").splitlines() if "/home/u/.npm" in line]
    assert len(binds) == 1 and "mode: rw" in binds[0]


def test_top_level_dirs_are_suggested_commented_out():
    text = audit.render_profile(_report(_ro("/home"), _ro("/home/u/.gitconfig")), "n")
    assert "#  - { source: /home, mode: ro" in text
    assert "\n  - { source: /home/u/.gitconfig, mode: ro" in text

    profile = parse_profile(yaml.safe_load(text), "<generated>")
    assert [b.source for b in profile.binds] == ["/home/u/.gitconfig"]  # the comment stays inert


def test_a_profile_of_only_broad_paths_is_still_valid_yaml():
    profile = parse_profile(yaml.safe_load(audit.render_profile(_report(_ro("/etc")), "n")), "<gen>")
    assert profile.binds == []


def test_nonstandard_port_is_kept_in_the_host_pattern():
    assert "git.example.com:2222" in audit.render_profile(_report(hosts=["git.example.com:2222"]), "n")


def test_report_splits_into_sections_with_counts():
    report = _report(*([_ro("/home/u/.cache/node/a")] * 3), hosts=["registry.npmjs.org:443"])
    out = audit.render_report(report)
    assert "read" in out and "network" in out
    assert "/home/u/.cache/node" in out and "x3" in out


def test_bind_usage_counts_hits_and_flags_dead_grants(tmp_path):
    policy = _policy(tmp_path)  # base binds /usr ro plus optional /etc/* files
    usage = audit.bind_usage([_ro("/usr/lib/libc.so.6"), _ro("/usr/bin/git")], policy)
    assert usage["/usr"] == 2
    assert usage["/etc/ssl"] == 0  # granted but never touched: safe to delete
    assert set(usage) == {b.source for b in policy.binds}


def test_granted_section_is_opt_in():
    report = _report(_ro("/home/u/.npmrc"))
    report.granted.update({"/usr": 12, "/etc/ssl": 0})
    assert "already granted" not in audit.render_report(report)

    shown = audit.render_report(report, show_granted=True)
    assert "already granted" in shown
    assert "/usr" in shown and "x12" in shown
    assert "/etc/ssl" in shown and "(unused)" in shown


def test_empty_report_says_so():
    assert "nothing outside the policy" in audit.render_report(audit.AuditReport(command=["true"], returncode=0))


def test_network_only_report_says_the_filesystem_was_not_traced():
    report = _report(hosts=["a.com:443"])
    report.traced = False
    assert "network only" in audit.render_report(report)


def test_profile_name_comes_from_the_command():
    assert audit.profile_name(["/usr/bin/npm", "install"]) == "audit-npm"


def test_default_profile_path_is_a_temp_file_not_the_project(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    target = cli._temp_profile("audit-npm")
    assert target.parent == Path(tempfile.gettempdir())
    assert tmp_path not in target.parents
    target.unlink()


# --- integration ------------------------------------------------------------------

needs_sandbox = pytest.mark.skipif(not hozo.check_available(), reason="no sandbox runtime installed")

# Stands in for strace so this runs without it installed.
_FAKE_STRACE = """\
#!/bin/sh
while [ "$1" != "-o" ]; do shift; done
shift
out="$1"
shift
printf '1  openat(AT_FDCWD, "/home/nobody/.toolrc", O_RDONLY) = 3\\n' > "$out"
printf '1  openat(AT_FDCWD, "/home/nobody/.tool/db", O_WRONLY|O_CREAT) = -1 EROFS (x)\\n' >> "$out"
exec "$@"
"""


@needs_sandbox
def test_run_audit_wires_trace_output_back_into_a_report(tmp_path, monkeypatch):
    fake = tmp_path / "fake-strace"
    fake.write_text(_FAKE_STRACE)
    fake.chmod(0o755)
    # audit.shutil is the shutil module itself, so a blanket patch would also hide bwrap.
    real_which = shutil.which
    monkeypatch.setattr(audit.shutil, "which", lambda name: str(fake) if name == "strace" else real_which(name))

    report = audit.run_audit(SandboxRequest(command=["true"], project=str(tmp_path)))

    assert report.returncode == 0  # the real command still ran, and its status passed through
    profile = parse_profile(yaml.safe_load(audit.render_profile(report, "n")), "<generated>")
    assert {(b.source, b.mode) for b in profile.binds} == {
        ("/home/nobody/.toolrc", "ro"),
        ("/home/nobody/.tool", "rw"),  # rolled up to the dotdir, and the failed write still counts
    }


# Not under /tmp: base mounts a tmpfs there, so pytest temp dirs are invisible in-sandbox.
_UNBOUND_HOST_FILE = "/etc/os-release"

needs_host_file = pytest.mark.skipif(not os.path.exists(_UNBOUND_HOST_FILE), reason=f"{_UNBOUND_HOST_FILE} not present")


@needs_strace
@needs_host_file
def test_audit_reports_a_read_the_policy_would_deny(tmp_path):
    report = audit.run_audit(SandboxRequest(command=["cat", _UNBOUND_HOST_FILE], project=str(tmp_path)))

    assert report.returncode == 0  # widened, so the command itself succeeded
    assert _ro(_UNBOUND_HOST_FILE) in report.files
    assert _UNBOUND_HOST_FILE in audit.render_report(report)


@needs_strace
@needs_host_file
def test_audit_output_is_actionable(tmp_path):
    """Positive control: the suggested profile must actually work under real enforcement."""
    request = SandboxRequest(command=["cat", _UNBOUND_HOST_FILE], project=str(tmp_path))
    assert hozo.run(request, capture=True).returncode != 0  # guard: denied before the audit

    report = audit.run_audit(request)
    pdir = profiles_dir()
    pdir.mkdir(parents=True, exist_ok=True)
    (pdir / "audited.yaml").write_text(audit.render_profile(report, "audited"))

    assert hozo.run(replace(request, profiles=["audited"]), capture=True).returncode == 0
