"""The renderer is pure, so ``simulate`` runs the emitted program for any arch from any
host and reports the seccomp action."""

import re
import struct
from pathlib import Path

import pytest
from conftest import linux_only, policy_with_base

from hozo import seccomp
from hozo.backend import Backend
from hozo.bwrap import BubblewrapBackend, build_bwrap_argv
from hozo.errors import HozoError, ProfileError
from hozo.explain import explain_policy
from hozo.policy import ResolvedPolicy
from hozo.profiles import parse_profile
from hozo.seatbelt import build_seatbelt_profile

ALLOW = 0x7FFF0000
KILL = 0x80000000
LOG = 0x7FFC0000
ERRNO_ENOSYS = 0x00050026

X86_64 = seccomp.AUDIT_ARCH["x86_64"]
AARCH64 = seccomp.AUDIT_ARCH["aarch64"]
X32_BIT = 0x40000000


def simulate(program: bytes, *, arch: int, nr: int) -> int:
    """The action the kernel would apply to (arch, nr)."""
    instructions = [struct.unpack("=HBBI", program[i : i + 8]) for i in range(0, len(program), 8)]
    packet = {seccomp._NR_OFFSET: nr, seccomp._ARCH_OFFSET: arch}
    accumulator = 0
    pc = 0
    for _ in range(len(instructions) + 1):  # no backward jumps are emitted, so this bounds it
        code, jt, jf, k = instructions[pc]
        if code == seccomp._LD_W_ABS:
            accumulator = packet[k]
            pc += 1
        elif code == seccomp._JEQ_K:
            pc += 1 + (jt if accumulator == k else jf)
        elif code == seccomp._JGE_K:
            pc += 1 + (jt if accumulator >= k else jf)
        elif code == seccomp._RET_K:
            return k
        else:
            raise AssertionError(f"unexpected opcode {code:#x} at pc={pc}")
    raise AssertionError("filter did not reach a return")


def policy(deny, action="errno") -> ResolvedPolicy:
    return ResolvedPolicy(syscall_deny=list(deny), syscall_action=action)


def nr(name, arch="x86_64") -> int:
    return seccomp.syscall_table(arch)[name]


# --- structure -------------------------------------------------------------------------


def test_no_denylist_means_no_filter():
    assert seccomp.build_seccomp_filter(policy([])) is None


def test_program_is_a_whole_number_of_instructions():
    program = seccomp.build_seccomp_filter(policy(["bpf"]), arch="x86_64")
    assert len(program) % 8 == 0


def test_duplicate_names_emit_one_check():
    once = seccomp.build_seccomp_filter(policy(["bpf"]), arch="x86_64")
    twice = seccomp.build_seccomp_filter(policy(["bpf", "bpf"]), arch="x86_64")
    assert once == twice


def test_order_of_the_denylist_does_not_change_the_program():
    """Numbers are sorted, so merge order cannot perturb the filter."""
    a = seccomp.build_seccomp_filter(policy(["bpf", "userfaultfd", "keyctl"]), arch="x86_64")
    b = seccomp.build_seccomp_filter(policy(["keyctl", "bpf", "userfaultfd"]), arch="x86_64")
    assert a == b


def test_a_name_missing_on_this_arch_is_an_error_not_a_silent_gap():
    """A name valid on another arch must fail here, not drop out of the list. The `$` pins
    a repeated name to one mention."""
    with pytest.raises(HozoError, match=r"syscall not available on x86_64: definitely_not_a_syscall$"):
        seccomp.build_seccomp_filter(policy(["definitely_not_a_syscall"] * 2), arch="x86_64")


def test_an_arch_with_no_table_yields_no_filter_rather_than_failing():
    """No table means no filter, not a failed run."""
    assert seccomp.build_seccomp_filter(policy(["bpf"]), arch="s390x") is None
    assert seccomp.syscall_table("s390x") is None


def test_invalid_action_is_an_error():
    with pytest.raises(HozoError, match="invalid syscall action"):
        seccomp.build_seccomp_filter(policy(["bpf"], action="explode"), arch="x86_64")


def _names(count, arch="x86_64"):
    """`count` distinct syscall names."""
    names = sorted(seccomp.syscall_table(arch))[:count]
    assert len(names) == count, "table too small for this test"
    return names


_LIMIT = 255 - 4  # instruction 1 jumps over the head plus every check


def test_the_longest_compilable_denylist_is_at_the_jump_limit():
    assert seccomp.build_seccomp_filter(policy(_names(_LIMIT)), arch="x86_64")


def test_one_syscall_past_the_jump_limit_is_a_clear_error():
    """Rather than emitting a filter whose offsets have wrapped."""
    with pytest.raises(HozoError, match="jump offsets are 8-bit"):
        seccomp.build_seccomp_filter(policy(_names(_LIMIT + 1)), arch="x86_64")


def test_every_supported_arch_has_a_syscall_table():
    """syscall_table() assumes the gate and the data agree."""
    assert set(seccomp.AUDIT_ARCH) == set(seccomp._tables())


def test_known_syscalls_spans_every_arch():
    """The parse-time vocabulary is the union of both arches."""
    assert seccomp.known_syscalls() >= set(seccomp.syscall_table("x86_64"))
    assert seccomp.known_syscalls() >= set(seccomp.syscall_table("aarch64"))


_X86_64_HEADER = Path("/usr/include/asm/unistd_64.h")


@pytest.mark.skipif(not _X86_64_HEADER.is_file(), reason="no kernel headers installed")
def test_shipped_x86_64_numbers_match_the_kernel_headers():
    """syscalls.json is generated, so check it against the authoritative source wherever
    that source exists rather than trusting whichever machine last ran the generator."""
    header = {
        name: int(number)
        for name, number in re.findall(r"^#define\s+__NR_(\w+)\s+(\d+)\s*$", _X86_64_HEADER.read_text(), re.M)
        if name != "syscalls"
    }
    assert header, "parsed no syscalls out of the header"
    assert {name: seccomp.syscall_table("x86_64").get(name) for name in header} == header


# --- behaviour, by simulation ----------------------------------------------------------


def test_every_name_in_a_multi_entry_denylist_is_actually_denied():
    """An off-by-one in the jump arithmetic lands a check on the wrong return."""
    names = ["io_uring_setup", "bpf", "userfaultfd", "perf_event_open", "keyctl", "delete_module"]
    program = seccomp.build_seccomp_filter(policy(names), arch="x86_64")
    for name in names:
        assert simulate(program, arch=X86_64, nr=nr(name)) == ERRNO_ENOSYS, name
    for name in ["read", "write", "openat", "execve", "clone", "unshare", "ptrace"]:
        assert simulate(program, arch=X86_64, nr=nr(name)) == ALLOW, name


def test_neighbouring_syscall_numbers_are_not_caught():
    program = seccomp.build_seccomp_filter(policy(["bpf"]), arch="x86_64")
    for offset in (-1, 1):
        assert simulate(program, arch=X86_64, nr=nr("bpf") + offset) == ALLOW


@pytest.mark.parametrize("name", ["bpf", "read"])
def test_the_x32_abi_is_rejected_wholesale(name):
    """x32 sets bit 30 in nr, which a bare equality test would miss."""
    program = seccomp.build_seccomp_filter(policy(["bpf"]), arch="x86_64")
    assert simulate(program, arch=X86_64, nr=X32_BIT | nr(name)) == KILL


def test_foreign_arch_is_killed_not_allowed():
    """A filter cannot vouch for another arch's numbering."""
    program = seccomp.build_seccomp_filter(policy(["bpf"]), arch="x86_64")
    assert simulate(program, arch=AARCH64, nr=nr("read")) == KILL
    assert simulate(program, arch=0x40000003, nr=1) == KILL  # AUDIT_ARCH_I386


def test_aarch64_filter_uses_aarch64_numbers():
    program = seccomp.build_seccomp_filter(policy(["bpf"]), arch="aarch64")
    assert simulate(program, arch=AARCH64, nr=nr("bpf", "aarch64")) == ERRNO_ENOSYS
    # 321 is bpf on x86_64 and something else entirely on aarch64.
    assert simulate(program, arch=AARCH64, nr=nr("bpf", "x86_64")) == ALLOW
    assert simulate(program, arch=X86_64, nr=nr("bpf", "aarch64")) == KILL


def test_aarch64_has_no_x32_guard():
    """x32 is x86-only; the guard would reject valid aarch64 numbers."""
    program = seccomp.build_seccomp_filter(policy(["bpf"]), arch="aarch64")
    assert len(program) == len(seccomp.build_seccomp_filter(policy(["bpf"]), arch="x86_64")) - 8


@pytest.mark.parametrize("action,expected", [("errno", ERRNO_ENOSYS), ("kill", KILL), ("log", LOG)])
def test_action_selects_the_return_value(action, expected):
    program = seccomp.build_seccomp_filter(policy(["bpf"], action=action), arch="x86_64")
    assert simulate(program, arch=X86_64, nr=nr("bpf")) == expected
    assert simulate(program, arch=X86_64, nr=nr("read")) == ALLOW


# --- the shipped default ---------------------------------------------------------------


def _base_policy(tmp_path) -> ResolvedPolicy:
    return policy_with_base("base", tmp_path)


def test_base_denylist_compiles_on_every_supported_arch(tmp_path):
    """An x86_64-only name would break aarch64 users at run time."""
    resolved = _base_policy(tmp_path)
    for arch in sorted(seccomp.AUDIT_ARCH):
        assert seccomp.build_seccomp_filter(resolved, arch=arch)


def test_base_denies_the_headline_kernel_lpe_sources(tmp_path):
    denied = set(_base_policy(tmp_path).syscall_deny)
    assert {"io_uring_setup", "bpf", "userfaultfd", "perf_event_open"} <= denied


def test_base_does_not_break_nested_sandboxing_or_audit(tmp_path):
    """Deliberate omissions: nested bwrap needs unshare, `hozo audit` needs ptrace."""
    denied = set(_base_policy(tmp_path).syscall_deny)
    assert denied.isdisjoint({"unshare", "clone", "ptrace", "process_vm_readv"})


# --- profile parsing and merge ---------------------------------------------------------


def test_profile_parses_deny_and_action():
    profile = parse_profile({"name": "p", "syscalls": {"action": "kill", "deny": ["bpf"]}}, "<test>")
    assert profile.syscall_deny == ["bpf"]
    assert profile.syscall_action == "kill"


def test_profile_action_defaults_to_unset():
    profile = parse_profile({"name": "p", "syscalls": {"deny": ["bpf"]}}, "<test>")
    assert profile.syscall_action is None


def test_bad_action_is_a_profile_error():
    with pytest.raises(ProfileError, match="syscalls.action must be one of"):
        parse_profile({"name": "p", "syscalls": {"action": "nope"}}, "<test>")


def test_non_mapping_syscalls_is_a_profile_error():
    with pytest.raises(ProfileError, match="syscalls must be a mapping"):
        parse_profile({"name": "p", "syscalls": ["bpf"]}, "<test>")


def test_non_list_deny_is_a_profile_error():
    with pytest.raises(ProfileError, match="syscalls.deny must be a list"):
        parse_profile({"name": "p", "syscalls": {"deny": "bpf"}}, "<test>")


def test_unknown_name_is_caught_at_parse_time_on_any_platform():
    """The boundary macOS also crosses, so a typo cannot lie dormant until Linux."""
    with pytest.raises(ProfileError, match="unknown syscall in syscalls.deny: nope_not_real"):
        parse_profile({"name": "p", "syscalls": {"deny": ["bpf", "nope_not_real"]}}, "<test>")


def _merge(make_profile, layers, tmp_path) -> ResolvedPolicy:
    """Through the real loader, like every other merge test."""
    for name, body in layers.items():
        make_profile(name, body)
    return policy_with_base(None, tmp_path, profiles=list(layers))


def test_denylists_union_across_layers(make_profile, tmp_path):
    resolved = _merge(
        make_profile,
        {
            "a": "syscalls:\n  deny: [bpf, keyctl]\n",
            "b": "syscalls:\n  deny: [keyctl, userfaultfd]\n",
        },
        tmp_path,
    )
    assert resolved.syscall_deny == ["bpf", "keyctl", "userfaultfd"]


def test_composition_only_ever_tightens(make_profile, tmp_path):
    """There is no 'allow' field, so a later layer cannot widen an earlier one."""
    resolved = _merge(make_profile, {"a": "syscalls:\n  deny: [bpf]\n", "b": "syscalls:\n  deny: []\n"}, tmp_path)
    assert resolved.syscall_deny == ["bpf"]


def test_last_layer_wins_on_action(make_profile, tmp_path):
    resolved = _merge(
        make_profile,
        {"a": "syscalls:\n  action: errno\n  deny: [bpf]\n", "b": "syscalls:\n  action: log\n"},
        tmp_path,
    )
    assert resolved.syscall_action == "log"


def test_action_defaults_to_errno_when_no_layer_sets_it(make_profile, tmp_path):
    resolved = _merge(make_profile, {"a": "syscalls:\n  deny: [bpf]\n"}, tmp_path)
    assert resolved.syscall_action == "errno"


# --- backend wiring --------------------------------------------------------------------


class _NoFilterBackend(Backend):
    """A backend that cannot filter syscalls, so the shared half of `explain` is testable."""

    name = "stub"

    def is_available(self):
        return True

    def describe(self, policy):
        return "stub invocation"

    def run(self, policy, *, environ=None, capture=False):
        raise AssertionError("not executed")


@linux_only
def test_bwrap_argv_passes_the_fd(tmp_path):
    argv = build_bwrap_argv(_base_policy(tmp_path), seccomp_fd="7")
    assert argv[argv.index("--seccomp") + 1] == "7"


@linux_only
def test_bwrap_argv_omits_seccomp_without_an_fd(tmp_path):
    assert "--seccomp" not in build_bwrap_argv(_base_policy(tmp_path))


@linux_only
def test_describe_omits_seccomp_when_the_denylist_is_empty(tmp_path):
    resolved = _base_policy(tmp_path)
    resolved.syscall_deny = []
    assert "--seccomp" not in BubblewrapBackend().describe(resolved)


@linux_only
def test_describe_reports_the_filter(tmp_path):
    assert "--seccomp" in BubblewrapBackend().describe(_base_policy(tmp_path))


@linux_only
def test_describe_names_the_denied_syscalls(tmp_path):
    text = BubblewrapBackend().describe(_base_policy(tmp_path))
    assert "Syscalls: deny -> errno" in text
    assert "io_uring_setup" in text


@linux_only
def test_describe_says_so_when_the_host_arch_has_no_table(monkeypatch, tmp_path):
    """The gap must be visible rather than silently dropping the filter."""
    monkeypatch.setattr("hozo.bwrap.host_arch", lambda: "s390x")
    monkeypatch.setattr("hozo.seccomp.host_arch", lambda: "s390x")
    text = BubblewrapBackend().describe(_base_policy(tmp_path))
    assert "NOT FILTERED" in text
    assert "--seccomp" not in text


def test_seatbelt_ignores_the_denylist_rather_than_failing(tmp_path):
    """Profiles are shared across platforms, so this is a no-op, not an error."""
    resolved = ResolvedPolicy(command=["true"], cwd=str(tmp_path), syscall_deny=["bpf"])
    assert "bpf" not in build_seatbelt_profile(resolved)


def test_explain_does_not_claim_syscall_filtering_in_its_backend_neutral_half(tmp_path):
    """Seatbelt cannot filter syscalls, so the shared header must not advertise it."""
    resolved = _base_policy(tmp_path)
    header = explain_policy(resolved, environ={}, backend=_NoFilterBackend()).split("\n\n")[0]
    assert "Syscalls" not in header
    assert "io_uring_setup" not in header
