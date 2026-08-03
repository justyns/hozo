"""
Use strace to figure out what files/hosts a command is trying to access.  This is meant to be run
with the "insecure" profile so nothing is actually blocked in this mode.
"""

from __future__ import annotations

import logging
import os
import re
import shlex
import shutil
import tempfile
from collections import Counter
from contextlib import ExitStack, contextmanager
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Literal

from .errors import HozoError
from .executor import SandboxRunner
from .paths import state_dir
from .policy import ResolvedPolicy, SandboxRequest, resolve_policy
from .profiles import Bind

AUDIT_PROFILE = "insecure"

BANNER = """\
!! AUDIT !!
   This mode does not enforce any restrictions, but it logs what the command tries to access.
   It should not be used for commands you do not trust.
"""

_STRACE_FLAGS = ("-f", "-qq", "-s", "256", "-e", "signal=none", "-e", "trace=%file")

#   1234  openat(AT_FDCWD, "/etc/hosts", O_RDONLY|O_CLOEXEC) = 3
_CALL = re.compile(r"^(?:\d+\s+)?(\w+)\((.*)$")
_QUOTED = re.compile(r'"((?:[^"\\]|\\.)*)"')

_MIN_GRANT_DEPTH = 3  # /home/<user>/<dotdir>
_TOP_LEVEL_DEPTH = 1

_WRITE_FLAGS = ("O_WRONLY", "O_RDWR", "O_CREAT", "O_TRUNC", "O_APPEND")
_OPEN_CALLS = frozenset({"open", "openat", "openat2", "creat"})
_TWO_PATH_CALLS = frozenset({"rename", "renameat", "renameat2", "link", "linkat", "symlink", "symlinkat"})
_WRITE_CALLS = _TWO_PATH_CALLS | {
    "unlink",
    "unlinkat",
    "mkdir",
    "mkdirat",
    "rmdir",
    "chmod",
    "fchmodat",
    "chown",
    "fchownat",
    "truncate",
    "utimensat",
    "mknod",
    "mknodat",
}


@dataclass(frozen=True)
class FileAccess:
    path: str
    mode: Literal["ro", "rw"]

    @property
    def write(self) -> bool:
        return self.mode == "rw"


@dataclass
class AuditReport:
    command: list[str]
    returncode: int
    files: Counter = field(default_factory=Counter)
    hosts: Counter = field(default_factory=Counter)
    granted: Counter = field(default_factory=Counter)
    traced: bool = True

    @property
    def empty(self) -> bool:
        return not self.files and not self.hosts


def parse_strace(text: str) -> list[FileAccess]:
    accesses: list[FileAccess] = []
    for line in text.splitlines():
        match = _CALL.match(line.strip())
        if not match:
            continue
        call, args = match.group(1), match.group(2)
        paths = [p for p in _QUOTED.findall(args) if p.startswith("/")]
        if not paths:
            continue

        if call in _OPEN_CALLS:
            mode = "rw" if any(flag in args for flag in _WRITE_FLAGS) else "ro"
        else:
            mode = "rw" if call in _WRITE_CALLS else "ro"

        wanted = paths[:2] if call in _TWO_PATH_CALLS else paths[:1]
        accesses += [FileAccess(path, mode) for path in wanted]
    return accesses


def _depth(path: str) -> int:
    return len([part for part in path.split("/") if part])


def _under(path: str, root: str) -> bool:
    return path == root or path.startswith(root.rstrip("/") + "/")


def _granted(access: FileAccess, policy: ResolvedPolicy) -> bool:
    if policy.proc and _under(access.path, "/proc"):
        return True
    if policy.dev and _under(access.path, "/dev"):
        return True
    if policy.home and _under(access.path, policy.home):
        return True
    if any(_under(access.path, t) for t in policy.tmpfs):
        return True
    return any(_under(access.path, b.source) for b in policy.binds if b.mode == "rw" or not access.write)


def bind_usage(accesses: list[FileAccess], policy: ResolvedPolicy) -> Counter:
    hits: Counter = Counter({bind.source: 0 for bind in policy.binds})
    for path, seen in Counter(access.path for access in accesses).items():
        for source in hits:
            if _under(path, source):
                hits[source] += seen
    return hits


def denied(accesses: list[FileAccess], policy: ResolvedPolicy, *, ignore: tuple[str, ...] = ()) -> list[FileAccess]:
    return [
        access
        for access in accesses
        if not any(access.path.startswith(prefix) for prefix in ignore) and not _granted(access, policy)
    ]


def _grant_path(path: str) -> str:
    if os.path.isdir(path):
        return path
    parent = os.path.dirname(path)
    return parent if _depth(parent) >= _MIN_GRANT_DEPTH else path


def group(files: Counter) -> Counter:
    grouped: Counter = Counter()
    for access, seen in files.items():
        grouped[replace(access, path=_grant_path(access.path))] += seen
    return grouped


def _too_broad(path: str) -> bool:
    return _depth(path) <= _TOP_LEVEL_DEPTH


def _host_pattern(target: str) -> str:
    host, _, port = target.rpartition(":")
    return host if port in ("80", "443") else target


def profile_name(command: list[str]) -> str:
    stem = Path(command[0]).name if command else "run"
    return "audit-" + (re.sub(r"[^a-zA-Z0-9_-]", "-", stem) or "run")


def render_report(report: AuditReport, *, show_granted: bool = False) -> str:
    note = "" if report.traced else " (network only, filesystem not traced)"
    files = group(report.files)
    total = len(files) + len(report.hosts)
    header = "nothing" if report.empty else f"{total} target{'' if total == 1 else 's'}"
    lines = [f"=== hozo audit: {header} outside the policy{note} ==="]

    blocks = [
        ("read", [(a.path, n) for a, n in files.items() if not a.write]),
        ("write", [(a.path, n) for a, n in files.items() if a.write]),
        ("network", list(report.hosts.items())),
    ]
    if show_granted:
        blocks.append(("already granted", list(report.granted.items())))
    for label, rows in blocks:
        if not rows:
            continue
        lines += ["", label]
        for target, count in sorted(rows, key=lambda r: (-r[1], r[0])):
            lines.append(f"  {target:<52} " + (f"x{count}" if count else "(unused)"))
    return "\n".join(lines) + "\n"


def _bind_line(bind: Bind) -> str:
    return f"  - {{ source: {bind.source}, mode: {bind.mode}, optional: true }}"


def _suggested_binds(files: Counter) -> list[Bind]:
    modes: dict[str, str] = {}
    for access in files:
        if access.write or access.path not in modes:
            modes[access.path] = access.mode
    return [Bind(source=path, mode=modes[path], optional=True) for path in sorted(modes)]


def render_profile(report: AuditReport, name: str) -> str:
    binds = _suggested_binds(group(report.files))
    hosts = sorted({_host_pattern(target) for target in report.hosts})
    granted = [b for b in binds if not _too_broad(b.source)]
    broad = [b for b in binds if _too_broad(b.source)]

    lines = [
        f"# Generated by `hozo audit` from: {shlex.join(report.command)}",
        "# Records everything the command touched, which is more than it needs. Trim it.",
        f"name: {name}",
    ]
    if granted:
        lines += ["binds:", *(_bind_line(b) for b in granted)]
    if hosts:
        lines += ["proxy:", "  allow_hosts:", *(f"    - {host}" for host in hosts)]
    if broad:
        lines += [
            "",
            "# Also touched. Left commented out: each is a whole top-level directory, so",
            "# granting one would undo most of the sandbox.",
            *("#" + _bind_line(b) for b in broad),
        ]
    return "\n".join(lines) + "\n"


def widen(request: SandboxRequest) -> SandboxRequest:
    return replace(
        request,
        profiles=[*request.profiles, AUDIT_PROFILE],
        binds=list(request.binds),
        network="proxy",  # inline: from the profile it would lose to +untrusted's 'none'
    )


def _traced(request: SandboxRequest, trace_file: Path) -> SandboxRequest:
    return replace(
        request,
        binds=[*request.binds, Bind(source=str(trace_file.parent), mode="rw")],
        command=[_check_strace(), *_STRACE_FLAGS, "-o", str(trace_file), *request.command],
    )


def _check_strace() -> str:
    strace = shutil.which("strace")
    if strace is None:
        raise HozoError(
            "audit needs 'strace' to see filesystem access, and it isn't installed.\n"
            "Or audit egress only: hozo audit --network-only ..."
        )
    return strace


class _ConnectSink(logging.Handler):
    _OUTCOMES = ("ALLOW ", "BLOCK ", "FAIL ")

    def __init__(self) -> None:
        super().__init__()
        self.hosts: Counter = Counter()

    def emit(self, record: logging.LogRecord) -> None:
        if not isinstance(record.msg, str) or not record.msg.startswith(self._OUTCOMES):
            return
        if isinstance(record.args, tuple) and len(record.args) >= 2:
            self.hosts[f"{record.args[0]}:{record.args[1]}"] += 1


@contextmanager
def _connect_sink():
    sink = _ConnectSink()
    logger = logging.getLogger("hozo.proxy")
    logger.setLevel(logging.INFO)
    logger.addHandler(sink)
    try:
        yield sink
    finally:
        logger.removeHandler(sink)


@contextmanager
def _trace_workspace():
    base = state_dir() / "audit"
    base.mkdir(parents=True, exist_ok=True)
    workdir = Path(tempfile.mkdtemp(prefix="audit-", dir=base))
    try:
        yield workdir
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


def run_audit(
    request: SandboxRequest,
    *,
    network_only: bool = False,
    environ: dict[str, str] | None = None,
) -> AuditReport:
    reference = resolve_policy(request)
    run_request = widen(request)
    report = AuditReport(command=list(request.command), returncode=0, traced=not network_only)

    with ExitStack() as stack:
        sink = stack.enter_context(_connect_sink())
        trace_file = None
        if report.traced:
            workdir = stack.enter_context(_trace_workspace())
            trace_file = workdir / "trace.log"
            run_request = _traced(run_request, trace_file)

        report.returncode = SandboxRunner().run(resolve_policy(run_request), environ=environ).returncode

        if trace_file is not None and trace_file.exists():
            found = parse_strace(trace_file.read_text(encoding="utf-8", errors="replace"))
            report.files.update(denied(found, reference, ignore=(str(trace_file.parent),)))
            report.granted.update(bind_usage(found, reference))
        report.hosts.update(sink.hosts)

    return report
