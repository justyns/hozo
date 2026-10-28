"""Thin CLI over the library. Everything after ``--`` is the command, passed verbatim and never
shell-parsed."""

from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path

from . import __version__, audit
from .errors import HozoError
from .executor import SandboxRunner
from .explain import explain_policy
from .policy import SandboxRequest, resolve_policy
from .profiles import Bind, available_profiles

_VERBS = ("run", "explain", "profile", "audit")
_VALUE_OPTS = {"--project": "project", "--network": "network"}
_BOOL_FLAGS = {"--no-base": "no_base", "--override": "override"}

_USAGE = """\
hozo: run tools in composable sandboxes

  hozo +profile [+profile ...] -- COMMAND [ARGS...]
  hozo explain +profile ... -- COMMAND
  hozo audit   +profile ... -- COMMAND
  hozo profile list

Grants (deny-by-default): --allow-net[=HOST,...]  --allow-read=PATH,...  --allow-write=PATH,...
                          --allow-env=NAME,...
Flags: --project PATH  --network none|proxy|host  --no-base  --override  --version
Audit: --network-only  --show-granted  --audit-out=PATH
"""


class _UsageError(Exception):
    """``code`` is the exit status. Without a message, main prints the usage."""

    def __init__(self, code: int, message: str | None = None):
        super().__init__(message)
        self.code = code
        self.message = message


def _csv(tok: str) -> list[str]:
    return [item for item in tok.split("=", 1)[1].split(",") if item]


def _is_profile(tok: str) -> bool:
    return tok.startswith("+") and len(tok) > 1


_AUDIT_BOOL_OPTS = ("--network-only", "--show-granted")


def _is_audit_opt(tok: str) -> bool:
    return tok in _AUDIT_BOOL_OPTS or tok.startswith("--audit-out=")


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv:
        print(_USAGE)
        return 0

    command: list[str] = []
    if "--" in argv:
        idx = argv.index("--")
        argv, command = argv[:idx], argv[idx + 1 :]
    # After the split, so `-- cmd --version` stays part of the command.
    if "--version" in argv:
        print(__version__)
        return 0
    profiles = [tok[1:] for tok in argv if _is_profile(tok)]
    audit_opts = {tok[2:].replace("-", "_"): True for tok in argv if tok in _AUDIT_BOOL_OPTS}
    audit_out = next((tok.split("=", 1)[1] for tok in argv if tok.startswith("--audit-out=")), None)
    tokens = [tok for tok in argv if not _is_profile(tok) and not _is_audit_opt(tok)]

    try:
        request, positional = _parse_flags(tokens)
        verb = positional.pop(0) if positional and positional[0] in _VERBS else "run"
        if verb == "profile":
            return _cmd_profile(positional)
        if not command:
            raise _UsageError(2, f"'{verb}' needs a command after '--'")
        if verb != "audit" and (audit_opts or audit_out is not None):
            raise _UsageError(2, "--network-only, --show-granted and --audit-out only apply to 'hozo audit'")
        request.profiles, request.command = profiles, command

        if verb == "audit":
            return _cmd_audit(request, out_path=audit_out, **audit_opts)

        policy = resolve_policy(request)
        if verb == "explain":
            print(explain_policy(policy))
            return 0
        return SandboxRunner().exec(policy)
    except _UsageError as exc:
        if exc.message:
            print(f"hozo: {exc.message}", file=sys.stderr)
        else:
            print(_USAGE)
        return exc.code
    except HozoError as exc:
        print(f"hozo: {exc}", file=sys.stderr)
        return 1


def _parse_flags(tokens: list[str]) -> tuple[SandboxRequest, list[str]]:
    request = SandboxRequest()
    positional: list[str] = []
    walker = iter(tokens)
    for tok in walker:
        if tok in ("-h", "--help"):
            raise _UsageError(0)
        elif tok in _VALUE_OPTS:
            value = next(walker, None)
            if value is None or value.startswith("-"):
                raise _UsageError(2, f"option {tok} needs a value")
            setattr(request, _VALUE_OPTS[tok], value)
        elif tok in _BOOL_FLAGS:
            setattr(request, _BOOL_FLAGS[tok], True)
        elif tok == "--allow-net":
            request.network = "host"
        elif tok.startswith("--allow-net="):
            request.network = "proxy"
            request.allow_hosts += _csv(tok)
        elif tok.startswith("--allow-env="):
            request.env_allow += _csv(tok)
        elif tok.startswith("--allow-read="):
            request.binds += _binds(tok, "ro")
        elif tok.startswith("--allow-write="):
            request.binds += _binds(tok, "rw")
        elif tok in ("--allow-env", "--allow-read", "--allow-write"):
            raise _UsageError(2, f"{tok} needs values, e.g. {tok}=A,B")
        elif tok.startswith("-"):
            raise _UsageError(2, f"unknown option {tok!r}")
        else:
            positional.append(tok)
    return request, positional


def _binds(tok: str, mode: str) -> list[Bind]:
    return [Bind(source=os.path.abspath(path), mode=mode) for path in _csv(tok)]


def _cmd_audit(
    request: SandboxRequest,
    *,
    out_path: str | None,
    network_only: bool = False,
    show_granted: bool = False,
) -> int:
    """Prints the report to stderr to keep the audited command's stdout pipeable."""
    print(audit.BANNER, end="", file=sys.stderr)
    report = audit.run_audit(request, network_only=network_only)
    print("\n" + audit.render_report(report, show_granted=show_granted), end="", file=sys.stderr)

    if not report.empty:
        name = audit.profile_name(request.command)
        target = Path(out_path) if out_path else _temp_profile(name)
        target.write_text(audit.render_profile(report, name), encoding="utf-8")
        print(f"\nSuggested profile: {target}", file=sys.stderr)
    return report.returncode


def _temp_profile(name: str) -> Path:
    """Temp file outside the project, to keep untracked files out of the repo."""
    fd, path = tempfile.mkstemp(prefix=f"hozo-{name}-", suffix=".yaml")
    os.close(fd)
    return Path(path)


def _cmd_profile(args: list[str]) -> int:
    if args and args[0] == "list":
        for name, origin in sorted(available_profiles().items()):
            print(f"{name:20} {origin}")
        return 0
    raise _UsageError(2, "usage: hozo profile list")
