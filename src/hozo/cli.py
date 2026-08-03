"""Thin CLI over the library.

Grammar (``+name`` tokens select profiles; everything after ``--`` is the command,
kept verbatim and never shell-parsed):

    hozo +p [+p ...] -- CMD [ARGS...]        # run (default verb)
    hozo run     +p ... -- CMD ...
    hozo explain +p ... -- CMD ...
    hozo profile list

Grants are deny-by-default — nothing is allowed unless a profile or an --allow-* flag
grants it: --allow-net[=HOST,...], --allow-read=PATH,..., --allow-write=PATH,....
"""

from __future__ import annotations

import os
import sys

from .errors import HozoError
from .executor import SandboxRunner
from .explain import explain_policy
from .policy import SandboxRequest, resolve_policy
from .profiles import Bind, available_profiles

_VERBS = ("run", "explain", "profile")
_VALUE_OPTS = {"--project": "project", "--network": "network"}
_BOOL_FLAGS = {"--no-base": "no_base", "--override": "override"}

_USAGE = """\
hozo — run tools in composable bubblewrap sandboxes

  hozo +profile [+profile ...] -- COMMAND [ARGS...]
  hozo explain +profile ... -- COMMAND
  hozo profile list

Grants (deny-by-default): --allow-net[=HOST,...]  --allow-read=PATH,...  --allow-write=PATH,...
Flags: --project PATH  --network none|proxy|host  --no-base  --override
"""


class _UsageError(Exception):
    """Stop parsing and exit: with a message it's an error on stderr; without one it prints
    help. ``code`` is the process exit status (2 for errors, 0 for --help)."""

    def __init__(self, code: int, message: str | None = None):
        super().__init__(message)
        self.code = code
        self.message = message


def _csv(tok: str) -> list[str]:
    return [item for item in tok.split("=", 1)[1].split(",") if item]


def _is_profile(tok: str) -> bool:
    return tok.startswith("+") and len(tok) > 1


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv:
        print(_USAGE)
        return 0

    # TODO: maybe argparse or click would be better
    command: list[str] = []
    if "--" in argv:
        idx = argv.index("--")
        argv, command = argv[:idx], argv[idx + 1 :]
    profiles = [tok[1:] for tok in argv if _is_profile(tok)]
    tokens = [tok for tok in argv if not _is_profile(tok)]

    try:
        opts, positional = _parse_flags(tokens)
        verb = positional.pop(0) if positional and positional[0] in _VERBS else "run"
        if verb == "profile":
            return _cmd_profile(positional)
        if not command:
            raise _UsageError(2, f"'{verb}' needs a command after '--'")
        return _cmd_run(profiles, command, opts, explain_only=(verb == "explain"))
    except _UsageError as exc:
        if exc.message:
            print(f"hozo: {exc.message}", file=sys.stderr)
        else:
            print(_USAGE)
        return exc.code
    except HozoError as exc:
        print(f"hozo: {exc}", file=sys.stderr)
        return 1


def _parse_flags(tokens: list[str]) -> tuple[dict, list[str]]:
    """Split remaining tokens into (opts, positionals). Raises ``_UsageError`` on a bad flag."""
    opts = {
        "project": None,
        "network": None,
        "allow_hosts": [],
        "allow_read": [],
        "allow_write": [],
        "no_base": False,
        "override": False,
    }
    positional: list[str] = []
    walker = iter(tokens)
    for tok in walker:
        if tok in ("-h", "--help"):
            raise _UsageError(0)
        elif tok in _VALUE_OPTS:
            value = next(walker, None)
            if value is None or value.startswith("-"):
                raise _UsageError(2, f"option {tok} needs a value")
            opts[_VALUE_OPTS[tok]] = value
        elif tok in _BOOL_FLAGS:
            opts[_BOOL_FLAGS[tok]] = True
        elif tok == "--allow-net":  # bare = full host network
            opts["network"] = "host"
        elif tok.startswith("--allow-net="):  # specific hosts -> proxy allowlist
            opts["network"] = "proxy"
            opts["allow_hosts"] += _csv(tok)
        elif tok.startswith("--allow-read="):
            opts["allow_read"] += _csv(tok)
        elif tok.startswith("--allow-write="):
            opts["allow_write"] += _csv(tok)
        elif tok in ("--allow-read", "--allow-write"):
            raise _UsageError(2, f"{tok} needs paths, e.g. {tok}=/path/a,/path/b")
        elif tok.startswith("-"):
            raise _UsageError(2, f"unknown option {tok!r}")
        else:
            positional.append(tok)
    return opts, positional


def _build_request(profiles: list[str], command: list[str], opts: dict) -> SandboxRequest:
    binds = [Bind(source=os.path.abspath(p), mode="ro") for p in opts["allow_read"]]
    binds += [Bind(source=os.path.abspath(p), mode="rw") for p in opts["allow_write"]]
    return SandboxRequest(
        command=command,
        project=opts["project"],
        profiles=profiles,
        network=opts["network"],
        allow_hosts=opts["allow_hosts"],
        binds=binds,
        no_base=opts["no_base"],
        override=opts["override"],
    )


def _cmd_run(profiles: list[str], command: list[str], opts: dict, *, explain_only: bool) -> int:
    policy = resolve_policy(_build_request(profiles, command, opts))
    if explain_only:
        print(explain_policy(policy))
        return 0
    return SandboxRunner().run(policy).returncode


def _cmd_profile(args: list[str]) -> int:
    if args and args[0] == "list":
        for name, origin in sorted(available_profiles().items()):
            print(f"{name:20} {origin}")
        return 0
    raise _UsageError(2, "usage: hozo profile list")


if __name__ == "__main__":
    sys.exit(main())
