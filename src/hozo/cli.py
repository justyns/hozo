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
# Flags that map straight onto a SandboxRequest field.
_VALUE_OPTS = {"--project": "project", "--network": "network"}
_BOOL_FLAGS = {"--no-base": "no_base", "--override": "override"}

_USAGE = """\
hozo — run tools in composable sandboxes

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
        request, positional = _parse_flags(tokens)
        verb = positional.pop(0) if positional and positional[0] in _VERBS else "run"
        if verb == "profile":
            return _cmd_profile(positional)
        if not command:
            raise _UsageError(2, f"'{verb}' needs a command after '--'")
        request.profiles, request.command = profiles, command

        policy = resolve_policy(request)
        if verb == "explain":
            print(explain_policy(policy))
            return 0
        return SandboxRunner().run(policy).returncode
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
    """Fold the flag tokens into a SandboxRequest; return it plus the leftover positionals.
    Raises ``_UsageError`` on a bad flag."""
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
        elif tok == "--allow-net":  # bare = full host network
            request.network = "host"
        elif tok.startswith("--allow-net="):  # specific hosts -> proxy allowlist
            request.network = "proxy"
            request.allow_hosts += _csv(tok)
        elif tok.startswith("--allow-read="):
            request.binds += _binds(tok, "ro")
        elif tok.startswith("--allow-write="):
            request.binds += _binds(tok, "rw")
        elif tok in ("--allow-read", "--allow-write"):
            raise _UsageError(2, f"{tok} needs paths, e.g. {tok}=/path/a,/path/b")
        elif tok.startswith("-"):
            raise _UsageError(2, f"unknown option {tok!r}")
        else:
            positional.append(tok)
    return request, positional


def _binds(tok: str, mode: str) -> list[Bind]:
    return [Bind(source=os.path.abspath(path), mode=mode) for path in _csv(tok)]


def _cmd_profile(args: list[str]) -> int:
    if args and args[0] == "list":
        for name, origin in sorted(available_profiles().items()):
            print(f"{name:20} {origin}")
        return 0
    raise _UsageError(2, "usage: hozo profile list")


if __name__ == "__main__":
    sys.exit(main())
