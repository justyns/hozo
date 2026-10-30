"""XDG base-directory paths for Hozo, and host-path placeholder expansion."""

import getpass
import os
import re
from pathlib import Path

from .errors import HozoError

_APP = "hozo"
_PLACEHOLDER = re.compile(r"\{(\w+)\}")


def _xdg(env_var: str, *default_parts: str) -> Path:
    base = os.environ.get(env_var)
    if base:
        return Path(base) / _APP
    return Path.home().joinpath(*default_parts, _APP)


def config_dir() -> Path:
    return _xdg("XDG_CONFIG_HOME", ".config")


def state_dir() -> Path:
    return _xdg("XDG_STATE_HOME", ".local", "state")


def profiles_dir() -> Path:
    return config_dir() / "profiles"


# Placeholders that need no request context.
_RESOLVERS = {
    "home": Path.home,
    "user": getpass.getuser,
    "ssh_auth_sock": lambda: os.environ.get("SSH_AUTH_SOCK", ""),
}

# Filled in by build_env, since only a backend knows the per-run temp dir.
SCRATCH_PLACEHOLDER = "{scratch}"


def expand_path(value: str, *, project: Path | None = None, defer: tuple[str, ...] = ()) -> str:
    """Expand Hozo placeholders and ``~`` in a path. Unknown placeholders raise; anything
    in ``defer`` is left for a later pass."""

    def resolve(match: re.Match) -> str:
        name = match.group(1)
        if match.group(0) in defer:
            return match.group(0)
        if name == "project":
            if project is None:
                raise HozoError(f"{{project}} used but no project path is available: {value!r}")
            return str(project)
        resolver = _RESOLVERS.get(name)
        if resolver is None:
            raise HozoError(f"unknown placeholder {{{name}}} in {value!r}")
        return str(resolver())

    return os.path.expanduser(_PLACEHOLDER.sub(resolve, value))
