"""Profile dataclasses + YAML loading/validation.

A profile is one composable layer. Built-ins ship in ``builtin_profiles/``; users
add or override by dropping ``<name>.yaml`` into ``~/.config/hozo/profiles/`` (user
wins on the same name).
"""

from __future__ import annotations

import functools
import importlib.resources as resources
from dataclasses import dataclass, field

import yaml

from .errors import ProfileError
from .paths import profiles_dir
from .proxy import valid_port_spec

NETWORK_MODES = ("none", "proxy", "host")
_BIND_MODES = ("ro", "rw")


@dataclass
class Bind:
    source: str
    mode: str = "ro"
    optional: bool = False


@dataclass
class Profile:
    name: str
    description: str = ""
    source: str = ""
    network_mode: str | None = None  # None means "unset" (resolver default applies)
    clear_env: bool | None = None  # None == unset; resolver defaults to True (scrub)
    cwd: str | None = None
    home: str | None = None  # absolute path for $HOME — a fresh empty dir each run
    env_allow: list[str] = field(default_factory=list)
    env_set: dict[str, str] = field(default_factory=dict)
    prepend_path: list[str] = field(default_factory=list)
    binds: list[Bind] = field(default_factory=list)
    tmpfs: list[str] = field(default_factory=list)
    proc: bool = False
    dev: bool = False
    proxy_allow_hosts: list[str] = field(default_factory=list)


def _abs_or_placeholder(value: str) -> bool:
    """True if a path is absolute, starts with ~, or contains a {placeholder}."""
    return value.startswith(("/", "~")) or "{" in value


def _str_list(value, where: str) -> list[str]:
    if value is None:
        return []
    if not isinstance(value, list) or not all(isinstance(x, str) for x in value):
        raise ProfileError(f"{where} must be a list of strings")
    return list(value)


def _str_map(value, where: str) -> dict[str, str]:
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise ProfileError(f"{where} must be a mapping")
    return {str(k): str(v) for k, v in value.items()}


def _parse_bind(raw, source: str) -> Bind:
    if not isinstance(raw, dict):
        raise ProfileError(f"{source}: each bind must be a mapping")
    src = raw.get("source")
    if not isinstance(src, str) or not _abs_or_placeholder(src):
        raise ProfileError(f"{source}: bind 'source' must be an absolute path or placeholder: {src!r}")
    mode = raw.get("mode", "ro")
    if mode not in _BIND_MODES:
        raise ProfileError(f"{source}: bind 'mode' must be 'ro' or 'rw': {mode!r}")
    return Bind(source=src, mode=mode, optional=bool(raw.get("optional", False)))


def parse_profile(data, source: str) -> Profile:
    if not isinstance(data, dict):
        raise ProfileError(f"{source}: top-level YAML must be a mapping")

    name = data.get("name")
    if not isinstance(name, str) or not name:
        raise ProfileError(f"{source}: missing or invalid 'name'")

    profile = Profile(name=name, description=str(data.get("description", "")), source=source)

    network = data.get("network")
    if isinstance(network, dict) and network.get("mode") is not None:
        mode = network["mode"]
        if mode not in NETWORK_MODES:
            raise ProfileError(f"{source}: network.mode must be one of {NETWORK_MODES}, got {mode!r}")
        profile.network_mode = mode

    process = data.get("process")
    if isinstance(process, dict):
        if "clear_env" in process:
            profile.clear_env = bool(process["clear_env"])
        profile.cwd = process.get("cwd")

    home = data.get("home")
    if home is not None:
        if not isinstance(home, str) or not _abs_or_placeholder(home):
            raise ProfileError(f"{source}: home must be an absolute path or placeholder")
        profile.home = home

    env = data.get("env")
    if isinstance(env, dict):
        profile.env_allow = _str_list(env.get("allow"), f"{source}: env.allow")
        profile.env_set = _str_map(env.get("set"), f"{source}: env.set")
        profile.prepend_path = _str_list(env.get("prepend_path"), f"{source}: env.prepend_path")
    elif env is not None:
        raise ProfileError(f"{source}: env must be a mapping")

    for raw in data.get("binds") or []:
        profile.binds.append(_parse_bind(raw, source))

    profile.tmpfs = _str_list(data.get("tmpfs"), f"{source}: tmpfs")
    for path in profile.tmpfs:
        if not path.startswith("/"):
            raise ProfileError(f"{source}: tmpfs path must be absolute: {path!r}")

    special = data.get("special")
    if isinstance(special, dict):
        profile.proc = bool(special.get("proc", False))
        profile.dev = bool(special.get("dev", False))

    proxy = data.get("proxy")
    if isinstance(proxy, dict):
        profile.proxy_allow_hosts = _str_list(proxy.get("allow_hosts"), f"{source}: proxy.allow_hosts")
        for pattern in profile.proxy_allow_hosts:
            if not valid_port_spec(pattern):
                raise ProfileError(f"{source}: invalid port in proxy.allow_hosts: {pattern!r}")

    return profile


def _load_yaml(text: str, source: str) -> dict:
    try:
        return yaml.safe_load(text) or {}
    except yaml.YAMLError as exc:
        raise ProfileError(f"{source}: invalid YAML: {exc}") from exc


@functools.cache
def _builtin_dir():
    return resources.files("hozo").joinpath("builtin_profiles")


def builtin_names() -> list[str]:
    return sorted(entry.name[:-5] for entry in _builtin_dir().iterdir() if entry.name.endswith(".yaml"))


def available_profiles() -> dict[str, str]:
    """Map profile name -> origin ('builtin' or 'user'); user shadows builtin."""
    result = {name: "builtin" for name in builtin_names()}
    user_dir = profiles_dir()
    if user_dir.is_dir():
        for path in sorted(user_dir.glob("*.yaml")):
            result[path.stem] = "user"
    return result


def load_profile(name: str) -> Profile:
    user_file = profiles_dir() / f"{name}.yaml"
    if user_file.is_file():
        text = user_file.read_text(encoding="utf-8")
        return parse_profile(_load_yaml(text, str(user_file)), str(user_file))
    builtin = _builtin_dir().joinpath(f"{name}.yaml")
    if builtin.is_file():
        text = builtin.read_text(encoding="utf-8")
        return parse_profile(_load_yaml(text, f"<builtin:{name}>"), f"<builtin:{name}>")
    raise ProfileError(f"profile not found: {name!r}")
