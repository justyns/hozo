"""Resolve a SandboxRequest into a ResolvedPolicy.

Layers merge in order: base, named profiles, then the request's inline fields. Conflicting
binds or env values raise MergeConflictError unless ``override`` is set. Home and cwd take the
last layer's value, and network takes the most restrictive.
"""

from __future__ import annotations

import getpass
import os
from dataclasses import dataclass, field
from pathlib import Path

from .env import matches_any
from .errors import HozoError, MergeConflictError
from .paths import SCRATCH_PLACEHOLDER, expand_path
from .profiles import NETWORK_MODES, Bind, Profile, default_base_name, load_profile
from .proxy import valid_port_spec

_NETWORK_RANK = {mode: rank for rank, mode in enumerate(NETWORK_MODES)}  # smaller = more restrictive


@dataclass
class SandboxRequest:
    command: list[str] = field(default_factory=list)
    project: str | None = None
    profiles: list[str] = field(default_factory=list)
    env: dict[str, str] = field(default_factory=dict)
    network: str | None = None
    allow_hosts: list[str] = field(default_factory=list)
    env_allow: list[str] = field(default_factory=list)
    binds: list[Bind] = field(default_factory=list)
    bind_project: bool = True
    no_base: bool = False
    override: bool = False


@dataclass
class ResolvedPolicy:
    """``_merge_layers`` starts from these defaults."""

    command: list[str] = field(default_factory=list)
    profiles_applied: list[str] = field(default_factory=list)
    network_mode: str = "none"
    clear_env: bool = True
    cwd: str = "{project}"
    home: str | None = None
    binds: list[Bind] = field(default_factory=list)
    tmpfs: list[str] = field(default_factory=list)
    env_allow: list[str] = field(default_factory=list)
    env_set: dict[str, str] = field(default_factory=dict)
    prepend_path: list[str] = field(default_factory=list)
    proc: bool = False
    dev: bool = False
    proxy_allow_hosts: list[str] = field(default_factory=list)
    syscall_deny: list[str] = field(default_factory=list)
    syscall_action: str = "errno"


def _union(into: list[str], more: list[str]) -> None:
    for item in more:
        if item not in into:
            into.append(item)


def _absolute(value: str, label: str) -> str:
    if not value.startswith("/"):
        raise HozoError(f"{label} must resolve to an absolute path: {value!r}")
    return value


def _add_expanded_bind(binds: list[Bind], bind: Bind, project: Path, *, override: bool) -> None:
    """Drops an optional bind whose source expands to nothing."""
    source = expand_path(bind.source, project=project)
    if source or not bind.optional:
        expanded = Bind(source=_absolute(source, "bind source"), mode=bind.mode, optional=bind.optional)
        _add_bind(binds, expanded, override=override)


def _add_bind(binds: list[Bind], bind: Bind, *, override: bool) -> None:
    for i, existing in enumerate(binds):
        if existing.source != bind.source:
            continue
        if existing.mode == bind.mode:
            existing.optional = existing.optional and bind.optional
            return
        if override:
            binds[i] = bind
            return
        raise MergeConflictError(
            f"bind {bind.source!r} requested by two layers with different modes: {existing.mode} vs {bind.mode}"
        )
    binds.append(bind)


def _merge_layers(layers: list[Profile], *, project: Path, override: bool) -> ResolvedPolicy:
    policy = ResolvedPolicy(profiles_applied=[layer.name for layer in layers])
    explicit_modes: list[str] = []
    for layer in layers:
        _union(policy.env_allow, layer.env_allow)
        for key, value in layer.env_set.items():
            if key in policy.env_set and policy.env_set[key] != value and not override:
                raise MergeConflictError(f"env {key!r} set to conflicting values: {policy.env_set[key]!r} vs {value!r}")
            policy.env_set[key] = value
        policy.prepend_path += layer.prepend_path
        _union(policy.tmpfs, layer.tmpfs)
        for bind in layer.binds:
            _add_expanded_bind(policy.binds, bind, project, override=override)
        _union(policy.proxy_allow_hosts, layer.proxy_allow_hosts)
        _union(policy.syscall_deny, layer.syscall_deny)
        if layer.syscall_action:
            policy.syscall_action = layer.syscall_action
        policy.proc = policy.proc or layer.proc
        policy.dev = policy.dev or layer.dev
        if layer.clear_env is not None:
            policy.clear_env = layer.clear_env
        if layer.cwd:
            policy.cwd = layer.cwd
        if layer.home:
            policy.home = layer.home
        if layer.network_mode:
            explicit_modes.append(layer.network_mode)

    if explicit_modes:
        policy.network_mode = min(explicit_modes, key=_NETWORK_RANK.__getitem__)
    return policy


def _apply_xdg_defaults(policy: ResolvedPolicy) -> None:
    """Point XDG dirs under the sandbox home unless a profile sets them."""
    if not policy.home:
        return
    for var, sub in (
        ("XDG_CONFIG_HOME", ".config"),
        ("XDG_CACHE_HOME", ".cache"),
        ("XDG_DATA_HOME", ".local/share"),
        ("XDG_STATE_HOME", ".local/state"),
    ):
        policy.env_set.setdefault(var, f"{policy.home}/{sub}")


def resolve_policy(request: SandboxRequest) -> ResolvedPolicy:
    project = Path(os.path.abspath(request.project or os.getcwd()))

    layers: list[Profile] = []
    if not request.no_base:
        layers.append(load_profile(default_base_name()))
    for name in request.profiles:
        layers.append(load_profile(name))

    policy = _merge_layers(layers, project=project, override=request.override)

    policy.cwd = _absolute(expand_path(policy.cwd, project=project), "working dir")
    if policy.home:
        policy.home = _absolute(expand_path(policy.home, project=project), "home")
    policy.prepend_path = [expand_path(p, project=project) for p in policy.prepend_path]

    if request.bind_project:
        _add_bind(policy.binds, Bind(source=str(project), mode="rw"), override=True)

    policy.env_set.update(request.env)
    _union(policy.env_allow, request.env_allow)

    # Only values with a {placeholder} expand. A leading '~' stays literal.
    policy.env_set = {
        key: expand_path(value, project=project, defer=(SCRATCH_PLACEHOLDER,)) if "{" in value else value
        for key, value in policy.env_set.items()
    }
    if request.network is not None:
        if request.network not in _NETWORK_RANK:
            raise HozoError(f"invalid network mode: {request.network!r}")
        policy.network_mode = request.network
    for host in request.allow_hosts:
        if not valid_port_spec(host):
            raise HozoError(f"invalid port in allow_hosts: {host!r}")
    _union(policy.proxy_allow_hosts, request.allow_hosts)
    for bind in request.binds:
        _add_expanded_bind(policy.binds, bind, project, override=True)

    if policy.home:
        policy.env_set.setdefault("HOME", policy.home)
    user = getpass.getuser()
    policy.env_set.setdefault("USER", user)
    policy.env_set.setdefault("LOGNAME", user)

    _apply_xdg_defaults(policy)

    # Requested passthroughs use the host value, not a default.
    policy.env_set = {key: value for key, value in policy.env_set.items() if not matches_any(key, request.env_allow)}

    policy.command = list(request.command)
    return policy
