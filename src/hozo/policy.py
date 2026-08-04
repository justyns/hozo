"""Resolve a SandboxRequest into a ResolvedPolicy

Merge order: implicit ``base`` -> named profiles (in CLI order) -> request inline
overrides (highest priority). Binds and env ``set`` raise ``MergeConflictError`` on
conflicting values (unless ``request.override``); scalar singletons (home, cwd) take
the last layer's value and network takes the most-restrictive. Inline request
fields always win.
"""

from __future__ import annotations

import getpass
import os
from dataclasses import dataclass, field
from pathlib import Path

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
    binds: list[Bind] = field(default_factory=list)
    bind_project: bool = True
    no_base: bool = False
    override: bool = False


@dataclass
class ResolvedPolicy:
    """Defaults here *are* the resolver's starting point — ``_merge_layers`` folds layers
    onto a bare ``ResolvedPolicy()`` rather than restating them."""

    command: list[str] = field(default_factory=list)
    profiles_applied: list[str] = field(default_factory=list)
    network_mode: str = "none"
    clear_env: bool = True  # secure default; a layer can opt out with clear_env: false
    cwd: str = "{project}"  # expanded against the project path by resolve_policy
    home: str | None = None
    binds: list[Bind] = field(default_factory=list)
    tmpfs: list[str] = field(default_factory=list)
    env_allow: list[str] = field(default_factory=list)
    env_set: dict[str, str] = field(default_factory=dict)
    prepend_path: list[str] = field(default_factory=list)
    proc: bool = False
    dev: bool = False
    proxy_allow_hosts: list[str] = field(default_factory=list)


def _union(into: list[str], more: list[str]) -> None:
    for item in more:
        if item not in into:
            into.append(item)


def _absolute(value: str, label: str) -> str:
    if not value.startswith("/"):
        raise HozoError(f"{label} must resolve to an absolute path: {value!r}")
    return value


def _expand_bind(bind: Bind, project: str) -> Bind:
    source = expand_path(bind.source, project=Path(project))
    _absolute(source, "bind source")
    return Bind(source=source, mode=bind.mode, optional=bind.optional)


def _add_bind(binds: list[Bind], bind: Bind, *, override: bool) -> None:
    for i, existing in enumerate(binds):
        if existing.source != bind.source:
            continue
        if existing.mode == bind.mode:
            # same mount from two layers; a required bind wins over an optional one
            existing.optional = existing.optional and bind.optional
            return
        if override:
            binds[i] = bind
            return
        raise MergeConflictError(
            f"bind {bind.source!r} requested by two layers with different modes: {existing.mode} vs {bind.mode}"
        )
    binds.append(bind)


def _merge_layers(layers: list[Profile], *, project: str, override: bool) -> ResolvedPolicy:
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
            _add_bind(policy.binds, _expand_bind(bind, project), override=override)
        _union(policy.proxy_allow_hosts, layer.proxy_allow_hosts)
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
    """Point XDG dirs at the (writable) sandbox home so cache binds line up. A profile
    that sets them explicitly wins. Lives here so ``explain`` reports them truthfully."""
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
    # Absolutize so a relative --project (e.g. '..') resolves predictably before it
    # becomes a bind source.
    project = os.path.abspath(request.project or os.getcwd())

    layers: list[Profile] = []
    if not request.no_base:
        layers.append(load_profile(default_base_name()))
    for name in request.profiles:
        layers.append(load_profile(name))

    policy = _merge_layers(layers, project=project, override=request.override)

    # Expand placeholders ({project}, {home}, ~, ...) in the working dir, home, and PATH.
    proj = Path(project)
    policy.cwd = _absolute(expand_path(policy.cwd, project=proj), "working dir")
    if policy.home:
        policy.home = _absolute(expand_path(policy.home, project=proj), "home")
    policy.prepend_path = [expand_path(p, project=proj) for p in policy.prepend_path]

    # The project is mounted read-write in place at its real host path; cwd defaults to it.
    if request.bind_project:
        _add_bind(policy.binds, Bind(source=project, mode="rw"), override=True)

    # Inline request fields win unconditionally over profiles.
    policy.env_set.update(request.env)

    # Braced values only, so a value that merely starts with '~' stays literal.
    policy.env_set = {
        key: expand_path(value, project=proj, defer=(SCRATCH_PLACEHOLDER,)) if "{" in value else value
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
        _add_bind(policy.binds, _expand_bind(bind, project), override=True)

    # Identity: HOME follows the sandbox home; USER/LOGNAME default to the real user.
    if policy.home:
        policy.env_set.setdefault("HOME", policy.home)
    user = getpass.getuser()
    policy.env_set.setdefault("USER", user)
    policy.env_set.setdefault("LOGNAME", user)

    _apply_xdg_defaults(policy)

    policy.command = list(request.command)
    return policy
