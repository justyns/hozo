# Hozo — agent/dev notes

Small CLI **and library** for running tools inside composable sandboxes: `bubblewrap` on
Linux, `sandbox-exec` (Seatbelt) on macOS. The backend is auto-selected by platform.

## Architecture

Three layers, pure-data seam between policy and side effects:

1. **Policy resolution** (no side effects, no bwrap needed): `resolve_policy(request) ->
   ResolvedPolicy`, `build_bwrap_argv(policy) -> list[str]`, `explain_policy(policy) -> str`.
2. **Execution** (`SandboxRunner.run` → `Backend`): the selected backend translates policy→argv
   and runs it (the bwrap backend also manages the proxy).
3. **CLI** (`cli.py`): thin wrapper that builds a `SandboxRequest`.

Pipeline: load profiles → merge → backend (`backend.py`: the `Backend` ABC + platform-aware
`get_backend`; `bwrap.py`: `BubblewrapBackend`; `seatbelt.py`: `SeatbeltBackend` + the SBPL
renderer). Binds are **identity-only** — a host path is always made available at the same
path in the sandbox (no source→target remapping), so both backends can express every bind.

macOS notes: Seatbelt filters access to the real filesystem (it can't remap or overlay), so
`$HOME` stays real and only explicitly-bound subpaths under it are reachable; isolation is
weaker than Linux namespaces (no PID/process isolation). Bind sources are `realpath`'d to
their `/private/...` form. The proxy runs on a TCP loopback port (no `bridge.py`).

Public API lives in `hozo/__init__.py`.

## Hard rules

- **No upward deps.** Hozo is a leaf library — it never imports the tools that consume it.
- **Never execute shell strings.** Build the runtime invocation as an argv list; SBPL egress
  filtering can't match hostnames, so host allowlisting stays in the proxy.
- **Never print secret values** (`explain` shows env var *names* only).
- **Fail closed:** a missing backend binary is an error, never a silent unsandboxed run.
- **Two in-code backends.** `Backend` ABC in `backend.py`; `BubblewrapBackend` (`bwrap.py`,
  Linux) and `SeatbeltBackend` (`seatbelt.py`, macOS), chosen by a plain platform-aware
  factory, not plugin discovery. Keep modules small and glanceable.

## Dev loop

```bash
uv sync
uv run pytest
uv run ruff check src tests
uv run black src tests
```

Unit tests need no `bwrap`; integration tests are guarded by `skipif(not shutil.which("bwrap"))`.

## Commits

Conventional Commits (`feat:`, `fix:`, `test:`, `refactor:`, `docs:`, `chore:`). Scopes:
`profiles`, `policy`, `bwrap`, `seatbelt`, `env`, `proxy`, `cli`.
