# Hozo — agent/dev notes

Small Linux CLI **and library** for running tools inside composable `bubblewrap` sandboxes.

## Architecture

Three layers, pure-data seam between policy and side effects:

1. **Policy resolution** (no side effects, no bwrap needed): `resolve_policy(request) ->
   ResolvedPolicy`, `build_bwrap_argv(policy) -> list[str]`, `explain_policy(policy) -> str`.
2. **Execution** (`SandboxRunner.run` → `Backend`): the selected backend translates policy→argv
   and runs it (the bwrap backend also manages the proxy).
3. **CLI** (`cli.py`): thin wrapper that builds a `SandboxRequest`.

Pipeline: load profiles → merge → backend (`backend.py`: the `Backend` ABC + `get_backend`;
`bwrap.py`: `BubblewrapBackend` + the renderer).

Public API lives in `hozo/__init__.py`.

## Hard rules

- **No upward deps.** Hozo is a leaf library — it never imports the tools that consume it.
- **Never execute shell strings.** Build `bwrap` as an argv list.
- **Never print secret values** (`explain` shows env var *names* only).
- **Fail closed:** missing `bwrap` is an error, never a silent unsandboxed run.
- **One in-code backend (bwrap).** `Backend` ABC in `backend.py`, `BubblewrapBackend` in
  `bwrap.py`; a plain in-code factory, not plugin discovery. Keep modules small and glanceable.

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
`profiles`, `policy`, `bwrap`, `env`, `proxy`, `cli`.
