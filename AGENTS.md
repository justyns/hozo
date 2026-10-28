# Hozo agent notes

CLI and library that run tools in composable sandboxes: `bubblewrap` on Linux, `sandbox-exec`
(Seatbelt) on macOS, picked by platform.

## Architecture

1. Policy resolution, with no side effects: `resolve_policy(request) -> ResolvedPolicy`
   (`policy.py`) loads profiles and merges them.
2. Rendering, also pure: `build_bwrap_argv`, `build_seatbelt_profile`, `build_seccomp_filter`,
   `explain_policy`.
3. Execution: `SandboxRunner.run`/`exec` hands the policy to the `Backend` from `get_backend`
   (`backend.py`). `BubblewrapBackend` (`bwrap.py`) and `SeatbeltBackend` (`seatbelt.py`) each
   start the egress proxy in proxy mode.
4. CLI (`cli.py`) builds a `SandboxRequest`.

Binds are identity-only. A host path appears at the same path in the sandbox, so both backends
can express every bind.

The `base` seccomp denylist leaves out `unshare` and `ptrace` for nested sandboxes and
`hozo audit`. An arch with no syscall table gets no filter, and Seatbelt ignores `syscalls`.
Neither case is an error, since profiles are shared across platforms.

Path placeholders (`{home}`, `{project}`, `{user}`, `{ssh_auth_sock}`) expand during policy
resolution, in binds and `env.set` values. `{scratch}` expands later in `build_env`, because
only the backend creates the per-run temp dir.

`audit.py` (`hozo audit`) runs the command with the `insecure` profile added, `network="proxy"`
set inline, and `strace` inside the sandbox, then reports what the original policy would deny.
It relies on:

- identity-only binds, so traced paths are host paths
- binds applied after `--dir`, so `insecure`'s `/home` bind shows over `base`'s empty `$HOME`
- `insecure`'s allowlist (`*:*` plus `0.0.0.0/0:*` and `[::/0]:*`) allowing all egress
- `strace` running inside the sandbox, so bwrap's own setup stays out of the trace

`insecure` binds top-level dirs one by one. Binding `/` would mount over `/proc`, `/dev` and the
merged-/usr symlinks.

macOS: Seatbelt filters access to the real filesystem and cannot remap paths, so `$HOME` is the
real home and only bound subpaths under it are reachable. It has no PID isolation. The proxy
listens on a loopback TCP port, with no `bridge.py`. SBPL cannot match hostnames, so host
allowlisting stays in the proxy.

Public API lives in `hozo/__init__.py`.

## Hard rules

- Hozo is a leaf library and never imports the tools that use it.
- Build runtime invocations as argv lists. The proxy bridge's `sh -c` quotes the command with
  `shlex.join`.
- Never print secret values. `explain` shows env var names only.
- Fail closed. A missing backend binary is an error, never an unsandboxed run.

## Dev loop

```bash
uv sync
uv run pytest
uv run ruff check src tests
uv run black src tests
```

Unit tests need no `bwrap`; integration tests are guarded by `skipif(not hozo.check_available())`.
The filesystem half of `hozo audit` also needs `strace` (`tests/test_audit.py::needs_strace`).

## Commits

Conventional Commits (`feat:`, `fix:`, `test:`, `refactor:`, `docs:`, `chore:`). Scopes:
`profiles`, `policy`, `bwrap`, `seatbelt`, `seccomp`, `env`, `proxy`, `cli`, `audit`.
