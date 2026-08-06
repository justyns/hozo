# Hozo

Simple wrapper around [`bubblewrap`](https://github.com/containers/bubblewrap) (Linux) and [`sandbox-exec`](https://keith.github.io/xcode-man-pages/sandbox-exec.1.html) / Seatbelt (macOS) that provides composable profiles for sandboxing. The backend is chosen automatically by platform; the CLI and profiles are the same on both.

Read/write/network access are all deny by default except for a minimal set of directories.

**Note**:  Hozo is not a full isolation solution, but it does make it easier to run untrusted code with a sane default policy and a few composable profiles.  This won't protect you against entirely malicious code or kernel exploits, but will help avoid accidentally leaking secrets/files, and also reduce the blast radius of a misbehaving tool.  On Linux it uses bubblewrap (kernel namespaces); on macOS it uses Seatbelt, which filters filesystem/network access but does **not** isolate processes (no separate PID namespace), so isolation there is weaker.

## Requirements

- Linux with `bubblewrap` (`bwrap`), or macOS with `sandbox-exec` (ships with macOS).
- Python ≥ 3.11. On Linux, proxy mode also needs `python3` inside the sandbox (for the egress bridge); macOS needs nothing extra.

## Install

```bash
uv tool install hozo
hozo --help
```

## Quick start

```bash
hozo +untrusted -- make test          # no network, no secrets, cwd writable
hozo +untrusted -- bash               # sandboxed shell
hozo explain +untrusted -- echo hi    # shows the resolved policy (bwrap args / SBPL profile)
hozo +node +proxy -- npm install      # network limited to the npm registry
hozo --allow-net=pypi.org -- pip install requests   # grant just this host
hozo --allow-read=/etc/hosts +untrusted -- cat /etc/hosts
hozo audit -- ./some-tool             # what would this need? (see below)
hozo profile list                     # built-in + your profiles
```

By default, the current directory is mounted read-write at the same path inside the sandbox.  So if you're in `/home/user/myproject`, then `/home/user/myproject` is mounted read-write inside the sandbox.  Other adjacent directories like `/home/user/myotherproject` are _NOT_ visible.

This allows you to run commands like `make` or `pytest` in a sandboxed environment without worrying about them accessing other files on your system.

## Profiles

Profiles are composable YAML files that define what is allowed inside the sandbox.  Multiple profiles can be combined and merged to create a final policy for the sandbox.

Several built-in profiles are provided with Hozo, but you can create your own custom profiles by putting them in `~/.config/hozo/profiles/<name>.yaml`.  Built-in profiles can also be overridden by a user profile of the same name.

`hozo profile list` shows what's available.  `hozo explain +a +b -- cmd` shows the merged result.

## Policies

Profiles are deny-by-default.  The `base` profile always applies, and other profiles can be added to grant more access.

Network is also off by default.  The `+proxy` profile enables egress through a host-side proxy, but still allows no hosts by default.  Grant hosts with `--allow-net=HOST,HOST`.

Ad-hoc allows can be granted on the cli:

- `--allow-net=HOST,HOST` allows connecting to these hosts via the proxy
- `--allow-net` with no value opens full host networking, no proxy required
- `--allow-read=PATH,PATH` / `--allow-write=PATH,PATH` allows reading/writing to specific paths.

### Syscall filtering (Linux)

`base` loads a seccomp filter denying `io_uring_*`, `bpf`, `userfaultfd`,
`perf_event_open`, the kernel keyring, and module/kexec loading: syscalls with a history of
kernel privilege-escalation bugs. Denied calls return `ENOSYS`, which callers that probe for
a feature handle as "unsupported". `unshare` and `ptrace` stay allowed, so nested sandboxes
and `hozo audit` keep working.

A tool that needs one of these has to override `base`, since denies only accumulate across
profiles.

```yaml
syscalls:
  action: errno   # errno | kill | log ('log' permits and records)
  deny:
    - perf_event_open
```

Denies from every applied profile are unioned. Ignored under macOS Seatbelt.

## Finding out what a tool needs

If you want to build a new profile for a tool or command, the easiest way to start
is by using `hozo audit`.  It runs the command in a sandbox with a very permissive policy, and reports what it accessed.

```bash
hozo audit +node -- npm install       # what does npm need beyond +node?
hozo audit --network-only -- ./tool   # egress only; no strace needed
hozo audit --show-granted -- ./tool   # also show which existing grants got used
hozo audit --audit-out=p.yaml -- make # write the suggested profile somewhere specific
```

A profile is generated in a temporary file and printed to stdout.  You can review it and 
make changes before saving it to your own profile directory.

## Network egress

Network egress is off by default.  There are three modes:

- Allow all egress.
- Allow egress to specific hosts.
- No egress at all.

```bash
hozo +proxy -- curl https://pypi.org/                        # blocked: no hosts granted
hozo --allow-net=pypi.org -- curl https://pypi.org/simple/   # 200
hozo --allow-net=pypi.org -- curl https://example.com/       # blocked: 403
hozo +python +proxy -- uv pip install ruff                   # +python grants PyPI, +proxy enables egress
```

## Everyday use

To launch a tool sandboxed without typing the full command each time, use a shell alias:

```bash
alias claude='hozo +claude -- claude'
```

A tool starts with a clean home: `$HOME` keeps its real path, but nothing under it is visible unless a profile binds it explicitly. To persist a tool's login/config, bind its config dir read-write in a profile — it's made available at the same path inside the sandbox:

```yaml
# ~/.config/hozo/profiles/mytool.yaml
name: mytool
binds:
  - { source: "~/.config/mytool", mode: rw, optional: true }
```

## Development

```bash
uv run pytest
uv run ruff check src tests
uv run black src tests
```

## Status

This is a personal project for my own needs. Use at your own risk.  Issues and PRs welcome.
