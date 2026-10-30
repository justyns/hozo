# Hozo

Composable sandbox profiles over [`bubblewrap`](https://github.com/containers/bubblewrap) on Linux and [`sandbox-exec`](https://keith.github.io/xcode-man-pages/sandbox-exec.1.html) (Seatbelt) on macOS.

Read/write/network access are all deny by default except for a minimal set of directories.

**Note**:  Hozo is not a full isolation solution, but it does make it easier to run untrusted code with a sane default policy and a few composable profiles.  This won't protect you against entirely malicious code or kernel exploits, but will help avoid accidentally leaking secrets/files, and also reduce the blast radius of a misbehaving tool.  On Linux it uses bubblewrap (kernel namespaces); on macOS it uses Seatbelt, which filters filesystem/network access but does **not** isolate processes (no separate PID namespace), so isolation there is weaker.

## Requirements

- Linux with `bubblewrap` (`bwrap`), or macOS with `sandbox-exec` (ships with macOS).
- Python 3.11+. On Linux, proxy mode runs the host's `python3` inside the sandbox.

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
hozo --allow-net=github.com -- git clone https://github.com/containers/bubblewrap   # grant just this host
hozo --allow-read=$HOME/.gitconfig +untrusted -- git config -l
hozo audit -- ./some-tool             # what would this need? (see below)
hozo profile list                     # built-in + your profiles
```

By default, the current directory is mounted read-write at the same path inside the sandbox.  So if you're in `/home/user/myproject`, then `/home/user/myproject` is mounted read-write inside the sandbox.  Other adjacent directories like `/home/user/myotherproject` are _NOT_ visible.

This allows you to run commands like `make` or `pytest` in a sandboxed environment without worrying about them accessing other files on your system.

## Profiles

Profiles are YAML files merged in command-line order. Put your own in `~/.config/hozo/profiles/<name>.yaml`. A user profile overrides a built-in of the same name. `hozo profile list` shows what's available, and `hozo explain +a +b -- cmd` shows the merged result.

`base` (`base-macos` on macOS) applies to every run unless you pass `--no-base`. Other profiles add access. `+proxy` routes egress through a host-side proxy that allows no hosts until a profile or `--allow-net=HOST` grants them.

Command-line grants:

- `--allow-net=HOST,HOST` allows these hosts through the proxy
- `--allow-net=10.0.0.0/8,[fd00::/8]:443` allows IPs
- `--allow-net` with no value allows all egress
- `--allow-read=PATH,PATH` / `--allow-write=PATH,PATH` mount these paths read-only / read-write
- `--allow-env=NAME,NAME` passes these environment variables through

### Syscall filtering (Linux)

On Linux, `base` loads a seccomp filter that denies `io_uring_*`, `bpf`, `userfaultfd`,
`perf_event_open`, `open_by_handle_at`, the kernel keyring, and module/kexec loading. Denied
calls return `ENOSYS`. `unshare` and `ptrace` stay allowed for nested sandboxes and `hozo audit`.

Denies accumulate across profiles. `action` takes the last profile's value, so a profile that
sets `action: log` permits every denied call and records it.

```yaml
syscalls:
  action: errno   # errno | kill | log ('log' permits and records)
  deny:
    - perf_event_open
```

## Finding out what a tool needs

`hozo audit` runs the command with every host path readable and all egress allowed, and lists
what the requested profiles would deny.

```bash
hozo audit +node -- npm install       # what does npm need beyond +node?
hozo audit --network-only -- ./tool   # egress only; no strace needed
hozo audit --show-granted -- ./tool   # also show which existing grants got used
hozo audit --audit-out=p.yaml -- make # write the suggested profile somewhere specific
```

If the command touched anything outside the policy, audit writes a suggested profile to a temp
file (or `--audit-out`) and prints its path. Review it, then copy it into your profile directory.

## Network egress

```bash
hozo +proxy -- curl https://pypi.org/                        # blocked: no hosts granted
hozo --allow-net=pypi.org -- curl https://pypi.org/simple/   # 200
hozo --allow-net=pypi.org -- curl https://example.com/       # blocked: 403
hozo +python +proxy -- uv pip install ruff                   # +python grants PyPI, +proxy enables egress
```

## Everyday use

Use a shell alias to run a tool sandboxed by default:

```bash
alias claude='hozo +claude -- claude'
```

`$HOME` keeps its real path but starts empty. To keep a tool's login or config, bind its config dir read-write in a profile:

```yaml
# ~/.config/hozo/profiles/mytool.yaml
name: mytool
binds:
  - { source: "~/.config/mytool", mode: rw, optional: true }
```

## Status

Personal project. Use at your own risk. Issues and PRs welcome.
