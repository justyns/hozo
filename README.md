# Hozo

Simple wrapper around [`bubblewrap`](https://github.com/containers/bubblewrap)  that provides composable profiles for sandboxing.

Read/write/network access are all deny by default except for a minimal set of directories.

**Note**:  Hozo uses bubblewrap and is still subject to its limitations.  It's not a full isolation solution, but it does make it easier to run untrusted code with a sane default policy and a few composable profiles.  This won't protect you against entirely malicious code or kernel exploits, but will help avoid accidentally leaking secrets/files, and also reduce the blast radius of a misbehaving tool.

## Requirements

- Linux with `bubblewrap` (`bwrap`). Other OSes are not supported.
- Python ≥ 3.11. Proxy mode also needs `python3` inside the sandbox.

## Install

```bash
uv tool install hozo
hozo --help
```

## Quick start

```bash
hozo +untrusted -- make test          # no network, no secrets, cwd writable
hozo +untrusted -- bash               # sandboxed shell
hozo explain +untrusted -- echo hi    # shows what bwrap args would be used
hozo +node +proxy -- npm install      # network limited to the npm registry
hozo --allow-net=pypi.org -- pip install requests   # grant just this host
hozo --allow-read=/etc/hosts +untrusted -- cat /etc/hosts
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

The sandbox home is wiped each run. To persist a tool's login/config, bind a host dir over the sandbox home in a profile:

```yaml
# ~/.config/hozo/profiles/claude-home.yaml
name: claude-home
binds:
  - { source: "~/.hozo/claude", target: "{home}", mode: rw }
```

## Development

```bash
uv run pytest
uv run ruff check src tests
uv run black src tests
```

## Status

This is a personal project for my own needs. Use at your own risk.  Issues and PRs welcome.
