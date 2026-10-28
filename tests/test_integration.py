"""Integration tests: run real commands in a real sandbox and check the security
contract from the inside — what should be reachable is, and what shouldn't be isn't.

Backend-agnostic on purpose. These run against whichever runtime the platform provides
(bwrap on Linux, Seatbelt on macOS) so both get identical scrutiny, and the enforcement
claims are tested rather than the rendered policy that is supposed to produce them.

The probes are bash rather than python: `/dev/tcp` is a bash builtin, so they need nothing
inside the sandbox beyond a shell that both platforms ship in /bin.
"""

import os
import shutil
import signal
import socket
import subprocess
import tempfile
import threading
import uuid
from pathlib import Path

import pytest
from conftest import HOZO_CLI, linux_only, macos_only, proxy_up, wait_until

import hozo

pytestmark = pytest.mark.skipif(not hozo.check_available(), reason="no sandbox runtime installed")

# Open a CONNECT tunnel through $HTTP_PROXY to $1 and print the status line.
_VIA_PROXY = r"""
proxy=${HTTP_PROXY#http://}
exec 3<>/dev/tcp/${proxy%%:*}/${proxy##*:}
printf 'CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n' "$1" "$1" >&3
head -n 1 <&3
"""

# Ignore the proxy entirely and dial $1 directly.
_DIRECT = r"""
host=${1%%:*}
port=${1##*:}
(exec 3<>/dev/tcp/$host/$port) 2>/dev/null && echo REACHED || echo BLOCKED
"""


def _run(command, project, **kw):
    return hozo.run(hozo.SandboxRequest(command=command, project=str(project), **kw), capture=True)


def _bash(script, arg, project, **kw):
    return _run(["/bin/bash", "-c", script, "_", arg], project, **kw)


@pytest.fixture
def upstream():
    """A host-side listener that the sandbox is only ever allowed to reach via the proxy."""
    server = socket.socket()
    server.bind(("127.0.0.1", 0))
    server.listen(8)

    def serve():
        while True:
            try:
                conn, _ = server.accept()
            except OSError:
                return
            conn.sendall(b"hello")
            conn.close()

    threading.Thread(target=serve, daemon=True).start()
    yield server.getsockname()[1]
    server.close()


# --- filesystem ---


def test_project_is_readable_and_writable(tmp_path):
    (tmp_path / "inside.txt").write_text("inside")
    res = _run(["/bin/sh", "-c", "cat inside.txt && echo made > new.txt"], tmp_path)
    assert res.returncode == 0, res.stderr
    assert "inside" in res.stdout
    assert (tmp_path / "new.txt").read_text().strip() == "made"


def test_unbound_sibling_is_denied(tmp_path):
    project = tmp_path / "project"
    project.mkdir()
    (tmp_path / "secret.txt").write_text("classified")
    res = _run(["/bin/cat", str(tmp_path / "secret.txt")], project)
    assert res.returncode != 0
    assert "classified" not in res.stdout


def test_symlink_does_not_escape_the_project(tmp_path):
    """A symlink is not a hole: following it still lands on a path that was never bound."""
    project = tmp_path / "project"
    project.mkdir()
    (tmp_path / "secret.txt").write_text("classified")
    (project / "escape").symlink_to(tmp_path / "secret.txt")
    res = _run(["/bin/cat", "escape"], project)
    assert res.returncode != 0
    assert "classified" not in res.stdout


def test_home_contents_are_not_exposed(tmp_path):
    # $HOME keeps its real path, but nothing under it is bound, so the listing is empty
    # (bwrap mounts an empty dir there) or fails outright (Seatbelt denies the read).
    res = _run(["/bin/sh", "-c", "ls -a ~ | wc -l"], tmp_path)
    assert res.returncode != 0 or res.stdout.strip() in {"0", "1", "2"}


def test_allow_read_grants_exactly_one_path(tmp_path):
    project = tmp_path / "project"
    project.mkdir()
    (tmp_path / "granted.txt").write_text("readable")
    (tmp_path / "ungranted.txt").write_text("classified")
    granted = hozo.Bind(source=str(tmp_path / "granted.txt"), mode="ro")

    res = _run(["/bin/cat", str(tmp_path / "granted.txt")], project, binds=[granted])
    assert res.returncode == 0 and "readable" in res.stdout

    res = _run(["/bin/cat", str(tmp_path / "ungranted.txt")], project, binds=[granted])
    assert res.returncode != 0 and "classified" not in res.stdout


def test_read_only_bind_rejects_writes(tmp_path):
    project = tmp_path / "project"
    project.mkdir()
    readonly = tmp_path / "ro"
    readonly.mkdir()
    (readonly / "f.txt").write_text("original")

    res = _bash(
        'echo tampered > "$1"/f.txt && echo WROTE || echo REFUSED',
        str(readonly),
        project,
        binds=[hozo.Bind(source=str(readonly), mode="ro")],
    )
    assert res.stdout.strip() == "REFUSED"
    assert (readonly / "f.txt").read_text() == "original"


# --- network ---


def test_allowed_host_is_reachable_through_the_proxy(tmp_path, upstream):
    res = _bash(_VIA_PROXY, f"127.0.0.1:{upstream}", tmp_path, network="proxy", allow_hosts=[f"127.0.0.1:{upstream}"])
    assert res.returncode == 0, res.stderr
    assert "200" in res.stdout


def test_unlisted_host_is_refused_by_the_proxy(tmp_path, upstream):
    res = _bash(_VIA_PROXY, "blocked.example:443", tmp_path, network="proxy", allow_hosts=[f"127.0.0.1:{upstream}"])
    assert res.returncode == 0, res.stderr
    assert "403" in res.stdout


def test_proxy_cannot_be_bypassed(tmp_path, upstream):
    """The allowlist is enforcement, not advice: the very host:port the proxy is willing to
    reach stays unreachable when the sandbox dials it directly, ignoring $HTTP_PROXY."""
    res = _bash(_DIRECT, f"127.0.0.1:{upstream}", tmp_path, network="proxy", allow_hosts=[f"127.0.0.1:{upstream}"])
    assert res.returncode == 0, res.stderr
    assert res.stdout.strip() == "BLOCKED"


def test_network_none_has_no_egress(tmp_path, upstream):
    res = _bash(_DIRECT, f"127.0.0.1:{upstream}", tmp_path, network="none")
    assert res.returncode == 0, res.stderr
    assert res.stdout.strip() == "BLOCKED"


def test_host_network_reaches_upstream(tmp_path, upstream):
    """Control for every BLOCKED above: the same probe must report REACHED when egress is
    allowed, so a broken probe or a dead fixture can't make the denial tests pass for free."""
    res = _bash(_DIRECT, f"127.0.0.1:{upstream}", tmp_path, network="host")
    assert res.returncode == 0, res.stderr
    assert res.stdout.strip() == "REACHED"


# --- lifetime ---


def _cli(tmp_path, script):
    proc = subprocess.Popen(
        [*HOZO_CLI, "--allow-net=example.com", "--", "/bin/bash", "-c", script],
        cwd=tmp_path,
        stdout=subprocess.PIPE,
        text=True,
    )
    return proc, proc.stdout.readline().split()


@pytest.mark.parametrize("sig", [signal.SIGKILL, signal.SIGTERM, signal.SIGINT])
def test_killing_hozo_kills_the_sandboxed_command(tmp_path, sig):
    token = f"hozo-lifetime-{uuid.uuid4().hex}"
    hozo_proc, _ = _cli(tmp_path, f"echo ready; exec -a {token} sleep 300")

    def sleepers():
        # The sleep's argv[0] is the token; hozo's and bwrap's argv only contain it.
        ps = subprocess.run(["ps", "ax", "-o", "command"], capture_output=True, text=True).stdout
        return [line for line in ps.splitlines() if line.strip().startswith(token)]

    assert wait_until(sleepers)
    hozo_proc.send_signal(sig)
    hozo_proc.wait()
    assert wait_until(lambda: not sleepers()), sleepers()


@macos_only
def test_seatbelt_cli_execs_and_cleans_up_after_a_kill(tmp_path):
    hozo_proc, (pid, scratch, proxy) = _cli(tmp_path, 'echo "$$ $TMPDIR $HTTP_PROXY"; exec sleep 300')
    port = int(proxy.rsplit(":", 1)[1])
    assert int(pid) == hozo_proc.pid
    assert proxy_up(port) and os.path.isdir(scratch)

    hozo_proc.kill()
    hozo_proc.wait()
    assert wait_until(lambda: not os.path.exists(scratch))
    assert wait_until(lambda: not proxy_up(port))


# --- ssh ---


@pytest.fixture
def sshd():
    """Stand-in SSH server that sends a banner and records the client's first bytes."""
    server = socket.socket()
    server.bind(("127.0.0.1", 0))
    server.listen(8)
    received = []

    def serve():
        while True:
            try:
                conn, _ = server.accept()
            except OSError:
                return
            conn.sendall(b"SSH-2.0-hozo-stub\r\n")
            received.append(conn.recv(256))
            conn.close()

    threading.Thread(target=serve, daemon=True).start()
    yield server.getsockname()[1], received
    server.close()


def _git_ssh(port, project, **kw):
    return _run(["git", "ls-remote", f"ssh://git@127.0.0.1:{port}/org/repo"], project, profiles=["ssh"], **kw)


def test_ssh_tunnels_through_the_proxy(tmp_path, sshd):
    port, received = sshd
    res = _git_ssh(port, tmp_path, network="proxy", allow_hosts=[f"127.0.0.1:{port}"])
    assert received and received[0].startswith(b"SSH-2.0-"), res.stderr


def test_ssh_to_an_unlisted_port_is_refused_by_the_proxy(tmp_path, sshd):
    port, received = sshd
    res = _git_ssh(port, tmp_path, network="proxy", allow_hosts=["127.0.0.1"])  # 80/443 only
    assert res.returncode != 0
    assert "403" in res.stderr
    assert not received


def test_ssh_profile_grants_nothing_without_network(tmp_path, sshd):
    port, received = sshd
    assert _git_ssh(port, tmp_path).returncode != 0
    assert not received


def test_ssh_goes_direct_on_host_network(tmp_path, sshd):
    port, received = sshd
    res = _git_ssh(port, tmp_path, network="host")
    assert received and received[0].startswith(b"SSH-2.0-"), res.stderr


@pytest.fixture(params=["tmp", "run-user", "home"])
def ssh_agent(request, tmp_path, monkeypatch):
    """A throwaway agent and key, its socket where real agents live (tmp, /run/user, ~/.ssh/agent beside a decoy key)."""
    home = tempfile.mkdtemp(prefix="h-")  # short: sun_path caps at 104 on macOS
    monkeypatch.setenv("HOME", home)
    ssh_dir = Path(home) / ".ssh"
    (ssh_dir / "agent").mkdir(parents=True)
    (ssh_dir / "id_ed25519").write_text("DECOY-PRIVATE-KEY")
    base = None
    if request.param == "run-user":
        base = f"/run/user/{os.getuid()}"
        if not os.access(base, os.W_OK):
            pytest.skip(f"{base} not writable")
    elif request.param == "home":
        base = str(ssh_dir / "agent")
    sock_dir = tempfile.mkdtemp(prefix="ha-", dir=base)
    sock = os.path.join(sock_dir, "a.sock")
    agent = subprocess.Popen(["ssh-agent", "-D", "-a", sock], stdout=subprocess.DEVNULL)
    try:
        assert wait_until(lambda: os.path.exists(sock))
        key = tmp_path / "key"
        subprocess.run(
            ["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", "hozo-test-key", "-f", str(key)], check=True
        )
        subprocess.run(["ssh-add", "-q", str(key)], env={"SSH_AUTH_SOCK": sock}, check=True)
        monkeypatch.setenv("SSH_AUTH_SOCK", sock)
        yield sock
    finally:
        agent.kill()
        agent.wait()
        shutil.rmtree(sock_dir)
        shutil.rmtree(home)


def test_ssh_agent_is_forwarded(tmp_path, ssh_agent):
    res = _run(["ssh-add", "-l"], tmp_path, profiles=["ssh-agent"])
    assert res.returncode == 0, res.stderr
    assert "hozo-test-key" in res.stdout


def test_forwarded_agent_hides_the_rest_of_ssh_dir(tmp_path, ssh_agent):
    res = _run(["/bin/sh", "-c", 'cat "$HOME/.ssh/id_ed25519"'], tmp_path, profiles=["ssh-agent"])
    assert res.returncode != 0
    assert "DECOY" not in res.stdout


def test_agent_is_not_forwarded_without_the_profile(tmp_path, ssh_agent):
    res = _run(["ssh-add", "-l"], tmp_path, env_allow=["SSH_AUTH_SOCK"])
    assert res.returncode != 0
    assert "hozo-test-key" not in res.stdout


# The bash probes above can't reach a raw syscall, so these go through python3's ctypes.
# `hozo audit` already depends on an in-sandbox interpreter, so this adds no new
# assumption about the /usr bind.
_SYSCALL = r"""
import ctypes, os, sys
libc = ctypes.CDLL(None, use_errno=True)
ctypes.set_errno(0)
rc = libc.syscall(int(sys.argv[1]), 0, 0, 0)
print("ENOSYS" if rc == -1 and ctypes.get_errno() == 38 else f"CALLED:{rc}")
"""


def _syscall(number, project, **kw):
    return _run(["python3", "-c", _SYSCALL, str(number)], project, **kw)


@linux_only
def test_seccomp_filter_is_actually_loaded(tmp_path):
    """The finding this closes was `Seccomp: 0` in /proc/self/status — assert the kernel
    took the filter, not merely that hozo passed the flag."""
    res = _run(["/bin/sh", "-c", "grep ^Seccomp /proc/self/status"], tmp_path)
    assert "Seccomp:\t2" in res.stdout, res.stdout
    assert "Seccomp_filters:\t1" in res.stdout, res.stdout


@linux_only
def test_denied_syscall_returns_enosys(tmp_path):
    """io_uring_setup(425) is the headline entry in base's denylist."""
    res = _syscall(425, tmp_path)
    assert res.returncode == 0, res.stderr
    assert res.stdout.strip() == "ENOSYS", res.stdout


@linux_only
def test_undenied_syscall_still_works(tmp_path):
    """Control for the test above: getpid(39) proves the ENOSYS came from the denylist and
    not from a filter that rejects everything."""
    res = _syscall(39, tmp_path)
    assert res.returncode == 0, res.stderr
    assert res.stdout.startswith("CALLED:"), res.stdout


@linux_only
def test_nested_sandboxing_is_not_broken_by_the_filter(tmp_path):
    """unshare/clone are deliberately absent from the denylist because Claude Code runs its
    own bwrap inside hozo's. Assert that stays true."""
    res = _run(["/bin/sh", "-c", "unshare --user --map-root-user true && echo NESTED_OK"], tmp_path)
    assert res.stdout.strip() == "NESTED_OK", f"{res.stdout} {res.stderr}"
