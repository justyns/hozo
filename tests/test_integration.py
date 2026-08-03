"""Integration tests: run real commands in a real sandbox and check the security
contract from the inside — what should be reachable is, and what shouldn't be isn't.

Backend-agnostic on purpose. These run against whichever runtime the platform provides
(bwrap on Linux, Seatbelt on macOS) so both get identical scrutiny, and the enforcement
claims are tested rather than the rendered policy that is supposed to produce them.

The probes are bash rather than python: `/dev/tcp` is a bash builtin, so they need nothing
inside the sandbox beyond a shell that both platforms ship in /bin.
"""

import socket
import threading

import pytest

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
