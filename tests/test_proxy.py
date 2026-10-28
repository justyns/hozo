import asyncio
import tempfile
from pathlib import Path

import pytest

import hozo
from hozo import proxy


@pytest.fixture
def sock_path():
    """A Unix socket path short enough for the ~104-byte sun_path limit — pytest's
    tmp_path already exceeds it on macOS, where TMPDIR is a long /var/folders path."""
    with tempfile.TemporaryDirectory() as tmp:
        yield Path(tmp) / "p.sock"


@pytest.mark.parametrize(
    "pattern,host,port,ok",
    [
        ("github.com", "github.com", 443, True),
        ("github.com", "github.com", 22, False),
        ("github.com:22", "github.com", 22, True),
        ("*.github.com", "api.github.com", 443, True),
        ("*.github.com", "github.com", 443, False),
        ("*:*", "anything.example", 1234, True),
        ("127.0.0.1", "127.0.0.1", 443, True),
        ("10.0.0.1", "127.0.0.1", 443, False),
        ("10.0.0.0/8", "10.1.2.3", 443, True),
        ("10.0.0.0/8", "11.0.0.1", 443, False),
        ("10.0.0.0/8", "10.1.2.3", 22, False),
        ("127.0.0.0/8", "0x7f.1", 443, True),  # inet_aton forms are normalized first
        ("127.0.0.0/8", "2130706433", 443, True),
        ("*:*", "127.0.0.1", 443, False),  # globs never match an IP
        ("*", "10.0.0.1", 443, False),
        ("fd00::/8", "fd00::1", 443, True),
        ("[fd00::/8]:8443", "fd00::1", 8443, True),
        ("[fd00::/8]:8443", "fd00::1", 443, False),
        ("[::1]:*", "::1", 9, True),
        ("fd00::/8", "10.0.0.1", 443, False),
        ("[::/0]:443", "::ffff:169.254.169.254", 443, False),  # IPv4-mapped is matched as IPv4
        ("10.0.0.0/8", "::ffff:10.0.0.1", 443, True),
        ("*", "127.0.0.1.", 443, False),
    ],
)
def test_domain_matches(pattern, host, port, ok):
    assert proxy._domain_matches(host, port, [pattern]) is ok


@pytest.mark.parametrize(
    "pattern,ok",
    [
        ("github.com:22", True),
        ("github.com:https", False),
        ("fd00::/8", True),
        ("[fd00::/8]:443", True),
        ("[::1]:*", True),
        ("[::1]:x", False),
        ("example.com:²", False),
    ],
)
def test_valid_port_spec(pattern, ok):
    assert proxy.valid_port_spec(pattern) is ok


def test_empty_allowlist_denies_everything():
    assert proxy._domain_matches("github.com", 443, []) is False


async def _connect(sock_path, target):
    reader, writer = await asyncio.open_unix_connection(str(sock_path))
    writer.write(f"CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n".encode())
    await writer.drain()
    status = await reader.readline()
    return status, writer


def test_proxy_allows_listed_host(sock_path):
    async def main():
        async def echo(reader, writer):
            await reader.read(64)
            writer.write(b"ok")
            await writer.drain()
            writer.close()

        upstream = await asyncio.start_server(echo, "127.0.0.1", 0)
        port = upstream.sockets[0].getsockname()[1]
        # default ports are 80/443, so allow the ephemeral upstream port explicitly
        prox = proxy.ConnectProxy(sock_path, allowed_hosts=[f"localhost:{port}"])
        await prox.start()
        try:
            status, writer = await _connect(sock_path, f"localhost:{port}")
            writer.close()
            assert b"200" in status
        finally:
            await prox.stop()
            upstream.close()

    asyncio.run(main())


def test_proxy_blocks_unlisted_host(sock_path):
    async def main():
        prox = proxy.ConnectProxy(sock_path, allowed_hosts=["example.org"])
        await prox.start()
        try:
            status, writer = await _connect(sock_path, "localhost:9")
            writer.close()
            assert b"403" in status
        finally:
            await prox.stop()

    asyncio.run(main())


@pytest.mark.parametrize(
    "target",
    ["127.0.0.1:443", "2130706433:443", "0177.0.0.1:443", "127.1:443", "[::1]:443", "::1:443"],
)
def test_proxy_blocks_bare_ip(sock_path, target):
    async def main():
        prox = proxy.ConnectProxy(sock_path, allowed_hosts=["*:*"])
        await prox.start()
        try:
            status, writer = await _connect(sock_path, target)
            writer.close()
            assert b"403" in status
        finally:
            await prox.stop()

    asyncio.run(main())


async def _send_raw(sock_path, data):
    reader, writer = await asyncio.open_unix_connection(str(sock_path))
    writer.write(data)
    await writer.drain()
    try:
        status = await asyncio.wait_for(reader.readline(), timeout=2)
    except asyncio.TimeoutError:
        status = b""
    writer.close()
    return status


@pytest.mark.parametrize(
    "request_bytes",
    [
        b"CONNECT localhost:9 HTTP/1.1\r\n" + (b"X-Pad: " + b"a" * 1000 + b"\r\n") * 70 + b"\r\n",
        b"CONNECT localhost:9 HTTP/1.1\r\nX-Pad: " + b"a" * 70_000 + b"\r\n\r\n",
    ],
    ids=["many-headers", "one-long-line"],
)
def test_proxy_rejects_oversized_headers(sock_path, request_bytes):
    async def main():
        prox = proxy.ConnectProxy(sock_path, allowed_hosts=["*:*"])
        await prox.start()
        try:
            assert b"400" in await _send_raw(sock_path, request_bytes)
        finally:
            await prox.stop()

    asyncio.run(main())


def test_proxy_rejects_slow_headers(sock_path, monkeypatch):
    monkeypatch.setattr(proxy, "_REQUEST_TIMEOUT", 0.2)

    async def main():
        prox = proxy.ConnectProxy(sock_path, allowed_hosts=["*:*"])
        await prox.start()
        try:
            # the blank line ending the headers never arrives
            assert b"400" in await _send_raw(sock_path, b"CONNECT localhost:9 HTTP/1.1\r\nHost: x\r\n")
        finally:
            await prox.stop()

    asyncio.run(main())


@pytest.mark.parametrize("target", ["127.0.0.1", "127.1", "0x7f.0.0.1"])
@pytest.mark.parametrize("entry", ["127.0.0.1:{port}", "127.0.0.0/8:{port}"])
def test_proxy_allows_listed_ip(sock_path, target, entry):
    async def main():
        async def echo(reader, writer):
            await reader.read(64)
            writer.write(b"ok")
            await writer.drain()
            writer.close()

        upstream = await asyncio.start_server(echo, "127.0.0.1", 0)
        port = upstream.sockets[0].getsockname()[1]
        prox = proxy.ConnectProxy(sock_path, allowed_hosts=[entry.format(port=port)])
        await prox.start()
        try:
            status, writer = await _connect(sock_path, f"{target}:{port}")
            writer.close()
            assert b"200" in status
        finally:
            await prox.stop()
            upstream.close()

    asyncio.run(main())


def test_proxy_tcp_loopback_mode():
    # macOS uses a TCP loopback listener instead of a Unix socket (no in-sandbox bridge).
    async def main():
        async def echo(reader, writer):
            await reader.read(64)
            writer.write(b"ok")
            await writer.drain()
            writer.close()

        upstream = await asyncio.start_server(echo, "127.0.0.1", 0)
        uport = upstream.sockets[0].getsockname()[1]
        prox = proxy.ConnectProxy(0, allowed_hosts=[f"localhost:{uport}"])
        await prox.start()
        try:
            assert isinstance(prox.port, int) and prox.port > 0  # ephemeral port exposed
            reader, writer = await asyncio.open_connection("127.0.0.1", prox.port)
            writer.write(f"CONNECT localhost:{uport} HTTP/1.1\r\nHost: x\r\n\r\n".encode())
            await writer.drain()
            status = await reader.readline()
            writer.close()
            assert b"200" in status
        finally:
            await prox.stop()
            upstream.close()

    asyncio.run(main())


@pytest.mark.skipif(not hozo.check_available(), reason="no sandbox runtime installed")
def test_proxy_mode_end_to_end(tmp_path):
    # Full lifecycle: proxy started, sandbox runs the command with egress wired up, then
    # torn down. No external network. The port is the fixed bridge port on Linux and an
    # ephemeral loopback port on macOS, so only its shape is asserted.
    result = hozo.run(
        hozo.SandboxRequest(command=["printenv", "HTTP_PROXY"], project=str(tmp_path), profiles=["proxy"]),
        capture=True,
    )
    assert result.returncode == 0
    host, _, port = result.stdout.strip().removeprefix("http://").partition(":")
    assert host == "127.0.0.1" and port.isdigit()
