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
        ("127.0.0.1", "127.0.0.1", 443, True),  # bare IPs match like any other host
        ("10.0.0.1", "127.0.0.1", 443, False),
    ],
)
def test_domain_matches(pattern, host, port, ok):
    assert proxy._domain_matches(host, port, [pattern]) is ok


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


def test_proxy_allows_listed_ip(sock_path):
    async def main():
        async def echo(reader, writer):
            await reader.read(64)
            writer.write(b"ok")
            await writer.drain()
            writer.close()

        upstream = await asyncio.start_server(echo, "127.0.0.1", 0)
        port = upstream.sockets[0].getsockname()[1]
        prox = proxy.ConnectProxy(sock_path, allowed_hosts=[f"127.0.0.1:{port}"])
        await prox.start()
        try:
            status, writer = await _connect(sock_path, f"127.0.0.1:{port}")
            writer.close()
            assert b"200" in status  # a listed IP is reachable
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
