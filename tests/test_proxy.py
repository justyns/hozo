import asyncio

import pytest

import hozo
from hozo import proxy


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


def test_proxy_allows_listed_host(tmp_path):
    async def main():
        async def echo(reader, writer):
            await reader.read(64)
            writer.write(b"ok")
            await writer.drain()
            writer.close()

        upstream = await asyncio.start_server(echo, "127.0.0.1", 0)
        port = upstream.sockets[0].getsockname()[1]
        # default ports are 80/443, so allow the ephemeral upstream port explicitly
        prox = proxy.ConnectProxy(tmp_path / "p.sock", allowed_hosts=[f"localhost:{port}"])
        await prox.start()
        try:
            status, writer = await _connect(tmp_path / "p.sock", f"localhost:{port}")
            writer.close()
            assert b"200" in status
        finally:
            await prox.stop()
            upstream.close()

    asyncio.run(main())


def test_proxy_blocks_unlisted_host(tmp_path):
    async def main():
        prox = proxy.ConnectProxy(tmp_path / "p.sock", allowed_hosts=["example.org"])
        await prox.start()
        try:
            status, writer = await _connect(tmp_path / "p.sock", "localhost:9")
            writer.close()
            assert b"403" in status
        finally:
            await prox.stop()

    asyncio.run(main())


def test_proxy_allows_listed_ip(tmp_path):
    async def main():
        async def echo(reader, writer):
            await reader.read(64)
            writer.write(b"ok")
            await writer.drain()
            writer.close()

        upstream = await asyncio.start_server(echo, "127.0.0.1", 0)
        port = upstream.sockets[0].getsockname()[1]
        prox = proxy.ConnectProxy(tmp_path / "p.sock", allowed_hosts=[f"127.0.0.1:{port}"])
        await prox.start()
        try:
            status, writer = await _connect(tmp_path / "p.sock", f"127.0.0.1:{port}")
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
        prox = proxy.ConnectProxy(allowed_hosts=[f"localhost:{uport}"], tcp_port=0)
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


@pytest.mark.skipif(not hozo.check_available(), reason="bwrap not installed")
def test_proxy_mode_end_to_end(tmp_path):
    # Full lifecycle: temp socket + bridge written, proxy started, sandbox runs the
    # bridge-wrapped command, env injected, then torn down. No external network.
    result = hozo.run(
        hozo.SandboxRequest(command=["printenv", "HTTP_PROXY"], project=str(tmp_path), profiles=["proxy"]),
        capture=True,
    )
    assert result.returncode == 0
    assert "127.0.0.1:12345" in result.stdout
