"""Stdlib HTTP CONNECT proxy with a glob host allowlist and per-pattern ports.

An empty allowlist denies everything, and a bare IP matches only an IP or CIDR entry. On Linux
it listens on a Unix socket that ``bridge.py`` exposes inside the sandbox.
"""

from __future__ import annotations

import asyncio
import fnmatch
import ipaddress
import logging
import socket
import threading
from dataclasses import dataclass
from pathlib import Path

from .errors import HozoError

logger = logging.getLogger("hozo.proxy")

_DEFAULT_PORTS = {80, 443}
_REQUEST_TIMEOUT = 10  # seconds to read the request line and all headers
_MAX_HEADER_BYTES = 64 * 1024

BRIDGE_PORT = 12345
PROXY_SOCKET_TARGET = "/run/hozo-proxy.sock"
BRIDGE_SCRIPT_TARGET = "/run/hozo-bridge.py"


@dataclass
class ProxyMount:
    """Host paths the renderer binds into the sandbox for proxy mode."""

    socket_path: str
    script_path: str


def proxy_env(port: int) -> dict[str, str]:
    url = f"http://127.0.0.1:{port}"
    no_proxy = "localhost,127.0.0.1,::1"
    return {
        "HTTP_PROXY": url,
        "HTTPS_PROXY": url,
        "http_proxy": url,
        "https_proxy": url,
        "NO_PROXY": no_proxy,
        "no_proxy": no_proxy,
    }


def _split_pattern(pattern: str) -> tuple[str, str | None]:
    """IPv6 takes a port only in brackets, e.g. ``[fd00::/8]:443``."""
    if pattern.startswith("["):
        host, _, rest = pattern[1:].partition("]")
        return host, rest.removeprefix(":") or None
    if pattern.count(":") == 1:
        host, port = pattern.split(":")
        return host, port
    return pattern, None


def _parse_pattern(pattern: str) -> tuple[str, set[int]]:
    """No port means 80 and 443. ``host:*`` allows every port."""
    host, port = _split_pattern(pattern)
    if port is None:
        return (host, set(_DEFAULT_PORTS))
    if port == "*":
        return (host, set())  # empty set == all ports
    return (host, {int(port)})


def valid_port_spec(pattern: str) -> bool:
    """True if the pattern's port is absent, '*' or numeric."""
    port = _split_pattern(pattern)[1]
    return port is None or port == "*" or (port.isascii() and port.isdigit())


def _ip_address(host: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    """Returns an IPv4-mapped IPv6 address as the IPv4 address it dials."""
    host = host.removesuffix(".")
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        # getaddrinfo also dials the integer, octal and short IPv4 forms ip_address rejects.
        try:
            return ipaddress.IPv4Address(socket.inet_aton(host))
        except OSError:
            return None
    if ip.version == 6 and ip.ipv4_mapped:
        return ip.ipv4_mapped
    return ip


def _in_network(ip: ipaddress.IPv4Address | ipaddress.IPv6Address, pattern: str) -> bool:
    try:
        return ip in ipaddress.ip_network(pattern, strict=False)
    except ValueError:
        return False


async def _read_request_head(reader: asyncio.StreamReader) -> bytes | None:
    """The request line once the headers are read; None past the time or size budget."""
    try:
        async with asyncio.timeout(_REQUEST_TIMEOUT):
            first = line = await reader.readline()
            total = len(first)
            while line not in (b"\r\n", b"\n", b""):
                line = await reader.readline()
                total += len(line)
                if total > _MAX_HEADER_BYTES:
                    return None
            return first
    except (TimeoutError, ValueError):
        return None


def _domain_matches(domain: str, port: int, allowed: list[str]) -> bool:
    domain = domain.lower()
    ip = _ip_address(domain)
    for pattern in allowed:
        pat_host, pat_ports = _parse_pattern(pattern.lower())
        if pat_ports and port not in pat_ports:
            continue
        if _in_network(ip, pat_host) if ip is not None else fnmatch.fnmatch(domain, pat_host):
            return True
    return False


class ConnectProxy:
    """``listen`` is a Unix socket ``Path`` (Linux, behind the bridge) or a loopback TCP port
    (macOS). Port 0 picks a free one, read back from ``port``."""

    def __init__(self, listen: Path | int, allowed_hosts: list[str]):
        self.listen = listen
        self.allowed_hosts = allowed_hosts
        self.port: int | None = None  # bound TCP port; stays None when listening on a socket path
        self._server: asyncio.AbstractServer | None = None

    async def start(self) -> None:
        if isinstance(self.listen, Path):
            self.listen.unlink(missing_ok=True)
            self._server = await asyncio.start_unix_server(self._handle_client, path=str(self.listen))
        else:
            self._server = await asyncio.start_server(self._handle_client, host="127.0.0.1", port=self.listen)
            self.port = self._server.sockets[0].getsockname()[1]
        address = str(self.listen) if isinstance(self.listen, Path) else f"127.0.0.1:{self.port}"
        logger.info("proxy listening on %s (allow=%s)", address, self.allowed_hosts)

    async def stop(self) -> None:
        if self._server:
            self._server.close()
            await self._server.wait_closed()
            self._server = None
        if isinstance(self.listen, Path):
            self.listen.unlink(missing_ok=True)

    async def _handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            first_line = await _read_request_head(reader)
            if first_line is None:
                await self._reject(writer, "400 Bad Request", "request headers too large or too slow")
                logger.info("DROP client exceeded the header time/size budget")
                return
            parts = first_line.decode("utf-8", "replace").split()
            if len(parts) < 3 or parts[0].upper() != "CONNECT":
                await self._reject(writer, "400 Bad Request", "only CONNECT is supported")
                return
            await self._handle_connect(parts[1], reader, writer)
        except Exception as exc:  # close the writer whatever the client sent
            logger.debug("proxy client error: %s", exc)
            await self._close(writer)

    async def _handle_connect(self, target: str, reader, writer) -> None:
        host, port_str = _split_pattern(target)
        port_str = port_str or "443"
        try:
            port = int(port_str)
        except ValueError:
            await self._reject(writer, "400 Bad Request", f"invalid port: {port_str}")
            return

        ip = _ip_address(host)
        if ip is not None:
            host = str(ip)  # dial and log the address that was matched
        if not _domain_matches(host, port, self.allowed_hosts):
            await self._reject(writer, "403 Forbidden", "host not in allowlist")
            logger.info("BLOCK %s:%d (not in allowlist)", host, port)
            return
        try:
            upstream_reader, upstream_writer = await asyncio.open_connection(host, port)
        except Exception as exc:
            await self._reject(writer, "502 Bad Gateway", str(exc))
            logger.info("FAIL %s:%d (%s)", host, port, exc)
            return
        logger.info("ALLOW %s:%d", host, port)
        writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        await writer.drain()
        await self._relay(reader, writer, upstream_reader, upstream_writer)

    async def _relay(self, client_reader, client_writer, upstream_reader, upstream_writer) -> None:
        async def pipe(src, dst):
            try:
                while data := await src.read(8192):
                    dst.write(data)
                    await dst.drain()
            except (ConnectionError, asyncio.CancelledError):
                pass
            finally:
                await self._close(dst)

        await asyncio.gather(
            pipe(client_reader, upstream_writer),
            pipe(upstream_reader, client_writer),
            return_exceptions=True,
        )

    async def _reject(self, writer, status: str, body: str) -> None:
        writer.write(f"HTTP/1.1 {status}\r\n\r\n{body}\r\n".encode())
        await writer.drain()
        await self._close(writer)

    @staticmethod
    async def _close(writer) -> None:
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass


class BackgroundProxy:
    """Run a ConnectProxy on a daemon thread. It is listening once ``__enter__`` returns and
    stops on exit."""

    def __init__(self, listen: Path | int, allowed_hosts: list[str]):
        self._proxy = ConnectProxy(listen, allowed_hosts)
        self._loop = asyncio.new_event_loop()
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._ready = threading.Event()

    @property
    def port(self) -> int | None:
        """Bound TCP port, set after ``__enter__``."""
        return self._proxy.port

    def _serve(self) -> None:
        asyncio.set_event_loop(self._loop)
        self._loop.run_until_complete(self._proxy.start())
        self._ready.set()
        self._loop.run_forever()

    def __enter__(self) -> BackgroundProxy:
        self._thread.start()
        if not self._ready.wait(timeout=5):
            raise HozoError("egress proxy failed to start")
        return self

    def __exit__(self, *exc) -> None:
        asyncio.run_coroutine_threadsafe(self._proxy.stop(), self._loop).result(timeout=5)
        self._loop.call_soon_threadsafe(self._loop.stop)
        self._thread.join(timeout=5)
        self._loop.close()
