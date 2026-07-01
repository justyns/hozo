"""HTTP CONNECT proxy over a Unix domain socket — allowlisted sandbox egress.

Stdlib only. CONNECT-only, glob host allowlist with per-pattern ports, request logging.
An **empty** allowlist denies everything; ``None`` disables filtering (allow all). Hosts
and bare IPs are matched the same way. Pairs with the in-sandbox TCP->UDS bridge
(``bridge.py``) so ``HTTP(S)_PROXY`` works while the sandbox stays --unshare-net.
"""

from __future__ import annotations

import asyncio
import fnmatch
import logging
import threading
from dataclasses import dataclass
from pathlib import Path

from .errors import HozoError

logger = logging.getLogger("hozo.proxy")

_DEFAULT_PORTS = {80, 443}

# In-sandbox conventions (must match the bwrap renderer).
BRIDGE_PORT = 12345
PROXY_SOCKET_TARGET = "/run/hozo-proxy.sock"
BRIDGE_SCRIPT_TARGET = "/run/hozo-bridge.py"


def bridge_script_path() -> str:
    """Host path to the in-sandbox bridge script, bound read-only into the sandbox."""
    return str(Path(__file__).with_name("bridge.py"))


@dataclass
class ProxyMount:
    """Host paths the renderer binds into the sandbox for proxy mode."""

    socket_path: str  # host UDS the proxy listens on -> /run/hozo-proxy.sock
    script_path: str  # host bridge script -> /run/hozo-bridge.py


def _parse_pattern(pattern: str) -> tuple[str, set[int]]:
    """Parse a host pattern into (domain_glob, allowed_ports). ``host:*`` = all ports."""
    if ":" in pattern:
        domain, port_str = pattern.rsplit(":", 1)
        if port_str == "*":
            return (domain, set())  # empty set == all ports
        return (domain, {int(port_str)})
    return (pattern, set(_DEFAULT_PORTS))


def valid_port_spec(pattern: str) -> bool:
    """False if a host pattern carries a non-numeric, non-'*' port (would crash _parse_pattern)."""
    if ":" not in pattern:
        return True
    port = pattern.rsplit(":", 1)[1]
    return port == "*" or port.isdigit()


def _domain_matches(domain: str, port: int, allowed: list[str]) -> bool:
    domain = domain.lower()
    for pattern in allowed:
        pat_domain, pat_ports = _parse_pattern(pattern.lower())
        if fnmatch.fnmatch(domain, pat_domain) and (not pat_ports or port in pat_ports):
            return True
    return False


class ConnectProxy:
    """CONNECT proxy on a Unix socket. ``allowed_hosts=None`` disables filtering."""

    def __init__(self, socket_path: Path, allowed_hosts: list[str] | None = None):
        self.socket_path = Path(socket_path)
        self.allowed_hosts = allowed_hosts
        self._server: asyncio.AbstractServer | None = None

    async def start(self) -> None:
        self.socket_path.unlink(missing_ok=True)
        self._server = await asyncio.start_unix_server(self._handle_client, path=str(self.socket_path))
        logger.info("proxy listening on %s (allow=%s)", self.socket_path, self.allowed_hosts)

    async def stop(self) -> None:
        if self._server:
            self._server.close()
            await self._server.wait_closed()
            self._server = None
        self.socket_path.unlink(missing_ok=True)

    async def _handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            first_line = await asyncio.wait_for(reader.readline(), timeout=30)
            parts = first_line.decode("utf-8", "replace").split()
            if len(parts) < 3 or parts[0].upper() != "CONNECT":
                await self._reject(writer, "400 Bad Request", "only CONNECT is supported")
                return
            await self._handle_connect(parts[1], reader, writer)
        except Exception as exc:  # noqa: BLE001 - proxy must never crash on a bad client
            logger.debug("proxy client error: %s", exc)
            await self._close(writer)

    async def _handle_connect(self, target: str, reader, writer) -> None:
        host, _, port_str = target.rpartition(":")
        if not host:
            host, port = target, 443
        else:
            try:
                port = int(port_str)
            except ValueError:
                await self._reject(writer, "400 Bad Request", f"invalid port: {port_str}")
                return

        while True:  # drain request headers
            line = await reader.readline()
            if line in (b"\r\n", b"\n", b""):
                break

        upstream = await self._check_and_connect(host, port, writer)
        if upstream is None:
            return
        upstream_reader, upstream_writer = upstream
        writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        await writer.drain()
        await self._relay(reader, writer, upstream_reader, upstream_writer)

    async def _check_and_connect(self, host: str, port: int, writer):
        if self.allowed_hosts is not None and not _domain_matches(host, port, self.allowed_hosts):
            await self._reject(writer, "403 Forbidden", "host not in allowlist")
            logger.info("BLOCK %s:%d (not in allowlist)", host, port)
            return None
        try:
            conn = await asyncio.open_connection(host, port)
        except Exception as exc:  # noqa: BLE001
            await self._reject(writer, "502 Bad Gateway", str(exc))
            logger.info("FAIL %s:%d (%s)", host, port, exc)
            return None
        logger.info("ALLOW %s:%d", host, port)
        return conn

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
        except Exception:  # noqa: BLE001
            pass


class BackgroundProxy:
    """Run a ConnectProxy on its own event loop in a daemon thread.

    Use as a context manager around a blocking subprocess: the proxy is listening
    by the time ``__enter__`` returns and is torn down on exit.
    """

    def __init__(self, socket_path: Path, allowed_hosts: list[str] | None):
        self._proxy = ConnectProxy(socket_path, allowed_hosts)
        self._loop = asyncio.new_event_loop()
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._ready = threading.Event()

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
