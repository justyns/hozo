"""In-sandbox TCP->UDS bridge: forward localhost:<port> to the host proxy's Unix socket.

Runs under the sandbox's own python3 (bound in read-only), so ``HTTP(S)_PROXY`` pointed at
127.0.0.1:<port> reaches the host CONNECT proxy while the sandbox stays --unshare-net.
Invoked as: ``python3 bridge.py <unix-socket> <listen-port>``, which returns as soon as the
port is accepting connections (see ``main``) so the caller can chain the real command.
"""

import os
import socket
import sys
import threading


def relay(src, dst):
    try:
        while True:
            data = src.recv(8192)
            if not data:
                break
            dst.sendall(data)
    except OSError:
        pass
    finally:
        try:
            dst.shutdown(socket.SHUT_WR)
        except OSError:
            pass


def handle(client, proxy_sock):
    try:
        upstream = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        upstream.connect(proxy_sock)
        threads = [
            threading.Thread(target=relay, args=(client, upstream), daemon=True),
            threading.Thread(target=relay, args=(upstream, client), daemon=True),
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
    except OSError:
        pass
    finally:
        client.close()


def main():
    proxy_sock, port = sys.argv[1], int(sys.argv[2])
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("127.0.0.1", port))
    server.listen(16)
    # Serve from a child and exit the parent, so whoever launched us blocks exactly until
    # the port is listening — no sleep-and-hope, and a failed bind is a non-zero exit
    # rather than a command that starts with a dead proxy.
    if os.fork() > 0:
        os._exit(0)
    while True:
        conn, _ = server.accept()
        threading.Thread(target=handle, args=(conn, proxy_sock), daemon=True).start()


if __name__ == "__main__":
    main()
