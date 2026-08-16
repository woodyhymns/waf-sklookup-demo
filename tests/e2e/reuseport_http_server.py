#!/usr/bin/env python3
"""Multi-worker SO_REUSEPORT HTTP server for sk_lookup end-to-end validation.

This is deliberately small and dependency-free. Each process owns one listening
socket on the same internal address, and every response names the worker and
reports `conn.getsockname()`. That lets the E2E test prove both properties that
matter for the WAF design:

* eBPF sk_lookup can steer a connection to an *unbound* external port into the
  fixed internal listener; and
* after steering, the accepted connection preserves the client's original
  destination port, which is the value the WAF must classify on.

Run (normally from tests/e2e/run-real-kernel-validation.sh):

    ./reuseport_http_server.py --listen 127.0.0.1:18080 --workers 4

The program writes one ready line per worker, accepts HTTP/1.1 requests, and
terminates every worker cleanly on SIGTERM/SIGINT.
"""

from __future__ import annotations

import argparse
import multiprocessing as mp
import os
import signal
import socket
import sys
import threading
from typing import Tuple


def parse_addr(raw: str) -> Tuple[str, int]:
    # Accept both conventional [::1]:8080 and the IPv4 host:port form.
    if raw.startswith("["):
        host, rest = raw[1:].split("]:", 1)
        return host, int(rest)
    host, port = raw.rsplit(":", 1)
    return host, int(port)


def response(worker: int, conn: socket.socket, close: bool) -> bytes:
    local_ip, local_port = conn.getsockname()[:2]
    peer_ip, peer_port = conn.getpeername()[:2]
    body = (
        f"worker={worker}\n"
        f"pid={os.getpid()}\n"
        f"local={local_ip}:{local_port}\n"
        f"peer={peer_ip}:{peer_port}\n"
    ).encode()
    connection = b"close" if close else b"keep-alive"
    return (
        b"HTTP/1.1 200 OK\r\n"
        b"Content-Type: text/plain\r\n"
        + b"Connection: " + connection + b"\r\n"
        + f"Content-Length: {len(body)}\r\n\r\n".encode()
        + body
    )


def handle_connection(worker: int, conn: socket.socket) -> None:
    """Serve one TCP connection without blocking the worker's accept loop.

    OpenResty has an event loop and can keep many HTTP keep-alive connections
    active per worker. The initial E2E stand-in served them serially, so four
    persistent `wrk` connections occupied all four workers and a new dynamic
    port looked unreachable even though BPF had assigned it correctly. A small
    daemon thread per accepted connection mirrors the relevant concurrency
    property without turning this helper into an HTTP server implementation.
    """
    with conn:
        conn.settimeout(1)
        try:
            while True:
                request = conn.recv(8192)
                if not request:
                    break
                close = b"connection: close" in request.lower()
                conn.sendall(response(worker, conn, close))
                if close:
                    break
        except (OSError, TimeoutError):
            pass


def worker_main(worker: int, host: str, port: int, ready_fd: int) -> None:
    stop = False

    def stop_handler(_signum: int, _frame: object) -> None:
        nonlocal stop
        stop = True

    signal.signal(signal.SIGTERM, stop_handler)
    signal.signal(signal.SIGINT, stop_handler)

    family = socket.AF_INET6 if ":" in host else socket.AF_INET
    sock = socket.socket(family, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
    # Keep the test address family pure. On Linux an IPv6 wildcard socket can
    # otherwise also accept IPv4 connections and hide a broken tcp6 path.
    if family == socket.AF_INET6:
        sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
        sock.bind((host, port, 0, 0))
    else:
        sock.bind((host, port))
    sock.listen(512)
    sock.settimeout(0.2)

    # A pipe makes the parent wait for *all* actual binds, not sleep blindly.
    os.write(ready_fd, f"READY worker={worker} pid={os.getpid()}\n".encode())
    os.close(ready_fd)

    while not stop:
        try:
            conn, _ = sock.accept()
        except TimeoutError:
            continue
        except OSError:
            if stop:
                break
            raise
        threading.Thread(
            target=handle_connection,
            args=(worker, conn),
            daemon=True,
        ).start()
    sock.close()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--listen", required=True, help="IPv4 host:port or [IPv6]:port")
    parser.add_argument("--workers", type=int, default=4)
    args = parser.parse_args()
    if args.workers < 2:
        parser.error("--workers must be >= 2 for a reuseport test")

    host, port = parse_addr(args.listen)
    read_fd, write_fd = os.pipe()
    children = []
    for worker in range(args.workers):
        # Each child needs its own descriptor; parent closes its final write end
        # below so a failed child cannot leave readiness blocked forever.
        fd = os.dup(write_fd)
        child = mp.Process(target=worker_main, args=(worker, host, port, fd))
        child.start()
        os.close(fd)
        children.append(child)
    os.close(write_fd)

    ready = b""
    while ready.count(b"\n") < args.workers:
        chunk = os.read(read_fd, 4096)
        if not chunk:
            for child in children:
                child.join(timeout=0.1)
            raise RuntimeError(f"only {ready.count(b'\\n')}/{args.workers} workers became ready: {ready!r}")
        ready += chunk
    os.close(read_fd)
    sys.stdout.buffer.write(ready)
    sys.stdout.flush()

    stopping = False

    def parent_stop(_signum: int, _frame: object) -> None:
        nonlocal stopping
        stopping = True

    signal.signal(signal.SIGTERM, parent_stop)
    signal.signal(signal.SIGINT, parent_stop)
    try:
        while not stopping and any(c.is_alive() for c in children):
            for child in children:
                child.join(timeout=0.2)
    finally:
        for child in children:
            if child.is_alive():
                child.terminate()
        for child in children:
            child.join(timeout=3)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
