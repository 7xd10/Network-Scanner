"""Shared fixtures.

The integration tests bind real loopback sockets rather than mocking
``asyncio.open_connection``, so the open/closed distinction is exercised against
the kernel's actual behaviour. Only the *filtered* path is simulated, because a
deterministic silent-drop cannot be produced locally.
"""

from __future__ import annotations

import contextlib
import socket
import threading
from dataclasses import dataclass
from typing import Iterator, List, Optional

import pytest

from netscan.models import (
    HostResult,
    PortResult,
    PortState,
    RiskLevel,
    ScanMeta,
    ScanReport,
    utc_now,
)


@dataclass
class Listener:
    """A loopback TCP listener that runs for the duration of a test."""

    port: int
    _server: Optional[socket.socket]
    _thread: Optional[threading.Thread]
    _stop: threading.Event
    banner: Optional[bytes] = None

    def close(self) -> None:
        self._stop.set()
        if self._server is not None:
            with contextlib.suppress(OSError):
                self._server.close()
        if self._thread is not None:
            self._thread.join(timeout=2.0)


def _start_listener(banner: Optional[bytes]) -> Listener:
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("127.0.0.1", 0))
    server.listen(8)
    server.settimeout(0.2)
    port = server.getsockname()[1]
    stop = threading.Event()

    def serve() -> None:
        while not stop.is_set():
            try:
                conn, _addr = server.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            try:
                if banner is not None:
                    conn.sendall(banner)
                conn.settimeout(0.2)
                with contextlib.suppress(socket.timeout, OSError):
                    conn.recv(4096)
            finally:
                with contextlib.suppress(OSError):
                    conn.close()

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    return Listener(port=port, _server=server, _thread=thread, _stop=stop, banner=banner)


@pytest.fixture
def open_port() -> Iterator[Listener]:
    listener = _start_listener(b"SSH-2.0-OpenSSH_9.6\r\n")
    try:
        yield listener
    finally:
        listener.close()


@pytest.fixture
def silent_port() -> Iterator[Listener]:
    """Accepts the connection and sends nothing, exercising the banner timeout."""
    listener = _start_listener(None)
    try:
        yield listener
    finally:
        listener.close()


def _free_port() -> int:
    probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])
    finally:
        probe.close()


@pytest.fixture
def closed_port() -> int:
    """A loopback port with nothing bound. Connecting yields ECONNREFUSED."""
    return _free_port()


@pytest.fixture
def sample_host(open_port: Listener, closed_port: int) -> HostResult:
    ports: List[PortResult] = [
        PortResult(
            host="127.0.0.1",
            address="127.0.0.1",
            port=open_port.port,
            state=PortState.OPEN,
            service="ssh",
            description="Secure Shell; remote administration",
            risk=RiskLevel.NONE,
            banner="SSH-2.0-OpenSSH_9.6",
            latency_ms=0.4,
        ),
        PortResult(
            host="127.0.0.1",
            address="127.0.0.1",
            port=closed_port,
            state=PortState.CLOSED,
            latency_ms=0.1,
        ),
    ]
    return HostResult(
        target="127.0.0.1",
        address="127.0.0.1",
        family="IPv4",
        resolved=True,
        ports=tuple(ports),
        started_at=utc_now(),
        finished_at=utc_now(),
    )


@pytest.fixture
def sample_report(sample_host: HostResult) -> ScanReport:
    now = utc_now()
    return ScanReport(
        meta=ScanMeta(
            tool="netscan",
            version="2.0.0",
            started_at=now,
            finished_at=now,
            targets_requested=1,
            addresses_scanned=1,
            ports_per_address=2,
            concurrency=10,
            timeout_s=1.0,
            retries=0,
            banner_grab=True,
            argv=["netscan", "127.0.0.1"],
        ),
        hosts=(sample_host,),
    )


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


def pytest_configure(config: pytest.Config) -> None:
    # pytest-asyncio 0.23 wants an explicit loop policy hint; keep it quiet.
    del config
