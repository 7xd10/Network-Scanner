"""The scanner engine.

One asyncio event loop, a fixed worker pool, and a pull-based job iterator. The
pool size is the concurrency ceiling, so the number of live tasks never exceeds
``options.concurrency`` regardless of how many addresses or ports were
requested. That matters: the obvious implementation (``asyncio.gather`` over
every ``(address, port)`` pair) allocates one task per probe, and a /24 with 1000
ports would put 256 000 tasks on the heap before the first connection completes.

State semantics are nmap-compatible and deliberate:

* A TCP RST raises ``ConnectionRefusedError`` -> ``CLOSED``. The host is up and
  nothing is listening.
* No response within the timeout -> ``FILTERED``. A firewall dropped the packet,
  or the host is rate limiting, or it is down. We do not claim to know which.
* A routing error (``EHOSTUNREACH``/``ENETUNREACH``) -> ``FILTERED`` with the
  OS error preserved in ``PortResult.error``.
* Anything else -> ``ERROR`` with the exception class and message recorded.

Collapsing ``FILTERED`` into ``CLOSED`` is the defect this rewrite exists to fix.
"""

from __future__ import annotations

import asyncio
import contextlib
import errno
import re
import socket
import time
from dataclasses import dataclass, field
from typing import Callable, Iterator, List, Optional, Sequence, Tuple

from . import __version__
from .models import (
    HostResult,
    PortResult,
    PortState,
    RiskLevel,
    ScanMeta,
    ScanReport,
    ServiceInfo,
    utc_now,
)
from .services import service_for
from .targets import Target

__all__ = ["TOOL_NAME", "ScanOptions", "Scanner"]

TOOL_NAME = "netscan"

#: Bytes that are safe to render in a terminal-friendly banner string.
_PRINTABLE = set(bytes(range(0x20, 0x7F)))

#: CSI / SGR escapes, which service banners sometimes leak into the stream.
_ANSI_RE = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]")


@dataclass(frozen=True)
class ScanOptions:
    """Everything that changes scan behaviour. Immutable so it can be shared."""

    ports: Sequence[int]
    concurrency: int = 500
    timeout: float = 2.0
    retries: int = 1
    banner_grab: bool = True
    banner_bytes: int = 1024
    banner_timeout: float = 1.5
    reverse_dns: bool = False
    resolve_timeout: float = 5.0
    rate_limit: float = 0.0
    """Probes per second across the whole scan. ``0`` disables pacing."""
    argv: Sequence[str] = ()

    def __post_init__(self) -> None:
        if not self.ports:
            raise ValueError("ScanOptions.ports must not be empty")
        if self.concurrency < 1:
            raise ValueError("ScanOptions.concurrency must be >= 1")
        if self.timeout <= 0:
            raise ValueError("ScanOptions.timeout must be > 0")
        if self.retries < 0:
            raise ValueError("ScanOptions.retries must be >= 0")
        if self.banner_bytes < 1:
            raise ValueError("ScanOptions.banner_bytes must be >= 1")
        if self.rate_limit < 0:
            raise ValueError("ScanOptions.rate_limit must be >= 0")


@dataclass
class _Host:
    """Mutable during assembly, frozen into a HostResult at the end."""

    target: str
    address: str
    family: str
    resolved: bool = True
    reverse_dns: Optional[str] = None
    error: Optional[str] = None
    started_at: Optional[object] = None
    finished_at: Optional[object] = None
    ports: List[PortResult] = field(default_factory=list)


class _RateLimiter:
    """Monotonic token bucket with a single asyncio lock.

    A lock is enough: probes are scheduled from one event loop, so there is no
    inter-thread contention, and holding the lock across the ``await`` is what
    serialises the pacing decisions.
    """

    def __init__(self, per_second: float) -> None:
        self._interval = 1.0 / per_second if per_second > 0 else 0.0
        self._next_at = 0.0
        self._lock = asyncio.Lock()

    async def acquire(self) -> None:
        if self._interval <= 0:
            return
        async with self._lock:
            now = time.monotonic()
            if now < self._next_at:
                await asyncio.sleep(self._next_at - now)
                now = self._next_at
            self._next_at = now + self._interval


class Scanner:
    """Runs a scan. Construct once per run; the object holds no global state."""

    def __init__(
        self,
        options: ScanOptions,
        *,
        on_result: Optional[Callable[[PortResult], None]] = None,
        on_progress: Optional[Callable[[int, int], None]] = None,
    ) -> None:
        self._options = options
        self._on_result = on_result
        self._on_progress = on_progress
        self._limiter = _RateLimiter(options.rate_limit)
        self._done = 0
        self._total = 0

    # -- public ---------------------------------------------------------------

    async def scan(self, targets: Sequence[Target]) -> ScanReport:
        """Probe every ``(target, port)`` pair and return a complete report."""
        started = utc_now()
        hosts = await self._resolve(targets)

        total_probes = len(hosts) * len(self._options.ports)
        self._total = total_probes
        self._done = 0

        if on_progress := self._on_progress:
            on_progress(0, total_probes)

        jobs = self._iter_jobs(hosts)
        workers = [
            asyncio.ensure_future(self._worker(jobs, hosts))
            for _ in range(min(self._options.concurrency, max(1, total_probes)))
        ]
        if workers:
            results = await asyncio.gather(*workers, return_exceptions=True)
            for outcome in results:
                if isinstance(outcome, BaseException):
                    # A worker crash must not silently truncate the report.
                    raise outcome

        finished = utc_now()
        host_results = [self._freeze(host) for host in hosts]

        meta = ScanMeta(
            tool=TOOL_NAME,
            version=__version__,
            started_at=started,
            finished_at=finished,
            targets_requested=len(targets),
            addresses_scanned=len(hosts),
            ports_per_address=len(self._options.ports),
            concurrency=self._options.concurrency,
            timeout_s=self._options.timeout,
            retries=self._options.retries,
            banner_grab=self._options.banner_grab,
            argv=list(self._options.argv),
        )
        return ScanReport(meta=meta, hosts=host_results)

    # -- resolution -----------------------------------------------------------

    async def _resolve(self, targets: Sequence[Target]) -> List[_Host]:
        """Turn targets into concrete addresses.

        Literal addresses pass straight through. Hostnames are resolved with a
        bounded timeout; one hostname may yield several addresses (A and AAAA),
        and each becomes its own host entry because each needs its own sockets.
        """
        loop = asyncio.get_running_loop()
        hosts: List[_Host] = []

        async def resolve_one(target: Target) -> None:
            if target.address is not None:
                addr = target.address
                family = "IPv6" if ":" in addr else "IPv4"
                hosts.append(_Host(target=target.label, address=addr, family=family))
                return
            assert target.hostname is not None
            try:
                infos = await asyncio.wait_for(
                    loop.getaddrinfo(
                        target.hostname,
                        None,
                        type=socket.SOCK_STREAM,
                    ),
                    timeout=self._options.resolve_timeout,
                )
            except asyncio.TimeoutError:
                hosts.append(
                    _Host(
                        target=target.hostname,
                        address="",
                        family="unknown",
                        resolved=False,
                        error=f"DNS resolution timed out after {self._options.resolve_timeout}s",
                    )
                )
                return
            except (socket.gaierror, OSError) as exc:
                hosts.append(
                    _Host(
                        target=target.hostname,
                        address="",
                        family="unknown",
                        resolved=False,
                        error=f"DNS resolution failed: {exc}",
                    )
                )
                return

            seen: set[Tuple[str, int]] = set()
            for af, _type, _proto, _canon, sockaddr in infos:
                addr = str(sockaddr[0])
                key = (addr, af)
                if key in seen:
                    continue
                seen.add(key)
                hosts.append(
                    _Host(
                        target=target.hostname,
                        address=addr,
                        family="IPv6" if af == socket.AF_INET6 else "IPv4",
                    )
                )

        # Hostname resolution is bounded by the number of hostname targets, which
        # is small by construction (each literal address is a separate Target).
        await asyncio.gather(*(resolve_one(t) for t in targets))

        if self._options.reverse_dns:
            await asyncio.gather(*(self._reverse(host, loop) for host in hosts if host.resolved))
        return hosts

    async def _reverse(self, host: _Host, loop: asyncio.AbstractEventLoop) -> None:
        try:
            name, _service = await asyncio.wait_for(
                loop.getnameinfo((host.address, 0), socket.NI_NAMEREQD),
                timeout=self._options.resolve_timeout,
            )
        except (asyncio.TimeoutError, OSError):
            return
        if name and name != host.address:
            host.reverse_dns = name

    # -- probing --------------------------------------------------------------

    def _iter_jobs(self, hosts: Sequence[_Host]) -> Iterator[Tuple[int, int]]:
        for host_index in range(len(hosts)):
            for port in self._options.ports:
                yield host_index, int(port)

    async def _worker(self, jobs: Iterator[Tuple[int, int]], hosts: Sequence[_Host]) -> None:
        for host_index, port in jobs:
            host = hosts[host_index]
            result = await self._probe(host, port)
            host.ports.append(result)
            self._done += 1
            if self._on_result is not None:
                self._on_result(result)
            if self._on_progress is not None and (
                self._done % 25 == 0 or self._done == self._total
            ):
                self._on_progress(self._done, self._total)

    async def _probe(self, host: _Host, port: int) -> PortResult:
        info = service_for(port)
        attempt = 0
        last_state: Optional[PortState] = None
        last_error: Optional[str] = None
        total_latency = 0.0

        while attempt <= self._options.retries:
            await self._limiter.acquire()
            started = time.perf_counter()
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(host=host.address, port=port),
                    timeout=self._options.timeout,
                )
            except asyncio.TimeoutError:
                total_latency += (time.perf_counter() - started) * 1000.0
                last_state = PortState.FILTERED
                last_error = f"no response within {self._options.timeout}s"
                attempt += 1
                continue
            except ConnectionRefusedError:
                total_latency += (time.perf_counter() - started) * 1000.0
                return self._result(host, port, PortState.CLOSED, info, total_latency, None)
            except OSError as exc:
                total_latency += (time.perf_counter() - started) * 1000.0
                if exc.errno in (errno.EHOSTUNREACH, errno.ENETUNREACH, errno.EHOSTDOWN):
                    last_state = PortState.FILTERED
                    last_error = f"{exc.__class__.__name__}: {exc.strerror or exc}"
                    attempt += 1
                    continue
                if exc.errno == errno.ECONNREFUSED:
                    return self._result(host, port, PortState.CLOSED, info, total_latency, None)
                return self._result(
                    host,
                    port,
                    PortState.ERROR,
                    info,
                    total_latency,
                    f"{exc.__class__.__name__}: {exc.strerror or exc}",
                )

            connect_latency = (time.perf_counter() - started) * 1000.0
            banner: Optional[str] = None
            try:
                if self._options.banner_grab:
                    banner = await self._grab_banner(reader, writer, info)
            finally:
                writer.close()
                with contextlib.suppress(asyncio.TimeoutError, OSError):
                    await asyncio.wait_for(writer.wait_closed(), timeout=1.0)
            return self._result(
                host, port, PortState.OPEN, info, connect_latency, None, banner=banner
            )

        assert last_state is not None
        return self._result(host, port, last_state, info, total_latency, last_error)

    async def _grab_banner(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        info: ServiceInfo,
    ) -> Optional[str]:
        if info.probe:
            try:
                writer.write(info.probe)
                await writer.drain()
            except (ConnectionError, OSError):
                return None
        try:
            chunk = await asyncio.wait_for(
                reader.read(self._options.banner_bytes),
                timeout=self._options.banner_timeout,
            )
        except (asyncio.TimeoutError, ConnectionError, OSError):
            return None
        if not chunk:
            return None
        return _sanitise_banner(chunk)

    # -- assembly -------------------------------------------------------------

    def _result(
        self,
        host: _Host,
        port: int,
        state: PortState,
        info: ServiceInfo,
        latency_ms: float,
        error: Optional[str],
        *,
        banner: Optional[str] = None,
    ) -> PortResult:
        open_port = state is PortState.OPEN
        return PortResult(
            host=host.target,
            address=host.address,
            port=port,
            state=state,
            service=info.name if open_port else None,
            description=info.description if open_port else None,
            risk=info.risk if open_port else RiskLevel.NONE,
            banner=banner,
            latency_ms=latency_ms,
            error=error,
        )

    @staticmethod
    def _freeze(host: _Host) -> HostResult:
        ordered = sorted(host.ports, key=lambda p: (not p.is_open, p.port))
        return HostResult(
            target=host.target,
            address=host.address,
            family=host.family,
            resolved=host.resolved,
            ports=tuple(ordered),
            reverse_dns=host.reverse_dns,
            error=host.error,
        )


def _sanitise_banner(raw: bytes) -> str:
    """Decode a banner into a single printable line.

    Service banners routinely contain NULs, ANSI escapes and NTLM blobs. Printing
    them verbatim corrupts the terminal and breaks CSV quoting, so ANSI sequences
    are removed, every other byte outside printable ASCII becomes a space, and
    runs of whitespace collapse.
    """
    decoded = raw.decode("utf-8", errors="replace")
    decoded = _ANSI_RE.sub("", decoded)
    cleaned = "".join(ch if (ord(ch) in _PRINTABLE or ch in "\r\n\t") else " " for ch in decoded)
    return " ".join(cleaned.split())


async def scan(
    targets: Sequence[Target],
    options: ScanOptions,
    *,
    on_result: Optional[Callable[[PortResult], None]] = None,
    on_progress: Optional[Callable[[int, int], None]] = None,
) -> ScanReport:
    """Convenience wrapper around :class:`Scanner` for one-shot use."""
    return await Scanner(options, on_result=on_result, on_progress=on_progress).scan(targets)
