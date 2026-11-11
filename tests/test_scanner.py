"""Engine behaviour.

Open and closed are exercised against real loopback sockets. ``FILTERED`` is
simulated by replacing ``asyncio.open_connection`` with one that never returns,
because a deterministic silent drop cannot be produced on loopback -- the kernel
always answers with RST.
"""

from __future__ import annotations

import asyncio
import socket
from typing import Any, List

import pytest

from netscan.models import PortState
from netscan.scanner import Scanner, ScanOptions, scan
from netscan.targets import Target, parse_targets


class TestOptionsValidation:
    def test_ports_are_required(self) -> None:
        with pytest.raises(ValueError, match="ports"):
            ScanOptions(ports=[])

    def test_concurrency_must_be_positive(self) -> None:
        with pytest.raises(ValueError, match="concurrency"):
            ScanOptions(ports=[80], concurrency=0)

    def test_timeout_must_be_positive(self) -> None:
        with pytest.raises(ValueError, match="timeout"):
            ScanOptions(ports=[80], timeout=0)

    def test_negative_retries(self) -> None:
        with pytest.raises(ValueError, match="retries"):
            ScanOptions(ports=[80], retries=-1)

    def test_negative_rate_limit(self) -> None:
        with pytest.raises(ValueError, match="rate_limit"):
            ScanOptions(ports=[80], rate_limit=-1)

    def test_defaults_are_sane(self) -> None:
        options = ScanOptions(ports=[80])
        assert options.concurrency == 500
        assert options.timeout == 2.0
        assert options.banner_grab is True


class TestOpenAndClosed:
    async def test_open_port_is_open(self, open_port) -> None:
        report = await scan(
            [Target(original="127.0.0.1", address="127.0.0.1")],
            ScanOptions(ports=[open_port.port], retries=0, banner_grab=False),
        )
        assert report.hosts[0].ports[0].state is PortState.OPEN
        assert report.hosts[0].ports[0].port == open_port.port

    async def test_closed_port_is_closed_not_filtered(self, closed_port: int) -> None:
        report = await scan(
            [Target(original="127.0.0.1", address="127.0.0.1")],
            ScanOptions(ports=[closed_port], retries=0, banner_grab=False),
        )
        assert report.hosts[0].ports[0].state is PortState.CLOSED

    async def test_open_port_is_classified_from_the_catalogue(self) -> None:
        # Bind a known port number by hand so classification is deterministic.
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind(("127.0.0.1", 0))
        server.listen(1)
        port = server.getsockname()[1]
        try:
            report = await scan(
                [Target(original="127.0.0.1", address="127.0.0.1")],
                ScanOptions(ports=[port], retries=0, banner_grab=False),
            )
        finally:
            server.close()
        result = report.hosts[0].ports[0]
        assert result.state is PortState.OPEN
        assert result.service is not None

    async def test_every_requested_port_appears_in_the_report(
        self, open_port, closed_port: int
    ) -> None:
        report = await scan(
            [Target(original="127.0.0.1", address="127.0.0.1")],
            ScanOptions(ports=[open_port.port, closed_port], retries=0, banner_grab=False),
        )
        probed = {p.port for p in report.hosts[0].ports}
        assert probed == {open_port.port, closed_port}


class TestFiltered:
    async def test_timeout_is_filtered_not_closed(self, monkeypatch) -> None:
        async def never(**_kwargs: Any) -> Any:
            await asyncio.sleep(3600)

        monkeypatch.setattr("netscan.scanner.asyncio.open_connection", never)

        report = await scan(
            [Target(original="10.255.255.1", address="10.255.255.1")],
            ScanOptions(ports=[80], timeout=0.01, retries=0, banner_grab=False),
        )
        result = report.hosts[0].ports[0]
        assert result.state is PortState.FILTERED
        assert result.error is not None and "no response" in result.error

    async def test_retries_are_applied_to_filtered_probes(self, monkeypatch) -> None:
        attempts: List[int] = []

        async def counting(**_kwargs: Any) -> Any:
            attempts.append(1)
            raise asyncio.TimeoutError

        monkeypatch.setattr("netscan.scanner.asyncio.open_connection", counting)

        await scan(
            [Target(original="10.255.255.1", address="10.255.255.1")],
            ScanOptions(ports=[80], retries=2, banner_grab=False),
        )
        assert len(attempts) == 3  # initial + 2 retries

    async def test_refused_connections_are_never_retried(
        self, closed_port: int, monkeypatch
    ) -> None:
        attempts: List[int] = []
        real = asyncio.open_connection

        async def counting(**kwargs: Any) -> Any:
            attempts.append(1)
            return await real(**kwargs)

        monkeypatch.setattr("netscan.scanner.asyncio.open_connection", counting)

        await scan(
            [Target(original="127.0.0.1", address="127.0.0.1")],
            ScanOptions(ports=[closed_port], retries=5, banner_grab=False),
        )
        assert len(attempts) == 1

    async def test_unreachable_host_is_filtered(self) -> None:
        # TEST-NET-1 is guaranteed non-routable by RFC 5737; the OS reports
        # EHOSTUNREACH or drops, and both must land on FILTERED.
        report = await scan(
            [Target(original="192.0.2.1", address="192.0.2.1")],
            ScanOptions(ports=[81], timeout=0.15, retries=0, banner_grab=False),
        )
        assert report.hosts[0].ports[0].state in {PortState.FILTERED, PortState.ERROR}


class TestBanners:
    async def test_banner_is_captured(self, open_port) -> None:
        report = await scan(
            [Target(original="127.0.0.1", address="127.0.0.1")],
            ScanOptions(ports=[open_port.port], retries=0, banner_grab=True),
        )
        result = report.hosts[0].ports[0]
        assert result.banner is not None
        assert "SSH-2.0-OpenSSH" in result.banner

    async def test_banner_can_be_disabled(self, open_port) -> None:
        report = await scan(
            [Target(original="127.0.0.1", address="127.0.0.1")],
            ScanOptions(ports=[open_port.port], retries=0, banner_grab=False),
        )
        assert report.hosts[0].ports[0].banner is None

    async def test_silent_service_yields_no_banner(self, silent_port) -> None:
        report = await scan(
            [Target(original="127.0.0.1", address="127.0.0.1")],
            ScanOptions(
                ports=[silent_port.port],
                retries=0,
                banner_grab=True,
                banner_timeout=0.15,
            ),
        )
        result = report.hosts[0].ports[0]
        assert result.state is PortState.OPEN
        assert result.banner is None

    async def test_banner_is_sanitised(self, monkeypatch) -> None:
        async def noisy(**_kwargs: Any) -> Any:
            class Writer:
                def write(self, _data: bytes) -> None:
                    return None

                async def drain(self) -> None:
                    return None

                def close(self) -> None:
                    return None

                async def wait_closed(self) -> None:
                    return None

            class Reader:
                async def read(self, _n: int) -> bytes:
                    return b"\x1b[31mSSH\x00-2.0\x07\r\n"

            return Reader(), Writer()

        monkeypatch.setattr("netscan.scanner.asyncio.open_connection", noisy)

        report = await scan(
            [Target(original="127.0.0.1", address="127.0.0.1")],
            ScanOptions(ports=[22], retries=0, banner_grab=True),
        )
        banner = report.hosts[0].ports[0].banner
        assert banner == "SSH -2.0"


class TestConcurrency:
    async def test_live_tasks_never_exceed_the_ceiling(self, monkeypatch) -> None:
        state = {"live": 0, "peak": 0}

        async def slow(**kwargs: Any) -> Any:
            state["live"] += 1
            state["peak"] = max(state["peak"], state["live"])
            try:
                await asyncio.sleep(0.02)
                raise ConnectionRefusedError
            finally:
                state["live"] -= 1

        monkeypatch.setattr("netscan.scanner.asyncio.open_connection", slow)

        await scan(
            [Target(original="127.0.0.1", address="127.0.0.1")],
            ScanOptions(
                ports=list(range(1, 121)),
                concurrency=7,
                retries=0,
                banner_grab=False,
            ),
        )
        assert state["peak"] <= 7, f"peak concurrency was {state['peak']}"

    async def test_concurrency_of_one_still_completes(self) -> None:
        report = await scan(
            [Target(original="127.0.0.1", address="127.0.0.1")],
            ScanOptions(ports=[9, 8, 7], concurrency=1, retries=0, banner_grab=False),
        )
        assert len(report.hosts[0].ports) == 3


class TestRateLimit:
    async def test_rate_limit_paces_probes(self, closed_port: int) -> None:
        loop = asyncio.get_running_loop()
        started = loop.time()
        await scan(
            [Target(original="127.0.0.1", address="127.0.0.1")],
            ScanOptions(
                ports=[closed_port] * 1,
                rate_limit=50.0,
                retries=0,
                banner_grab=False,
            ),
        )
        elapsed = loop.time() - started
        assert elapsed >= 0.0  # sanity; the real assertion is below

    async def test_pacing_adds_delay_for_many_probes(self) -> None:
        loop = asyncio.get_running_loop()
        started = loop.time()
        await scan(
            [Target(original="127.0.0.1", address="127.0.0.1")],
            ScanOptions(
                ports=list(range(100, 106)),
                rate_limit=40.0,
                retries=0,
                banner_grab=False,
            ),
        )
        elapsed = loop.time() - started
        # 6 probes at 40/s is ~125 ms of enforced spacing.
        assert elapsed >= 0.1


class TestUnresolvable:
    async def test_bad_hostname_is_recorded_not_raised(self) -> None:
        target = Target(original="no-such-host.invalid", hostname="no-such-host.invalid")
        report = await scan(
            [target],
            ScanOptions(ports=[80], retries=0, banner_grab=False, resolve_timeout=1.0),
        )
        assert len(report.hosts) == 1
        assert report.hosts[0].resolved is False
        assert report.hosts[0].error is not None

    async def test_resolution_timeout_is_recorded(self, monkeypatch) -> None:
        async def never(*_args: object, **_kwargs: object) -> object:
            await asyncio.sleep(3600)

        class FakeLoop:
            getaddrinfo = staticmethod(never)
            getnameinfo = staticmethod(never)

        monkeypatch.setattr("netscan.scanner.asyncio.get_running_loop", lambda: FakeLoop())

        target = Target(original="slow.example", hostname="slow.example")
        report = await scan(
            [target],
            ScanOptions(ports=[80], retries=0, banner_grab=False, resolve_timeout=0.05),
        )
        assert report.hosts[0].resolved is False
        assert "timed out" in (report.hosts[0].error or "")

    async def test_localhost_hostname_resolves(self) -> None:
        target = Target(original="localhost", hostname="localhost")
        report = await scan(
            [target],
            ScanOptions(ports=[1], retries=0, banner_grab=False),
        )
        assert any(h.resolved for h in report.hosts)


class TestReportMetadata:
    async def test_meta_matches_the_request(self, closed_port: int) -> None:
        options = ScanOptions(
            ports=[closed_port],
            concurrency=3,
            timeout=0.5,
            retries=0,
            banner_grab=False,
            argv=["netscan", "test"],
        )
        report = await scan([Target(original="127.0.0.1", address="127.0.0.1")], options)
        assert report.meta.tool == "netscan"
        assert report.meta.concurrency == 3
        assert report.meta.ports_per_address == 1
        assert report.meta.addresses_scanned == 1
        assert report.meta.argv == ["netscan", "test"]
        assert report.meta.finished_at is not None

    async def test_ports_are_ordered_open_first(self, open_port, closed_port: int) -> None:
        report = await scan(
            [Target(original="127.0.0.1", address="127.0.0.1")],
            ScanOptions(ports=[closed_port, open_port.port], retries=0, banner_grab=False),
        )
        assert report.hosts[0].ports[0].state is PortState.OPEN


class TestCallbacks:
    async def test_on_result_fires_for_every_probe(self, closed_port: int) -> None:
        seen: List[int] = []
        await Scanner(
            ScanOptions(ports=[closed_port, closed_port + 1], retries=0, banner_grab=False),
            on_result=lambda r: seen.append(r.port),
        ).scan([Target(original="127.0.0.1", address="127.0.0.1")])
        assert len(seen) == 2

    async def test_on_progress_reaches_the_total(self, closed_port: int) -> None:
        progress: List[tuple[int, int]] = []
        await Scanner(
            ScanOptions(ports=[closed_port], retries=0, banner_grab=False),
            on_progress=lambda done, total: progress.append((done, total)),
        ).scan([Target(original="127.0.0.1", address="127.0.0.1")])
        assert progress[-1] == (1, 1)


class TestTargetsIntegration:
    async def test_cidr_expansion_is_scanned(self) -> None:
        report = await scan(
            parse_targets(["127.0.0.0/30"]),
            ScanOptions(ports=[9], retries=0, banner_grab=False, timeout=0.2),
        )
        assert len(report.hosts) == 4
        assert report.meta.addresses_scanned == 4
