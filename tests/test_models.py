"""Model contract tests. ``to_dict`` is the on-wire shape, so it gets pinned."""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

import pytest

from netscan.models import (
    HostResult,
    PortResult,
    PortState,
    RiskLevel,
    ScanReport,
    TargetError,
    iso,
    normalise_address,
    utc_now,
)


class TestRiskOrdering:
    def test_rank_increases_with_severity(self) -> None:
        ordered = [
            RiskLevel.NONE,
            RiskLevel.LOW,
            RiskLevel.MEDIUM,
            RiskLevel.HIGH,
            RiskLevel.CRITICAL,
        ]
        ranks = [level.rank for level in ordered]
        assert ranks == sorted(ranks)
        assert len(set(ranks)) == len(ranks)

    def test_rank_comparison_is_usable(self) -> None:
        assert RiskLevel.CRITICAL.rank > RiskLevel.HIGH.rank
        assert RiskLevel.NONE.rank < RiskLevel.LOW.rank


class TestPortResult:
    def test_open_helper(self) -> None:
        result = PortResult(host="h", address="1.2.3.4", port=80, state=PortState.OPEN)
        assert result.is_open is True

    def test_non_open_helper(self) -> None:
        for state in (PortState.CLOSED, PortState.FILTERED, PortState.ERROR):
            result = PortResult(host="h", address="1.2.3.4", port=80, state=state)
            assert result.is_open is False

    def test_to_dict_shape(self) -> None:
        result = PortResult(
            host="h",
            address="1.2.3.4",
            port=443,
            state=PortState.OPEN,
            service="https",
            risk=RiskLevel.LOW,
            latency_ms=1.23456,
        )
        payload = result.to_dict()
        assert set(payload) == {
            "host",
            "address",
            "port",
            "protocol",
            "state",
            "service",
            "description",
            "risk",
            "banner",
            "latency_ms",
            "error",
        }
        assert payload["state"] == "open"
        assert payload["risk"] == "low"
        assert payload["latency_ms"] == 1.235

    def test_latency_of_none_stays_none(self) -> None:
        result = PortResult(host="h", address="1.2.3.4", port=1, state=PortState.ERROR)
        assert result.to_dict()["latency_ms"] is None

    def test_to_dict_is_json_serialisable(self) -> None:
        result = PortResult(host="h", address="1.2.3.4", port=80, state=PortState.OPEN)
        json.dumps(result.to_dict())


class TestHostResult:
    def test_open_ports_filters(self) -> None:
        ports = (
            PortResult(host="h", address="1.1.1.1", port=22, state=PortState.OPEN),
            PortResult(host="h", address="1.1.1.1", port=23, state=PortState.CLOSED),
        )
        host = HostResult(target="h", address="1.1.1.1", family="IPv4", resolved=True, ports=ports)
        assert [p.port for p in host.open_ports] == [22]

    def test_highest_risk_picks_the_worst_open_port(self) -> None:
        ports = (
            PortResult(
                host="h", address="1.1.1.1", port=22, state=PortState.OPEN, risk=RiskLevel.NONE
            ),
            PortResult(
                host="h",
                address="1.1.1.1",
                port=6379,
                state=PortState.OPEN,
                risk=RiskLevel.CRITICAL,
            ),
        )
        host = HostResult(target="h", address="1.1.1.1", family="IPv4", resolved=True, ports=ports)
        assert host.highest_risk is RiskLevel.CRITICAL

    def test_closed_ports_do_not_contribute_risk(self) -> None:
        ports = (
            PortResult(
                host="h",
                address="1.1.1.1",
                port=6379,
                state=PortState.CLOSED,
                risk=RiskLevel.CRITICAL,
            ),
        )
        host = HostResult(target="h", address="1.1.1.1", family="IPv4", resolved=True, ports=ports)
        assert host.highest_risk is RiskLevel.NONE

    def test_duration_of_none_when_timestamps_missing(self) -> None:
        host = HostResult(target="h", address="1.1.1.1", family="IPv4", resolved=True)
        assert host.duration_ms is None

    def test_duration_is_positive(self) -> None:
        start = utc_now()
        host = HostResult(
            target="h",
            address="1.1.1.1",
            family="IPv4",
            resolved=True,
            started_at=start,
            finished_at=start + timedelta(milliseconds=250),
        )
        assert host.duration_ms == pytest.approx(250.0)


class TestScanReport:
    def test_open_port_total(self, sample_report: ScanReport) -> None:
        assert sample_report.open_port_total == 1

    def test_highest_risk_across_hosts(self, sample_report: ScanReport) -> None:
        assert sample_report.highest_risk is RiskLevel.NONE

    def test_to_dict_has_meta_summary_hosts(self, sample_report: ScanReport) -> None:
        payload = sample_report.to_dict()
        assert set(payload) == {"meta", "summary", "hosts"}
        assert payload["summary"]["hosts"] == 1
        assert payload["summary"]["open_ports"] == 1
        assert payload["summary"]["highest_risk"] == "none"

    def test_to_dict_is_json_serialisable(self, sample_report: ScanReport) -> None:
        json.dumps(sample_report.to_dict())


class TestTimestamps:
    def test_utc_now_is_timezone_aware(self) -> None:
        assert utc_now().tzinfo is not None

    def test_iso_uses_z_suffix(self) -> None:
        stamp = datetime(2026, 11, 11, 12, 0, 0, tzinfo=timezone.utc)
        assert iso(stamp) == "2026-11-11T12:00:00.000Z"

    def test_iso_converts_from_other_offsets(self) -> None:
        stamp = datetime(2026, 11, 11, 13, 0, 0, tzinfo=timezone(timedelta(hours=1)))
        assert iso(stamp) == "2026-11-11T12:00:00.000Z"

    def test_iso_of_none(self) -> None:
        assert iso(None) is None


class TestAddressNormalisation:
    def test_valid(self) -> None:
        assert normalise_address(" 10.0.0.1 ") == "10.0.0.1"

    def test_ipv6_is_compressed(self) -> None:
        assert normalise_address("2001:0db8:0000:0000:0000:0000:0000:0001") == "2001:db8::1"

    def test_invalid(self) -> None:
        with pytest.raises(TargetError):
            normalise_address("not-an-ip")


class TestScanMeta:
    def test_round_trip(self, sample_report: ScanReport) -> None:
        payload = sample_report.meta.to_dict()
        assert payload["tool"] == "netscan"
        assert payload["argv"] == ["netscan", "127.0.0.1"]
        json.dumps(payload)
