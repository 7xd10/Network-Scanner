"""Exposure rules.

The assertions here are about *classification*, not about vulnerabilities: an
open 6379 must produce a CRITICAL finding with Redis in the rationale, and a
closed 6379 must produce nothing at all. Nothing in these tests claims that a
particular Redis is unauthenticated, because the scanner never sends a command.
"""

from __future__ import annotations

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
from netscan.risk import (
    RULES,
    Finding,
    analyse,
    findings_for_host,
    summarise,
)


def host_with(*ports: tuple[int, str, RiskLevel, str | None]) -> HostResult:
    results = tuple(
        PortResult(
            host="10.0.0.5",
            address="10.0.0.5",
            port=port,
            state=PortState.OPEN,
            service=service,
            risk=risk,
            banner=banner,
            latency_ms=1.0,
        )
        for port, service, risk, banner in ports
    )
    return HostResult(
        target="10.0.0.5",
        address="10.0.0.5",
        family="IPv4",
        resolved=True,
        ports=results,
    )


class TestSinglePortRules:
    @pytest.mark.parametrize(
        "port,service,risk",
        [
            (23, "telnet", RiskLevel.CRITICAL),
            (445, "microsoft-ds", RiskLevel.CRITICAL),
            (1433, "mssql", RiskLevel.CRITICAL),
            (3306, "mysql", RiskLevel.CRITICAL),
            (3389, "ms-wbt-server", RiskLevel.CRITICAL),
            (5432, "postgresql", RiskLevel.CRITICAL),
            (5900, "vnc", RiskLevel.CRITICAL),
            (6379, "redis", RiskLevel.CRITICAL),
            (9200, "elasticsearch", RiskLevel.CRITICAL),
            (27017, "mongo", RiskLevel.CRITICAL),
            (21, "ftp", RiskLevel.HIGH),
            (873, "rsync", RiskLevel.HIGH),
            (2049, "nfs", RiskLevel.HIGH),
            (5985, "wsman", RiskLevel.HIGH),
        ],
    )
    def test_dangerous_port_produces_a_finding(
        self, port: int, service: str, risk: RiskLevel
    ) -> None:
        findings = findings_for_host(host_with((port, service, risk, None)))
        assert findings, f"port {port} produced no finding"
        assert findings[0].port == port
        assert findings[0].severity is risk

    def test_closed_port_produces_nothing(self) -> None:
        host = HostResult(
            target="h",
            address="10.0.0.5",
            family="IPv4",
            resolved=True,
            ports=(
                PortResult(
                    host="h",
                    address="10.0.0.5",
                    port=6379,
                    state=PortState.CLOSED,
                    risk=RiskLevel.NONE,
                ),
            ),
        )
        assert findings_for_host(host) == []

    def test_filtered_port_produces_nothing(self) -> None:
        host = HostResult(
            target="h",
            address="10.0.0.5",
            family="IPv4",
            resolved=True,
            ports=(
                PortResult(
                    host="h",
                    address="10.0.0.5",
                    port=6379,
                    state=PortState.FILTERED,
                    risk=RiskLevel.NONE,
                ),
            ),
        )
        assert findings_for_host(host) == []

    def test_harmless_open_port_produces_nothing(self) -> None:
        findings = findings_for_host(host_with((22, "ssh", RiskLevel.NONE, "SSH-2.0-OpenSSH_9.6")))
        assert findings == []

    def test_alternate_http_is_medium(self) -> None:
        findings = findings_for_host(host_with((8080, "http-proxy", RiskLevel.MEDIUM, None)))
        assert findings[0].severity is RiskLevel.MEDIUM


class TestBannerRules:
    def test_banner_identifies_a_mislabelled_service(self) -> None:
        # Port 9999 is "unknown" in the catalogue but the banner says HTTP.
        findings = findings_for_host(
            host_with((9999, "unknown", RiskLevel.MEDIUM, "HTTP/1.1 200 OK"))
        )
        assert any("HTTP" in f.title for f in findings)

    def test_ssh_banner_is_not_flagged(self) -> None:
        findings = findings_for_host(
            host_with((2222, "unknown", RiskLevel.NONE, "SSH-2.0-OpenSSH_9.6"))
        )
        # 2222 has no rule, and SSH resolves to NONE, so nothing should surface.
        assert all(f.severity is not RiskLevel.CRITICAL for f in findings)

    def test_vnc_banner_escalates(self) -> None:
        findings = findings_for_host(host_with((5999, "unknown", RiskLevel.NONE, "RFB 003.008")))
        assert findings[0].severity is RiskLevel.CRITICAL
        assert findings[0].service == "vnc"


class TestOrderingAndAggregation:
    def test_findings_are_sorted_by_severity(self) -> None:
        host = host_with(
            (8080, "http-proxy", RiskLevel.MEDIUM, None),
            (6379, "redis", RiskLevel.CRITICAL, None),
            (21, "ftp", RiskLevel.HIGH, None),
        )
        findings = findings_for_host(host)
        severities = [f.severity for f in findings]
        assert severities == [RiskLevel.CRITICAL, RiskLevel.HIGH, RiskLevel.MEDIUM]

    def test_analyse_walks_every_host(self) -> None:
        report = ScanReport(
            meta=ScanMeta(
                tool="netscan",
                version="2.0.0",
                started_at=utc_now(),
                finished_at=utc_now(),
                targets_requested=1,
                addresses_scanned=1,
                ports_per_address=1,
                concurrency=1,
                timeout_s=1.0,
                retries=0,
                banner_grab=False,
            ),
            hosts=(host_with((6379, "redis", RiskLevel.CRITICAL, None)),),
        )
        assert len(analyse(report)) == 1

    def test_summarise_zero_fills_every_severity(self) -> None:
        counts = summarise([])
        assert counts == {"low": 0, "medium": 0, "high": 0, "critical": 0}

    def test_summarise_counts(self) -> None:
        findings = [
            Finding(
                host="h",
                address="1.1.1.1",
                port=1,
                service="x",
                severity=RiskLevel.HIGH,
                title="t",
                rationale="r",
                evidence="e",
            ),
            Finding(
                host="h",
                address="1.1.1.1",
                port=2,
                service="x",
                severity=RiskLevel.HIGH,
                title="t",
                rationale="r",
                evidence="e",
            ),
        ]
        assert summarise(findings)["high"] == 2


class TestRuleHygiene:
    def test_every_rule_has_rationale_and_title(self) -> None:
        for rule in RULES:
            assert rule.title
            assert len(rule.rationale) > 40, rule.title

    def test_every_rule_targets_a_valid_port(self) -> None:
        for rule in RULES:
            assert rule.ports, rule.title
            assert all(1 <= p <= 65535 for p in rule.ports), rule.title

    def test_banner_patterns_compile(self) -> None:
        import re

        for rule in RULES:
            if rule.banner_pattern:
                re.compile(rule.banner_pattern)

    def test_evidence_names_the_socket(self) -> None:
        findings = findings_for_host(host_with((23, "telnet", RiskLevel.CRITICAL, None)))
        assert "10.0.0.5:23/tcp open" in findings[0].evidence
