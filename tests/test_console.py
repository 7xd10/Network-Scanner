"""Console rendering.

Colour must be off by default in a pipe and on when forced, because a CI log full
of escape codes is worse than no colour at all.
"""

from __future__ import annotations

from netscan.console import Style, render_findings, render_report, render_result, supports_colour
from netscan.models import (
    HostResult,
    PortResult,
    PortState,
    RiskLevel,
    ScanMeta,
    ScanReport,
    utc_now,
)
from netscan.risk import Finding

PLAIN = Style(enabled=False)
COLOUR = Style(enabled=True)


def report_with(*ports: PortResult) -> ScanReport:
    now = utc_now()
    host = HostResult(
        target="10.0.0.5",
        address="10.0.0.5",
        family="IPv4",
        resolved=True,
        ports=ports,
    )
    return ScanReport(
        meta=ScanMeta(
            tool="netscan",
            version="2.0.0",
            started_at=now,
            finished_at=now,
            targets_requested=1,
            addresses_scanned=1,
            ports_per_address=len(ports),
            concurrency=10,
            timeout_s=1.0,
            retries=0,
            banner_grab=True,
        ),
        hosts=(host,),
    )


OPEN = PortResult(
    host="10.0.0.5",
    address="10.0.0.5",
    port=22,
    state=PortState.OPEN,
    service="ssh",
    risk=RiskLevel.NONE,
    banner="SSH-2.0-OpenSSH_9.6",
    latency_ms=0.5,
)
CLOSED = PortResult(
    host="10.0.0.5",
    address="10.0.0.5",
    port=23,
    state=PortState.CLOSED,
    latency_ms=0.2,
)
RISKY = PortResult(
    host="10.0.0.5",
    address="10.0.0.5",
    port=6379,
    state=PortState.OPEN,
    service="redis",
    risk=RiskLevel.CRITICAL,
)


class TestColourDetection:
    def test_no_color_variable_wins(self, monkeypatch) -> None:
        monkeypatch.setenv("NO_COLOR", "1")
        assert supports_colour() is False

    def test_dumb_terminal(self, monkeypatch) -> None:
        monkeypatch.delenv("NO_COLOR", raising=False)
        monkeypatch.setenv("TERM", "dumb")
        assert supports_colour() is False

    def test_force_color_overrides(self, monkeypatch) -> None:
        monkeypatch.delenv("NO_COLOR", raising=False)
        monkeypatch.setenv("FORCE_COLOR", "1")
        assert supports_colour() is True


class TestStyle:
    def test_disabled_style_is_a_noop(self) -> None:
        assert PLAIN.bold("x") == "x"
        assert PLAIN.red("x") == "x"

    def test_enabled_style_wraps_and_resets(self) -> None:
        painted = COLOUR.red("x")
        assert painted.startswith("\033[31m")
        assert painted.endswith("\033[0m")

    def test_risk_labels(self) -> None:
        assert "CRITICAL" in COLOUR.risk(RiskLevel.CRITICAL)
        assert "NONE" in PLAIN.risk(RiskLevel.NONE)


class TestReportRendering:
    def test_lists_open_ports_with_service(self) -> None:
        text = render_report(report_with(OPEN), [], style=PLAIN, width=120)
        assert "22/tcp" in text
        assert "ssh" in text

    def test_closed_ports_are_hidden_by_default(self) -> None:
        text = render_report(report_with(OPEN, CLOSED), [], style=PLAIN, width=120)
        assert "23/tcp" not in text

    def test_closed_ports_can_be_shown(self) -> None:
        text = render_report(
            report_with(OPEN, CLOSED), [], style=PLAIN, width=120, show_closed=True
        )
        assert "23/tcp" in text
        assert "closed" in text

    def test_risk_is_labelled(self) -> None:
        text = render_report(report_with(RISKY), [], style=PLAIN, width=120)
        assert "CRITICAL" in text

    def test_banner_is_shown(self) -> None:
        text = render_report(report_with(OPEN), [], style=PLAIN, width=120)
        assert "SSH-2.0-OpenSSH" in text

    def test_long_banner_is_clipped(self) -> None:
        long_port = PortResult(
            host="h",
            address="10.0.0.5",
            port=80,
            state=PortState.OPEN,
            service="http",
            banner="A" * 400,
        )
        text = render_report(report_with(long_port), [], style=PLAIN, width=80)
        assert "A" * 400 not in text
        assert "\u2026" in text

    def test_unresolved_host_is_reported(self) -> None:
        host = HostResult(
            target="bad.invalid",
            address="",
            family="unknown",
            resolved=False,
            error="DNS resolution failed: name not known",
        )
        report = ScanReport(meta=report_with().meta, hosts=(host,))
        text = render_report(report, [], style=PLAIN, width=120)
        assert "unresolved" in text
        assert "name not known" in text

    def test_host_with_no_open_ports(self) -> None:
        text = render_report(report_with(CLOSED), [], style=PLAIN, width=120)
        assert "no open TCP ports" in text

    def test_summary_line_is_present(self) -> None:
        text = render_report(report_with(OPEN), [], style=PLAIN, width=120)
        assert "summary" in text
        assert "hosts 1" in text

    def test_no_colour_output_has_no_escape_codes(self) -> None:
        text = render_report(report_with(OPEN), [], style=PLAIN, width=120)
        assert "\033[" not in text

    def test_colour_output_has_escape_codes(self) -> None:
        text = render_report(report_with(RISKY), [], style=COLOUR, width=120)
        assert "\033[" in text

    def test_reverse_dns_is_shown(self) -> None:
        host = HostResult(
            target="10.0.0.5",
            address="10.0.0.5",
            family="IPv4",
            resolved=True,
            ports=(OPEN,),
            reverse_dns="host.example",
        )
        report = ScanReport(meta=report_with().meta, hosts=(host,))
        assert "host.example" in render_report(report, [], style=PLAIN, width=120)

    def test_started_timestamp_uses_the_shared_iso_form(self) -> None:
        # The console, Markdown and JSON must render the same instant identically,
        # so two reports of one scan diff cleanly.
        report = report_with(OPEN)
        text = render_report(report, [], style=PLAIN, width=120)
        assert "started 2026-" in text or "started 20" in text
        assert "+00:00" not in text
        assert "000Z" in text or "Z\n" in text


class TestFindingsRendering:
    def test_empty_is_explicit(self) -> None:
        assert "no exposure findings" in render_findings([], style=PLAIN)

    def test_finding_body_is_rendered(self) -> None:
        finding = Finding(
            host="h",
            address="10.0.0.5",
            port=6379,
            service="redis",
            severity=RiskLevel.CRITICAL,
            title="Redis is reachable",
            rationale="Redis has no authentication by default and CONFIG SET can write files.",
            evidence="10.0.0.5:6379/tcp open",
        )
        text = render_findings([finding], style=PLAIN, width=100)
        assert "Redis is reachable" in text
        assert "CONFIG SET" in text
        assert "10.0.0.5:6379/tcp open" in text

    def test_long_rationale_wraps(self) -> None:
        finding = Finding(
            host="h",
            address="10.0.0.5",
            port=1,
            service="x",
            severity=RiskLevel.HIGH,
            title="t",
            rationale=" ".join(["word"] * 200),
            evidence="e",
        )
        text = render_findings([finding], style=PLAIN, width=60)
        assert all(len(line) < 120 for line in text.splitlines())


class TestRenderResult:
    def test_open_port_is_printed(self) -> None:
        assert "22" in render_result(OPEN, style=PLAIN)

    def test_closed_port_is_silent(self) -> None:
        assert render_result(CLOSED, style=PLAIN) == ""

    def test_filtered_port_is_printed(self) -> None:
        filtered = PortResult(
            host="h",
            address="10.0.0.5",
            port=81,
            state=PortState.FILTERED,
            error="no response within 2.0s",
        )
        assert "filtered" in render_result(filtered, style=PLAIN)

    def test_risk_appears_only_for_risky_open_ports(self) -> None:
        assert "CRITICAL" in render_result(RISKY, style=PLAIN)
        assert "NONE" not in render_result(OPEN, style=PLAIN)


class TestWidthHandling:
    def test_narrow_terminal_does_not_raise(self) -> None:
        text = render_report(report_with(OPEN), [], style=PLAIN, width=60)
        assert "22/tcp" in text

    def test_default_width_is_used_when_width_is_none(self) -> None:
        assert render_report(report_with(OPEN), [], style=PLAIN)
