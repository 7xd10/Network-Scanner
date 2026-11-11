"""Serialisation contract.

The CSV tests matter most: the legacy implementation built CSV rows with
``",".join()`` and produced unparseable output for any banner containing a comma,
which is nearly all HTTP banners.
"""

from __future__ import annotations

import csv
import io
import json
from pathlib import Path

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
from netscan.report import CSV_COLUMNS, FORMATS, render, write_report
from netscan.risk import Finding


def make_report(ports: tuple[PortResult, ...]) -> ScanReport:
    now = utc_now()
    host = HostResult(
        target="10.0.0.5",
        address="10.0.0.5",
        family="IPv4",
        resolved=True,
        ports=ports,
        reverse_dns="host.example",
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
            retries=1,
            banner_grab=True,
            argv=["netscan", "10.0.0.5"],
        ),
        hosts=(host,),
    )


@pytest.fixture
def report_with_banner() -> ScanReport:
    return make_report(
        (
            PortResult(
                host="10.0.0.5",
                address="10.0.0.5",
                port=80,
                state=PortState.OPEN,
                service="http",
                description="HTTP web server",
                risk=RiskLevel.LOW,
                banner='Apache/2.4.52 (Ubuntu), "quoted", line\nbreak',
                latency_ms=1.5,
            ),
            PortResult(
                host="10.0.0.5",
                address="10.0.0.5",
                port=81,
                state=PortState.FILTERED,
                error="no response within 1.0s",
            ),
        )
    )


@pytest.fixture
def sample_finding() -> Finding:
    return Finding(
        host="10.0.0.5",
        address="10.0.0.5",
        port=80,
        service="http",
        severity=RiskLevel.LOW,
        title="Alternate HTTP port is open",
        rationale="Management consoles are frequently here.",
        evidence="10.0.0.5:80/tcp open",
    )


class TestJson:
    def test_is_valid_json(self, report_with_banner: ScanReport, sample_finding: Finding) -> None:
        text = render(report_with_banner, [sample_finding], "json")
        document = json.loads(text)
        assert document["meta"]["tool"] == "netscan"
        assert document["summary"]["open_ports"] == 1
        assert len(document["hosts"]) == 1
        assert len(document["findings"]) == 1

    def test_ends_with_a_newline(self, report_with_banner: ScanReport) -> None:
        assert render(report_with_banner, [], "json").endswith("\n")

    def test_unicode_survives(self) -> None:
        report = make_report(
            (
                PortResult(
                    host="h",
                    address="10.0.0.5",
                    port=80,
                    state=PortState.OPEN,
                    banner="Serveur \u00e9v\u00e9nement",
                ),
            )
        )
        assert "\u00e9v\u00e9nement" in render(report, [], "json")


class TestNdjson:
    def test_every_line_is_json(
        self, report_with_banner: ScanReport, sample_finding: Finding
    ) -> None:
        text = render(report_with_banner, [sample_finding], "ndjson")
        for line in text.strip().splitlines():
            json.loads(line)

    def test_record_order(self, report_with_banner: ScanReport, sample_finding: Finding) -> None:
        text = render(report_with_banner, [sample_finding], "ndjson")
        kinds = [json.loads(line)["type"] for line in text.strip().splitlines()]
        assert kinds[0] == "meta"
        assert kinds[-1] == "summary"
        assert "host" in kinds
        assert "port" in kinds
        assert "finding" in kinds

    def test_only_open_ports_are_emitted(self, report_with_banner: ScanReport) -> None:
        text = render(report_with_banner, [], "ndjson")
        port_records = [
            json.loads(line)
            for line in text.strip().splitlines()
            if json.loads(line)["type"] == "port"
        ]
        assert len(port_records) == 1
        assert port_records[0]["port"] == 80


class TestCsv:
    def test_header_matches_the_contract(self, report_with_banner: ScanReport) -> None:
        text = render(report_with_banner, [], "csv")
        header = text.splitlines()[0]
        assert tuple(header.split(",")) == CSV_COLUMNS

    def test_banner_with_comma_and_newline_survives(self, report_with_banner: ScanReport) -> None:
        text = render(report_with_banner, [], "csv")
        rows = list(csv.DictReader(io.StringIO(text)))
        banner = rows[0]["banner"]
        assert "Apache/2.4.52" in banner
        assert '"quoted"' in banner
        assert "\n" in banner

    def test_every_probed_port_becomes_a_row(self, report_with_banner: ScanReport) -> None:
        rows = list(csv.DictReader(io.StringIO(render(report_with_banner, [], "csv"))))
        assert len(rows) == 2
        assert {row["state"] for row in rows} == {"open", "filtered"}

    def test_filtered_row_carries_the_reason(self, report_with_banner: ScanReport) -> None:
        rows = list(csv.DictReader(io.StringIO(render(report_with_banner, [], "csv"))))
        filtered = next(row for row in rows if row["state"] == "filtered")
        assert "no response" in filtered["error"]

    def test_unresolved_host_gets_a_row(self) -> None:
        report = make_report(())
        host = HostResult(
            target="bad.invalid",
            address="",
            family="unknown",
            resolved=False,
            error="DNS resolution failed",
        )
        broken = ScanReport(meta=report.meta, hosts=(host,))
        rows = list(csv.DictReader(io.StringIO(render(broken, [], "csv"))))
        assert rows[0]["state"] == "unresolved"


class TestMarkdown:
    def test_has_a_title_and_a_table(self, report_with_banner: ScanReport) -> None:
        text = render(report_with_banner, [], "md")
        assert text.startswith("# Network scan report")
        assert "| Port | Service | Risk | Banner |" in text

    def test_timestamps_use_the_shared_iso_form(self, report_with_banner: ScanReport) -> None:
        text = render(report_with_banner, [], "md")
        assert "**Started**: 20" in text
        assert "+00:00" not in text
        assert "Z" in text

    def test_pipes_in_banners_are_escaped(self) -> None:
        report = make_report(
            (
                PortResult(
                    host="h",
                    address="10.0.0.5",
                    port=80,
                    state=PortState.OPEN,
                    service="http",
                    banner="a|b|c",
                ),
            )
        )
        text = render(report, [], "md")
        assert "a\\|b\\|c" in text

    def test_findings_section_is_rendered(
        self, report_with_banner: ScanReport, sample_finding: Finding
    ) -> None:
        text = render(report_with_banner, [sample_finding], "md")
        assert "## Findings" in text
        assert "LOW" in text
        assert "Alternate HTTP port is open" in text
        assert "10.0.0.5:80/tcp open" in text

    def test_unresolved_host_is_labelled(self) -> None:
        report = make_report(())
        host = HostResult(
            target="bad.invalid",
            address="",
            family="unknown",
            resolved=False,
            error="DNS resolution failed",
        )
        broken = ScanReport(meta=report.meta, hosts=(host,))
        text = render(broken, [], "md")
        assert "unresolvable" in text
        assert "DNS resolution failed" in text

    def test_host_with_no_open_ports_says_so(self) -> None:
        report = make_report(
            (
                PortResult(
                    host="h",
                    address="10.0.0.5",
                    port=81,
                    state=PortState.CLOSED,
                ),
            )
        )
        assert "No open TCP ports" in render(report, [], "md")


class TestNdjsonUnresolved:
    def test_unresolved_host_record(self) -> None:
        report = make_report(())
        host = HostResult(
            target="bad.invalid",
            address="",
            family="unknown",
            resolved=False,
            error="DNS resolution failed",
        )
        broken = ScanReport(meta=report.meta, hosts=(host,))
        records = [json.loads(line) for line in render(broken, [], "ndjson").strip().splitlines()]
        host_records = [r for r in records if r["type"] == "host"]
        assert host_records[0]["resolved"] is False
        assert host_records[0]["error"] == "DNS resolution failed"


class TestFormatDispatch:
    def test_every_declared_format_renders(self, report_with_banner: ScanReport) -> None:
        for fmt in FORMATS:
            if fmt == "console":
                continue
            assert render(report_with_banner, [], fmt)

    def test_console_is_not_a_file_format(self, report_with_banner: ScanReport) -> None:
        with pytest.raises(ValueError, match="console"):
            render(report_with_banner, [], "console")

    def test_unknown_format_names_the_options(self, report_with_banner: ScanReport) -> None:
        with pytest.raises(ValueError, match="unknown format"):
            render(report_with_banner, [], "yaml")


class TestAtomicWrite:
    def test_file_is_created(self, tmp_path: Path, report_with_banner: ScanReport) -> None:
        destination = tmp_path / "out.json"
        write_report(report_with_banner, [], fmt="json", output=str(destination))
        assert json.loads(destination.read_text(encoding="utf-8"))

    def test_parent_directories_are_created(
        self, tmp_path: Path, report_with_banner: ScanReport
    ) -> None:
        destination = tmp_path / "deep" / "nested" / "out.csv"
        write_report(report_with_banner, [], fmt="csv", output=str(destination))
        assert destination.exists()

    def test_no_temp_files_are_left_behind(
        self, tmp_path: Path, report_with_banner: ScanReport
    ) -> None:
        write_report(report_with_banner, [], fmt="json", output=str(tmp_path / "out.json"))
        leftovers = [p.name for p in tmp_path.iterdir() if p.name.endswith(".tmp")]
        assert leftovers == []

    def test_existing_file_is_replaced(
        self, tmp_path: Path, report_with_banner: ScanReport
    ) -> None:
        destination = tmp_path / "out.json"
        destination.write_text("stale", encoding="utf-8")
        write_report(report_with_banner, [], fmt="json", output=str(destination))
        assert json.loads(destination.read_text(encoding="utf-8"))["meta"]["tool"] == "netscan"

    def test_stream_output_returns_the_text(self, report_with_banner: ScanReport) -> None:
        buffer = io.StringIO()
        returned = write_report(report_with_banner, [], fmt="json", stream=buffer)
        assert returned is not None
        assert returned == buffer.getvalue()

    def test_named_output_returns_none(
        self, tmp_path: Path, report_with_banner: ScanReport
    ) -> None:
        assert (
            write_report(report_with_banner, [], fmt="json", output=str(tmp_path / "o.json"))
            is None
        )

    def test_missing_sink_is_an_error(self, report_with_banner: ScanReport) -> None:
        with pytest.raises(ValueError, match="output or stream"):
            write_report(report_with_banner, [], fmt="json")
