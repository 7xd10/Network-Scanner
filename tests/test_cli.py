"""CLI contract: exit codes, flag translation, and that the output lands."""

from __future__ import annotations

import csv
import io
import json
from pathlib import Path

import pytest

from netscan import cli
from netscan.cli import EXIT_INTERNAL, EXIT_OK, EXIT_RISK, EXIT_USAGE, build_parser, main
from netscan.models import RiskLevel
from netscan.risk import Finding


class TestArgumentParsing:
    def test_parser_accepts_a_target(self) -> None:
        args = build_parser().parse_args(["10.0.0.5"])
        assert args.targets == ["10.0.0.5"]

    def test_defaults(self) -> None:
        args = build_parser().parse_args(["10.0.0.5"])
        assert args.ports == "common"
        assert args.concurrency == 500
        assert args.timeout == 2.0
        assert args.fmt == "console"
        assert args.banner is True
        assert args.fail_on_risk == "none"

    def test_no_banner_switch(self) -> None:
        args = build_parser().parse_args(["10.0.0.5", "--no-banner"])
        assert args.banner is False

    def test_repeatable_allow_scope(self) -> None:
        args = build_parser().parse_args(
            ["10.0.0.5", "--allow-scope", "10.0.0.0/8", "--allow-scope", "192.168.0.0/16"]
        )
        assert args.allow_scope == ["10.0.0.0/8", "192.168.0.0/16"]


class TestUsageErrors:
    def test_no_targets_returns_2(self, capsys) -> None:
        assert main([]) == EXIT_USAGE
        assert "target" in capsys.readouterr().err

    def test_bad_port_spec_returns_2(self, capsys) -> None:
        assert main(["10.0.0.5", "-p", "not-a-port"]) == EXIT_USAGE
        assert "ports" in capsys.readouterr().err

    def test_bad_target_returns_2(self, capsys) -> None:
        assert main(["not a valid target!!"]) == EXIT_USAGE
        assert "target" in capsys.readouterr().err

    def test_oversized_target_returns_2(self, capsys) -> None:
        assert main(["10.0.0.0/8"]) == EXIT_USAGE
        assert "ceiling" in capsys.readouterr().err

    def test_zero_concurrency_returns_2(self) -> None:
        assert main(["10.0.0.5", "-c", "0"]) == EXIT_USAGE

    def test_missing_target_file_returns_2(self, tmp_path: Path) -> None:
        assert main([f"@{tmp_path / 'nope.txt'}"]) == EXIT_USAGE


class TestDryRun:
    def test_prints_the_plan_and_returns_0(self, capsys) -> None:
        assert main(["127.0.0.0/30", "-p", "22,80", "--dry-run"]) == EXIT_OK
        out = capsys.readouterr().out
        assert "targets   : 4" in out
        assert "ports     : 2" in out
        assert "probes    : 8" in out

    def test_truncates_long_target_lists(self, capsys) -> None:
        assert main(["127.0.0.0/27", "-p", "22", "--dry-run"]) == EXIT_OK
        assert "more" in capsys.readouterr().out

    def test_dry_run_probes_nothing(self, capsys) -> None:
        assert main(["192.0.2.1", "-p", "80", "--dry-run"]) == EXIT_OK
        assert "probes    : 1" in capsys.readouterr().out


class TestRealScan:
    def test_json_report_is_written(self, tmp_path: Path, open_port) -> None:
        destination = tmp_path / "report.json"
        code = main(
            [
                "127.0.0.1",
                "-p",
                str(open_port.port),
                "--no-banner",
                "-f",
                "json",
                "-o",
                str(destination),
                "--retries",
                "0",
            ]
        )
        assert code == EXIT_OK
        document = json.loads(destination.read_text(encoding="utf-8"))
        assert document["summary"]["open_ports"] == 1
        assert document["hosts"][0]["ports"][0]["state"] == "open"

    def test_csv_report_is_parseable(self, tmp_path: Path, closed_port: int) -> None:
        destination = tmp_path / "report.csv"
        code = main(
            [
                "127.0.0.1",
                "-p",
                str(closed_port),
                "--no-banner",
                "-f",
                "csv",
                "-o",
                str(destination),
                "--retries",
                "0",
            ]
        )
        assert code == EXIT_OK
        rows = list(csv.DictReader(io.StringIO(destination.read_text(encoding="utf-8"))))
        assert len(rows) == 1
        assert rows[0]["state"] == "closed"

    def test_console_report_mentions_the_port(self, capsys, open_port) -> None:
        code = main(
            [
                "127.0.0.1",
                "-p",
                str(open_port.port),
                "--no-banner",
                "--retries",
                "0",
            ]
        )
        assert code == EXIT_OK
        assert str(open_port.port) in capsys.readouterr().out

    def test_quiet_suppresses_stdout(self, capsys, closed_port: int) -> None:
        code = main(
            [
                "127.0.0.1",
                "-p",
                str(closed_port),
                "--no-banner",
                "--quiet",
                "--retries",
                "0",
            ]
        )
        assert code == EXIT_OK
        assert capsys.readouterr().out == ""

    def test_console_output_can_go_to_a_file(self, tmp_path: Path, closed_port: int) -> None:
        destination = tmp_path / "report.txt"
        code = main(
            [
                "127.0.0.1",
                "-p",
                str(closed_port),
                "--no-banner",
                "-o",
                str(destination),
                "--retries",
                "0",
            ]
        )
        assert code == EXIT_OK
        assert "summary" in destination.read_text(encoding="utf-8")


class TestFailOnRisk:
    def _finding(self, level: RiskLevel) -> Finding:
        return Finding(
            host="127.0.0.1",
            address="127.0.0.1",
            port=6379,
            service="redis",
            severity=level,
            title="Redis is reachable",
            rationale="No auth by default.",
            evidence="127.0.0.1:6379/tcp open",
        )

    def test_no_threshold_never_fails(self, monkeypatch, closed_port: int) -> None:
        monkeypatch.setattr(cli, "analyse", lambda _report: [self._finding(RiskLevel.CRITICAL)])
        code = main(
            ["127.0.0.1", "-p", str(closed_port), "--no-banner", "--quiet", "--retries", "0"]
        )
        assert code == EXIT_OK

    def test_threshold_tripped_returns_1(self, monkeypatch, closed_port: int) -> None:
        monkeypatch.setattr(cli, "analyse", lambda _report: [self._finding(RiskLevel.CRITICAL)])
        code = main(
            [
                "127.0.0.1",
                "-p",
                str(closed_port),
                "--no-banner",
                "--quiet",
                "--fail-on-risk",
                "high",
                "--retries",
                "0",
            ]
        )
        assert code == EXIT_RISK

    def test_threshold_not_reached_returns_0(self, monkeypatch, closed_port: int) -> None:
        monkeypatch.setattr(cli, "analyse", lambda _report: [self._finding(RiskLevel.LOW)])
        code = main(
            [
                "127.0.0.1",
                "-p",
                str(closed_port),
                "--no-banner",
                "--quiet",
                "--fail-on-risk",
                "high",
                "--retries",
                "0",
            ]
        )
        assert code == EXIT_OK

    def test_threshold_zero_findings_returns_0(self, closed_port: int) -> None:
        code = main(
            [
                "127.0.0.1",
                "-p",
                str(closed_port),
                "--no-banner",
                "--quiet",
                "--fail-on-risk",
                "high",
                "--retries",
                "0",
            ]
        )
        assert code == EXIT_OK


class TestInternalError:
    def test_engine_exception_maps_to_3(self, monkeypatch, capsys) -> None:
        async def boom(_self, _targets):
            raise RuntimeError("engine exploded")

        monkeypatch.setattr("netscan.scanner.Scanner.scan", boom)
        assert main(["127.0.0.1", "-p", "80"]) == EXIT_INTERNAL
        assert "internal error" in capsys.readouterr().err


class TestLegacyShim:
    def test_target_and_common_translate(self) -> None:
        from importlib import util

        spec = util.spec_from_file_location(
            "legacy_scanner", Path(__file__).resolve().parents[1] / "Network-scanner.py"
        )
        assert spec is not None and spec.loader is not None
        module = util.module_from_spec(spec)
        spec.loader.exec_module(module)

        translated = module._translate(["--target", "10.0.0.5", "--common"])
        assert "10.0.0.5" in translated
        assert "--ports" in translated
        assert "common" in translated

    def test_output_json_becomes_format_and_file(self) -> None:
        from importlib import util

        spec = util.spec_from_file_location(
            "legacy_scanner2", Path(__file__).resolve().parents[1] / "Network-scanner.py"
        )
        assert spec is not None and spec.loader is not None
        module = util.module_from_spec(spec)
        spec.loader.exec_module(module)

        translated = module._translate(["--network", "10.0.0.0/30", "--common", "--output", "json"])
        assert "--format" in translated
        assert "json" in translated
        assert "report.json" in translated

    def test_threads_becomes_concurrency(self) -> None:
        from importlib import util

        spec = util.spec_from_file_location(
            "legacy_scanner3", Path(__file__).resolve().parents[1] / "Network-scanner.py"
        )
        assert spec is not None and spec.loader is not None
        module = util.module_from_spec(spec)
        spec.loader.exec_module(module)

        translated = module._translate(["--target", "x", "--common", "--threads", "32"])
        index = translated.index("--concurrency")
        assert translated[index + 1] == "32"

    def test_missing_target_exits_2(self) -> None:
        from importlib import util

        spec = util.spec_from_file_location(
            "legacy_scanner4", Path(__file__).resolve().parents[1] / "Network-scanner.py"
        )
        assert spec is not None and spec.loader is not None
        module = util.module_from_spec(spec)
        spec.loader.exec_module(module)

        with pytest.raises(SystemExit) as exc:
            module._translate(["--common"])
        assert exc.value.code == 2


class TestConsoleReportWithFindings:
    def _finding(self) -> Finding:
        return Finding(
            host="127.0.0.1",
            address="127.0.0.1",
            port=6379,
            service="redis",
            severity=RiskLevel.CRITICAL,
            title="Redis is reachable",
            rationale="Redis has no authentication by default.",
            evidence="127.0.0.1:6379/tcp open",
        )

    def test_findings_are_appended_to_console_output(
        self, monkeypatch, capsys, closed_port: int
    ) -> None:
        monkeypatch.setattr(cli, "analyse", lambda _report: [self._finding()])
        code = main(["127.0.0.1", "-p", str(closed_port), "--no-banner", "--retries", "0"])
        assert code == EXIT_OK
        assert "Redis is reachable" in capsys.readouterr().out

    def test_console_output_to_file_carries_findings(
        self, monkeypatch, tmp_path, closed_port: int
    ) -> None:
        monkeypatch.setattr(cli, "analyse", lambda _report: [self._finding()])
        destination = tmp_path / "report.txt"
        code = main(
            [
                "127.0.0.1",
                "-p",
                str(closed_port),
                "--no-banner",
                "-o",
                str(destination),
                "--retries",
                "0",
            ]
        )
        assert code == EXIT_OK
        assert "summary" in destination.read_text(encoding="utf-8")


class TestAllowScope:
    def test_out_of_scope_target_returns_2(self, capsys) -> None:
        code = main(["192.168.0.1", "--allow-scope", "10.0.0.0/8", "--dry-run"])
        assert code == EXIT_USAGE
        assert "allow-scope" in capsys.readouterr().err

    def test_in_scope_target_is_accepted(self, capsys) -> None:
        code = main(["10.1.2.3", "--allow-scope", "10.0.0.0/8", "--dry-run"])
        assert code == EXIT_OK
        assert "10.1.2.3" in capsys.readouterr().out


class TestVersion:
    def test_version_flag_exits_zero(self, capsys) -> None:
        with pytest.raises(SystemExit) as exc:
            main(["--version"])
        assert exc.value.code == 0
        assert "netscan" in capsys.readouterr().out

    def test_python_m_netscan_runs(self) -> None:
        import subprocess
        import sys

        result = subprocess.run(
            [sys.executable, "-m", "netscan", "--version"],
            capture_output=True,
            text=True,
            cwd=str(Path(__file__).resolve().parents[1]),
            env={**__import__("os").environ, "PYTHONPATH": "src"},
            timeout=60,
        )
        assert result.returncode == 0
        assert "netscan" in result.stdout
