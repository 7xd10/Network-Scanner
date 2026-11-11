"""Command line interface.

Exit codes are contractual and documented in the README:

====  ==========================================================================
0     The scan ran to completion. Findings, if any, were reported.
1     The scan ran to completion and ``--fail-on-risk`` was tripped.
2     Usage or input error: bad target, bad port spec, unreadable file.
3     Internal error: an unexpected exception escaped the engine.
130   Interrupted by SIGINT (Ctrl-C).
====  ==========================================================================

The previous implementation returned 1 whenever a risky port was found, which
made it impossible to tell "the scan failed" from "the scan worked and found
something". That is why ``--fail-on-risk`` exists and why it is off by default.
"""

from __future__ import annotations

import argparse
import asyncio
import logging
import sys
from typing import Optional, Sequence

from . import __version__
from .console import Style, render_findings, render_report, render_result, supports_colour
from .models import RiskLevel, ScanReport, TargetError
from .report import FORMATS, write_report
from .risk import analyse
from .scanner import Scanner, ScanOptions
from .targets import DEFAULT_MAX_ADDRESSES, MAX_ADDRESSES, parse_port_spec, parse_targets

__all__ = ["build_parser", "main"]

_LOG = logging.getLogger("netscan")

EXIT_OK = 0
EXIT_RISK = 1
EXIT_USAGE = 2
EXIT_INTERNAL = 3
EXIT_INTERRUPT = 130

_RISK_CHOICES = ("none", "low", "medium", "high", "critical")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="netscan",
        description=(
            "Asynchronous TCP port scanner with service detection, banner grabbing "
            "and exposure classification."
        ),
        epilog=(
            "examples:\n"
            "  netscan 192.168.1.10\n"
            "  netscan 10.0.0.0/24 -p 22,80,443 --stream\n"
            "  netscan example.com -p common -f json -o report.json\n"
            "  netscan @targets.txt -p 1-1024 --fail-on-risk high\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "targets",
        nargs="*",
        help=(
            "addresses, CIDRs, ranges, hostnames, @files, or comma-separated mixes "
            "(e.g. 10.0.0.5 10.0.1.0/24 example.com @list.txt)"
        ),
    )
    parser.add_argument(
        "-p",
        "--ports",
        default="common",
        metavar="SPEC",
        help=(
            "ports to probe: 22,80,443 | 1-1024 | common | critical | web | db | "
            "remote | all | a service name (default: common)"
        ),
    )
    parser.add_argument(
        "-c",
        "--concurrency",
        type=int,
        default=500,
        metavar="N",
        help="maximum simultaneous probes (default: 500)",
    )
    parser.add_argument(
        "-t",
        "--timeout",
        type=float,
        default=2.0,
        metavar="SECONDS",
        help="per-probe connect timeout (default: 2.0)",
    )
    parser.add_argument(
        "--retries",
        type=int,
        default=1,
        metavar="N",
        help="retries for filtered probes; refused connections are never retried (default: 1)",
    )
    parser.add_argument(
        "--banner",
        dest="banner",
        action="store_true",
        default=True,
        help="read service banners from open ports (default)",
    )
    parser.add_argument(
        "--no-banner",
        dest="banner",
        action="store_false",
        help="skip banner grabbing; noticeably faster",
    )
    parser.add_argument(
        "--banner-bytes",
        type=int,
        default=1024,
        metavar="N",
        help="maximum bytes read per banner (default: 1024)",
    )
    parser.add_argument(
        "--banner-timeout",
        type=float,
        default=1.5,
        metavar="SECONDS",
        help="how long to wait for a banner after connecting (default: 1.5)",
    )
    parser.add_argument(
        "--reverse-dns",
        action="store_true",
        help="resolve PTR records for each address",
    )
    parser.add_argument(
        "--resolve-timeout",
        type=float,
        default=5.0,
        metavar="SECONDS",
        help="DNS resolution timeout per name (default: 5.0)",
    )
    parser.add_argument(
        "--rate-limit",
        type=float,
        default=0.0,
        metavar="PER_SECOND",
        help="cap total probes per second; 0 disables pacing (default: 0)",
    )
    parser.add_argument(
        "-f",
        "--format",
        dest="fmt",
        choices=("console", *FORMATS[1:]),
        default="console",
        help="output format (default: console)",
    )
    parser.add_argument(
        "-o",
        "--output",
        metavar="PATH",
        help="write the report to PATH atomically; '-' means stdout",
    )
    parser.add_argument(
        "--stream",
        action="store_true",
        help="print open ports as they are found (console mode only)",
    )
    parser.add_argument(
        "--show-closed",
        action="store_true",
        help="also list closed and filtered ports in the console report",
    )
    parser.add_argument(
        "--max-hosts",
        type=int,
        default=DEFAULT_MAX_ADDRESSES,
        metavar="N",
        help=(
            f"refuse to expand more than N addresses, hard ceiling {MAX_ADDRESSES} "
            f"(default: {DEFAULT_MAX_ADDRESSES})"
        ),
    )
    parser.add_argument(
        "--allow-scope",
        action="append",
        default=[],
        metavar="CIDR",
        help="only scan addresses inside this CIDR; repeatable",
    )
    parser.add_argument(
        "--fail-on-risk",
        choices=_RISK_CHOICES,
        default="none",
        metavar="LEVEL",
        help=(
            "exit 1 when a finding at or above LEVEL is present "
            f"({', '.join(_RISK_CHOICES)}; default: none)"
        ),
    )
    parser.add_argument(
        "-q",
        "--quiet",
        action="store_true",
        help="suppress the console report; findings still drive the exit code",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="count",
        default=0,
        help="increase log verbosity; repeat for debug",
    )
    parser.add_argument(
        "--log-file",
        metavar="PATH",
        help="write logs to PATH instead of stderr",
    )
    parser.add_argument(
        "--no-colour",
        action="store_true",
        help="disable ANSI colour even on a TTY",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="expand targets and ports, print the plan, then exit without probing",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"netscan {__version__}",
    )
    return parser


def _configure_logging(verbose: int, log_file: Optional[str]) -> None:
    level = logging.WARNING
    if verbose == 1:
        level = logging.INFO
    elif verbose >= 2:
        level = logging.DEBUG
    handler: logging.Handler
    if log_file:
        handler = logging.FileHandler(log_file, encoding="utf-8")
    else:
        handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)-7s %(name)s: %(message)s"))
    root = logging.getLogger("netscan")
    root.handlers.clear()
    root.addHandler(handler)
    root.setLevel(level)
    root.propagate = False


def _severity_at_or_above(findings_risk: RiskLevel, threshold: RiskLevel) -> bool:
    return findings_risk.rank >= threshold.rank and threshold is not RiskLevel.NONE


def main(argv: Optional[Sequence[str]] = None) -> int:
    """Entry point. Returns a process exit code; never calls ``sys.exit`` itself."""
    args_list = list(sys.argv[1:] if argv is None else argv)
    parser = build_parser()
    args = parser.parse_args(args_list)

    _configure_logging(args.verbose, args.log_file)

    if not args.targets:
        parser.print_usage(sys.stderr)
        print("netscan: error: at least one target is required", file=sys.stderr)
        return EXIT_USAGE

    try:
        ports = parse_port_spec(args.ports)
    except TargetError as exc:
        print(f"netscan: invalid --ports: {exc}", file=sys.stderr)
        return EXIT_USAGE

    if not 1 <= args.concurrency <= 100_000:
        print("netscan: --concurrency must be between 1 and 100000", file=sys.stderr)
        return EXIT_USAGE
    if args.max_hosts < 1:
        print("netscan: --max-hosts must be >= 1", file=sys.stderr)
        return EXIT_USAGE

    try:
        targets = parse_targets(
            args.targets,
            max_addresses=min(args.max_hosts, MAX_ADDRESSES),
            allow_scope=args.allow_scope,
        )
    except TargetError as exc:
        print(f"netscan: invalid target: {exc}", file=sys.stderr)
        return EXIT_USAGE

    if args.dry_run:
        print(f"targets   : {len(targets)} address(es)")
        for target in targets[:20]:
            print(f"  {target}")
        if len(targets) > 20:
            print(f"  ... {len(targets) - 20} more")
        print(f"ports     : {len(ports)} ({_describe_ports(ports)})")
        print(f"probes    : {len(targets) * len(ports)}")
        return EXIT_OK

    options = ScanOptions(
        ports=ports,
        concurrency=args.concurrency,
        timeout=args.timeout,
        retries=args.retries,
        banner_grab=args.banner,
        banner_bytes=args.banner_bytes,
        banner_timeout=args.banner_timeout,
        reverse_dns=args.reverse_dns,
        resolve_timeout=args.resolve_timeout,
        rate_limit=args.rate_limit,
        argv=args_list,
    )

    style = Style(enabled=supports_colour() and not args.no_colour and not args.quiet)
    stream_wanted = args.stream and args.fmt == "console" and not args.quiet

    def on_result(result: object) -> None:
        if not stream_wanted:
            return
        line = render_result(result, style=style)  # type: ignore[arg-type]
        if line:
            print(line, flush=True)

    scanner = Scanner(options, on_result=on_result)

    try:
        report = asyncio.run(scanner.scan(targets))
    except KeyboardInterrupt:
        print("netscan: interrupted", file=sys.stderr)
        return EXIT_INTERRUPT
    except Exception as exc:
        _LOG.exception("scan failed")
        print(f"netscan: internal error: {exc}", file=sys.stderr)
        return EXIT_INTERNAL

    findings = analyse(report)

    if not args.quiet:
        _emit(report, findings, args, style)

    threshold = RiskLevel(args.fail_on_risk)
    if threshold is not RiskLevel.NONE:
        top = _highest_severity(findings)
        if _severity_at_or_above(top, threshold):
            _LOG.info(
                "failing because findings reach %s (threshold %s)",
                top.value,
                threshold.value,
            )
            return EXIT_RISK
    return EXIT_OK


def _emit(
    report: ScanReport,
    findings: Sequence[object],
    args: argparse.Namespace,
    style: Style,
) -> None:
    typed_findings = [f for f in findings if hasattr(f, "severity")]

    if args.fmt == "console":
        text = render_report(
            report,
            typed_findings,  # type: ignore[arg-type]
            style=style,
            show_closed=args.show_closed,
        )
        if args.output:
            with open(args.output, "w", encoding="utf-8", newline="") as handle:
                handle.write(text)
        else:
            sys.stdout.write(text)
            if findings:
                sys.stdout.write("\n")
                sys.stdout.write(render_findings(typed_findings, style=style))  # type: ignore[arg-type]
        return

    write_report(
        report,
        typed_findings,  # type: ignore[arg-type]
        fmt=args.fmt,
        output=args.output,
        stream=sys.stdout,
    )


def _highest_severity(findings: Sequence[object]) -> RiskLevel:
    highest = RiskLevel.NONE
    for finding in findings:
        level = getattr(finding, "severity", RiskLevel.NONE)
        if isinstance(level, RiskLevel) and level.rank > highest.rank:
            highest = level
    return highest


def _describe_ports(ports: Sequence[int]) -> str:
    if len(ports) <= 8:
        return ", ".join(str(p) for p in ports)
    return f"{ports[0]}..{ports[-1]}"


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
