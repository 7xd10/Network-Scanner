"""Terminal rendering.

Colour is opt-in: enabled only when stdout is a TTY, ``TERM`` is not ``dumb``,
and ``NO_COLOR`` is unset. Panes are width-aware so a banner never wraps and
breaks the table, and every non-printable character is stripped before printing
because service banners are attacker-controlled bytes.
"""

from __future__ import annotations

import os
import shutil
import sys
from dataclasses import dataclass
from typing import Iterable, List, Optional, Sequence, TextIO

from .models import PortResult, PortState, RiskLevel, ScanReport, iso
from .risk import Finding

__all__ = ["Style", "render_findings", "render_report", "render_result", "supports_colour"]


@dataclass(frozen=True)
class Style:
    enabled: bool

    def _wrap(self, code: str, text: str) -> str:
        if not self.enabled:
            return text
        return f"\033[{code}m{text}\033[0m"

    def bold(self, text: str) -> str:
        return self._wrap("1", text)

    def dim(self, text: str) -> str:
        return self._wrap("2", text)

    def red(self, text: str) -> str:
        return self._wrap("31", text)

    def green(self, text: str) -> str:
        return self._wrap("32", text)

    def yellow(self, text: str) -> str:
        return self._wrap("33", text)

    def blue(self, text: str) -> str:
        return self._wrap("34", text)

    def magenta(self, text: str) -> str:
        return self._wrap("35", text)

    def cyan(self, text: str) -> str:
        return self._wrap("36", text)

    def risk(self, level: RiskLevel) -> str:
        labels = {
            RiskLevel.CRITICAL: (self.red, "CRITICAL"),
            RiskLevel.HIGH: (self.magenta, "HIGH"),
            RiskLevel.MEDIUM: (self.yellow, "MEDIUM"),
            RiskLevel.LOW: (self.cyan, "LOW"),
            RiskLevel.NONE: (self.dim, "NONE"),
        }
        paint, label = labels[level]
        return paint(label)

    def state(self, state: PortState) -> str:
        labels = {
            PortState.OPEN: (self.green, "open"),
            PortState.CLOSED: (self.dim, "closed"),
            PortState.FILTERED: (self.yellow, "filtered"),
            PortState.ERROR: (self.red, "error"),
        }
        paint, label = labels[state]
        return paint(label)


def supports_colour(stream: Optional[TextIO] = None) -> bool:
    target = stream if stream is not None else sys.stdout
    if os.environ.get("NO_COLOR"):
        return False
    if os.environ.get("TERM", "") == "dumb":
        return False
    if os.environ.get("FORCE_COLOR"):
        return True
    try:
        return bool(target.isatty())
    except (AttributeError, ValueError):
        return False


def _width(default: int = 120) -> int:
    try:
        return max(60, shutil.get_terminal_size((default, 24)).columns)
    except OSError:
        return default


def _clip(text: str, limit: int) -> str:
    if limit <= 0:
        return ""
    if len(text) <= limit:
        return text
    if limit <= 1:
        return text[:limit]
    return text[: limit - 1] + "\u2026"


_HEADER = r"""
 _   _      _   ____
| \ | | ___| |_/ ___|  ___ __ _ _ __
|  \| |/ _ \ __\___ \ / __/ _` | '_ \
| |\  |  __/ |_ ___) | (_| (_| | | | |
|_| \_|\___|\__|____/ \___\__,_|_| |_|
"""


def render_report(
    report: ScanReport,
    findings: Sequence[Finding],
    *,
    style: Optional[Style] = None,
    show_closed: bool = False,
    width: Optional[int] = None,
) -> str:
    """Full human-readable report. Pure function; returns a string."""
    s = style if style is not None else Style(supports_colour())
    columns = width if width is not None else _width()

    lines: List[str] = []
    meta = report.meta
    lines.append(s.cyan(_HEADER.rstrip("\n")))
    lines.append(
        s.dim(
            f"targets {meta.addresses_scanned} | ports/address {meta.ports_per_address} "
            f"| concurrency {meta.concurrency} | timeout {meta.timeout_s}s "
            f"| retries {meta.retries}"
        )
    )
    if meta.started_at is not None:
        # iso() is the one timestamp formatter in the package; JSON, Markdown and
        # the console must agree or two reports of the same scan diff.
        lines.append(s.dim(f"started {iso(meta.started_at)}"))
    lines.append("")

    for host in report.hosts:
        if not host.resolved:
            lines.append(s.bold(f"[{host.target}]") + " " + s.red("unresolved"))
            lines.append("  " + s.dim(host.error or "resolution failed"))
            lines.append("")
            continue

        suffix = f" ({host.reverse_dns})" if host.reverse_dns else ""
        lines.append(
            s.bold(f"[{host.address}]")
            + s.dim(f" {host.target}{suffix} {host.family}")
            + s.dim(f"  {len(host.open_ports)} open / {len(host.ports)} probed")
        )
        open_ports = list(host.open_ports)
        if not open_ports:
            lines.append("  " + s.dim("no open TCP ports in the scanned range"))
            lines.append("")
            continue

        banner_budget = max(20, columns - 52)
        lines.append("  " + s.dim(f"{'PORT':<7} {'SERVICE':<18} {'RISK':<9} BANNER"))
        for port in open_ports:
            service = _clip(port.service or "unknown", 17)
            risk_text = s.risk(port.risk)
            pad = " " * max(1, 9 - len(port.risk.value))
            banner = _clip(port.banner or "", banner_budget)
            lines.append(
                f"  {str(port.port) + '/tcp':<7} {service:<18} {risk_text}{pad} "
                + (s.dim(banner) if banner else "")
            )
        lines.append("")

        if show_closed:
            others = [p for p in host.ports if not p.is_open]
            if others:
                lines.append("  " + s.dim("not open:"))
                for port in others:
                    lines.append(
                        f"    {str(port.port) + '/tcp':<7} {s.state(port.state)}"
                        + (s.dim(f" ({port.error})") if port.error else "")
                    )
                lines.append("")

    lines.append(s.bold("summary"))
    lines.append(
        f"  hosts {len(report.hosts)} | open ports {report.open_port_total} | "
        f"highest risk {s.risk(report.highest_risk)}"
    )

    if findings:
        counts: dict[str, int] = {}
        for finding in findings:
            counts[finding.severity.value] = counts.get(finding.severity.value, 0) + 1
        breakdown = ", ".join(
            f"{counts[level]} {level}"
            for level in ("critical", "high", "medium", "low")
            if counts.get(level)
        )
        lines.append(f"  findings {len(findings)} ({breakdown})")
    else:
        lines.append("  " + s.dim("no exposure findings"))

    return "\n".join(lines) + "\n"


def render_findings(
    findings: Sequence[Finding],
    *,
    style: Optional[Style] = None,
    width: Optional[int] = None,
) -> str:
    s = style if style is not None else Style(supports_colour())
    columns = width if width is not None else _width()
    if not findings:
        return s.dim("no exposure findings") + "\n"

    lines: List[str] = [s.bold(f"{len(findings)} findings"), ""]
    for finding in findings:
        head = (
            s.risk(finding.severity)
            + " "
            + s.bold(f"{finding.address}:{finding.port}")
            + " "
            + s.cyan(finding.service)
        )
        lines.append(head)
        lines.append("  " + _clip(finding.title, columns - 2))
        for chunk in _wrap_text(finding.rationale, columns - 4):
            lines.append("  " + s.dim(chunk))
        lines.append("  " + s.dim(_clip(finding.evidence, columns - 2)))
        lines.append("")
    return "\n".join(lines)


def render_result(
    result: PortResult,
    *,
    style: Optional[Style] = None,
) -> str:
    """One line for one port, used by ``--stream``."""
    s = style if style is not None else Style(supports_colour())
    if result.state is PortState.OPEN:
        label = s.green("open    ")
    elif result.state is PortState.CLOSED:
        return ""
    elif result.state is PortState.FILTERED:
        label = s.yellow("filtered")
    else:
        label = s.red("error   ")

    service = (result.service or "").ljust(18)
    banner = f" {s.dim(_clip(result.banner or '', 100))}" if result.banner else ""
    risk = ""
    if result.state is PortState.OPEN and result.risk is not RiskLevel.NONE:
        risk = f" {s.risk(result.risk)}"
    return f"{result.address}:{result.port:<5} {label} {service}{risk}{banner}"


def _wrap_text(text: str, width: int) -> List[str]:
    words = text.split()
    if not words:
        return []
    lines: List[str] = []
    current: List[str] = []
    length = 0
    for word in words:
        addition = len(word) + (1 if current else 0)
        if length + addition > width and current:
            lines.append(" ".join(current))
            current = [word]
            length = len(word)
        else:
            current.append(word)
            length += addition
    if current:
        lines.append(" ".join(current))
    return lines


def iter_open(results: Iterable[PortResult]) -> Iterable[PortResult]:
    for result in results:
        if result.is_open:
            yield result
