"""Report serialisation.

Four formats, one contract: every writer consumes the same :class:`ScanReport`
and produces deterministic bytes for the same input. ``--format json --output
out.json`` and ``--format ndjson --output out.ndjson`` differ only in framing.

Files are written atomically: a temp file in the destination directory, then a
``os.replace``. A scan that is interrupted mid-write leaves the previous report
intact rather than a truncated one.
"""

from __future__ import annotations

import contextlib
import csv
import io
import json
import os
import tempfile
from pathlib import Path
from typing import Callable, Iterable, List, Optional, Sequence, TextIO

from .models import PortResult, ScanReport, iso
from .risk import Finding

__all__ = ["FORMATS", "render", "render_findings_json", "write_report"]

CSV_COLUMNS: Sequence[str] = (
    "host",
    "address",
    "port",
    "protocol",
    "state",
    "service",
    "description",
    "risk",
    "latency_ms",
    "banner",
    "error",
)

FORMATS: Sequence[str] = ("console", "json", "ndjson", "csv", "md")


def _json_dump(obj: object, *, indent: Optional[int] = None) -> str:
    return json.dumps(obj, indent=indent, sort_keys=False, ensure_ascii=False, default=str)


def _render_json(report: ScanReport, findings: Sequence[Finding]) -> str:
    document = report.to_dict()
    document["findings"] = [f.to_dict() for f in findings]
    return _json_dump(document, indent=2) + "\n"


def _render_ndjson(report: ScanReport, findings: Sequence[Finding]) -> str:
    """One JSON object per line: a header, every open port, then findings.

    Closed and filtered ports are omitted from NDJSON on purpose -- streaming
    consumers want the signal, and a /24 with 1000 ports would otherwise produce
    a quarter of a million noise records.
    """
    lines: List[str] = []
    lines.append(_json_dump({"type": "meta", **report.meta.to_dict()}))
    for host in report.hosts:
        if not host.resolved:
            lines.append(
                _json_dump(
                    {
                        "type": "host",
                        "target": host.target,
                        "address": host.address,
                        "resolved": False,
                        "error": host.error,
                    }
                )
            )
            continue
        lines.append(
            _json_dump(
                {
                    "type": "host",
                    "target": host.target,
                    "address": host.address,
                    "family": host.family,
                    "resolved": True,
                    "reverse_dns": host.reverse_dns,
                    "open_ports": [p.port for p in host.open_ports],
                }
            )
        )
        for port in host.open_ports:
            lines.append(_json_dump({"type": "port", **port.to_dict()}))
    for finding in findings:
        lines.append(_json_dump({"type": "finding", **finding.to_dict()}))
    lines.append(
        _json_dump(
            {
                "type": "summary",
                "hosts": len(report.hosts),
                "open_ports": report.open_port_total,
                "highest_risk": report.highest_risk.value,
                "findings": len(findings),
            }
        )
    )
    return "\n".join(lines) + "\n"


def _render_csv(report: ScanReport, findings: Sequence[Finding]) -> str:
    """One row per probed port, including closed and filtered ones.

    ``csv.writer`` handles quoting, so a banner containing a comma, a quote or a
    newline survives the round trip -- the previous implementation wrote CSV with
    ``str.join`` and produced unparseable output for any banner containing a
    comma, which is most of them.
    """
    buffer = io.StringIO()
    writer = csv.writer(buffer, lineterminator="\n", quoting=csv.QUOTE_MINIMAL)
    writer.writerow(CSV_COLUMNS)
    for host in report.hosts:
        if not host.resolved:
            writer.writerow(
                [host.target, "", "", "", "unresolved", "", "", "", "", "", host.error or ""]
            )
            continue
        for port in host.ports:
            writer.writerow(
                [
                    port.host,
                    port.address,
                    port.port,
                    port.protocol,
                    port.state.value,
                    port.service or "",
                    port.description or "",
                    port.risk.value,
                    "" if port.latency_ms is None else f"{port.latency_ms:.3f}",
                    port.banner or "",
                    port.error or "",
                ]
            )
    return buffer.getvalue()


def _render_markdown(report: ScanReport, findings: Sequence[Finding]) -> str:
    meta = report.meta
    lines: List[str] = ["# Network scan report", ""]
    lines.append(f"- **Tool**: {meta.tool} {meta.version}")
    lines.append(f"- **Started**: {iso(meta.started_at)}")
    if meta.finished_at is not None:
        lines.append(f"- **Finished**: {iso(meta.finished_at)}")
    lines.append(f"- **Addresses scanned**: {meta.addresses_scanned}")
    lines.append(f"- **Ports per address**: {meta.ports_per_address}")
    lines.append(f"- **Open ports**: {report.open_port_total}")
    lines.append(f"- **Highest risk**: {report.highest_risk.value.upper()}")
    lines.append("")

    if findings:
        lines.append("## Findings")
        lines.append("")
        lines.append("| Severity | Host | Port | Service | Title |")
        lines.append("| --- | --- | --- | --- | --- |")
        for f in findings:
            lines.append(
                f"| {f.severity.value.upper()} | `{f.address}` | {f.port} | "
                f"{f.service} | {f.title} |"
            )
        lines.append("")
        for f in findings:
            lines.append(f"### {f.severity.value.upper()} — {f.title} (`{f.address}:{f.port}`)")
            lines.append("")
            lines.append(f.rationale)
            lines.append("")
            lines.append(f"```\n{f.evidence}\n```")
            lines.append("")

    lines.append("## Open ports")
    lines.append("")
    for host in report.hosts:
        if not host.resolved:
            lines.append(f"### `{host.target}` — unresolvable")
            lines.append("")
            lines.append(f"{host.error or 'resolution failed'}")
            lines.append("")
            continue
        suffix = f" ({host.reverse_dns})" if host.reverse_dns else ""
        lines.append(f"### `{host.address}` — {host.target}{suffix}")
        lines.append("")
        if not host.open_ports:
            lines.append("No open TCP ports in the scanned range.")
            lines.append("")
            continue
        lines.append("| Port | Service | Risk | Banner |")
        lines.append("| --- | --- | --- | --- |")
        for port in host.open_ports:
            banner = (port.banner or "").replace("|", "\\|")[:120]
            lines.append(
                f"| {port.port}/tcp | {port.service or 'unknown'} | {port.risk.value} | {banner} |"
            )
        lines.append("")
    return "\n".join(lines) + "\n"


_RENDERERS: dict[str, Callable[[ScanReport, Sequence[Finding]], str]] = {
    "json": _render_json,
    "ndjson": _render_ndjson,
    "csv": _render_csv,
    "md": _render_markdown,
}


def render(
    report: ScanReport,
    findings: Sequence[Finding],
    fmt: str,
) -> str:
    """Render a report to a string. ``console`` is handled by :mod:`netscan.console`."""
    if fmt == "console":
        raise ValueError("console rendering is handled by netscan.console")
    try:
        renderer = _RENDERERS[fmt]
    except KeyError:
        raise ValueError(f"unknown format {fmt!r}; choose from {', '.join(FORMATS)}") from None
    return renderer(report, findings)


def render_findings_json(findings: Sequence[Finding]) -> str:
    return _json_dump([f.to_dict() for f in findings], indent=2) + "\n"


def write_report(
    report: ScanReport,
    findings: Sequence[Finding],
    *,
    fmt: str,
    output: Optional[str] = None,
    stream: Optional[TextIO] = None,
) -> Optional[str]:
    """Write ``report`` to ``output`` (atomically) or to ``stream``.

    Returns the rendered text when it went to a stream, otherwise ``None`` -- the
    caller does not need to hold a potentially large string after a file write.
    """
    if fmt == "console":
        raise ValueError("console rendering is handled by netscan.console")
    text = render(report, findings, fmt)

    if output is None or output == "-":
        target = stream
        if target is None:
            raise ValueError("write_report needs either output or stream")
        target.write(text)
        target.flush()
        return text

    path = Path(output).expanduser()
    if path.parent and not path.parent.exists():
        path.parent.mkdir(parents=True, exist_ok=True)

    directory = path.parent if str(path.parent) else Path(".")
    # Opened without a context manager on purpose: the file must survive the
    # `with` block so that os.replace can move it into place afterwards.
    handle = tempfile.NamedTemporaryFile(  # noqa: SIM115
        mode="w",
        encoding="utf-8",
        newline="",
        dir=str(directory),
        prefix=f".{path.name}.",
        suffix=".tmp",
        delete=False,
    )
    try:
        with handle:
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(handle.name, path)
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(handle.name)
        raise
    return None


def ports_as_rows(ports: Iterable[PortResult]) -> List[List[object]]:
    """Flatten ports into CSV rows. Exposed for tests and downstream tooling."""
    return [
        [
            p.host,
            p.address,
            p.port,
            p.protocol,
            p.state.value,
            p.service or "",
            p.description or "",
            p.risk.value,
            "" if p.latency_ms is None else f"{p.latency_ms:.3f}",
            p.banner or "",
            p.error or "",
        ]
        for p in ports
    ]
