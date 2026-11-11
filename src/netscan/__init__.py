"""netscan -- asynchronous TCP port scanner.

Public surface:

* :class:`netscan.scanner.Scanner` / :func:`netscan.scanner.scan` -- the engine.
* :class:`netscan.models.ScanReport` -- the result document.
* :func:`netscan.risk.analyse` -- exposure findings.
* :func:`netscan.report.write_report` -- serialisation.
* :func:`netscan.cli.main` -- the command line.

The package has no runtime dependencies outside the standard library.
"""

from __future__ import annotations

__all__ = [
    "HostResult",
    "PortResult",
    "PortState",
    "RiskLevel",
    "ScanOptions",
    "ScanReport",
    "Scanner",
    "__version__",
    "analyse",
    "parse_port_spec",
    "parse_targets",
]

__version__ = "2.0.0"

from .models import HostResult, PortResult, PortState, RiskLevel, ScanReport
from .risk import analyse
from .scanner import Scanner, ScanOptions
from .targets import parse_port_spec, parse_targets
