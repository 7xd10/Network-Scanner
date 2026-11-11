#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Compatibility entry point for the pre-2.0 command line.

This file exists so that an existing invocation such as::

    python Network-scanner.py --target 10.0.0.5 --common --output json

keeps working after the 2.0 restructure. It translates the legacy flags onto
``netscan`` and hands over. Every option below maps onto a real feature now --
``--banner`` and ``--quiet`` used to be parsed and then ignored, and
``--output csv`` used to write JSON regardless.

New work should call the packaged CLI::

    netscan 10.0.0.5 -p common -f json -o report.json

Exit codes are the packaged ones; see ``netscan.cli``.
"""

from __future__ import annotations

import sys
import warnings
from pathlib import Path

_SRC = Path(__file__).resolve().parent / "src"
if _SRC.is_dir() and str(_SRC) not in sys.path:
    # Running the shim from a checkout without `pip install -e .` must still work.
    sys.path.insert(0, str(_SRC))

_USAGE = """\
usage: Network-scanner.py --target HOST [--common | --critical | --all-ports | --ports SPEC]
                          [--threads N] [--timeout S] [--banner] [--quiet]
                          [--output console|json|csv]

This is the legacy front end. Prefer:

    netscan HOST [-p SPEC] [-c N] [-t S] [--no-banner] [-q] [-f console|json|csv]
"""


def _translate(argv: list[str]) -> list[str]:
    """Map legacy flags onto the packaged CLI. Returns argv for ``netscan.cli.main``."""
    out: list[str] = []
    targets: list[str] = []
    ports: str | None = None
    concurrency: str | None = None
    verbose_quiet = False
    wants_help = False

    index = 0
    while index < len(argv):
        token = argv[index]
        nxt = argv[index + 1] if index + 1 < len(argv) else None

        if token in {"-h", "--help"}:
            wants_help = True
            index += 1
            continue

        if token == "--target" and nxt is not None:
            targets.append(nxt)
            index += 2
            continue
        if token == "--network" and nxt is not None:
            targets.append(nxt)
            index += 2
            continue
        if token == "--targets" and nxt is not None:
            targets.append("@" + nxt)
            index += 2
            continue
        if token == "--ports" and nxt is not None:
            ports = nxt
            index += 2
            continue
        if token == "--common":
            ports = ports or "common"
            index += 1
            continue
        if token == "--all-ports":
            ports = "1-65535"
            index += 1
            continue
        if token == "--critical":
            ports = ports or "critical"
            index += 1
            continue
        if token == "--threads" and nxt is not None:
            concurrency = nxt
            index += 2
            continue
        if token == "--timeout" and nxt is not None:
            out.extend(["--timeout", nxt])
            index += 2
            continue
        if token == "--banner":
            # Banners are on by default in 2.0; the flag is now a no-op that
            # documents intent rather than a switch that does nothing.
            index += 1
            continue
        if token == "--quiet":
            out.append("--quiet")
            verbose_quiet = True
            index += 1
            continue
        if token == "--output" and nxt is not None:
            # Legacy: --output chose the *format* and always wrote JSON to disk.
            fmt = {"console": "console", "json": "json", "csv": "csv"}.get(nxt, "console")
            out.extend(["--format", fmt])
            if fmt != "console" and "--output-file" not in out:
                out.extend(["--output", f"report.{fmt}"])
            index += 2
            continue
        if token in {"--output-file", "-o"} and nxt is not None:
            out.extend(["--output", nxt])
            index += 2
            continue

        if token.startswith("-"):
            print(f"Network-scanner.py: unrecognised legacy option {token!r}", file=sys.stderr)
            print(_USAGE, file=sys.stderr)
            raise SystemExit(2)

        targets.append(token)
        index += 1

    if wants_help:
        print(_USAGE, file=sys.stderr)
        raise SystemExit(0)

    if not targets:
        print("Network-scanner.py: one of --target, --network or --targets is required", file=sys.stderr)
        print(_USAGE, file=sys.stderr)
        raise SystemExit(2)

    translated = list(out)
    if ports:
        translated.extend(["--ports", ports])
    if concurrency:
        translated.extend(["--concurrency", concurrency])
    if not verbose_quiet:
        print(
            "Network-scanner.py: this entry point is deprecated; use 'netscan'.",
            file=sys.stderr,
        )
    translated.extend(targets)
    return translated


def main(argv: list[str] | None = None) -> int:
    from netscan.cli import main as cli_main

    # Warned here rather than at import so that importing this module for
    # inspection stays silent; only an actual run is deprecated.
    warnings.warn(
        "Network-scanner.py is a compatibility shim; use the 'netscan' command "
        "instead (pip install -e . then: netscan -h).",
        DeprecationWarning,
        stacklevel=2,
    )

    args = list(sys.argv[1:] if argv is None else argv)
    return cli_main(_translate(args))


if __name__ == "__main__":
    raise SystemExit(main())
