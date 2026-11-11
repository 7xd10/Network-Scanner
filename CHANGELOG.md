# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.0.0] — 2026-11-11

The rewrite. `Network-scanner.py` was a single 606-line script with a threading
queue, no tests, and no packaging. This release replaces it with a typed,
tested, documented package while keeping a compatibility shim for the old flags.

### Added

- Asyncio engine with a fixed-size worker pool. Live task count is bounded by
  `--concurrency` regardless of how many addresses or ports were requested.
- `FILTERED` as a distinct port state. A refused connection is `CLOSED`; a
  timeout is `FILTERED`. The previous version mapped both to "closed".
- IPv6 support end to end: literals, CIDR, and AAAA resolution.
- `--profile`/`-p` presets (`common`, `critical`, `web`, `db`, `remote`, `all`)
  plus service-name resolution (`-p ssh,https`).
- Real top-100 port list. `--common` used to mean `list(PORT_SERVICES)[:100]`,
  which returned ports 1–119 and missed 3306, 3389 and 5900 entirely.
- Service-specific banner probes and per-service banner timeouts.
- `--rate-limit` with a monotonic token bucket.
- Output formats: `console`, `json`, `ndjson`, `csv`, `md`. All four file
  formats are implemented; only console ever worked before.
- Atomic report writes (temp file plus `os.replace`).
- Exposure analysis with a rationale per finding, `--fail-on-risk` threshold,
  and severity-ordered output.
- `--dry-run` to expand targets and ports without probing.
- `--allow-scope` to restrict expansion to declared CIDRs.
- `--max-hosts` ceiling and a hard `MAX_ADDRESSES` cap so a typo like
  `10.0.0.0/8` fails instead of starting 16 million probes.
- `pyproject.toml`, typed package with `py.typed`, `pytest` suite (244 tests,
  92% branch coverage), GitHub Actions matrix, pre-commit hooks, Dockerfile.
- Documented, contractual exit codes.

### Changed

- Logging is configured by the CLI, not at import time. Importing the package
  no longer creates `port_scanner.log` in the working directory.
- `--banner` and `--quiet` now do something. Both were parsed and ignored.
- Blanket `except:` in host discovery replaced with typed handlers; a failed
  resolution is recorded on the host, not raised.
- `ScanResult.timestamp` is a timezone-aware `datetime`, not an untyped `None`.
- Results are collected per host. The old code searched a flat global list for
  every port, which is O(n²) and returned the wrong host when a host repeated.
- Exit code 1 no longer means "a risky port was found". That behaviour is now
  opt-in via `--fail-on-risk`; unhandled failures exit 3.

### Fixed

- Duplicate `PORT_SERVICES` keys silently overwrote each other. 80, 8000, 8080,
  8888, 21, 23, 445, 3389 and 5900 each collapsed to a single entry.
- CSV output was written with `",".join()` and broke on any banner containing a
  comma, a quote or a newline.
- Banner text containing ANSI escapes or NUL bytes corrupted the terminal and
  broke CSV quoting.
- `--output csv` wrote JSON regardless of the flag.
- The `--output json` path always wrote `report.json` in the current directory,
  ignoring where the user pointed it.
- Banner typo: the console header read "Network Sccanner".
- `socket.connect_ex` was compared against `0` but its timeout path never
  raises, so slow hosts were reported as closed rather than filtered.
- Threads were joined without a bound; a hung probe held the process forever.

### Deprecated

- `Network-scanner.py` is now a shim that translates the legacy flags onto the
  packaged CLI and prints a deprecation notice. It still works; it will not
  gain features.

## [1.0.0] — 2025

Initial single-file scanner: threaded connect scan, hard-coded service table,
console and JSON output.
