# Contributing

## Development setup

```bash
git clone https://github.com/7xd10/Network-Scanner.git
cd Network-Scanner
python -m venv .venv
. .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
pre-commit install
```

The package has **zero runtime dependencies**. Everything under `src/netscan`
must run on a bare CPython 3.9+ install with no third-party imports. The `dev`
extra is for tooling only.

## Before opening a pull request

```bash
make check     # ruff + mypy + pytest
```

or individually:

```bash
ruff check src tests
mypy src/netscan
pytest -q
```

All three must pass. CI runs the suite on Python 3.9, 3.10, 3.11, 3.12 and 3.13
on Ubuntu, macOS and Windows; a change that passes locally on one platform and
fails on another will be caught before merge.

## What gets merged

- **A test for every behaviour change.** Bug fixes get a test that fails before
  the fix. New features get tests for the happy path and the error path.
- **No new runtime dependencies.** If you believe one is unavoidable, open an
  issue first and explain what the standard library cannot do.
- **Typed function signatures.** `mypy --strict` is enforced on `src/netscan`.
  `Any` needs a justification in the docstring.
- **Correct state semantics.** A timeout is `FILTERED`, not `CLOSED`. A refused
  connection is `CLOSED`. Do not collapse them, and do not add a code path that
  guesses which one a silent drop "really" was — the scanner cannot know.
- **Honest findings.** `netscan.risk` describes exposure that the scanner
  directly observed. Do not add a rule that claims a service is exploitable
  from a port number alone.

## Style

- Line length 100, enforced by ruff.
- `from __future__ import annotations` in every module; the package targets 3.9
  so `typing.List`/`Optional` are used deliberately in runtime positions.
- Comments explain *why*. A comment that restates the next line is noise.
- Docstrings on every public module, class and function.
- Error messages name the offending value and what was expected.

## Reporting a bug

Open an issue with:

1. `netscan --version` and your Python version.
2. The exact command line (redact anything sensitive).
3. What you expected and what happened.
4. The relevant part of `-vv --log-file /tmp/netscan.log` output.

For a security issue in the scanner itself, see [SECURITY.md](SECURITY.md)
instead of opening a public issue.

## Scope

`netscan` is a TCP port scanner. It does not send application-layer exploits.
Pull requests that add vulnerability exploitation are out of scope; pull
requests that improve detection accuracy, state classification, performance,
reporting or compatibility are very much in scope.
