# netscan

**Asynchronous TCP port scanner with service detection, banner grabbing and exposure classification.**

[![CI](https://github.com/7xd10/Network-Scanner/actions/workflows/ci.yml/badge.svg)](https://github.com/7xd10/Network-Scanner/actions/workflows/ci.yml)
[![Python](https://img.shields.io/badge/python-3.9%20%7C%203.10%20%7C%203.11%20%7C%203.12%20%7C%203.13-blue)](pyproject.toml)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![Typed](https://img.shields.io/badge/typed-py.typed-blue)](src/netscan/py.typed)
[![Coverage](https://img.shields.io/badge/coverage-92%25%20branch-brightgreen)](tests)

`netscan` opens TCP connections, records what answered, reads the service banner
when the service offers one, and tells you which of those listeners are usually
worth a human's attention. It sends no exploit payloads and makes no claim that
anything it sees is exploitable — it tells you what is listening and why that
matters.

Zero runtime dependencies. Pure standard library, Python 3.9 and later.

```
$ netscan 10.0.0.5 -p common

 _   _      _   ____
| \ | | ___| |_/ ___|  ___ __ _ _ __
|  \| |/ _ \ __\___ \ / __/ _` | '_ \
| |\  |  __/ |_ ___) | (_| (_| | | | |
|_| \_|\___|\__|____/ \___\__,_|_| |_|

targets 1 | ports/address 100 | concurrency 500 | timeout 2.0s | retries 1
started 2026-11-11T09:14:02.881Z

[10.0.0.5] 10.0.0.5 IPv4  7 open / 100 probed
  PORT    SERVICE            RISK      BANNER
  22/tcp  ssh                NONE      SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13
  80/tcp  http               LOW       HTTP/1.1 200 OK
  443/tcp https              LOW
  3306/tcp mysql             CRITICAL  5.7.44-log
  3389/tcp ms-wbt-server     CRITICAL
  6379/tcp redis             CRITICAL  -ERR wrong number of arguments
  8080/tcp http-proxy        MEDIUM    HTTP/1.1 200 OK

summary
  hosts 1 | open ports 7 | highest risk CRITICAL
  findings 4 (3 critical, 0 high, 1 medium)
```

---

## Contents

- [Why this exists](#why-this-exists)
- [Install](#install)
- [Quickstart](#quickstart)
- [Targets](#targets)
- [Port selection](#port-selection)
- [Output formats](#output-formats)
- [Exit codes](#exit-codes)
- [Every flag](#every-flag)
- [Library use](#library-use)
- [Measured performance](#measured-performance)
- [How the state machine works](#how-the-state-machine-works)
- [Exposure findings](#exposure-findings)
- [Architecture](#architecture)
- [Limitations](#limitations)
- [Legal](#legal)

---

## Why this exists

This started as a 606-line single-file script. It scanned, sort of, and it had
seventeen distinct defects — several of which silently produced wrong results
rather than crashing, which is worse. The full inventory is in
[CHANGELOG.md](CHANGELOG.md); the three that mattered:

1. **`PORT_SERVICES` was a list of `(port, name)` tuples converted to a dict.** Every
   duplicate key silently collapsed onto whichever entry was written first. Ports
   80, 8000, 8080, 8888, 21, 23, 445, 3389 and 5900 each lost their identity.
2. **`--common` meant `list(PORT_SERVICES)[:100]`.** That is the 100 *lowest-numbered*
   ports — 1, 7, 9, 13 and friends — while missing 3306, 3389 and 5900 entirely.
   The flag named "common" did not scan the common ports.
3. **A timeout was reported as closed.** `socket.connect_ex` was compared against
   `0`, but its timeout path returns rather than raising, and the code never
   distinguished them. A filtered port and a closed port are different
   observations, and collapsing them is the single most common port-scanner bug.

2.0 is a rewrite in which those classes of bug are not representable. The port
catalogue is a dict literal, so duplicate keys cannot survive. Presets are explicit
tuples, so "common" means nmap's top 100. `PortState` has four values and the
engine assigns them from the actual exception, not from a boolean.

---

## Install

```bash
python -m pip install .
```

From a checkout, for development:

```bash
python -m pip install -e ".[dev]"
```

Or run it without installing at all:

```bash
python -m netscan --help
```

Docker:

```bash
docker build -t netscan .
docker run --rm --network host netscan 127.0.0.1 -p common
```

`--network host` is Linux-only. On macOS and Windows, use
`docker run --rm netscan <target> -p <spec>` and accept that the container has its
own network namespace — scanning `127.0.0.1` from inside the container scans the
container, not the host.

### Requirements

| | |
|---|---|
| Python | 3.9, 3.10, 3.11, 3.12, 3.13 |
| Platform | Linux, macOS, Windows |
| Runtime deps | none |
| Privileges | none — TCP connect scan only |

No root, no raw sockets, no `CAP_NET_RAW`. A connect scan completes the handshake
through the kernel, so the tool runs as any user. The trade-off is that a connect
scan is visible in the target's application logs; that is documented under
[Limitations](#limitations).

---

## Quickstart

```bash
# one host, the real top-100 ports
netscan 192.168.1.10

# one host, an explicit port list
netscan 192.168.1.10 -p 22,80,443,3306,5432,6379

# a subnet, only database ports, results streamed as they land
netscan 10.0.0.0/24 -p db --stream

# a hostname, JSON to a file
netscan example.com -p common -f json -o report.json

# a list of targets from a file, fail the CI job on anything critical
netscan @targets.txt -p critical --fail-on-risk critical -q

# see the plan without sending a single packet
netscan 10.0.0.0/24 -p common --dry-run
```

---

## Targets

Any argument that is not a flag is a target. Multiple targets, comma-separated
targets, and `@file` references all work in one invocation.

| Form | Example | Notes |
|---|---|---|
| IPv4 literal | `10.0.0.5` | canonicalised |
| IPv4 CIDR | `10.0.0.0/24` | non-network addresses accepted (`10.0.0.5/30` → 4 hosts) |
| IPv4 range | `10.0.0.1-10.0.0.20` | inclusive |
| Abbreviated range | `10.0.0.1-20` | last octet only; start must be ≤ end |
| IPv6 literal | `2001:db8::1` | zone index (`%eth0`) stripped before connecting |
| IPv6 CIDR | `2001:db8::/120` | 256 addresses |
| Hostname | `example.com` | resolved at scan time; every A and AAAA record becomes its own host |
| File | `@targets.txt` | one spec per line, `#` starts a comment, blank lines ignored |
| Combination | `10.0.0.5,10.0.1.0/28,@more.txt` | comma-separated mixes inside one argument |

**Expansion is capped.** `DEFAULT_MAX_ADDRESSES` is 4096 and the absolute ceiling
is 65536, so a typo produces an error instead of sixteen million probes:

```
$ netscan 10.0.0.0/16 -p common
netscan: invalid target: '10.0.0.0/16' expands to 65536 addresses, ceiling is 4096
```

Duplicate addresses across overlapping specs are collapsed; order is preserved.

### Restricting scope

`--allow-scope CIDR` drops any address outside the given network and is
repeatable. Hostnames pass the static check because they are not resolved yet; if
you need a hard guarantee, pass IP literals.

```bash
netscan 10.0.0.0/16 --allow-scope 10.0.7.0/24 --max-hosts 4096 -p common
```

---

## Port selection

`-p` / `--ports` accepts numbers, ranges, presets, service names, and mixtures.
The result is always sorted and de-duplicated.

| Spec | Meaning |
|---|---|
| `22` | one port |
| `22,80,443` | a list |
| `1-1024` | an inclusive range |
| `common` / `top100` | nmap's top 100 TCP ports, in frequency order |
| `critical` | exposure that is a near-certain finding on any internet-facing host |
| `web` | ports that speak HTTP(S) in almost every deployment |
| `db` / `database` | database and cache listeners |
| `remote` | remote shell, remote desktop and remote management |
| `rdp`, `smb` | single-purpose shortcuts |
| `all` / `*` | 1–65535 |
| `ssh`, `https`, `redis` | every port whose catalogue name matches |

The default is `common`.

`common` is a hand-maintained tuple, not a slice of anything. A test asserts it
contains 22, 80, 443, 445, 1433, 3306, 3389, 5432, 5900 and 8080 and excludes
1–5, so the defect described above cannot come back silently.

---

## Output formats

`-f` / `--format` selects one of five. `-o` / `--output` writes it to a file
atomically — temp file in the same directory, `fsync`, then `os.replace`, so an
interrupted run leaves the previous report intact rather than a half-written one.
`-o -` writes to stdout.

| Format | Shape | Use it for |
|---|---|---|
| `console` | width-aware coloured table | reading |
| `json` | one document: `meta`, `summary`, `hosts`, `findings` | programmatic consumption, archiving |
| `ndjson` | one JSON object per line: `meta`, `host`, `port`, then `finding`, then `summary` | streaming into Splunk/Elastic/jq |
| `csv` | one row per *probed* port, closed and filtered included | spreadsheets, diffing two scans |
| `md` | Markdown with findings and per-host tables | pasting into a report |

CSV is written with `csv.writer`, which quotes correctly. A banner containing a
comma, a double quote and a newline round-trips through `csv.DictReader` intact —
a test asserts exactly that, because the old implementation built rows with
`",".join()` and produced unparseable output for practically every HTTP banner.

`ndjson` deliberately emits only open ports. A `/24` with 1000 ports would
otherwise produce a quarter of a million noise records; `csv` is the format that
keeps everything.

---

## Exit codes

Contractual. Scripts and CI jobs can depend on these.

| Code | Meaning |
|---|---|
| `0` | the scan ran to completion (findings may or may not exist) |
| `1` | the scan completed and `--fail-on-risk` was tripped |
| `2` | usage or input error: bad target, bad port spec, unreadable file, out-of-scope address |
| `3` | internal error: an unexpected exception escaped the engine |
| `130` | interrupted (Ctrl-C) |

The old script returned `1` whenever it saw a risky port, which made "the scan
failed" and "the scan worked and found something" indistinguishable. Finding a
risky port is a *successful* scan; that is why a non-zero exit for findings is
opt-in via `--fail-on-risk LEVEL` and off by default.

```bash
netscan 10.0.0.0/24 -p critical --fail-on-risk critical -q \
  || echo "critical exposure on the network"
```

---

## Every flag

```
positional arguments:
  targets                 addresses, CIDRs, ranges, hostnames, @files, or
                          comma-separated mixes

output
  -f, --format            console | json | ndjson | csv | md   (default: console)
  -o, --output PATH       write to PATH atomically; '-' means stdout
      --stream            print open ports as they are found (console only)
      --show-closed       also list closed and filtered ports in the console report
  -q, --quiet             suppress the console report; findings still drive the exit code
      --no-colour         disable ANSI colour even on a TTY

scanning
  -p, --ports SPEC        numbers, ranges, presets, service names, mixtures
  -c, --concurrency N     maximum simultaneous probes            (default: 500)
  -t, --timeout SECONDS   per-probe connect timeout              (default: 2.0)
      --retries N         retries for filtered probes only       (default: 1)
      --rate-limit N      total probes per second; 0 disables    (default: 0)

banners
      --banner            read service banners                   (default)
      --no-banner         skip banner grabbing; noticeably faster
      --banner-bytes N    maximum bytes read per banner          (default: 1024)
      --banner-timeout S  how long to wait for a banner          (default: 1.5)

resolution
      --reverse-dns       resolve PTR records per address
      --resolve-timeout S DNS timeout per name                   (default: 5.0)

safety
      --max-hosts N       refuse to expand more than N addresses (default: 4096)
      --allow-scope CIDR  only scan addresses inside CIDR; repeatable
      --dry-run           expand and print the plan, probe nothing

control
      --fail-on-risk LVL  none | low | medium | high | critical  (default: none)
  -v, --verbose           repeat for debug logging
      --log-file PATH     write logs to PATH instead of stderr
      --version
  -h, --help
```

**Rate limiting** is a monotonic token bucket shared across the whole scan, not a
per-worker sleep. `--rate-limit 20` means twenty probes per second end to end,
which is the flag that keeps a scan inside a bug-bounty programme's "no disruptive
traffic" clause.

**Retries** apply only to *filtered* probes. A refused connection is a definitive
answer from a live host; retrying it three times just triples the noise.

---

## Library use

The CLI is a thin layer over the package. Everything is importable and typed
(`py.typed` is shipped, so mypy and PyCharm use the annotations).

```python
import asyncio
from netscan import ScanOptions, Scanner, parse_port_spec, parse_targets

targets = parse_targets(["10.0.0.0/28"])
options = ScanOptions(
    ports=parse_port_spec("22,80,443,3306,6379"),
    concurrency=200,
    timeout=1.0,
    banner_grab=True,
)

scanner = Scanner(
    options,
    on_result=lambda port: print(port.address, port.port, port.state.value),
    on_progress=lambda done, total: None,
)
report = asyncio.run(scanner.scan(targets))

for host in report.hosts:
    for port in host.open_ports:
        print(f"{port.address}:{port.port} {port.service} {port.risk.value}")
```

Serialising, analysing and rendering are separate calls so you can use any one of
them on its own:

```python
from netscan.report import render, write_report
from netscan.risk import analyse, summarise
from netscan.console import Style, render_report

findings = analyse(report)                      # list[Finding], severity-ordered
print(summarise(findings))                      # {'low': 0, 'medium': 1, ...}
print(render(report, findings, "json"))
write_report(report, findings, fmt="csv", output="scan.csv")
print(render_report(report, findings, style=Style(enabled=False)))
```

`ScanReport`, `HostResult`, `PortResult` and `Finding` are frozen dataclasses with
`to_dict()`. Those `to_dict()` methods define the on-wire shape for every format;
changing a key is a breaking change.

---

## Measured performance

Linux, Python 3.12.3, loopback only, `--retries 0`. Wall clock and peak RSS from
`/usr/bin/time -v`.

| Scan | Wall | Peak RSS |
|---|---|---|
| 1000 ports on `127.0.0.1`, no banners, `-c 500` | **1.51 s** | 26.7 MB |
| 1000 ports on `127.0.0.1`, banners on, `-c 500` | **3.09 s** | 26.9 MB |
| top-100 × 256 hosts (`127.0.0.0/24`), no banners | **42.32 s** | 31.4 MB |
| `10.0.0.0/16 -p common --dry-run` | refused in <50 ms | — |

The `/24` number is the honest one: 25 600 probes at ~605 probes/second is
dominated by the two-second `--retries 1` backoff on the 255 hosts that never
answer, not by concurrency. Loopback answers every probe instantly, which is why
the single-host numbers look a hundred times faster.

**Memory is flat.** The engine keeps one task per worker, not one task per probe.
The naive implementation — `asyncio.gather` over every `(address, port)` pair —
would allocate 25 600 coroutine frames for the `/24` and about 65 million for a
`/16`, which is why 31.4 MB stays 31.4 MB here and would not with `gather`.
A test asserts the observed peak live-task count never exceeds `--concurrency`.

---

## How the state machine works

Four states, each assigned from a specific observed event. No guessing.

| State | Trigger | Meaning |
|---|---|---|
| `OPEN` | TCP handshake completed | something is listening |
| `CLOSED` | `ECONNREFUSED` (RST) | the host is up, nothing is listening |
| `FILTERED` | timeout, `EHOSTUNREACH`, `ENETUNREACH`, `EHOSTDOWN` | no answer — a firewall dropped it, or the host is down, or it is rate-limiting. We do not claim to know which. |
| `ERROR` | anything else | recorded with the exception class and message |

`OPEN` is the only state that gets a service name and a risk rating, because it is
the only state where something was actually observed listening.

Filtered probes are retried up to `--retries` times; refused probes never are.
A refused connection is a complete answer, and repeating it only produces load.

---

## Exposure findings

`netscan.risk` turns open ports into `Finding` objects with a severity, a title,
a rationale and the evidence that produced them.

```
CRITICAL 10.0.0.5:6379 redis
  Redis is reachable
  Redis has no authentication by default. CONFIG SET dir plus CONFIG SET
  dbfilename plus SAVE writes arbitrary files, which is a well-known path
  to SSH key injection and code execution.
  10.0.0.5:6379/tcp open | connect 0.8 ms | banner "-ERR wrong number of …
```

**What a finding is not.** It is not a claim that this Redis is unauthenticated.
The scanner never sent a command, so it cannot know. A finding says *"this socket
is open, this is the service it usually carries, and here is why that is usually
bad"* — which is what a defender can act on and what an assessor can verify by
hand. Rules are backed by the port number and, where the catalogue is uncertain,
by a banner regex. Nothing is inferred from a port number alone into a claim of
exploitability.

Banner hints escalate when the banner contradicts the port. A listener on 5999
that greets with `RFB 003.008` is VNC and is rated CRITICAL; the same port with an
`SSH-` greeting produces nothing, because SSH is not a finding.

`--fail-on-risk LEVEL` compares against the highest severity present. The
comparison uses `RiskLevel.rank`, not string equality, so `high` is tripped by a
`critical` finding.

---

## Architecture

```
src/netscan/
├── __init__.py     public surface, __version__
├── __main__.py     python -m netscan
├── models.py       frozen dataclasses: PortResult, HostResult, ScanReport, ScanMeta
│                   PortState, RiskLevel (+ rank), the on-wire to_dict() contract
├── services.py     port catalogue (dict, so duplicates are unrepresentable)
│                   presets, TOP_100, banner probes
├── targets.py      target/port parsing, expansion ceilings, --allow-scope
├── scanner.py      the engine: worker pool, rate limiter, state machine, banners
├── risk.py         Finding, FindingRule, RULES, banner escalation, summarise
├── report.py       json / ndjson / csv / md, atomic writes
├── console.py      width-aware colour rendering, TTY detection
└── cli.py          argparse, exit-code mapping, wiring
```

Dependency direction is acyclic: `cli → console/report → risk → models`, and
`scanner → services/targets → models`. Nothing imports upward. `models.py` imports
nothing from the package, which is what lets the reporters consume it without
dragging in the engine.

**One task per worker, not one per probe.** `_iter_jobs` is a generator; each of
the `--concurrency` workers pulls the next `(host_index, port)` pair, probes it,
and appends the result to its own host's list. Live task count is `concurrency`
regardless of the scan size.

**No global mutable state.** A `Scanner` holds no module-level results, so two
scanners can run concurrently in one process and a scan can be repeated. The old
script kept a single `results` list and searched it for every port, which is O(n²)
and returned the wrong host when a host appeared twice.

**Banners are untrusted input.** Service banners are attacker-controlled bytes.
`_sanitise_banner` strips ANSI escapes, maps everything outside printable ASCII to
a space, and collapses whitespace runs — so a banner containing `\x1b[2J` cannot
clear your terminal, and one containing `\x00` cannot truncate a CSV field.

**Reports are written atomically.** `NamedTemporaryFile` in the destination
directory, `fsync`, `os.replace`. A Ctrl-C during the write leaves the previous
report untouched.

---

## Limitations

Honest list. These are design boundaries, not bugs to be filed.

- **Connect scan only.** No SYN scan, no FIN/NULL/XMAS, no UDP, no `CAP_NET_RAW`.
  A connect scan completes the handshake, so it appears in the target's
  application logs and in any IDS that watches for completed connections. It also
  cannot distinguish "closed" from "firewall sent a RST" — nothing can.
- **No OS fingerprinting, no version-to-CVE mapping.** The banner is reported
  verbatim; deciding that `OpenSSH_8.2p1` correlates with a specific advisory is
  the reader's job, and the scanner will not guess a CVE from a string.
- **No UDP.** UDP requires a fundamentally different engine (no handshake, so no
  reliable open/closed signal for most protocols) and is deliberately out of scope.
- **IPv6 is address-by-address.** No multicast, no link-local scope discovery;
  a zone index is stripped before connecting, which is correct for global
  addresses and may not be for a specific interface.
- **DNS is resolved once, at the start.** A round-robin record that changes
  mid-scan is not re-resolved. Use IP literals when you need a fixed target set.
- **`--allow-scope` is a guardrail, not a sandbox.** It filters expanded literals
  at parse time. It is not a security control and does not constrain a hostname
  that resolves to an address outside the declared range.
- **Concurrency is bounded by file descriptors.** 500 simultaneous sockets needs
  a `ulimit -n` above 500; Linux defaults to 1024, which is enough, but raising
  `-c` past ~900 on a default macOS install will produce `EMFILE` errors recorded
  as `ERROR` state.

---

## Development

```bash
python -m pip install -e ".[dev]"
pre-commit install

make check     # ruff + mypy --strict + pytest with coverage
```

Current state: **244 tests passing, 92% branch coverage, ruff clean, mypy strict
clean** on Linux/Python 3.12. CI runs the same suite across Python 3.9–3.13 on
Ubuntu, macOS and Windows, plus a job that builds the wheel and installs it into a
clean virtualenv to prove the console entry point works from a real artefact.

See [CONTRIBUTING.md](CONTRIBUTING.md) for what gets merged, and
[SECURITY.md](SECURITY.md) for reporting a vulnerability in the scanner itself.

### Compatibility shim

`Network-scanner.py` still works. It translates the pre-2.0 flags onto the
packaged CLI and prints a deprecation notice:

```bash
python Network-scanner.py --target 10.0.0.5 --common --output json
```

| Legacy | Modern |
|---|---|
| `--target HOST` | positional `HOST` |
| `--network CIDR` | positional `CIDR` |
| `--targets FILE` | `@FILE` |
| `--common` | `-p common` (now actually the top 100) |
| `--critical` | `-p critical` |
| `--all-ports` | `-p 1-65535` |
| `--threads N` | `-c N` |
| `--banner` | on by default; `--no-banner` to disable |
| `--output json` | `-f json -o report.json` |
| `--quiet` | `-q` |

The shim will not gain features. New work should call `netscan`.

---

## Legal

A port scan is a series of TCP connections. Making them against a system you do
not own or have written permission to test is illegal in most jurisdictions —
in the US under the Computer Fraud and Abuse Act, in the UK under the Computer
Misuse Act, in the EU under national implementations of Directive 2013/40/EU, and
so on. "It only opened a socket" is not a defence that has ever worked.

Scan your own infrastructure, a lab, or a target inside a programme that
authorises it. If you are scanning a bounty target, respect its rules: they
almost always set a request ceiling, forbid automated scanners, and require an
identifying header on every request. `--rate-limit` and `--allow-scope` exist for
exactly those constraints.

The software is provided under the MIT licence, without warranty of any kind. The
authors accept no liability for use, misuse, or consequences.

---

MIT © 2026 [Youssef Alaoui Hichami](https://github.com/7xd10)
