"""Target parsing.

Accepts the forms people actually type:

* ``10.0.0.5``                   single IPv4 address
* ``10.0.0.0/24``                IPv4 CIDR
* ``10.0.0.1-10.0.0.20``         full IPv4 range
* ``10.0.0.1-20``                abbreviated IPv4 range (last octet)
* ``2001:db8::1``                single IPv6 address
* ``2001:db8::/120``             IPv6 CIDR
* ``example.com``                hostname, resolved at scan time
* ``@targets.txt``               file, one spec per line, ``#`` comments
* comma-separated combinations of the above

Expansion is hard-capped (``MAX_ADDRESSES``) so a typo like ``10.0.0.0/8`` fails
loudly instead of starting a 16-million-address scan. ``--allow-scope`` further
restricts what is expanded so a scan cannot wander off a declared range.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, List, Optional, Sequence, Tuple, Union

from .models import TargetError

__all__ = [
    "DEFAULT_MAX_ADDRESSES",
    "MAX_ADDRESSES",
    "ScopeError",
    "Target",
    "expand_target",
    "parse_targets",
]

#: Absolute ceiling regardless of flags. 2**16 addresses is ~65k probes per port,
#: which is already a very large scan and a reasonable guard against fat fingers.
MAX_ADDRESSES = 65536

#: Default ceiling, lowered by ``--max-hosts``.
DEFAULT_MAX_ADDRESSES = 4096

IPAddress = Union[ipaddress.IPv4Address, ipaddress.IPv6Address]
IPNetwork = Union[ipaddress.IPv4Network, ipaddress.IPv6Network]

_IPV4_RANGE_RE = re.compile(
    r"^(?P<start>\d{1,3}(?:\.\d{1,3}){3})\s*-\s*(?P<end>\d{1,3}(?:\.\d{1,3}){3}|\d{1,3})$"
)


class ScopeError(TargetError):
    """Raised when an address falls outside ``--allow-scope``."""


@dataclass(frozen=True)
class Target:
    """A single thing to probe.

    ``address`` is set for literals; ``hostname`` is set for names that must be
    resolved at scan time (DNS can change between parse and connect).
    """

    original: str
    address: Optional[str] = None
    hostname: Optional[str] = None
    network: Optional[str] = None
    """CIDR / range label this address was expanded from, for reporting."""

    @property
    def label(self) -> str:
        if self.hostname is not None:
            return self.hostname
        return self.address or self.original

    def __str__(self) -> str:
        if self.hostname is not None:
            return self.hostname
        return self.address or self.original


def _iter_ipv4_range(start: str, end: str) -> Iterable[ipaddress.IPv4Address]:
    first = ipaddress.IPv4Address(start)
    if end.isdigit():
        last_octet = int(end)
        if not 0 <= last_octet <= 255:
            raise TargetError(f"range end octet out of bounds: {end!r}")
        # "10.0.0.1-20" is only meaningful when the start's last octet is <= end.
        prefix = str(first).rsplit(".", 1)[0]
        if first.packed[3] > last_octet:
            raise TargetError(f"range start {start} is greater than end octet {end}")
        last = ipaddress.IPv4Address(f"{prefix}.{last_octet}")
    else:
        last = ipaddress.IPv4Address(end)

    if int(last) < int(first):
        raise TargetError(f"range start {start} is greater than end {end}")
    for value in range(int(first), int(last) + 1):
        yield ipaddress.IPv4Address(value)


def _strip_scope_id(value: str) -> str:
    """Drop an IPv6 zone index (``fe80::1%eth0``); socket will re-add it."""
    return value.split("%", 1)[0]


def _expand_one(
    spec: str,
) -> Tuple[Optional[IPAddress], Optional[IPNetwork], Optional[str]]:
    """Return ``(address, network, hostname)`` for one unexpanded spec."""
    text = spec.strip()
    if not text:
        raise TargetError("empty target")

    match = _IPV4_RANGE_RE.match(text)
    if match:
        start = ipaddress.IPv4Address(match.group("start"))
        end_text = match.group("end")
        last = ipaddress.IPv4Address(
            f"{str(start).rsplit('.', 1)[0]}.{end_text}" if end_text.isdigit() else end_text
        )
        if int(last) < int(start):
            raise TargetError(f"range start {start} is greater than end {last}")
        count = int(last) - int(start) + 1
        if count > MAX_ADDRESSES:
            raise TargetError(
                f"range {text!r} expands to {count} addresses, ceiling is {MAX_ADDRESSES}"
            )
        return None, ipaddress.ip_network(f"{start}/{last}", strict=False), None

    # CIDR
    if "/" in text:
        try:
            network = ipaddress.ip_network(_strip_scope_id(text), strict=False)
        except ValueError as exc:
            raise TargetError(f"invalid CIDR {text!r}: {exc}") from exc
        if network.num_addresses > MAX_ADDRESSES:
            raise TargetError(
                f"{text!r} expands to {network.num_addresses} addresses, "
                f"ceiling is {MAX_ADDRESSES}; split the scan or raise --max-hosts"
            )
        return None, network, None

    # Bare IP literal
    try:
        return ipaddress.ip_address(_strip_scope_id(text)), None, None
    except ValueError:
        pass

    # Hostname
    if re.fullmatch(r"[A-Za-z0-9_.-]{1,253}", text) and not text.replace(".", "").isdigit():
        return None, None, text

    raise TargetError(f"cannot parse target {text!r}")


def expand_target(
    spec: str,
    *,
    max_addresses: int = DEFAULT_MAX_ADDRESSES,
    allow_scope: Sequence[Union[str, IPNetwork]] = (),
) -> List[Target]:
    """Expand one spec into concrete :class:`Target` objects.

    Homogeneous networks are collapsed to a single :class:`Target` carrying a
    ``network`` label only when they are hostnames; literal addresses are always
    enumerated because each one needs its own connection.
    """
    text = spec.strip()
    if not text:
        raise TargetError("empty target")

    match = _IPV4_RANGE_RE.match(text)
    if match:
        addresses = list(_iter_ipv4_range(match.group("start"), match.group("end")))
        if len(addresses) > min(max_addresses, MAX_ADDRESSES):
            raise TargetError(
                f"range {text!r} expands to {len(addresses)} addresses, "
                f"ceiling is {min(max_addresses, MAX_ADDRESSES)}"
            )
        network_label = f"{addresses[0]}-{addresses[-1]}"
        targets = [Target(original=text, address=str(a), network=network_label) for a in addresses]
        return _apply_scope(targets, allow_scope)

    address, network, hostname = _expand_one(text)

    if hostname is not None:
        return [Target(original=text, hostname=hostname)]

    if address is not None:
        return _apply_scope([Target(original=text, address=str(address))], allow_scope)

    assert network is not None  # _expand_one contract
    limit = min(max_addresses, MAX_ADDRESSES)
    if network.num_addresses > limit:
        raise TargetError(
            f"{text!r} expands to {network.num_addresses} addresses, ceiling is {limit}"
        )
    targets = [Target(original=text, address=str(a), network=str(network)) for a in network]
    return _apply_scope(targets, allow_scope)


def _apply_scope(
    targets: Sequence[Target],
    allow_scope: Sequence[Union[str, IPNetwork]],
) -> List[Target]:
    if not allow_scope:
        return list(targets)

    networks: List[IPNetwork] = []
    for item in allow_scope:
        net: IPNetwork
        if isinstance(item, (ipaddress.IPv4Network, ipaddress.IPv6Network)):
            net = item
        else:
            net = ipaddress.ip_network(str(item), strict=False)
        networks.append(net)

    kept: List[Target] = []
    for target in targets:
        if target.hostname is not None:
            # Hostnames are resolved later; the resolver re-checks the result.
            kept.append(target)
            continue
        assert target.address is not None
        addr = ipaddress.ip_address(target.address)
        if any(addr in net for net in networks if net.version == addr.version):
            kept.append(target)
    if not kept:
        raise ScopeError(
            f"every address in this target is outside --allow-scope "
            f"({', '.join(str(n) for n in networks)})"
        )
    return kept


def _read_target_file(path: Path) -> List[str]:
    if not path.exists():
        raise TargetError(f"target file not found: {path}")
    if not path.is_file():
        raise TargetError(f"target file is not a regular file: {path}")
    specs: List[str] = []
    for raw in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw.split("#", 1)[0].strip()
        if line:
            specs.append(line)
    return specs


def parse_targets(
    specs: Sequence[str],
    *,
    max_addresses: int = DEFAULT_MAX_ADDRESSES,
    allow_scope: Sequence[Union[str, IPNetwork]] = (),
    dedupe: bool = True,
) -> List[Target]:
    """Parse and expand every spec, preserving order and removing duplicates."""
    flat: List[str] = []
    for spec in specs:
        for piece in spec.split(","):
            piece = piece.strip()
            if piece.startswith("@"):
                flat.extend(_read_target_file(Path(piece[1:])))
            elif piece:
                flat.append(piece)

    if not flat:
        raise TargetError("no targets supplied")

    expanded: List[Target] = []
    for spec in flat:
        expanded.extend(expand_target(spec, max_addresses=max_addresses, allow_scope=allow_scope))

    if len(expanded) > min(max_addresses, MAX_ADDRESSES):
        raise TargetError(
            f"target list expands to {len(expanded)} addresses, "
            f"ceiling is {min(max_addresses, MAX_ADDRESSES)}"
        )

    if not dedupe:
        return expanded

    seen = set()
    unique: List[Target] = []
    for target in expanded:
        key = (target.address, target.hostname)
        if key in seen:
            continue
        seen.add(key)
        unique.append(target)
    return unique


def parse_port_spec(spec: str, *, max_ports: int = 65535) -> List[int]:
    """Parse a port spec: ``22``, ``22,80,443``, ``1-1024``, ``http`` or mixtures.

    Named services resolve against the catalogue. Ranges are inclusive. Output is
    sorted and de-duplicated.
    """
    from .services import SERVICES, resolve_preset

    ports: set[int] = set()
    for chunk in spec.split(","):
        piece = chunk.strip()
        if not piece:
            continue
        lowered = piece.lower()

        if lowered in {"all", "*"}:
            ports.update(range(1, 65536))
            continue

        try:
            ports.update(resolve_preset(lowered))
            continue
        except KeyError:
            pass

        if "-" in piece.lstrip("-"):
            start_text, _, end_text = piece.partition("-")
            if start_text.isdigit() and end_text.isdigit():
                start = int(start_text)
                end = int(end_text)
                if start > end:
                    raise TargetError(f"port range {piece!r} is descending")
                if not 1 <= start <= 65535 or not 1 <= end <= 65535:
                    raise TargetError(f"port range {piece!r} outside 1-65535")
                ports.update(range(start, end + 1))
                continue

        if piece.isdigit():
            port = int(piece)
            if not 1 <= port <= 65535:
                raise TargetError(f"port {port} outside 1-65535")
            ports.add(port)
            continue

        matches = [p for p, info in SERVICES.items() if info.name == lowered]
        if matches:
            ports.update(matches)
            continue

        raise TargetError(f"unrecognised port or profile {piece!r}")

    if not ports:
        raise TargetError("port selection is empty")
    if len(ports) > max_ports:
        raise TargetError(f"{len(ports)} ports selected, ceiling is {max_ports}")
    return sorted(ports)
