"""Immutable result types produced by the scanner and consumed by the reporters.

Everything in this module is a frozen dataclass with fully resolved types. The
reporters serialise these objects directly, so ``to_dict`` is the single place
where the on-wire shape is defined -- changing it changes the JSON/CSV contract
and must be treated as a breaking change.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, Optional, Sequence


def utc_now() -> datetime:
    """Timestamp helper. Always timezone-aware; naive datetimes break comparisons."""
    return datetime.now(timezone.utc)


def iso(ts: Optional[datetime]) -> Optional[str]:
    """Serialise a datetime as RFC 3339 with a ``Z`` suffix (stable across Python versions)."""
    if ts is None:
        return None
    return ts.astimezone(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


class PortState(str, Enum):
    """Outcome of a single TCP connection attempt.

    ``FILTERED`` is deliberately distinct from ``CLOSED``: a refused connection
    means a host answered and nothing is listening, while a timeout means we do
    not know -- a firewall, a rate limiter, or a dropped packet are all possible.
    Collapsing the two into "closed" is the single most common port-scanner bug.
    """

    OPEN = "open"
    CLOSED = "closed"
    FILTERED = "filtered"
    ERROR = "error"


class RiskLevel(str, Enum):
    """Coarse exposure classification for a listening service."""

    NONE = "none"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        return _RISK_RANK[self]


_RISK_RANK: Dict[RiskLevel, int] = {}


def _init_ranks() -> None:
    for index, level in enumerate(
        (
            RiskLevel.NONE,
            RiskLevel.LOW,
            RiskLevel.MEDIUM,
            RiskLevel.HIGH,
            RiskLevel.CRITICAL,
        )
    ):
        _RISK_RANK[level] = index


_init_ranks()


@dataclass(frozen=True)
class ServiceInfo:
    """Static knowledge about a well-known TCP port."""

    name: str
    description: str
    risk: RiskLevel = RiskLevel.NONE
    probe: Optional[bytes] = None
    """Optional protocol probe sent before reading a banner.

    ``None`` means the service is expected to speak first (SSH, SMTP, MySQL and
    friends); the scanner simply reads. A non-``None`` value is sent verbatim.
    """


@dataclass(frozen=True)
class PortResult:
    """One port on one address."""

    host: str
    address: str
    port: int
    state: PortState
    protocol: str = "tcp"
    service: Optional[str] = None
    description: Optional[str] = None
    risk: RiskLevel = RiskLevel.NONE
    banner: Optional[str] = None
    latency_ms: Optional[float] = None
    error: Optional[str] = None

    @property
    def is_open(self) -> bool:
        return self.state is PortState.OPEN

    def to_dict(self) -> Dict[str, Any]:
        return {
            "host": self.host,
            "address": self.address,
            "port": self.port,
            "protocol": self.protocol,
            "state": self.state.value,
            "service": self.service,
            "description": self.description,
            "risk": self.risk.value,
            "banner": self.banner,
            "latency_ms": None if self.latency_ms is None else round(self.latency_ms, 3),
            "error": self.error,
        }


@dataclass(frozen=True)
class HostResult:
    """Every probed port for a single resolved address."""

    target: str
    address: str
    family: str
    resolved: bool
    ports: Sequence[PortResult] = ()
    reverse_dns: Optional[str] = None
    started_at: Optional[datetime] = None
    finished_at: Optional[datetime] = None
    error: Optional[str] = None

    @property
    def open_ports(self) -> Sequence[PortResult]:
        return tuple(p for p in self.ports if p.is_open)

    @property
    def duration_ms(self) -> Optional[float]:
        if self.started_at is None or self.finished_at is None:
            return None
        return (self.finished_at - self.started_at).total_seconds() * 1000.0

    @property
    def highest_risk(self) -> RiskLevel:
        risk = RiskLevel.NONE
        for port in self.open_ports:
            if port.risk.rank > risk.rank:
                risk = port.risk
        return risk

    def to_dict(self) -> Dict[str, Any]:
        return {
            "target": self.target,
            "address": self.address,
            "family": self.family,
            "resolved": self.resolved,
            "reverse_dns": self.reverse_dns,
            "started_at": iso(self.started_at),
            "finished_at": iso(self.finished_at),
            "duration_ms": (None if self.duration_ms is None else round(self.duration_ms, 3)),
            "error": self.error,
            "open_port_count": len(self.open_ports),
            "highest_risk": self.highest_risk.value,
            "ports": [p.to_dict() for p in self.ports],
        }


@dataclass(frozen=True)
class ScanMeta:
    """Provenance for a scan. Written into every report so results are reproducible."""

    tool: str
    version: str
    started_at: datetime
    finished_at: Optional[datetime]
    targets_requested: int
    addresses_scanned: int
    ports_per_address: int
    concurrency: int
    timeout_s: float
    retries: int
    banner_grab: bool
    argv: Sequence[str] = ()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "tool": self.tool,
            "version": self.version,
            "started_at": iso(self.started_at),
            "finished_at": iso(self.finished_at),
            "targets_requested": self.targets_requested,
            "addresses_scanned": self.addresses_scanned,
            "ports_per_address": self.ports_per_address,
            "concurrency": self.concurrency,
            "timeout_s": self.timeout_s,
            "retries": self.retries,
            "banner_grab": self.banner_grab,
            "argv": list(self.argv),
        }


@dataclass(frozen=True)
class ScanReport:
    """Top-level document. This is what the reporters consume."""

    meta: ScanMeta
    hosts: Sequence[HostResult]

    @property
    def open_port_total(self) -> int:
        return sum(len(h.open_ports) for h in self.hosts)

    @property
    def highest_risk(self) -> RiskLevel:
        risk = RiskLevel.NONE
        for host in self.hosts:
            if host.highest_risk.rank > risk.rank:
                risk = host.highest_risk
        return risk

    def to_dict(self) -> Dict[str, Any]:
        return {
            "meta": self.meta.to_dict(),
            "summary": {
                "hosts": len(self.hosts),
                "hosts_resolved": sum(1 for h in self.hosts if h.resolved),
                "open_ports": self.open_port_total,
                "highest_risk": self.highest_risk.value,
            },
            "hosts": [h.to_dict() for h in self.hosts],
        }


class TargetError(ValueError):
    """Raised when a target specification cannot be parsed."""


def normalise_address(value: str) -> str:
    """Canonicalise an IP literal; raise ``TargetError`` when it is not one."""
    try:
        return str(ipaddress.ip_address(value.strip()))
    except ValueError as exc:
        raise TargetError(f"not an IP address: {value!r}") from exc
