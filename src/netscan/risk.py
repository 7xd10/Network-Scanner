"""Exposure analysis.

This module answers one question: *what did the open ports mean?* It does not
guess at vulnerabilities it cannot see. Every finding below is backed by
something the scanner directly observed -- a listening socket, a service name
from the catalogue, and optionally a banner.

The distinction matters. A port scan produces evidence of exposure, not proof of
exploitability. ``6379/tcp open redis`` is a serious finding because Redis ships
with no authentication and ``CONFIG SET dir`` gives arbitrary file write; it is
*not* a claim that this particular Redis is unauthenticated, because the scanner
never sent a command. Findings say "listening, and here is why that is usually
bad", which is what a defender can act on and what an assessor can verify.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Dict, Iterable, List, Sequence

from .models import HostResult, PortResult, RiskLevel, ScanReport

__all__ = [
    "RULES",
    "Finding",
    "FindingRule",
    "analyse",
    "findings_for_host",
    "summarise",
]

_SEVERITY_ORDER: Dict[RiskLevel, int] = {
    RiskLevel.NONE: 0,
    RiskLevel.LOW: 1,
    RiskLevel.MEDIUM: 2,
    RiskLevel.HIGH: 3,
    RiskLevel.CRITICAL: 4,
}


@dataclass(frozen=True)
class Finding:
    """One actionable observation about one host."""

    host: str
    address: str
    port: int
    service: str
    severity: RiskLevel
    title: str
    rationale: str
    evidence: str

    def to_dict(self) -> Dict[str, object]:
        return {
            "host": self.host,
            "address": self.address,
            "port": self.port,
            "service": self.service,
            "severity": self.severity.value,
            "title": self.title,
            "rationale": self.rationale,
            "evidence": self.evidence,
        }


@dataclass(frozen=True)
class FindingRule:
    """A predicate over an open port plus the text emitted when it matches."""

    ports: Sequence[int]
    severity: RiskLevel
    title: str
    rationale: str
    banner_pattern: str = ""
    """Optional regex the banner must match. Empty means the port is enough."""
    services: Sequence[str] = ()


RULES: Sequence[FindingRule] = (
    FindingRule(
        ports=(23,),
        severity=RiskLevel.CRITICAL,
        title="Telnet is listening",
        rationale=(
            "Telnet transmits credentials and session data in cleartext and has no "
            "transport integrity. Any host on the path can read the session, and "
            "there is no mechanism to detect tampering."
        ),
    ),
    FindingRule(
        ports=(445,),
        severity=RiskLevel.CRITICAL,
        title="SMB is reachable",
        rationale=(
            "SMB is the primary lateral-movement and ransomware propagation channel "
            "on Windows networks. It should never be reachable from an untrusted "
            "network segment."
        ),
    ),
    FindingRule(
        ports=(512, 513, 514),
        severity=RiskLevel.CRITICAL,
        title="Berkeley r-services are listening",
        rationale=(
            "rsh/rlogin/rexec authenticate by source address and host file, not by "
            "credential. Any host that can spoof the trusted address gets a shell."
        ),
    ),
    FindingRule(
        ports=(1433, 1434),
        severity=RiskLevel.CRITICAL,
        title="Microsoft SQL Server is reachable",
        rationale=(
            "Direct database exposure bypasses application-layer authorisation. "
            "Weak or reused sa credentials and xp_cmdshell turn this into remote "
            "code execution."
        ),
    ),
    FindingRule(
        ports=(1521,),
        severity=RiskLevel.CRITICAL,
        title="Oracle listener is reachable",
        rationale=(
            "The Oracle TNS listener exposes instance names and has a long history "
            "of pre-authentication flaws. It belongs behind a firewall, not on a "
            "routable address."
        ),
    ),
    FindingRule(
        ports=(3306,),
        severity=RiskLevel.CRITICAL,
        title="MySQL/MariaDB is reachable",
        rationale=(
            "Database exposure allows offline credential attacks and, with "
            "FILE privilege, arbitrary file read and write on the server."
        ),
    ),
    FindingRule(
        ports=(5432,),
        severity=RiskLevel.CRITICAL,
        title="PostgreSQL is reachable",
        rationale=(
            "PostgreSQL exposed to an untrusted network permits credential "
            "stuffing and, where superuser access is obtained, COPY ... FROM "
            "PROGRAM for command execution."
        ),
    ),
    FindingRule(
        ports=(6379,),
        severity=RiskLevel.CRITICAL,
        title="Redis is reachable",
        rationale=(
            "Redis has no authentication by default. CONFIG SET dir plus "
            "CONFIG SET dbfilename plus SAVE writes arbitrary files, which is a "
            "well-known path to SSH key injection and code execution."
        ),
    ),
    FindingRule(
        ports=(9200, 9300),
        severity=RiskLevel.CRITICAL,
        title="Elasticsearch is reachable",
        rationale=(
            "Older Elasticsearch releases ship with no authentication at all, "
            "exposing every index. Even authenticated clusters rarely belong on a "
            "routable address."
        ),
    ),
    FindingRule(
        ports=(27017, 27018, 27019),
        severity=RiskLevel.CRITICAL,
        title="MongoDB is reachable",
        rationale=(
            "MongoDB historically defaults to no authentication. Exposed instances "
            "are routinely scraped and ransomed wholesale."
        ),
    ),
    FindingRule(
        ports=(11211,),
        severity=RiskLevel.CRITICAL,
        title="Memcached is reachable",
        rationale=(
            "Memcached has no authentication, leaks whatever is cached when "
            "misconfigured, and is a high-amplification reflection vector."
        ),
    ),
    FindingRule(
        ports=(3389,),
        severity=RiskLevel.CRITICAL,
        title="RDP is reachable",
        rationale=(
            "RDP is the most-attacked remote-access service on the internet. "
            "Exposure gives credential attacks and, with a pre-auth flaw, SYSTEM."
        ),
    ),
    FindingRule(
        ports=(5900, 5901, 5902, 5903, 5800, 5801),
        severity=RiskLevel.CRITICAL,
        title="VNC is reachable",
        rationale=(
            "Many VNC deployments are configured without a password, and the "
            "protocol has no meaningful brute-force resistance. A listening VNC "
            "port is frequently a direct desktop session."
        ),
    ),
    FindingRule(
        ports=(6000, 6001, 6002, 6003, 6004, 6005, 6006, 6007, 6009, 6059),
        severity=RiskLevel.CRITICAL,
        title="X11 is listening",
        rationale=(
            "An open X display accepts keystrokes, screenshots and clipboard reads "
            "from any client that can connect unless host-based access control is "
            "explicitly configured -- and it usually is not."
        ),
    ),
    FindingRule(
        ports=(21,),
        severity=RiskLevel.HIGH,
        title="FTP is listening",
        rationale=(
            "FTP sends credentials and data in cleartext and frequently permits "
            "anonymous access. It is also a common file-drop for web shells."
        ),
    ),
    FindingRule(
        ports=(69,),
        severity=RiskLevel.HIGH,
        title="TFTP is listening",
        rationale=(
            "TFTP has no authentication and no directory listing protection. It is "
            "used to exfiltrate device configurations and to stage firmware."
        ),
    ),
    FindingRule(
        ports=(135, 139),
        severity=RiskLevel.HIGH,
        title="Windows RPC/NetBIOS is reachable",
        rationale=(
            "The RPC endpoint mapper and NetBIOS session service enumerate users, "
            "shares and installed software, and are the discovery half of most "
            "Windows intrusions."
        ),
    ),
    FindingRule(
        ports=(161,),
        severity=RiskLevel.HIGH,
        title="SNMP is reachable",
        rationale=(
            "SNMPv1 and SNMPv2c authenticate with a cleartext community string, "
            "defaulting to 'public'. Read access discloses full interface, routing "
            "and process inventories."
        ),
    ),
    FindingRule(
        ports=(873,),
        severity=RiskLevel.HIGH,
        title="rsync daemon is reachable",
        rationale=(
            "rsync modules are commonly exported read-write without authentication, "
            "which allows reading or overwriting arbitrary served paths."
        ),
    ),
    FindingRule(
        ports=(2049,),
        severity=RiskLevel.HIGH,
        title="NFS is reachable",
        rationale=(
            "NFS export access control is IP-based and frequently '*' or a broad "
            "subnet. Client-side root is trusted by default unless root_squash is "
            "set."
        ),
    ),
    FindingRule(
        ports=(1080, 3128),
        severity=RiskLevel.HIGH,
        title="Forward proxy is listening",
        rationale=(
            "An open forward proxy relays traffic from anywhere to anywhere, "
            "laundering the origin of attacks and reaching internal segments the "
            "proxy can see."
        ),
    ),
    FindingRule(
        ports=(1099,),
        severity=RiskLevel.HIGH,
        title="Java RMI registry is reachable",
        rationale=(
            "RMI deserialises objects from the network. Exposed registries are a "
            "direct path to remote code execution via gadget chains."
        ),
    ),
    FindingRule(
        ports=(2375, 2376),
        severity=RiskLevel.CRITICAL,
        title="Docker daemon API is reachable",
        rationale=(
            "An unauthenticated Docker API is equivalent to root on the host: "
            "create a privileged container and mount the host filesystem."
        ),
    ),
    FindingRule(
        ports=(5985, 5986),
        severity=RiskLevel.HIGH,
        title="WinRM is reachable",
        rationale=(
            "WinRM accepts PowerShell remoting. Exposure enables password spraying "
            "against domain accounts and, on success, full remote execution."
        ),
    ),
    FindingRule(
        ports=(7001, 7002),
        severity=RiskLevel.HIGH,
        title="WebLogic is listening",
        rationale=(
            "WebLogic has a long record of pre-authentication deserialisation "
            "vulnerabilities in the T3 and IIOP protocols. The admin port should "
            "never be routable."
        ),
    ),
    FindingRule(
        ports=(4848,),
        severity=RiskLevel.HIGH,
        title="GlassFish admin console is listening",
        rationale=(
            "The GlassFish DAS accepts deployment of arbitrary WAR files once "
            "authenticated, and default credentials are common."
        ),
    ),
    FindingRule(
        ports=(8161, 61616),
        severity=RiskLevel.HIGH,
        title="ActiveMQ is listening",
        rationale=(
            "ActiveMQ's default admin credentials are admin/admin and the broker "
            "has had repeated deserialisation RCEs in its OpenWire transport."
        ),
    ),
    FindingRule(
        ports=(9000,),
        severity=RiskLevel.MEDIUM,
        title="Port 9000 is open",
        rationale=(
            "Commonly PHP-FPM (which executes any file it is pointed at if "
            "misconfigured), SonarQube, Portainer or a dev server. Fingerprint the "
            "banner before deciding."
        ),
    ),
    FindingRule(
        ports=(8080, 8081, 8180, 8888),
        severity=RiskLevel.MEDIUM,
        title="Alternate HTTP port is open",
        rationale=(
            "Alternate HTTP listeners are usually management consoles, debug "
            "endpoints or forgotten deployments with weaker authentication than "
            "the main site."
        ),
    ),
    FindingRule(
        ports=(10000,),
        severity=RiskLevel.HIGH,
        title="Webmin is listening",
        rationale=(
            "Webmin runs as root and has had multiple authentication-bypass and "
            "command-injection flaws. It should not be internet-facing."
        ),
    ),
    FindingRule(
        ports=(5000, 5001),
        severity=RiskLevel.LOW,
        title="Application port is open",
        rationale=(
            "Frequently a development server (Flask, .NET Kestrel) which exposes "
            "stack traces and a debugger when not run in production mode."
        ),
    ),
    FindingRule(
        ports=(111,),
        severity=RiskLevel.MEDIUM,
        title="rpcbind is listening",
        rationale=(
            "rpcbind enumerates every registered RPC service, including NFS and "
            "NIS. It is a discovery aid for an attacker and rarely needs to be "
            "externally visible."
        ),
    ),
    FindingRule(
        ports=(389, 636, 3268, 3269),
        severity=RiskLevel.MEDIUM,
        title="Directory service is reachable",
        rationale=(
            "LDAP permits anonymous or null-bind queries on many deployments, "
            "disclosing the full user and group tree."
        ),
    ),
    FindingRule(
        ports=(25, 465, 587, 110, 143, 993, 995),
        severity=RiskLevel.MEDIUM,
        title="Mail service is reachable",
        rationale=(
            "Mail services permit user enumeration through VRFY/RCPT probing and, "
            "when misconfigured as an open relay, become a spam origin."
        ),
    ),
    FindingRule(
        ports=(53,),
        severity=RiskLevel.MEDIUM,
        title="DNS is listening",
        rationale=(
            "A recursive resolver open to the internet is used for reflection and "
            "amplification, and zone transfer may disclose the full namespace."
        ),
    ),
    FindingRule(
        ports=(6000, 5900),
        severity=RiskLevel.CRITICAL,
        title="Remote desktop service is reachable",
        rationale="Interactive remote control is exposed to the network.",
    ),
    FindingRule(
        ports=(23,),
        severity=RiskLevel.CRITICAL,
        title="Telnet banner identified",
        rationale="Legacy cleartext remote shell confirmed by service banner.",
        banner_pattern=r"(?i)telnet",
    ),
)

#: Banners that identify a service as something other than the catalogue default.
_BANNER_HINTS: Sequence[tuple[re.Pattern[str], str, RiskLevel]] = (
    (re.compile(r"(?i)^SSH-"), "SSH", RiskLevel.NONE),
    (re.compile(r"(?i)^220[\s-].*smtp|^220[\s-].*mail"), "SMTP", RiskLevel.MEDIUM),
    (re.compile(r"(?i)^\+OK"), "POP3", RiskLevel.MEDIUM),
    (re.compile(r"(?i)^\* OK"), "IMAP", RiskLevel.MEDIUM),
    (re.compile(r"(?i)^HTTP/\d\.\d"), "HTTP", RiskLevel.LOW),
    (re.compile(r"(?i)^RFB \d"), "VNC", RiskLevel.CRITICAL),
    (re.compile(r"(?i)mysql_native_password|^\x00\x00\x00\x0a5\."), "MySQL", RiskLevel.CRITICAL),
    (re.compile(r"(?i)^-ERR.*redis|^\+PONG"), "Redis", RiskLevel.CRITICAL),
    (re.compile(r"(?i)^220.*ftp|^230.*logged"), "FTP", RiskLevel.HIGH),
    (re.compile(r"(?i)VMware|ESXi"), "VMware", RiskLevel.HIGH),
)


def _host_findings(host: HostResult) -> List[Finding]:
    findings: List[Finding] = []
    seen: set[tuple[int, str]] = set()

    for port in host.open_ports:
        matched = False
        for rule in RULES:
            if port.port not in rule.ports:
                continue
            if rule.banner_pattern and not (
                port.banner and re.search(rule.banner_pattern, port.banner)
            ):
                continue
            key = (port.port, rule.title)
            if key in seen:
                continue
            seen.add(key)
            matched = True
            findings.append(
                Finding(
                    host=host.target,
                    address=host.address,
                    port=port.port,
                    service=port.service or "unknown",
                    severity=rule.severity,
                    title=rule.title,
                    rationale=rule.rationale,
                    evidence=_evidence(port),
                )
            )
        if not matched and port.banner:
            for pattern, name, severity in _BANNER_HINTS:
                if pattern.search(port.banner):
                    # A hint that resolves to NONE says nothing a reader can act
                    # on; it would only pad the findings list with noise.
                    if severity is RiskLevel.NONE:
                        break
                    findings.append(
                        Finding(
                            host=host.target,
                            address=host.address,
                            port=port.port,
                            service=name.lower(),
                            severity=severity,
                            title=f"Banner identifies the service as {name}",
                            rationale=(
                                "The service volunteered an identifier that differs "
                                "from the port's usual occupant, so the catalogue "
                                "description above may be wrong. Treat the banner as "
                                "the authoritative answer."
                            ),
                            evidence=_evidence(port),
                        )
                    )
                    break

    findings.sort(key=lambda f: (-_SEVERITY_ORDER[f.severity], f.port))
    return findings


def _evidence(port: PortResult) -> str:
    parts = [f"{port.address}:{port.port}/tcp open"]
    if port.latency_ms is not None:
        parts.append(f"connect {port.latency_ms:.1f} ms")
    if port.banner:
        parts.append(f'banner "{port.banner[:120]}"')
    return " | ".join(parts)


def findings_for_host(host: HostResult) -> List[Finding]:
    """All findings for a single host, highest severity first."""
    return _host_findings(host)


def analyse(report: ScanReport) -> List[Finding]:
    """All findings across a report, highest severity first."""
    findings: List[Finding] = []
    for host in report.hosts:
        findings.extend(_host_findings(host))
    findings.sort(key=lambda f: (-_SEVERITY_ORDER[f.severity], f.host, f.port))
    return findings


def summarise(findings: Iterable[Finding]) -> Dict[str, int]:
    """Count findings per severity. Always returns every key, zero-filled."""
    counts = {level.value: 0 for level in RiskLevel if level is not RiskLevel.NONE}
    for finding in findings:
        counts[finding.severity.value] += 1
    return counts
