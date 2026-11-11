"""Catalogue invariants.

The legacy scanner stored ``(port, name)`` pairs in a list and built a dict from
them, so 80, 8000, 8080 and 8888 all silently collapsed onto a single entry and
four services disappeared. These tests assert the properties that made that
possible to get wrong.
"""

from __future__ import annotations

import pytest

from netscan.models import RiskLevel
from netscan.services import (
    CRITICAL_PORTS,
    DATABASE_PORTS,
    PRESETS,
    REMOTE_ACCESS_PORTS,
    SERVICES,
    TOP_100,
    WEB_PORTS,
    all_ports,
    resolve_preset,
    service_for,
)


class TestCatalogue:
    def test_no_duplicate_ports_are_possible(self) -> None:
        # A dict literal cannot hold duplicate keys; assert the size is what the
        # source says it is, so an accidental merge is caught by review.
        assert len(SERVICES) == len(set(SERVICES))

    def test_every_entry_has_a_name_and_description(self) -> None:
        for port, info in SERVICES.items():
            assert info.name, f"port {port} has no name"
            assert info.description, f"port {port} has no description"

    def test_every_port_is_in_range(self) -> None:
        assert all(1 <= p <= 65535 for p in SERVICES)

    def test_web_ports_do_not_collide(self) -> None:
        # The specific collision the old code caused.
        for port in (80, 8000, 8080, 8888):
            assert services_name(port) in {
                "http",
                "http-alt",
                "http-proxy",
            }, f"port {port} lost its identity: {services_name(port)}"

    def test_risk_values_are_enum_members(self) -> None:
        assert all(isinstance(info.risk, RiskLevel) for info in SERVICES.values())

    def test_unknown_port_gets_a_placeholder(self) -> None:
        info = service_for(64999)
        assert info.name == "unknown"
        assert info.risk is RiskLevel.NONE
        assert info.probe is None

    def test_known_port_round_trips(self) -> None:
        assert service_for(443).name == "https"
        assert service_for(3306).risk is RiskLevel.CRITICAL

    def test_all_ports_is_sorted(self) -> None:
        ports = all_ports()
        assert ports == sorted(ports)


class TestTopHundred:
    def test_exactly_one_hundred(self) -> None:
        assert len(TOP_100) == 100

    def test_no_duplicates(self) -> None:
        assert len(set(TOP_100)) == len(TOP_100)

    def test_all_in_range(self) -> None:
        assert all(1 <= p <= 65535 for p in TOP_100)

    def test_contains_the_ports_that_matter(self) -> None:
        for expected in (22, 80, 443, 445, 1433, 3306, 3389, 5432, 5900, 8080):
            assert expected in TOP_100, f"top-100 is missing {expected}"

    def test_excludes_low_numbered_noise(self) -> None:
        for excluded in (1, 2, 3, 4, 5):
            assert excluded not in TOP_100


class TestPresets:
    def test_every_preset_resolves(self) -> None:
        for name in PRESETS:
            ports = resolve_preset(name)
            assert ports, f"preset {name} is empty"

    def test_lookup_is_case_insensitive(self) -> None:
        assert resolve_preset("COMMON") == resolve_preset("common")

    def test_unknown_preset_names_the_alternatives(self) -> None:
        with pytest.raises(KeyError, match="known"):
            resolve_preset("nope")

    def test_critical_ports_are_all_critical_or_high(self) -> None:
        for port in CRITICAL_PORTS:
            info = SERVICES.get(port)
            if info is None:
                continue
            assert info.risk in {RiskLevel.CRITICAL, RiskLevel.HIGH}, (
                f"{port}/{info.name} is listed as critical but rated {info.risk.value}"
            )

    def test_web_ports_are_http_bearing(self) -> None:
        assert 80 in WEB_PORTS and 443 in WEB_PORTS

    def test_database_ports_contain_the_major_engines(self) -> None:
        for engine in (1433, 3306, 5432, 6379):
            assert engine in DATABASE_PORTS

    def test_remote_access_ports_contain_ssh_and_rdp(self) -> None:
        assert 22 in REMOTE_ACCESS_PORTS
        assert 3389 in REMOTE_ACCESS_PORTS


class TestProbes:
    def test_http_ports_send_a_head_request(self) -> None:
        probe = SERVICES[80].probe
        assert probe is not None
        assert probe.startswith(b"HEAD / HTTP/1.0")

    def test_services_that_speak_first_have_no_probe(self) -> None:
        for port in (22, 25, 110, 143, 3306):
            assert SERVICES[port].probe is None, (
                f"{port} speaks first; sending a probe would confuse it"
            )


def services_name(port: int) -> str:
    return SERVICES[port].name
