"""Target and port parsing. These are the inputs a user types, so they get the
most edge-case attention."""

from __future__ import annotations

import ipaddress
import textwrap

import pytest

from netscan.models import TargetError
from netscan.targets import (
    MAX_ADDRESSES,
    ScopeError,
    expand_target,
    parse_port_spec,
    parse_targets,
)


class TestSingleAddresses:
    def test_ipv4_literal(self) -> None:
        targets = parse_targets(["10.0.0.5"])
        assert len(targets) == 1
        assert targets[0].address == "10.0.0.5"
        assert targets[0].hostname is None

    def test_ipv4_octal_looking_input(self) -> None:
        # ipaddress rejects leading-zero octets, which is the correct behaviour:
        # "010.0.0.1" is ambiguous between octal and decimal notation.
        with pytest.raises(TargetError):
            parse_targets(["010.000.000.001"])

    def test_ipv6_literal(self) -> None:
        targets = parse_targets(["2001:db8::1"])
        assert targets[0].address == "2001:db8::1"

    def test_ipv6_zone_index_is_stripped(self) -> None:
        targets = parse_targets(["fe80::1%eth0"])
        assert targets[0].address == "fe80::1"

    def test_hostname_is_kept_for_later_resolution(self) -> None:
        targets = parse_targets(["example.com"])
        assert targets[0].hostname == "example.com"
        assert targets[0].address is None

    def test_underscore_hostname_is_accepted(self) -> None:
        targets = parse_targets(["my_host.internal"])
        assert targets[0].hostname == "my_host.internal"

    def test_empty_spec_is_rejected(self) -> None:
        with pytest.raises(TargetError):
            parse_targets(["   "])

    def test_garbage_is_rejected(self) -> None:
        with pytest.raises(TargetError):
            parse_targets(["!!not-a-target!!"])


class TestCidr:
    def test_slash_24(self) -> None:
        targets = parse_targets(["192.168.1.0/30"])
        assert [t.address for t in targets] == [
            "192.168.1.0",
            "192.168.1.1",
            "192.168.1.2",
            "192.168.1.3",
        ]
        assert all(t.network == "192.168.1.0/30" for t in targets)

    def test_non_network_address_is_accepted(self) -> None:
        targets = parse_targets(["192.168.1.5/30"])
        assert len(targets) == 4

    def test_ipv6_cidr(self) -> None:
        targets = parse_targets(["2001:db8::/126"])
        assert len(targets) == 4
        assert all(":" in (t.address or "") for t in targets)

    def test_oversized_cidr_names_the_ceiling(self) -> None:
        with pytest.raises(TargetError, match="ceiling"):
            parse_targets(["10.0.0.0/8"])

    def test_max_hosts_flag_is_honoured(self) -> None:
        with pytest.raises(TargetError, match="ceiling"):
            parse_targets(["10.0.0.0/24"], max_addresses=16)

    def test_invalid_cidr(self) -> None:
        with pytest.raises(TargetError):
            parse_targets(["10.0.0.0/99"])


class TestRanges:
    def test_full_range(self) -> None:
        targets = parse_targets(["10.0.0.1-10.0.0.4"])
        assert [t.address for t in targets] == [
            "10.0.0.1",
            "10.0.0.2",
            "10.0.0.3",
            "10.0.0.4",
        ]

    def test_abbreviated_range(self) -> None:
        targets = parse_targets(["10.0.0.250-253"])
        assert [t.address for t in targets] == [
            "10.0.0.250",
            "10.0.0.251",
            "10.0.0.252",
            "10.0.0.253",
        ]

    def test_single_address_range(self) -> None:
        targets = parse_targets(["10.0.0.7-10.0.0.7"])
        assert len(targets) == 1

    def test_descending_range_is_rejected(self) -> None:
        with pytest.raises(TargetError, match="greater"):
            parse_targets(["10.0.0.9-10.0.0.2"])

    def test_descending_abbreviated_range_is_rejected(self) -> None:
        with pytest.raises(TargetError, match="greater"):
            parse_targets(["10.0.0.9-2"])

    def test_octet_out_of_bounds(self) -> None:
        with pytest.raises(TargetError):
            parse_targets(["10.0.0.1-999"])


class TestCombination:
    def test_comma_separated(self) -> None:
        targets = parse_targets(["10.0.0.1,10.0.0.2"])
        assert len(targets) == 2

    def test_multiple_arguments(self) -> None:
        targets = parse_targets(["10.0.0.1", "10.0.0.4/30"])
        assert len(targets) == 5

    def test_overlapping_arguments_are_deduplicated(self) -> None:
        # 10.0.0.1 is inside 10.0.0.0/30, so the union is four addresses.
        targets = parse_targets(["10.0.0.1", "10.0.0.0/30"])
        assert len(targets) == 4

    def test_duplicates_are_collapsed(self) -> None:
        targets = parse_targets(["10.0.0.1", "10.0.0.1", "10.0.0.0/30"])
        assert sorted({t.address for t in targets}) == [
            "10.0.0.0",
            "10.0.0.1",
            "10.0.0.2",
            "10.0.0.3",
        ]

    def test_dedupe_can_be_disabled(self) -> None:
        targets = parse_targets(["10.0.0.1", "10.0.0.1"], dedupe=False)
        assert len(targets) == 2

    def test_order_is_preserved(self) -> None:
        targets = parse_targets(["10.0.0.3", "10.0.0.1"])
        assert [t.address for t in targets] == ["10.0.0.3", "10.0.0.1"]


class TestTargetFile:
    def test_file_with_comments_and_blanks(self, tmp_path) -> None:
        path = tmp_path / "targets.txt"
        path.write_text(
            textwrap.dedent(
                """\
                # a comment
                10.0.0.1

                10.0.0.2  # trailing comment
                """
            ),
            encoding="utf-8",
        )
        targets = parse_targets([f"@{path}"])
        assert [t.address for t in targets] == ["10.0.0.1", "10.0.0.2"]

    def test_missing_file(self, tmp_path) -> None:
        with pytest.raises(TargetError, match="not found"):
            parse_targets([f"@{tmp_path / 'nope.txt'}"])

    def test_directory_is_rejected(self, tmp_path) -> None:
        with pytest.raises(TargetError, match="not a regular file"):
            parse_targets([f"@{tmp_path}"])


class TestScopeAllowList:
    def test_addresses_outside_scope_are_dropped(self) -> None:
        targets = parse_targets(["10.0.0.0/24"], allow_scope=["10.0.0.0/28"])
        assert len(targets) == 16

    def test_fully_out_of_scope_raises(self) -> None:
        with pytest.raises(ScopeError):
            parse_targets(["192.168.0.1"], allow_scope=["10.0.0.0/8"])

    def test_scope_accepts_network_objects(self) -> None:
        targets = parse_targets(["10.1.2.3"], allow_scope=[ipaddress.ip_network("10.1.0.0/16")])
        assert len(targets) == 1

    def test_hostnames_bypass_the_static_check(self) -> None:
        targets = parse_targets(["example.com"], allow_scope=["10.0.0.0/8"])
        assert targets[0].hostname == "example.com"


class TestExpansionCeiling:
    def test_total_expansion_is_capped(self) -> None:
        specs = [f"10.0.{n}.0/24" for n in range(20)]
        with pytest.raises(TargetError, match="ceiling"):
            parse_targets(specs)

    def test_absolute_ceiling_constant_is_sane(self) -> None:
        assert 0 < MAX_ADDRESSES <= 65536

    def test_expand_target_returns_list(self) -> None:
        assert isinstance(expand_target("10.0.0.1"), list)


class TestPortSpec:
    def test_single_port(self) -> None:
        assert parse_port_spec("22") == [22]

    def test_comma_list(self) -> None:
        assert parse_port_spec("443,22,80") == [22, 80, 443]

    def test_range(self) -> None:
        assert parse_port_spec("1-5") == [1, 2, 3, 4, 5]

    def test_range_and_list(self) -> None:
        assert parse_port_spec("1-3,80") == [1, 2, 3, 80]

    def test_preset_common_is_the_real_top_hundred(self) -> None:
        ports = parse_port_spec("common")
        assert len(ports) == 100
        assert 3389 in ports
        assert 3306 in ports
        assert 5900 in ports
        assert 1 not in ports

    def test_preset_critical(self) -> None:
        ports = parse_port_spec("critical")
        assert 445 in ports and 3389 in ports

    def test_preset_web(self) -> None:
        ports = parse_port_spec("web")
        assert 80 in ports and 443 in ports

    def test_service_name(self) -> None:
        assert 443 in parse_port_spec("https")
        assert 22 in parse_port_spec("ssh")

    def test_all_resolves_to_every_port(self) -> None:
        assert len(parse_port_spec("all")) == 65535

    def test_zero_is_rejected(self) -> None:
        with pytest.raises(TargetError):
            parse_port_spec("0")

    def test_above_65535_is_rejected(self) -> None:
        with pytest.raises(TargetError):
            parse_port_spec("65536")

    def test_descending_range_is_rejected(self) -> None:
        with pytest.raises(TargetError, match="descending"):
            parse_port_spec("100-50")

    def test_unknown_token(self) -> None:
        with pytest.raises(TargetError, match="unrecognised"):
            parse_port_spec("definitely-not-a-service")

    def test_empty(self) -> None:
        with pytest.raises(TargetError):
            parse_port_spec(",")
