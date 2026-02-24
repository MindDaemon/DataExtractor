import pytest

from common.cli import validate_ipv4, validate_non_empty, validate_snmp_oid, validate_udp_port


def test_validate_ipv4_accepts_ipv4():
    validate_ipv4("10.0.0.1", "--peer")


def test_validate_ipv4_rejects_non_ipv4():
    with pytest.raises(ValueError):
        validate_ipv4("not-an-ip", "--peer")


def test_validate_udp_port_range():
    validate_udp_port(53, "--dns-port")
    with pytest.raises(ValueError):
        validate_udp_port(0, "--dns-port")
    with pytest.raises(ValueError):
        validate_udp_port(70000, "--dns-port")


def test_validate_snmp_oid_format():
    validate_snmp_oid("1.3.6.1.4.1.55555.1.0")
    with pytest.raises(ValueError):
        validate_snmp_oid("1.3.6.bad.0")


def test_validate_non_empty():
    validate_non_empty("public", "--snmp-community")
    with pytest.raises(ValueError):
        validate_non_empty(" ", "--snmp-community")
