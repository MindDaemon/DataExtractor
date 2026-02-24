from __future__ import annotations

import ipaddress
import logging
import re

LOG_LEVELS = ("DEBUG", "INFO", "WARNING", "ERROR")
SNMP_OID_RE = re.compile(r"^\d+(?:\.\d+)+$")


def configure_logging(level: str) -> None:
    logging.basicConfig(
        level=getattr(logging, level.upper(), logging.INFO),
        format="%(levelname)s %(message)s",
    )


def validate_ipv4(value: str, label: str) -> None:
    try:
        addr = ipaddress.ip_address(value)
    except ValueError as exc:
        raise ValueError(f"{label} must be a valid IPv4 address: {value}") from exc
    if addr.version != 4:
        raise ValueError(f"{label} must be IPv4: {value}")


def validate_udp_port(value: int, label: str) -> None:
    if not (1 <= int(value) <= 65535):
        raise ValueError(f"{label} must be in range 1..65535")


def validate_non_empty(value: str, label: str) -> None:
    if value is None or str(value).strip() == "":
        raise ValueError(f"{label} must not be empty")


def validate_snmp_oid(value: str) -> None:
    if not SNMP_OID_RE.fullmatch(value.strip()):
        raise ValueError(f"SNMP OID format invalid: {value}")
