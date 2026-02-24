from __future__ import annotations

import random
from typing import Optional

from scapy.all import (  # type: ignore
    ASN1_OID,
    ASN1_STRING,
    IP,
    SNMP,
    SNMPset,
    SNMPvarbind,
    UDP,
    send,
    sniff,
)

from common.config import TYPE_ACK, TYPE_NACK
from common.frame import Frame


def _extract_value_bytes(value_obj) -> bytes | None:
    if value_obj is None:
        return None
    if hasattr(value_obj, "val"):
        raw = value_obj.val
        if isinstance(raw, bytes):
            return raw
        if isinstance(raw, str):
            return raw.encode("utf-8")
        return bytes(raw)
    if isinstance(value_obj, bytes):
        return value_obj
    if isinstance(value_obj, str):
        return value_obj.encode("utf-8")
    return None


def _extract_first_varbind(pkt) -> Optional[SNMPvarbind]:
    if not pkt.haslayer(SNMP):
        return None
    pdu = pkt[SNMP].PDU
    if not hasattr(pdu, "varbindlist") or not pdu.varbindlist:
        return None
    return pdu.varbindlist[0]


def send_frame(
    peer_ip: str,
    frame: Frame,
    iface: str,
    snmp_oid: str,
    snmp_port: int = 161,
    snmp_community: str = "public",
) -> None:
    vb = SNMPvarbind(oid=ASN1_OID(snmp_oid), value=ASN1_STRING(frame.pack()))
    pkt = (
        IP(dst=peer_ip)
        / UDP(sport=random.randint(1024, 65535), dport=snmp_port)
        / SNMP(community=snmp_community, PDU=SNMPset(id=random.randint(1, 0x7FFFFFFF), varbindlist=[vb]))
    )
    send(pkt, iface=iface, verbose=False)


def _parse_control_packet(
    pkt,
    peer_ip: str,
    snmp_oid: str,
    snmp_port: int,
    snmp_community: str,
) -> Optional[Frame]:
    if not pkt.haslayer(IP) or not pkt.haslayer(UDP) or not pkt.haslayer(SNMP):
        return None
    if pkt[IP].src != peer_ip:
        return None
    if pkt[UDP].dport != snmp_port:
        return None

    community_obj = pkt[SNMP].community
    community = community_obj.val.decode("utf-8", errors="ignore") if hasattr(community_obj, "val") else str(community_obj)
    if community != snmp_community:
        return None

    varbind = _extract_first_varbind(pkt)
    if varbind is None:
        return None

    oid_val = varbind.oid.val if hasattr(varbind.oid, "val") else str(varbind.oid)
    if str(oid_val) != snmp_oid:
        return None

    payload = _extract_value_bytes(varbind.value)
    if payload is None:
        return None

    try:
        return Frame.unpack(payload)
    except Exception:
        return None


def wait_for_ack(
    iface: str,
    peer_ip: str,
    session_id: int,
    seq: int,
    timeout: float,
    snmp_oid: str,
    snmp_port: int = 161,
    snmp_community: str = "public",
) -> tuple[bool, str]:
    packets = sniff(
        iface=iface,
        filter=f"udp and src host {peer_ip} and dst port {snmp_port}",
        timeout=timeout,
        count=40,
    )
    for pkt in packets:
        frame = _parse_control_packet(
            pkt,
            peer_ip=peer_ip,
            snmp_oid=snmp_oid,
            snmp_port=snmp_port,
            snmp_community=snmp_community,
        )
        if not frame:
            continue
        if frame.session_id != session_id or frame.seq != seq:
            continue
        if frame.msg_type == TYPE_ACK:
            return True, "ACK"
        if frame.msg_type == TYPE_NACK:
            reason = frame.payload.decode("utf-8", errors="replace") if frame.payload else "NACK"
            return False, f"NACK:{reason}"
    return False, "TIMEOUT"
