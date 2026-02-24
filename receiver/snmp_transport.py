from __future__ import annotations

import random
from typing import Optional

from scapy.all import (  # type: ignore
    ASN1_OID,
    ASN1_STRING,
    IP,
    SNMP,
    SNMPresponse,
    SNMPvarbind,
    UDP,
    send,
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


def extract_frame(
    pkt,
    peer_ip: str,
    snmp_oid: str,
    snmp_port: int = 161,
    snmp_community: str = "public",
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


def send_control(
    peer_ip: str,
    iface: str,
    msg_type: int,
    session_id: int,
    seq: int,
    total: int,
    snmp_oid: str,
    snmp_port: int = 161,
    snmp_community: str = "public",
    payload: bytes = b"",
) -> None:
    frame = Frame(msg_type=msg_type, session_id=session_id, seq=seq, total=total, payload=payload)
    vb = SNMPvarbind(oid=ASN1_OID(snmp_oid), value=ASN1_STRING(frame.pack()))
    pkt = (
        IP(dst=peer_ip)
        / UDP(sport=random.randint(1024, 65535), dport=snmp_port)
        / SNMP(community=snmp_community, PDU=SNMPresponse(id=random.randint(1, 0x7FFFFFFF), varbindlist=[vb]))
    )
    send(pkt, iface=iface, verbose=False)


def send_ack(
    peer_ip: str,
    iface: str,
    session_id: int,
    seq: int,
    total: int,
    snmp_oid: str,
    snmp_port: int = 161,
    snmp_community: str = "public",
) -> None:
    send_control(
        peer_ip,
        iface,
        TYPE_ACK,
        session_id,
        seq,
        total,
        snmp_oid=snmp_oid,
        snmp_port=snmp_port,
        snmp_community=snmp_community,
    )


def send_nack(
    peer_ip: str,
    iface: str,
    session_id: int,
    seq: int,
    total: int,
    snmp_oid: str,
    snmp_port: int = 161,
    snmp_community: str = "public",
    reason: str = "CRC",
) -> None:
    send_control(
        peer_ip,
        iface,
        TYPE_NACK,
        session_id,
        seq,
        total,
        snmp_oid=snmp_oid,
        snmp_port=snmp_port,
        snmp_community=snmp_community,
        payload=reason.encode(),
    )
