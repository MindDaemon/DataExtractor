import pytest

from common.dns_tunnel import (
    frame_bytes_to_qname,
    max_payload_bytes_for_domain,
    qname_to_frame_bytes,
)
from common.frame import Frame
from common.config import TYPE_DATA


def test_dns_qname_roundtrip():
    frame = Frame(msg_type=TYPE_DATA, session_id=77, seq=1, total=1, payload=b"abc123")
    domain = "exfil.lab"
    qname = frame_bytes_to_qname(frame.pack(), domain)
    recovered = qname_to_frame_bytes(qname, domain)
    assert recovered == frame.pack()


def test_dns_frame_too_large_raises():
    domain = "exfil.lab"
    max_payload = max_payload_bytes_for_domain(domain)
    oversized = Frame(msg_type=TYPE_DATA, session_id=1, seq=1, total=1, payload=b"x" * (max_payload + 1))
    with pytest.raises(ValueError):
        frame_bytes_to_qname(oversized.pack(), domain)
