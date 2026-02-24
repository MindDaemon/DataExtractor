import pytest

from common.frame import Frame
from common.config import TYPE_DATA


def test_frame_roundtrip():
    f = Frame(msg_type=TYPE_DATA, session_id=123, seq=1, total=10, payload=b"abc")
    raw = f.pack()
    f2 = Frame.unpack(raw)
    assert f2.msg_type == TYPE_DATA
    assert f2.session_id == 123
    assert f2.seq == 1
    assert f2.total == 10
    assert f2.payload == b"abc"


def test_frame_detects_header_tamper():
    f = Frame(msg_type=TYPE_DATA, session_id=123, seq=1, total=10, payload=b"abc")
    raw = bytearray(f.pack())
    raw[8] ^= 0x01  # flip one byte inside seq field
    with pytest.raises(ValueError):
        Frame.unpack(bytes(raw))
