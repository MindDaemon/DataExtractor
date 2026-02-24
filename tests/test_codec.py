import pytest

from common.codec import encode_payload, decode_payload


def test_codec_roundtrip():
    original = b"hello network security lab"
    encoded = encode_payload(original, psk="unit-test-key")
    decoded = decode_payload(encoded, psk="unit-test-key")
    assert decoded == original


def test_codec_wrong_key_fails():
    original = b"integrity + confidentiality"
    encoded = encode_payload(original, psk="correct-key")
    with pytest.raises(ValueError):
        decode_payload(encoded, psk="wrong-key")


def test_codec_requires_psk(monkeypatch):
    monkeypatch.delenv("NETSEC_PSK", raising=False)
    with pytest.raises(ValueError):
        encode_payload(b"no default psk")
