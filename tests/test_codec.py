from common.codec import encode_payload, decode_payload

def test_codec_roundtrip():
    original = b"hello network security lab"
    encoded = encode_payload(original)
    decoded = decode_payload(encoded)
    assert decoded == original
