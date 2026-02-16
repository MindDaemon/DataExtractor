import base64
import zlib

def encode_payload(plain: bytes) -> bytes:
    compressed = zlib.compress(plain, level=6)
    return base64.b64encode(compressed)

def decode_payload(encoded: bytes) -> bytes:
    compressed = base64.b64decode(encoded)
    return zlib.decompress(compressed)
