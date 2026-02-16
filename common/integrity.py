import hashlib
import zlib

def crc32_bytes(data: bytes) -> int:
    return zlib.crc32(data) & 0xFFFFFFFF

def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()
