from dataclasses import dataclass

MAGIC = b"NS"
VERSION = 1

TYPE_HELLO = 1
TYPE_DATA = 2
TYPE_ACK = 3
TYPE_NACK = 4
TYPE_FIN = 5

DEFAULT_CHUNK_SIZE = 256
DEFAULT_TIMEOUT = 1.5
DEFAULT_RETRIES = 4

@dataclass
class RuntimeConfig:
    iface: str
    peer_ip: str
    timeout: float = DEFAULT_TIMEOUT
    retries: int = DEFAULT_RETRIES
    chunk_size: int = DEFAULT_CHUNK_SIZE
