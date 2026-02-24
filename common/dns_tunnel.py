from __future__ import annotations

import base64
from common.frame import HEADER_SIZE

MAX_DNS_LABEL_LEN = 63
MAX_DNS_QNAME_LEN = 253


def normalize_domain(domain: str) -> str:
    cleaned = domain.strip().strip(".").lower()
    if not cleaned:
        raise ValueError("DNS domain must not be empty")
    labels = cleaned.split(".")
    if any(not label or len(label) > MAX_DNS_LABEL_LEN for label in labels):
        raise ValueError("Invalid DNS domain labels")
    return ".".join(labels)


def _encoded_qname_length(encoded: str, domain: str) -> int:
    if not encoded:
        return len(domain)
    label_count = (len(encoded) + MAX_DNS_LABEL_LEN - 1) // MAX_DNS_LABEL_LEN
    label_separators = max(0, label_count - 1)
    # +1 for dot before the configured domain.
    return len(encoded) + label_separators + 1 + len(domain)


def frame_bytes_to_qname(frame_bytes: bytes, domain: str) -> str:
    normalized_domain = normalize_domain(domain)
    encoded = base64.b32encode(frame_bytes).decode("ascii").rstrip("=").lower()
    if _encoded_qname_length(encoded, normalized_domain) > MAX_DNS_QNAME_LEN:
        raise ValueError("Frame too large for DNS qname transport; reduce chunk size")
    labels = [encoded[i : i + MAX_DNS_LABEL_LEN] for i in range(0, len(encoded), MAX_DNS_LABEL_LEN)]
    return ".".join([*labels, normalized_domain])


def qname_to_frame_bytes(qname: str, domain: str) -> bytes | None:
    normalized_domain = normalize_domain(domain)
    normalized_qname = qname.strip().strip(".").lower()
    domain_suffix = "." + normalized_domain
    if normalized_qname == normalized_domain:
        return None
    if not normalized_qname.endswith(domain_suffix):
        return None

    encoded_part = normalized_qname[: -len(domain_suffix)]
    if encoded_part.endswith("."):
        encoded_part = encoded_part[:-1]
    encoded = encoded_part.replace(".", "")
    if not encoded:
        return None

    pad_len = (-len(encoded)) % 8
    padded = (encoded + ("=" * pad_len)).upper()
    try:
        return base64.b32decode(padded, casefold=True)
    except Exception:
        return None


def max_frame_bytes_for_domain(domain: str) -> int:
    normalized_domain = normalize_domain(domain)
    best = 0
    # Covers practical frame sizes for this lab setup.
    for frame_size in range(1, 1025):
        encoded = base64.b32encode(bytes(frame_size)).decode("ascii").rstrip("=").lower()
        if _encoded_qname_length(encoded, normalized_domain) <= MAX_DNS_QNAME_LEN:
            best = frame_size
        else:
            break
    return best


def max_payload_bytes_for_domain(domain: str) -> int:
    max_payload = max_frame_bytes_for_domain(domain) - HEADER_SIZE
    if max_payload < 1:
        raise ValueError("DNS domain leaves no room for frame payload")
    return max_payload
