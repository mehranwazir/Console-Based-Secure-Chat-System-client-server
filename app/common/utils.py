# """Helper signatures: now_ms, b64e, b64d, sha256_hex."""

# def now_ms(): raise NotImplementedError

# def b64e(b: bytes): raise NotImplementedError

# def b64d(s: str): raise NotImplementedError

# def sha256_hex(data: bytes): raise NotImplementedError


"""
Helper signatures: now_ms, b64e, b64d, sha256_hex.
"""

import time
import base64
from hashlib import sha256


def now_ms() -> int:
    """
    Return current Unix timestamp in milliseconds.
    """
    return int(time.time() * 1000)


def b64e(b: bytes) -> str:
    """
    Base64 encode bytes → UTF-8 string.
    """
    return base64.b64encode(b).decode()


def b64d(s: str) -> bytes:
    """
    Base64 decode UTF-8 string → raw bytes.
    """
    return base64.b64decode(s)


def sha256_hex(data: bytes) -> str:
    """
    SHA-256 digest as lowercase hex string.
    Useful for transcript hash and debugging.
    """
    return sha256(data).hexdigest()



def make_message_digest_bytes(seqno: int, ts_ms: int, ct_base64: str) -> bytes:
    """
    Deterministic canonical byte structure:
        seqno   -> 8-byte big-endian
        ts_ms   -> 8-byte big-endian
        ct      -> raw bytes (base64-decoded)

    Returns the raw bytes that will be hashed and signed.
    """
    seq_bytes = seqno.to_bytes(8, "big")
    ts_bytes = int(ts_ms).to_bytes(8, "big")
    ct_bytes = b64d(ct_base64)
    return seq_bytes + ts_bytes + ct_bytes


def sha256_bytes(data: bytes) -> bytes:
    """
    Return raw SHA-256 digest bytes (not hex-encoded).
    Needed for RSA signing.
    """
    from hashlib import sha256
    return sha256(data).digest()
