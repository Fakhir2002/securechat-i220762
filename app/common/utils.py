"""Common utility helpers: base64, timestamps, SHA-256."""

import base64
import time
import hashlib
from typing import Union


def now_ms() -> int:
    """Return current time in Unix milliseconds."""
    return int(time.time() * 1000)


def sha256_hex(data: Union[bytes, str]) -> str:
    """
    Compute SHA-256 and return hex string.
    Accepts bytes or str (utf-8).
    """
    if isinstance(data, str):
        data = data.encode("utf-8")
    return hashlib.sha256(data).hexdigest()


def b64_encode(data: bytes) -> str:
    """
    Base64-encode bytes -> str (ASCII).
    """
    return base64.b64encode(data).decode("ascii")


def b64_decode(s: str) -> bytes:
    """
    Base64-decode str -> bytes.
    """
    return base64.b64decode(s.encode("ascii"))
