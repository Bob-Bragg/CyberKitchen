from __future__ import annotations
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Tuple
import base64, binascii, hashlib, hmac, json, math, re, urllib.parse
import regex as regex_lib  # supports timeouts
import jwt  # pyjwt (we won't verify by default)

# ------------------------------
# Utilities
# ------------------------------
def clamp_bytes(b: bytes, max_len: int = 2_000_000) -> bytes:
    if len(b) > max_len:
        return b[:max_len]
    return b

def to_bytes(x: Any, encoding: str = "utf-8") -> bytes:
    if isinstance(x, bytes):
        return x
    return str(x).encode(encoding, errors="replace")

def try_decode_utf8(b: bytes) -> str:
    try:
        return b.decode("utf-8")
    except Exception:
        return b.decode("latin-1", errors="replace")

def bytes_to_hex(b: bytes) -> str:
    return binascii.hexlify(b).decode("ascii")

def hex_to_bytes(s: str) -> bytes:
    s = s.strip().replace(" ", "").replace("\n", "")
    return binascii.unhexlify(s)

def estimate_entropy(b: bytes) -> float:
    if not b:
        return 0.0
    freq = [0]*256
    for x in b:
        freq[x]+=1
    ent = 0.0
    n = len(b)
    for c in freq:
        if c:
            p = c/n
            ent -= p*math.log2(p)
    return ent

def looks_like_base64(s: str) -> bool:
    s = s.strip()
    if len(s) < 8: return False
    if re.fullmatch(r"[A-Za-z0-9+/=\s]+", s) is None:
        return False
    try:
        base64.b64decode(s, validate=True)
        return True
    except Exception:
        return False

def looks_like_hex(s: str) -> bool:
    s = s.strip().replace(" ", "")
    return len(s) >= 2 and re.fullmatch(r"[0-9A-Fa-f]+", s) is not None and len(s) % 2 == 0

def looks_like_jwt(s: str) -> bool:
    parts = s.strip().split(".")
    return len(parts) in (2,3) and all(re.fullmatch(r"[A-Za-z0-9_\-]+", p or "") for p in parts)

def looks_like_url_encoded(s: str) -> bool:
    return "%" in s or "+" in s

# ------------------------------
# Operation spec / registry
# ------------------------------
@dataclass
class Operation:
    key: str
    name: str
    category: str
    fn: Callable[[bytes, Dict[str, Any]], Tuple[bytes, Dict[str, Any]]]
    params_schema: Dict[str, Any] = field(default_factory=dict)
    output_hint: str = "auto"  # "auto" | "text" | "hex" | "json"

OPS: Dict[str, Operation] = {}

def register(op: Operation):
    OPS[op.key] = op

# ------------------------------
# Implementations
# ------------------------------

# --- Encoding ---
def base64_encode(data: bytes, p: Dict[str, Any]):
    return base64.b64encode(data), {}

def base64_decode(data: bytes, p: Dict[str, Any]):
    try:
        return base64.b64decode(data, validate=False), {}
    except Exception as e:
        raise ValueError(f"Base64 decode failed: {e}")

def url_encode(data: bytes, p: Dict[str, Any]):
    return urllib.parse.quote_from_bytes(data).encode("ascii"), {}

def url_decode(data: bytes, p: Dict[str, Any]):
    try:
        s = try_decode_utf8(data)
        return urllib.parse.unquote_plus(s).encode("utf-8", errors="replace"), {}
    except Exception as e:
        raise ValueError(f"URL decode failed: {e}")

def hex_to_ascii(data: bytes, p: Dict[str, Any]):
    s = try_decode_utf8(data)
    try:
        return hex_to_bytes(s), {}
    except Exception as e:
        raise ValueError(f"Hex parse failed: {e}")

def ascii_to_hex(data: bytes, p: Dict[str, Any]):
    return bytes(bytes_to_hex(data), "ascii"), {"format":"hex"}

# --- Crypto ---
def hash_digest(data: bytes, p: Dict[str, Any]):
    algo
