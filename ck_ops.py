```python
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
    algo = p.get("algo","sha256").lower()
    if algo not in {"md5","sha1","sha256","sha512","blake2b"}:
        raise ValueError("Unsupported hash algo")
    h = getattr(hashlib, algo)()
    h.update(data)
    return h.hexdigest().encode("ascii"), {"algo":algo}

def hmac_sha256(data: bytes, p: Dict[str, Any]):
    key = p.get("key","")
    use_hex = bool(p.get("hex_key", False))
    key_bytes = hex_to_bytes(key) if use_hex else to_bytes(key)
    mac = hmac.new(key_bytes, data, hashlib.sha256).hexdigest()
    return mac.encode("ascii"), {}

def xor_cipher(data: bytes, p: Dict[str, Any]):
    key = p.get("key","")
    if not key:
        raise ValueError("XOR key required")
    key_bytes = hex_to_bytes(key) if p.get("hex_key", False) else to_bytes(key)
    out = bytes(b ^ key_bytes[i % len(key_bytes)] for i, b in enumerate(data))
    return out, {}

# --- Transform ---
def regex_find_replace(data: bytes, p: Dict[str, Any]):
    pattern = p.get("pattern","")
    repl = p.get("repl","")
    flags = regex_lib.DOTALL
    if p.get("ignore_case"): flags |= regex_lib.IGNORECASE
    try:
        s = try_decode_utf8(data)
        out = regex_lib.sub(pattern, repl, s, timeout=0.5, flags=flags)
        return out.encode("utf-8", errors="replace"), {}
    except regex_lib.TimeoutError:
        raise TimeoutError("Regex timed out")
    except Exception as e:
        raise ValueError(f"Regex error: {e}")

def case_convert(data: bytes, p: Dict[str, Any]):
    mode = p.get("mode","lower")
    s = try_decode_utf8(data)
    if mode=="lower": o = s.lower()
    elif mode=="upper": o = s.upper()
    elif mode=="title": o = s.title()
    else: o = s
    return o.encode("utf-8"), {}

def reverse_text(data: bytes, p: Dict[str, Any]):
    s = try_decode_utf8(data)
    return s[::-1].encode("utf-8"), {}

def unique_lines(data: bytes, p: Dict[str, Any]):
    s = try_decode_utf8(data)
    seen, out = set(), []
    for line in s.splitlines():
        if line not in seen:
            seen.add(line); out.append(line)
    return ("\n".join(out)).encode("utf-8"), {}

def sort_lines(data: bytes, p: Dict[str, Any]):
    s = try_decode_utf8(data)
    reverse = bool(p.get("descending", False))
    lines = sorted(s.splitlines(), reverse=reverse)
    return ("\n".join(lines)).encode("utf-8"), {}

def split_join(data: bytes, p: Dict[str, Any]):
    s = try_decode_utf8(data)
    sep = p.get("split_on","\\n").encode("utf-8").decode("unicode_escape")
    joiner = p.get("join_with","\\n").encode("utf-8").decode("unicode_escape")
    parts = s.split(sep)
    return joiner.join(parts).encode("utf-8"), {}

# --- Analysis ---
def char_freq(data: bytes, p: Dict[str, Any]):
    # returns JSON map of char->count (first 256 codepoints)
    s = try_decode_utf8(data)
    freq: Dict[str,int] = {}
    for ch in s:
        if ord(ch) < 256:
            freq[ch] = freq.get(ch,0)+1
    return json.dumps(freq, ensure_ascii=False, indent=2).encode("utf-8"), {"format":"json"}

def entropy_op(data: bytes, p: Dict[str, Any]):
    e = estimate_entropy(data)
    return f"{e:.4f}".encode("ascii"), {}

def jwt_decode(data: bytes, p: Dict[str, Any]):
    s = try_decode_utf8(data).strip()
    try:
        header = jwt.get_unverified_header(s)
        payload = jwt.decode(s, options={"verify_signature": False, "verify_exp": False})
        out = {"header": header, "payload": payload}
        return json.dumps(out, indent=2).encode("utf-8"), {"format":"json"}
    except Exception as e:
        raise ValueError(f"JWT parse failed: {e}")

# Register ops
register(Operation("b64e","Base64 Encode","Encoding", base64_encode))
register(Operation("b64d","Base64 Decode","Encoding", base64_decode))
register(Operation("urle","URL Encode","Encoding", url_encode))
register(Operation("urld","URL Decode","Encoding", url_decode))
register(Operation("hex2bin","Hex → Bytes","Encoding", hex_to_ascii))
register(Operation("bin2hex","Bytes → Hex","Encoding", ascii_to_hex, output_hint="hex"))

register(Operation("hash","Hash","Crypto", hash_digest, params_schema={"algo":["md5","sha1","sha256","sha512","blake2b"]}))
register(Operation("hmac256","HMAC-SHA256","Crypto", hmac_sha256, params_schema={"key":"", "hex_key": False}))
register(Operation("xor","XOR","Crypto", xor_cipher, params_schema={"key":"", "hex_key": False}))

register(Operation("re_sub","Regex Find/Replace","Transform", regex_find_replace, params_schema={"pattern":"", "repl":"", "ignore_case": False}))
register(Operation("case","Case Convert","Transform", case_convert, params_schema={"mode":["lower","upper","title"]}))
register(Operation("reverse","Reverse","Transform", reverse_text))
register(Operation("unique","Unique Lines","Transform", unique_lines))
register(Operation("sort","Sort Lines","Transform", sort_lines, params_schema={"descending": False}))
register(Operation("splitjoin","Split/Join","Transform", split_join, params_schema={"split_on":"\\n", "join_with":"\\n"}))

register(Operation("freq","Char/Byte Frequency (JSON)","Analysis", char_freq, output_hint="json"))
register(Operation("entropy","Entropy Estimate","Analysis", entropy_op))
register(Operation("jwt","JWT Decode (no verify)","Analysis", jwt_decode, output_hint="json"))

# ------------------------------
# Magic detection
# ------------------------------
def magic_detect(sample: str) -> List[Tuple[str, float]]:
    hints: List[Tuple[str, float]] = []
    if looks_like_base64(sample): hints.append(("Base64", 0.9))
    if looks_like_hex(sample): hints.append(("Hex", 0.8))
    if looks_like_jwt(sample): hints.append(("JWT", 0.95))
    if looks_like_url_encoded(sample): hints.append(("URL-Encoded", 0.6))
    return sorted(hints, key=lambda x: x[1], reverse=True)
