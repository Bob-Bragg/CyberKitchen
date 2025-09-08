from ck_ops import to_bytes, bytes_to_hex, hex_to_bytes, looks_like_base64, OPS

def test_hex_roundtrip():
    s = b"hello\x00world"
    hx = bytes_to_hex(s)
    assert hex_to_bytes(hx) == s

def test_b64():
    data = b"CyberKitchen"
    enc,_ = OPS["b64e"].fn(data, {})
    dec,_ = OPS["b64d"].fn(enc, {})
    assert dec == data

def test_hash_sha256():
    data = b"abc"
    out,_ = OPS["hash"].fn(data, {"algo":"sha256"})
    assert out.decode().startswith("ba7816bf")

def test_xor():
    data = b"\x00\x01\x02"
    out,_ = OPS["xor"].fn(data, {"key":"ff", "hex_key": True})
    assert out == b"\xff\xfe\xfd"

def test_magic():
    assert looks_like_base64("aGVsbG8=") is True
