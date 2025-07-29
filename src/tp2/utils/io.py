# -*- coding: utf-8 -*-
import sys, re, base64
from pathlib import Path
from typing import Optional

def _looks_like_c_hex(s: str) -> bool:
    return bool(re.search(r"(\\x[0-9A-Fa-f]{2}){4,}", s))

def _looks_like_raw_hex(s: str) -> bool:
    s2 = re.sub(r"[^0-9A-Fa-f]", "", s)
    return len(s2) >= 8 and len(s2) % 2 == 0 and all(c in "0123456789abcdefABCDEF" for c in s2)

def _from_c_hex(s: str) -> bytes:
    bs = re.findall(r"\\x([0-9A-Fa-f]{2})", s)
    return bytes(int(b, 16) for b in bs)

def _from_raw_hex(s: str) -> bytes:
    s2 = re.sub(r"[^0-9A-Fa-f]", "", s)
    return bytes.fromhex(s2)

def _maybe_base64(s: str) -> Optional[bytes]:
    s2 = re.sub(r"[\s\r\n]+", "", s)
    if len(s2) < 8:
        return None
    try:
        return base64.b64decode(s2, validate=True)
    except Exception:
        return None

def read_shellcode(stdin_ok=True, file: Optional[str] = None) -> bytes:
    data = b""
    if file:
        data = Path(file).read_bytes()
    elif stdin_ok and not sys.stdin.isatty():
        data = sys.stdin.buffer.read()

    if not data:
        raise SystemExit("[-] Aucun shellcode fourni (utilise --file ou pipe sur stdin).")

    try:
        s = data.decode("utf-8", "ignore")
    except Exception:
        return data

    if _looks_like_c_hex(s):
        return _from_c_hex(s)
    if _looks_like_raw_hex(s):
        return _from_raw_hex(s)
    b64 = _maybe_base64(s)
    if b64:
        return b64
    return data