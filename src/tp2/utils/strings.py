# -*- coding: utf-8 -*-
import re, math, ipaddress
from typing import Dict, List, Optional, Tuple

def shannon_entropy(b: bytes) -> float:
    if not b:
        return 0.0
    freqs = [0]*256
    for x in b: freqs[x] += 1
    ent = 0.0
    n = len(b)
    for c in freqs:
        if c:
            p = c/n
            ent -= p * math.log2(p)
    return round(ent, 3)

def find_nop_sled(b: bytes, min_len=16) -> Optional[Tuple[int, int]]:
    nop = 0x90
    cur = 0
    start = None
    for i, x in enumerate(b):
        if x == nop:
            if start is None:
                start = i
            cur += 1
        else:
            if cur >= min_len:
                return (start, cur)
            cur = 0; start = None
    if cur >= min_len and start is not None:
        return (start, cur)
    return None

def extract_strings(b: bytes, min_len=4) -> Dict[str, List[str]]:
    ascii_strs: List[str] = []
    buf = bytearray()
    for x in b:
        if 32 <= x <= 126:
            buf.append(x)
        else:
            if len(buf) >= min_len:
                ascii_strs.append(buf.decode("ascii", "ignore"))
            buf = bytearray()
    if len(buf) >= min_len:
        ascii_strs.append(buf.decode("ascii", "ignore"))

    utf16_strs: List[str] = []
    try:
        s = b.decode("utf-16le", "ignore")
        for m in re.finditer(r"[ -~]{%d,}" % min_len, s):
            utf16_strs.append(m.group(0))
    except Exception:
        pass

    urls, ips, paths = [], [], []
    for s in ascii_strs + utf16_strs:
        if "http://" in s or "https://" in s:
            for u in re.findall(r"https?://[^\s\"']+", s):
                urls.append(u.strip(" '\"\t\r\n,;"))
        for ip in re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", s):
            try:
                ipaddress.ip_address(ip)
                ips.append(ip)
            except Exception:
                pass
        for p in re.findall(r"[A-Za-z]:\\[^ \t\r\n\"']+|/[^ \t\r\n\"']+", s):
            paths.append(p.strip(" '\"\t\r\n,"))

    return {
        "ascii": sorted(set(ascii_strs))[:500],
        "utf16": sorted(set(utf16_strs))[:500],
        "urls": sorted(set(urls))[:200],
        "ips": sorted(set(ips))[:200],
        "paths": sorted(set(paths))[:200],
    }