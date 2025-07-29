# -*- coding: utf-8 -*-
from typing import Dict, Any
from capstone import Cs, CS_ARCH_X86, CS_MODE_32, CS_MODE_64

def disassemble(b: bytes, arch: str = "x86", base: int = 0x0, max_instr: int = 2000) -> Dict[str, Any]:
    if arch not in ("x86", "x64"):
        raise ValueError("arch doit être 'x86' ou 'x64'")
    mode = CS_MODE_32 if arch == "x86" else CS_MODE_64
    cs = Cs(CS_ARCH_X86, mode)
    cs.detail = False

    lines = []
    count = 0
    for i in cs.disasm(b, base):
        lines.append(f"0x{i.address:08x}: {i.mnemonic} {i.op_str}".strip())
        count += 1
        if count >= max_instr:
            break

    hist = {}
    for ln in lines:
        m = ln.split(": ", 1)[-1].split(" ", 1)[0]
        hist[m] = hist.get(m, 0) + 1

    return {
        "arch": arch,
        "base": f"0x{base:x}",
        "instructions": lines,
        "mnemonic_hist": sorted(hist.items(), key=lambda x: x[1], reverse=True)[:50],
        "truncated": len(lines) >= max_instr
    }