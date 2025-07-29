# -*- coding: utf-8 -*-
from typing import Any, Dict

try:
    import pylibemu
except Exception:
    pylibemu = None

def emulate_with_pylibemu(b: bytes, max_steps: int = 20000) -> Dict[str, Any]:
    if pylibemu is None:
        return {"available": False, "note": "pylibemu indisponible", "summary": "", "api_calls": []}

    emu = pylibemu.Emulator()
    starts = [0]
    if len(b) > 64:
        starts += [16, 32, 64]

    for off in starts:
        try:
            ret = emu.prepare(b[off:])
            if ret < 0:
                continue
            steps = 0
            while steps < max_steps and emu.execute(1) == 0:
                steps += 1
            summary = emu.emu_profile_output
            apis = []
            try:
                apis = emu.api_calls()
            except Exception:
                pass
            return {
                "available": True,
                "offset": off,
                "steps": steps,
                "summary": summary,
                "api_calls": apis
            }
        except Exception:
            continue
    return {"available": True, "note": "aucun point d’entrée trouvé", "summary": "", "api_calls": []}