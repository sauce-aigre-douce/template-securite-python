# -*- coding: utf-8 -*-
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

@dataclass
class ShellcodeMeta:
    size: int
    entropy: float
    arch_assumed: str
    base: str
    has_nop_sled: bool
    nop_sled: Optional[Dict[str, int]] = None

@dataclass
class ShellcodeReport:
    meta: ShellcodeMeta
    strings: Dict[str, List[str]]
    disassembly: Dict[str, Any]
    emulation: Dict[str, Any]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "meta": self.meta.__dict__,
            "strings": self.strings,
            "disassembly": self.disassembly,
            "emulation": self.emulation,
        }