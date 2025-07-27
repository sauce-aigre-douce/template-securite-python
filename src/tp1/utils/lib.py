# src/tp1/utils/lib.py
import json, socket, platform, datetime as dt
from pathlib import Path
from typing import Optional, Dict, Any
import pandas as pd

def reverse_dns(ip: str, timeout: float = 0.5) -> Optional[str]:
    try:
        socket.setdefaulttimeout(timeout)
        name, _, _ = socket.gethostbyaddr(ip)
        return name
    except Exception:
        return None

def ensure_parent(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)

def write_json(obj: Dict[str, Any], path: Path) -> None:
    ensure_parent(path)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(obj, f, ensure_ascii=False, indent=2)

def make_summary(
    counts: Dict[str, int],
    top_dest_df: pd.DataFrame,
    top_flows_df: pd.DataFrame,
    iface: str, seconds: int, bpf_filter: str,
) -> Dict[str, Any]:
    return {
        "meta": {
            "host": platform.node(),
            "iface": iface,
            "seconds": seconds,
            "bpf_filter": bpf_filter,
            "timestamp": dt.datetime.now().isoformat(timespec="seconds"),
        },
        "protocol_counts": counts,
        "top_destinations": top_dest_df.to_dict(orient="records"),
        "top_flows": top_flows_df.to_dict(orient="records"),
    }