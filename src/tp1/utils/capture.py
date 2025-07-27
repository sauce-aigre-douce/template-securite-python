# src/tp1/utils/capture.py
from typing import Iterable, Optional, Dict, Tuple, Set
from collections import Counter

from scapy.all import get_if_list, AsyncSniffer, wrpcap
from scapy.layers.inet import TCP, UDP, ICMP
from scapy.layers.l2 import ARP, SNAP
from scapy.packet import Packet

try:
    from scapy.arch.windows import get_windows_if_list
except Exception:
    get_windows_if_list = None

try:
    from scapy.layers.tls.all import TLS
except Exception:
    TLS = None

try:
    from scapy.contrib.quic import QUIC
except Exception:
    QUIC = None

try:
    from scapy.layers.http import HTTPRequest, HTTPResponse
except Exception:
    HTTPRequest = HTTPResponse = None

try:
    from scapy.layers.dns import DNS
except Exception:
    DNS = None

from pathlib import Path
import pandas as pd

COMMON_LAYERS = [("ARP", ARP), ("ICMP", ICMP), ("TCP", TCP), ("UDP", UDP)]

def list_interfaces_verbose() -> Iterable[str]:
    lines = []
    if get_windows_if_list:
        for i in get_windows_if_list():
            name = i.get("name")
            guid = i.get("guid")
            dev = f"\\\\Device\\\\NPF_{guid}" if guid else None
            ips = ", ".join(i.get("ips", [])) or "-"
            lines.append(f"{name} | {dev} | IPs: {ips}")
    else:
        for dev in get_if_list():
            lines.append(dev)
    return lines

def resolve_iface(name_or_device: Optional[str]) -> Optional[str]:
    if not name_or_device:
        return None
    s = name_or_device.strip()
    if s.startswith(r"\Device\NPF_"):
        return s
    if get_windows_if_list:
        winifs = list(get_windows_if_list() or [])
        for i in winifs:
            if i.get("name") == s and i.get("guid"):
                return f"\\Device\\NPF_{i['guid']}"
        alt = f"{s}-Npcap Packet Driver (NPCAP)-0000"
        for i in winifs:
            if i.get("name") == alt and i.get("guid"):
                return f"\\Device\\NPF_{i['guid']}"
    return s

def _is_quic_long_header(udp_payload: bytes) -> bool:
    return len(udp_payload) > 0 and (udp_payload[0] & 0xC0) == 0xC0

def detect_protocol(pkt: Packet, assume_quic_on_udp443: bool = False) -> str:
    if DNS and pkt.haslayer(DNS):
        return "DNS"

    if TLS and pkt.haslayer(TLS):
        try:
            tls = pkt[TLS]
            ver = getattr(tls, "version", None)
            if ver == 0x0303:
                return "TLSv1.2"
            elif ver == 0x0304:
                return "TLSv1.3"
            else:
                return "TLS"
        except Exception:
            return "TLS"

    if QUIC and pkt.haslayer(QUIC):
        return "QUIC"

    if pkt.haslayer(UDP):
        udp = pkt[UDP]
        if udp.sport == 1900 or udp.dport == 1900:
            try:
                raw = bytes(udp.payload)
                s = raw.decode("latin-1", "ignore")
                if any(x in s for x in ("M-SEARCH", "NOTIFY", "SSDP", "UPnP")):
                    return "SSDP"
            except Exception:
                pass
            return "SSDP"

        if udp.sport == 443 or udp.dport == 443:
            try:
                raw = bytes(udp.payload)
                if _is_quic_long_header(raw):
                    return "QUIC"
                return "QUIC" if assume_quic_on_udp443 else "UDP/443"
            except Exception:
                return "QUIC" if assume_quic_on_udp443 else "UDP/443"

    if pkt.haslayer(SNAP):
        snap = pkt[SNAP]
        try:
            if getattr(snap, "OUI", None) == 0x00000C:
                return "RLDP?"
        except Exception:
            pass

    if HTTPRequest and pkt.haslayer(HTTPRequest):
        return "HTTP"
    if HTTPResponse and pkt.haslayer(HTTPResponse):
        return "HTTP"

    for name, layer in COMMON_LAYERS:
        if pkt.haslayer(layer):
            return name
    try:
        return pkt.lastlayer().name
    except Exception:
        return "UNKNOWN"

def capture_and_analyze(
    iface: Optional[str],
    seconds: int,
    bpf_filter: Optional[str],
    assume_quic_on_udp443: bool = False,
):
    sniffer = AsyncSniffer(iface=iface, store=True, filter=bpf_filter)
    sniffer.start()
    sniffer.join(timeout=seconds)
    pkts = sniffer.stop()

    counts = Counter()
    for p in pkts:
        counts[detect_protocol(p, assume_quic_on_udp443)] += 1

    flows: Dict[tuple, dict] = {}
    dsts: Dict[str, dict] = {}
    for p in pkts:
        src = dst = sport = dport = proto = None
        try:
            if p.haslayer("IP"):
                ip = p.getlayer("IP")
                src, dst = ip.src, ip.dst
            elif p.haslayer("IPv6"):
                ip6 = p.getlayer("IPv6")
                src, dst = ip6.src, ip6.dst
        except Exception:
            pass
        try:
            if p.haslayer(TCP):
                l4 = p[TCP]; sport, dport = l4.sport, l4.dport; proto = "TCP"
            elif p.haslayer(UDP):
                l4 = p[UDP]; sport, dport = l4.sport, l4.dport; proto = "UDP"
        except Exception:
            pass

        plen = len(p) if hasattr(p, "__len__") else 0
        if proto and src and dst:
            key = (proto, src, sport or 0, dst, dport or 0)
            f = flows.setdefault(key, {"packets": 0, "bytes": 0})
            f["packets"] += 1
            f["bytes"] += plen

            d = dsts.setdefault(dst, {"packets": 0, "bytes": 0, "ports": Counter()})
            d["packets"] += 1
            d["bytes"] += plen
            if dport:
                d["ports"][dport] += 1

    dns_map: Dict[str, Set[str]] = {}
    for p in pkts:
        try:
            if DNS and p.haslayer(DNS):
                d = p[DNS]
                if getattr(d, "qr", 0) == 1 and hasattr(d, "an") and d.an:
                    ans = d.an
                    rrlist = []
                    while ans is not None:
                        rrlist.append(ans)
                        ans = getattr(ans, "an", None)
                    for rr in rrlist:
                        if getattr(rr, "type", None) in (1, 28):
                            name = rr.rrname.decode(errors="ignore").strip(".") if isinstance(rr.rrname, bytes) else str(rr.rrname).strip(".")
                            ip = getattr(rr, "rdata", None)
                            if ip:
                                dns_map.setdefault(ip, set()).add(name)
        except Exception:
            pass

    return dict(counts), pkts, flows, dsts, dns_map

def top_destinations_table(dsts: Dict[str, dict], dns_map: Dict[str, set], top_n: int, resolver) -> pd.DataFrame:
    rows = []
    for ip, stats in dsts.items():
        host_from_dns = ",".join(sorted(dns_map.get(ip, []))) if ip in dns_map else ""
        host_rev = resolver(ip) if (not host_from_dns) else ""
        ports = ",".join(str(p) for p, _ in stats["ports"].most_common(3))
        rows.append({
            "Destination IP": ip,
            "Host (DNS/revDNS)": host_from_dns or host_rev or "",
            "Packets": stats["packets"],
            "Bytes": stats["bytes"],
            "Top ports": ports,
        })
    return (pd.DataFrame(rows)
            .sort_values(["Packets", "Bytes"], ascending=False)
            .head(top_n).reset_index(drop=True))

def top_flows_table(flows: Dict[tuple, dict], top_n: int) -> pd.DataFrame:
    rows = []
    for (proto, src, sport, dst, dport), st in flows.items():
        rows.append({
            "Proto": proto, "Src": src, "SPort": sport,
            "Dst": dst, "DPort": dport,
            "Packets": st["packets"], "Bytes": st["bytes"],
        })
    return (pd.DataFrame(rows)
            .sort_values(["Packets", "Bytes"], ascending=False)
            .head(top_n).reset_index(drop=True))