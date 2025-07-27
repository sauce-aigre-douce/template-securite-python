# src/tp1/main.py  (ou tp1/main.py selon la structure du template)
import argparse
import datetime as dt
import socket
import json, platform, os
from collections import Counter
from pathlib import Path
from typing import Dict, Optional, Iterable

from scapy.all import get_if_list, AsyncSniffer, wrpcap
from scapy.layers.inet import TCP, UDP, ICMP
from scapy.layers.l2 import ARP, SNAP
from scapy.packet import Packet

try:
    import psutil  # pour corréler flux <-> processus (Windows)
except Exception:
    psutil = None

try:
    from scapy.arch.windows import get_windows_if_list  # Windows only
except Exception:
    get_windows_if_list = None

try:
    from scapy.layers.tls.all import TLS  # TLS record
except Exception:
    TLS = None

try:
    from scapy.contrib.quic import QUIC  # nécessite scapy >= 2.5 (selon install)
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

import pandas as pd
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.backends.backend_pdf import PdfPages


# --- AJOUTS POUR OPENAI ---
OPENAI_API_KEY = "REMPLACEZ_PAR_VOTRE_CLE"   # <<< clé en dur 
DEFAULT_AI_MODEL = "gpt-4.1-mini"


COMMON_LAYERS = [("ARP", ARP), ("ICMP", ICMP), ("TCP", TCP), ("UDP", UDP)]

ASSUME_QUIC_ON_UDP443 = False

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
# - Si l'on passe déjà un device Npcap (commence par \Device\NPF_), on le renvoie tel quel.
# - Si l'on passe un 'friendly name' (ex: 'Ethernet 2'), on construit \Device\NPF_{GUID}.
# - Fallback: si le GUID de l'interface ne marche pas, on essaie la variante '<name>-Npcap Packet Driver (NPCAP)-0000' (certains Windows exposent ce device).

    if not name_or_device:
        return None
    s = name_or_device.strip()

    # Déjà un device Npcap ? => on renvoie tel quel
    if s.startswith(r"\Device\NPF_"):
        return s

    # Mapping friendly name -> \Device\NPF_{GUID}
    if get_windows_if_list:
        winifs = list(get_windows_if_list() or [])

        # 1) Essayer le nom exact (ex: "Ethernet 2")
        for i in winifs:
            if i.get("name") == s and i.get("guid"):
                # IMPORTANT: un seul antislash dans la valeur finale
                return f"\\Device\\NPF_{i['guid']}"

        # 2) Fallback: variante Npcap Packet Driver (NPCAP)-0000
        alt = f"{s}-Npcap Packet Driver (NPCAP)-0000"
        for i in winifs:
            if i.get("name") == alt and i.get("guid"):
                return f"\\Device\\NPF_{i['guid']}"

    # Dernier recours : renvoyer tel quel (laisse Scapy tenter la résolution)
    return s

def _is_quic_long_header(udp_payload: bytes) -> bool:
    # QUIC long header: 0b11xxxxxx sur le 1er octet (RFC 9000)
    return len(udp_payload) > 0 and (udp_payload[0] & 0xC0) == 0xC0

def detect_protocol(pkt: Packet) -> str:
    # --- Protocoles applicatifs spécifiques d'abord ---

    # DNS
    if DNS and pkt.haslayer(DNS):
        return "DNS"

    # TLS (essayez d’identifier v1.2/v1.3 si observable)
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

    # QUIC (couche native)
    if QUIC and pkt.haslayer(QUIC):
        return "QUIC"

    # UDP-based (SSDP + QUIC heuristique)
    if pkt.haslayer(UDP):
        udp = pkt[UDP]

        # SSDP (UPnP) : UDP/1900 + signature HTTP-like
        if udp.sport == 1900 or udp.dport == 1900:
            try:
                raw = bytes(udp.payload)
                s = raw.decode("latin-1", "ignore")
                if "M-SEARCH" in s or "NOTIFY" in s or "SSDP" in s or "UPnP" in s:
                    return "SSDP"
            except Exception:
                pass
            return "SSDP"

        # QUIC (heuristique) : UDP/443 -> QUIC si long header, sinon selon option
        if udp.sport == 443 or udp.dport == 443:
            try:
                raw = bytes(udp.payload)
                # long header QUIC : 0b11xxxxxx
                if _is_quic_long_header(raw):
                    return "QUIC"
                return "QUIC" if ASSUME_QUIC_ON_UDP443 else "UDP/443"
            except Exception:
                return "QUIC" if ASSUME_QUIC_ON_UDP443 else "UDP/443"

    # RLDP (heuristique Cisco L2 via SNAP OUI 0x00000C)
    if pkt.haslayer(SNAP):
        snap = pkt[SNAP]
        try:
            if getattr(snap, "OUI", None) == 0x00000C:
                return "RLDP?"  # heuristique (sans dissector dédié)
        except Exception:
            pass

    # HTTP (si du HTTP clair circule)
    if HTTPRequest and pkt.haslayer(HTTPRequest):
        return "HTTP"
    if HTTPResponse and pkt.haslayer(HTTPResponse):
        return "HTTP"

    # --- Couches classiques ---
    for name, layer in COMMON_LAYERS:
        if pkt.haslayer(layer):
            return name

    try:
        return pkt.lastlayer().name
    except Exception:
        return "UNKNOWN"

def capture_and_analyze(iface: Optional[str], seconds: int, bpf_filter: Optional[str] = None):
    """
    Retourne:
      - counts: stats par protocole (dict)
      - pkts: liste des paquets
      - flows: dict[(proto, src, sport, dst, dport)] -> {"packets": int, "bytes": int}
      - dsts: dict[dst_ip] -> {"packets": int, "bytes": int, "ports": Counter}
      - dns_map: dict[ip] -> set([domain...]) depuis réponses DNS
    """
    sniffer = AsyncSniffer(iface=iface, store=True, filter=bpf_filter)
    sniffer.start()
    sniffer.join(timeout=seconds)
    pkts = sniffer.stop()

    counts = Counter()
    for p in pkts:
        counts[detect_protocol(p)] += 1

    flows: Dict[tuple, dict] = {}
    dsts: Dict[str, dict] = {}
    for p in pkts:
        src, dst, sport, dport, proto = None, None, None, None, None
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

    dns_map: Dict[str, set] = {}
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
                        if getattr(rr, "type", None) in (1, 28):  # A / AAAA
                            name = rr.rrname.decode(errors="ignore").strip(".") if isinstance(rr.rrname, bytes) else str(rr.rrname).strip(".")
                            ip = getattr(rr, "rdata", None)
                            if ip:
                                dns_map.setdefault(ip, set()).add(name)
        except Exception:
            pass

    return dict(counts), pkts, flows, dsts, dns_map

def reverse_dns(ip: str, timeout=0.5) -> Optional[str]:
    try:
        socket.setdefaulttimeout(timeout)
        name, _, _ = socket.gethostbyaddr(ip)
        return name
    except Exception:
        return None

def top_destinations_table(dsts: Dict[str, dict], dns_map: Dict[str, set], top_n: int, do_reverse: bool):
    rows = []
    for ip, stats in dsts.items():
        host_from_dns = ",".join(sorted(dns_map.get(ip, []))) if ip in dns_map else ""
        host_rev = reverse_dns(ip) if do_reverse and not host_from_dns else ""
        ports = ",".join(str(p) for p, _ in stats["ports"].most_common(3))
        rows.append({
            "Destination IP": ip,
            "Host (DNS/revDNS)": host_from_dns or host_rev or "",
            "Packets": stats["packets"],
            "Bytes": stats["bytes"],
            "Top ports": ports,
        })
    df = pd.DataFrame(rows).sort_values(["Packets", "Bytes"], ascending=False).head(top_n).reset_index(drop=True)
    return df

def top_flows_table(flows: Dict[tuple, dict], top_n: int):
    rows = []
    for (proto, src, sport, dst, dport), st in flows.items():
        rows.append({
            "Proto": proto,
            "Src": src, "SPort": sport,
            "Dst": dst, "DPort": dport,
            "Packets": st["packets"],
            "Bytes": st["bytes"],
        })
    df = pd.DataFrame(rows).sort_values(["Packets", "Bytes"], ascending=False).head(top_n).reset_index(drop=True)
    return df

def generate_ai_pdf_openai(summary_json: dict, out_pdf: str, model: str = DEFAULT_AI_MODEL, out_txt: Optional[str] = None) -> None:
    """
    Envoie le JSON d'analyse à l'API OpenAI (Responses API + Code Interpreter) pour:
      - tracer un histogramme des protocoles,
      - générer des tableaux (protocoles, top destinations, top flows),
      - rédiger une analyse textuelle,
      - exporter un PDF et le télécharger en local.
    Sauvegarde aussi un résumé texte optionnel si out_txt est fourni.
    """
    # import local pour éviter erreur si la lib n'est pas installée
    from openai import OpenAI
    import json

    if not OPENAI_API_KEY or OPENAI_API_KEY.startswith("REMPLACEZ"):
        raise RuntimeError("OPENAI_API_KEY n'est pas renseignée (ou placeholder).")

    client = OpenAI(api_key=OPENAI_API_KEY)

    # On sérialise le JSON en texte (solution simple et robuste)
    payload_str = json.dumps(summary_json, ensure_ascii=False, indent=2)

    # Prompt (instructions) : ce que nous demandons à l'IA
    instructions = (
        "Tu es un ingénieur analyste réseau. On te fournit un JSON de capture (protocoles, top destinations, top flows, méta). "
        "Ta mission : 1) Générer un PDF multi-pages avec: "
        "• Une page de titre récapitulative (iface, durée, filtre, timestamp) ; "
        "• Un histogramme des protocoles (Protocole vs Nombre de paquets) ; "
        "• Un tableau des protocoles (Protocole, Paquets, %) ; "
        "• Un tableau Top destinations (IP, Host, Packets, Bytes, Top ports) ; "
        "• Un tableau Top flows (proto, src:port -> dst:port, packets, bytes) ; "
        "• Une analyse écrite (activité probable de l'utilisateur, services contactés, QUIC/HTTP/3, CDNs, limites méthodo, recommandations). "
        "2) Le PDF doit s'appeler exactement 'report.pdf'. 3) Utilise matplotlib sans style custom. "
        "4) N'insère aucune donnée personnelle sensible hors JSON. "
        "5) Retourne aussi un court résumé texte (10-15 lignes) si demandé."
    )

    # Contenu envoyé : on met le JSON en clair dans le message
    user_text = (
        "Voici le JSON de la capture (clé 'meta', 'protocol_counts', 'top_destinations', 'top_flows') :\n\n"
        f"{payload_str}\n\n"
        "Consignes: Lis ce JSON en Python, construis les DataFrames, produis les figures avec matplotlib, "
        "mets tout dans un PDF 'report.pdf'."
    )

    # Appel Responses API + Code Interpreter
    # NB: on demande explicitement l'outil "code_interpreter"
    resp = client.responses.create(
        model=model,
        instructions=instructions,
        input=[{"role": "user", "content": [{"type": "input_text", "text": user_text}]}],
        tools=[{"type": "code_interpreter"}],
    )

    # On convertit la réponse en dict pour chercher les files générés par le code interpreter.
    # Selon la version du SDK, on a .model_dump() / .to_dict() / .json() ; on essaie plusieurs voies.
    try:
        data = resp.model_dump()
    except Exception:
        try:
            data = json.loads(resp.json())
        except Exception:
            # Dernier recours: str -> json (peut échouer si non JSON)
            data = {}

    # Recherche récursive de tous les file_id potentiels retournés par le tool code_interpreter
    def _collect_file_ids(obj):
        found = []
        if isinstance(obj, dict):
            for k, v in obj.items():
                if k == "file_id" and isinstance(v, str):
                    found.append(v)
                else:
                    found.extend(_collect_file_ids(v))
        elif isinstance(obj, list):
            for it in obj:
                found.extend(_collect_file_ids(it))
        return found

    file_ids = list(dict.fromkeys(_collect_file_ids(data)))  # unique et dans l'ordre

    if not file_ids:
        # Parfois, le modèle retourne d'abord un "intermediate" sans fichiers ; on retente via a) polling (non stream) ou b) instructions.
        # Ici, on échoue explicitement avec une erreur claire.
        raise RuntimeError("Aucun fichier PDF trouvé dans la réponse du Code Interpreter. Réessaie ou vérifie les logs de la réponse.")

    # Si plusieurs fichiers, on essaie de trouver celui qui est 'report.pdf' via metadata filename
    target_file_id = None
    for fid in file_ids:
        try:
            meta = client.files.retrieve(fid)
            fname = getattr(meta, "filename", "") or getattr(meta, "name", "")
            if isinstance(fname, str) and fname.lower().endswith(".pdf"):
                # on privilégie le report.pdf si dispo
                if fname == "report.pdf":
                    target_file_id = fid
                    break
                target_file_id = target_file_id or fid
        except Exception:
            pass

    # fallback si on n'a pas pu inspecter les métadonnées
    if target_file_id is None:
        target_file_id = file_ids[0]

    # Téléchargement du fichier
    out_path = Path(out_pdf)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    file_stream = client.files.content(target_file_id)

    # Récupération robuste des octets
    data_bytes = None
    try:
        data_bytes = file_stream.read()
    except Exception:
        data_bytes = getattr(file_stream, "content", None)
    if data_bytes is None:
        raise RuntimeError("Impossible de récupérer le contenu du PDF retourné par l'IA.")

    with open(out_path, "wb") as f:
        f.write(data_bytes)

    # Récupérer (optionnel) un résumé texte si demandé
    if out_txt:
        # On demande au modèle de résumer le rapport déjà produit en 10-15 lignes claires.
        sum_resp = client.responses.create(
            model=model,
            input=[{"role": "user", "content": [{"type": "input_text", "text": "Donne un résumé en 10-15 lignes du rapport PDF que tu viens de produire."}]}],
        )
        try:
            # Extraction "robuste" du texte
            text = None
            if hasattr(sum_resp, "output") and sum_resp.output:
                # output est une liste d'objets; on concatène les items de type "message"
                chunks = []
                for it in sum_resp.output:
                    # selon SDK, 'it' peut contenir 'content' -> [{'type':'output_text','text':...}]
                    cont = getattr(it, "content", None) or []
                    for c in cont:
                        t = getattr(c, "text", None) or getattr(c, "value", None)
                        if isinstance(t, str):
                            chunks.append(t)
                text = "\n".join(chunks).strip() or None
            if not text:
                # autre fallback simple
                text = str(sum_resp)
        except Exception:
            text = str(sum_resp)

        with open(out_txt, "w", encoding="utf-8") as f:
            f.write(text or "")

def generate_pdf(protocol_counts: Dict[str, int], output_path: str, title: str,
                 top_dst_df: Optional[pd.DataFrame] = None,
                 top_flows_df: Optional[pd.DataFrame] = None):
    import pandas as pd
    import matplotlib.pyplot as plt
    from matplotlib.backends.backend_pdf import PdfPages

    df = (pd.DataFrame(list(protocol_counts.items()), columns=["Protocole", "Paquets"])
            .sort_values("Paquets", ascending=False).reset_index(drop=True))
    total = int(df["Paquets"].sum()) if not df.empty else 0
    df["%"] = (df["Paquets"] / total * 100).round(2) if total else 0.0

    out = Path(output_path)
    out.parent.mkdir(parents=True, exist_ok=True)

    with PdfPages(str(out)) as pdf:
        # Page 1 – Graphique
        plt.figure(figsize=(8.27, 5.5))
        plt.title(f"{title}\n(total paquets = {total})")
        if not df.empty:
            plt.bar(df["Protocole"].astype(str), df["Paquets"])
            plt.xlabel("Protocole")
            plt.ylabel("Nombre de paquets")
            plt.xticks(rotation=45, ha="right")
        else:
            plt.text(0.5, 0.5, "Aucun paquet capturé", ha="center", va="center")
            plt.axis("off")
        pdf.savefig(bbox_inches="tight")
        plt.close()

        # Page 2 – Tableau
        plt.figure(figsize=(8.27, 5.5))
        plt.axis("off")
        plt.title("Tableau des protocoles")
        if not df.empty:
            table = plt.table(cellText=df.values, colLabels=df.columns, loc="center", cellLoc="center")
            table.auto_set_font_size(False)
            table.set_fontsize(8)
            table.scale(1, 1.2)
        else:
            plt.text(0.5, 0.5, "Aucune donnée", ha="center", va="center")
        pdf.savefig(bbox_inches="tight")
        plt.close()

        # Page 3 – Top destinations
        if top_dst_df is not None and not top_dst_df.empty:
            plt.figure(figsize=(8.27, 5.5)); plt.axis("off"); plt.title("Top destinations (IP / Host)")
            table = plt.table(cellText=top_dst_df.values, colLabels=top_dst_df.columns, loc="center", cellLoc="center")
            table.auto_set_font_size(False); table.set_fontsize(8); table.scale(1, 1.2)
            pdf.savefig(bbox_inches="tight"); plt.close()

        # Page 4 – Top flows
        if top_flows_df is not None and not top_flows_df.empty:
            plt.figure(figsize=(8.27, 5.5)); plt.axis("off"); plt.title("Top flows (proto, src:port -> dst:port)")
            table = plt.table(cellText=top_flows_df.values, colLabels=top_flows_df.columns, loc="center", cellLoc="center")
            table.auto_set_font_size(False); table.set_fontsize(8); table.scale(1, 1.2)
            pdf.savefig(bbox_inches="tight"); plt.close()

def _default_output_name() -> str:
    now = dt.datetime.now().strftime("%Y%m%d-%H%M%S")
    return f"reports/tp1-report-{now}.pdf"

def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        prog="tp1",
        description="TP1 – Capture réseau (Scapy) + stats par protocole + PDF",
    )
    parser.add_argument("--iface", default="Ethernet 2",
                        help='Nom Windows (ex: "Ethernet 2") ou device Npcap (ex: "\\Device\\NPF_{GUID}").')
    parser.add_argument("--seconds", type=int, default=30, help="Durée de capture en secondes (défaut: 30).")
    parser.add_argument("--filter", default='tcp or udp or icmp or arp',
                        help='Filtre BPF (ex: "tcp or udp or icmp or arp").')
    parser.add_argument("--out", default=_default_output_name(),
                        help="PDF de sortie (défaut: reports/tp1-report-<timestamp>.pdf).")
    parser.add_argument("--list-ifaces", action="store_true", help="Lister les interfaces et quitter.")
    parser.add_argument("--pcap", default=None, help="Chemin du PCAP à écrire (optionnel).")
    parser.add_argument("--assume-quic-on-udp443", action="store_true",
                        help="Compter UDP/443 comme QUIC par défaut (HTTP/3).")
    parser.add_argument("--resolve-dns", action="store_true",
                        help="Résoudre les IPs (reverse DNS) pour les top destinations.")
    parser.add_argument("--top", type=int, default=10, help="Nombre d'entrées dans les tableaux 'top'.")
    parser.add_argument("--ai-pdf", default=None,
                        help="Chemin du PDF à générer via OpenAI (remplace le PDF local si fourni).")
    parser.add_argument("--ai-model", default=DEFAULT_AI_MODEL,
                        help="Modèle OpenAI à utiliser (défaut: gpt-4.1-mini).")
    parser.add_argument("--ai-summary-txt", default=None,
                        help="Chemin d'un .txt pour sauvegarder un résumé textuel du rapport IA.")
    parser.add_argument("--json-out", default=None,
                        help="Chemin du JSON d'analyse (sinon dérivé automatiquement du --ai-pdf ou --out).")
    args = parser.parse_args(argv)

    global ASSUME_QUIC_ON_UDP443
    ASSUME_QUIC_ON_UDP443 = bool(args.assume_quic_on_udp443)

    if args.list_ifaces:
        print("Interfaces détectées :")
        for line in list_interfaces_verbose():
            print(f" - {line}")
        return 0

    iface = resolve_iface(args.iface)
    title = f"TP1 – Statistiques par protocole ({args.seconds}s, iface={args.iface})"

    print(f"[i] Capture {args.seconds}s sur: {iface or 'auto'}  | filtre: {args.filter}")
    counts, pkts, flows, dsts, dns_map = capture_and_analyze(
      iface=iface, seconds=args.seconds, bpf_filter=args.filter
    )

    print("[i] Résultats (protocoles) :")
    if counts:
        for proto, n in sorted(counts.items(), key=lambda x: x[1], reverse=True):
            print(f"    {proto:>10s} : {n}")
    else:
        print("    Aucun paquet capturé.")

    # Option PCAP
    if args.pcap:
        Path(args.pcap).parent.mkdir(parents=True, exist_ok=True)
        wrpcap(args.pcap, pkts)
        print(f"[✓] PCAP écrit : {args.pcap}")

    # Construire les tables "top"
    top_dst_df = top_destinations_table(dsts, dns_map, args.top, do_reverse=bool(args.resolve_dns))
    top_flows_df = top_flows_table(flows, args.top)

    summary = {
        "meta": {
            "host": platform.node(),
            "iface": args.iface,
            "seconds": args.seconds,
            "bpf_filter": args.filter,
            "timestamp": dt.datetime.now().isoformat(timespec="seconds"),
        },
        "protocol_counts": counts,  # dict {"TCP": n, ...}
        "top_destinations": top_dst_df.to_dict(orient="records"),
        "top_flows": top_flows_df.to_dict(orient="records"),
    }

    # Chemin JSON (si non fourni)
    if args.json_out:
        json_path = Path(args.json_out)
    else:
        base = Path(args.ai_pdf if args.ai_pdf else args.out)
        json_path = base.with_suffix(".json")
    json_path.parent.mkdir(parents=True, exist_ok=True)
    with open(json_path, "w", encoding="utf-8") as jf:
        json.dump(summary, jf, ensure_ascii=False, indent=2)

    # Impression console (inchangé)
    print("[i] Top destinations :")
    if not top_dst_df.empty:
        for _, r in top_dst_df.iterrows():
            print(f"    {r['Destination IP']:>15}  {r['Host (DNS/revDNS)']:<40}  pkts={r['Packets']:>6} bytes={r['Bytes']:>8} ports={r['Top ports']}")
    else:
        print("    (aucune)")

    print("[i] Top flows :")
    if not top_flows_df.empty:
        for _, r in top_flows_df.iterrows():
            print(f"    {r['Proto']} {r['Src']}:{r['SPort']} -> {r['Dst']}:{r['DPort']}  pkts={r['Packets']} bytes={r['Bytes']}")
    else:
        print("    (aucun)")

    # === Sortie finale ===
    if args.ai_pdf:
        print(f"[i] Génération du PDF via OpenAI ({args.ai_model}) ...")
        generate_ai_pdf_openai(summary, out_pdf=args.ai_pdf, model=args.ai_model, out_txt=args.ai_summary_txt)
        print(f"[✓] PDF (IA) généré : {args.ai_pdf}")
        if args.ai_summary_txt:
            print(f"[✓] Résumé texte (IA) : {args.ai_summary_txt}")
        print(f"[✓] JSON écrit : {json_path}")
    else:
        # PDF local matplotlib (fallback classique)
        generate_pdf(counts, args.out, title=title, top_dst_df=top_dst_df, top_flows_df=top_flows_df)
        print(f"[✓] PDF (local) généré : {args.out}")
        print(f"[✓] JSON écrit : {json_path}")

    return 0