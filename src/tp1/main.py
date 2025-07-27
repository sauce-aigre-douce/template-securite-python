# src/tp1/main.py
import argparse
import datetime as dt
from pathlib import Path

from tp1.utils.config import (
    DEFAULT_IFACE, DEFAULT_SECONDS, DEFAULT_BPF_FILTER, DEFAULT_TOP,
    DEFAULT_AI_MODEL, ASSUME_QUIC_ON_UDP443_DEFAULT,
)
from tp1.utils.lib import reverse_dns, write_json, make_summary
from tp1.utils.capture import (
    list_interfaces_verbose, resolve_iface,
    capture_and_analyze, top_destinations_table, top_flows_table,
)
from tp1.utils.report import generate_pdf_local, generate_pdf_openai

def _default_output_name() -> str:
    now = dt.datetime.now().strftime("%Y%m%d-%H%M%S")
    return f"reports/tp1-report-{now}.pdf"

def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="tp1", description="TP1 – Capture réseau (Scapy) + stats + PDF/IA")
    p.add_argument("--iface", default=DEFAULT_IFACE)
    p.add_argument("--seconds", type=int, default=DEFAULT_SECONDS)
    p.add_argument("--filter", default=DEFAULT_BPF_FILTER)
    p.add_argument("--out", default=_default_output_name())
    p.add_argument("--list-ifaces", action="store_true")
    p.add_argument("--pcap", default=None)
    p.add_argument("--assume-quic-on-udp443", action="store_true", default=ASSUME_QUIC_ON_UDP443_DEFAULT)
    p.add_argument("--resolve-dns", action="store_true")
    p.add_argument("--top", type=int, default=DEFAULT_TOP)
    p.add_argument("--ai-pdf", default=None)
    p.add_argument("--ai-model", default=DEFAULT_AI_MODEL)
    p.add_argument("--ai-summary-txt", default=None)
    p.add_argument("--json-out", default=None)
    args = p.parse_args(argv)

    if args.list_ifaces:
        print("Interfaces détectées :")
        for line in list_interfaces_verbose():
            print(f" - {line}")
        return 0

    iface_dev = resolve_iface(args.iface)
    print(f"[i] Capture {args.seconds}s sur: {iface_dev or 'auto'}  | filtre: {args.filter}")

    counts, pkts, flows, dsts, dns_map = capture_and_analyze(
        iface=iface_dev, seconds=args.seconds, bpf_filter=args.filter,
        assume_quic_on_udp443=args.assume_quic_on_udp443
    )

    # Résumé console
    print("[i] Résultats (protocoles) :")
    if counts:
        for proto, n in sorted(counts.items(), key=lambda x: x[1], reverse=True):
            print(f"    {proto:>10s} : {n}")
    else:
        print("    Aucun paquet capturé.")

    # PCAP (optionnel)
    if args.pcap:
        Path(args.pcap).parent.mkdir(parents=True, exist_ok=True)
        from scapy.all import wrpcap
        wrpcap(args.pcap, pkts)
        print(f"[✓] PCAP écrit : {args.pcap}")

    # Tables top
    resolver = (lambda ip: reverse_dns(ip)) if args.resolve_dns else (lambda ip: "")
    top_dst_df = top_destinations_table(dsts, dns_map, args.top, resolver=resolver)
    top_flows_df = top_flows_table(flows, args.top)

    # Impression console lisible
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

    # Construction du JSON
    summary = make_summary(counts, top_dst_df, top_flows_df, args.iface, args.seconds, args.filter)
    if args.json_out:
        json_path = Path(args.json_out)
    else:
        base = Path(args.ai_pdf if args.ai_pdf else args.out)
        json_path = base.with_suffix(".json")
    write_json(summary, json_path)
    print(f"[✓] JSON écrit : {json_path}")

    # Sorties PDF
    if args.ai_pdf:
        print(f"[i] Génération du PDF via OpenAI ({args.ai_model}) ...")
        generate_pdf_openai(summary, out_pdf=args.ai_pdf, model=args.ai_model, out_txt=args.ai_summary_txt)
        print(f"[✓] PDF (IA) généré : {args.ai_pdf}")
        if args.ai_summary_txt:
            print(f"[✓] Résumé texte (IA) : {args.ai_summary_txt}")
    else:
        title = f"TP1 – Statistiques par protocole ({args.seconds}s, iface={args.iface})"
        generate_pdf_local(counts, args.out, title=title, top_dst_df=top_dst_df, top_flows_df=top_flows_df)
        print(f"[✓] PDF (local) généré : {args.out}")

    return 0

def app():
    raise SystemExit(main())