# src/tp1/utils/report.py
from pathlib import Path
from typing import Dict, Optional
import pandas as pd
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.backends.backend_pdf import PdfPages

from .config import OPENAI_API_KEY, DEFAULT_AI_MODEL
from .lib import ensure_parent

def generate_pdf_local(protocol_counts: Dict[str, int], out_pdf: str, title: str,
                       top_dst_df: Optional[pd.DataFrame] = None,
                       top_flows_df: Optional[pd.DataFrame] = None) -> None:
    df = (pd.DataFrame(list(protocol_counts.items()), columns=["Protocole", "Paquets"])
            .sort_values("Paquets", ascending=False).reset_index(drop=True))
    total = int(df["Paquets"].sum()) if not df.empty else 0
    df["%"] = (df["Paquets"] / total * 100).round(2) if total else 0.0

    out = Path(out_pdf); ensure_parent(out)
    with PdfPages(str(out)) as pdf:
        # Page 1: bar chart
        plt.figure(figsize=(8.27, 5.5))
        plt.title(f"{title}\n(total paquets = {total})")
        if not df.empty:
            plt.bar(df["Protocole"].astype(str), df["Paquets"])
            plt.xlabel("Protocole"); plt.ylabel("Nombre de paquets")
            plt.xticks(rotation=45, ha="right")
        else:
            plt.text(0.5, 0.5, "Aucun paquet capturé", ha="center", va="center"); plt.axis("off")
        pdf.savefig(bbox_inches="tight"); plt.close()

        # Page 2: table des protocoles
        plt.figure(figsize=(8.27, 5.5)); plt.axis("off"); plt.title("Tableau des protocoles")
        if not df.empty:
            table = plt.table(cellText=df.values, colLabels=df.columns, loc="center", cellLoc="center")
            table.auto_set_font_size(False); table.set_fontsize(8); table.scale(1, 1.2)
        else:
            plt.text(0.5, 0.5, "Aucune donnée", ha="center", va="center")
        pdf.savefig(bbox_inches="tight"); plt.close()

        # Page 3: top destinations
        if top_dst_df is not None and not top_dst_df.empty:
            plt.figure(figsize=(8.27, 5.5)); plt.axis("off"); plt.title("Top destinations (IP / Host)")
            table = plt.table(cellText=top_dst_df.values, colLabels=top_dst_df.columns, loc="center", cellLoc="center")
            table.auto_set_font_size(False); table.set_fontsize(8); table.scale(1, 1.2)
            pdf.savefig(bbox_inches="tight"); plt.close()

        # Page 4: top flows
        if top_flows_df is not None and not top_flows_df.empty:
            plt.figure(figsize=(8.27, 5.5)); plt.axis("off"); plt.title("Top flows (proto, src:port -> dst:port)")
            table = plt.table(cellText=top_flows_df.values, colLabels=top_flows_df.columns, loc="center", cellLoc="center")
            table.auto_set_font_size(False); table.set_fontsize(8); table.scale(1, 1.2)
            pdf.savefig(bbox_inches="tight"); plt.close()

def generate_pdf_openai(summary_json: dict, out_pdf: str,
                        model: str = DEFAULT_AI_MODEL, out_txt: Optional[str] = None) -> None:
    if not OPENAI_API_KEY or OPENAI_API_KEY.startswith("REMPLACEZ"):
        raise RuntimeError("OPENAI_API_KEY n'est pas renseignée (ou placeholder).")

    from openai import OpenAI
    import json

    client = OpenAI(api_key=OPENAI_API_KEY)
    payload_str = json.dumps(summary_json, ensure_ascii=False, indent=2)

    instructions = (
        "Tu es un ingénieur analyste réseau. On te fournit un JSON de capture (protocoles, top destinations, top flows, méta). "
        "Ta mission : 1) Générer un PDF multi-pages avec: "
        "• Une page de titre (iface, durée, filtre, timestamp) ; "
        "• Un histogramme des protocoles ; "
        "• Un tableau des protocoles ; "
        "• Un tableau Top destinations ; "
        "• Un tableau Top flows ; "
        "• Une analyse écrite (activité probable, services, QUIC/HTTP/3, CDNs, limites, reco). "
        "2) Le PDF doit s'appeler exactement 'report.pdf'. 3) Utilise matplotlib sans style custom. "
        "4) N'insère aucune donnée personnelle sensible hors JSON. "
        "5) Retourne aussi un court résumé texte (10-15 lignes) si demandé."
    )
    user_text = (
        "Voici le JSON de la capture (clé 'meta', 'protocol_counts', 'top_destinations', 'top_flows') :\n\n"
        f"{payload_str}\n\n"
        "Consignes: Lis ce JSON en Python, construis les DataFrames, produis les figures avec matplotlib, "
        "puis exporte un PDF nommé 'report.pdf'."
    )

    resp = client.responses.create(
        model=model,
        instructions=instructions,
        input=[{"role": "user", "content": [{"type": "input_text", "text": user_text}]}],
        tools=[{"type": "code_interpreter"}],
    )

    # Récupération du/ des file_id créés par le Code Interpreter
    try:
        data = resp.model_dump()
    except Exception:
        import json as _json
        try:
            data = _json.loads(resp.json())
        except Exception:
            data = {}

    def _collect_file_ids(obj):
        out = []
        if isinstance(obj, dict):
            for k, v in obj.items():
                if k == "file_id" and isinstance(v, str):
                    out.append(v)
                else:
                    out.extend(_collect_file_ids(v))
        elif isinstance(obj, list):
            for it in obj:
                out.extend(_collect_file_ids(it))
        return out

    file_ids = list(dict.fromkeys(_collect_file_ids(data)))
    if not file_ids:
        raise RuntimeError("Aucun fichier PDF trouvé dans la réponse du Code Interpreter.")

    client_files = client.files
    target_file_id = None
    for fid in file_ids:
        try:
            meta = client_files.retrieve(fid)
            fname = getattr(meta, "filename", "") or getattr(meta, "name", "")
            if isinstance(fname, str) and fname.lower().endswith(".pdf"):
                if fname == "report.pdf":
                    target_file_id = fid
                    break
                target_file_id = target_file_id or fid
        except Exception:
            pass
    if target_file_id is None:
        target_file_id = file_ids[0]

    out_path = Path(out_pdf); ensure_parent(out_path)
    file_stream = client_files.content(target_file_id)
    data_bytes = getattr(file_stream, "read", lambda: getattr(file_stream, "content", None))()
    if not data_bytes:
        raise RuntimeError("Impossible de récupérer le contenu du PDF retourné par l'IA.")
    with open(out_path, "wb") as f:
        f.write(data_bytes)

    if out_txt:
        sum_resp = client.responses.create(
            model=model,
            input=[{"role": "user", "content": [{"type": "input_text", "text": "Donne un résumé en 10-15 lignes du rapport PDF que tu viens de produire."}]}],
        )
        # extraction robuste du texte
        text = None
        try:
            if hasattr(sum_resp, "output") and sum_resp.output:
                chunks = []
                for it in sum_resp.output:
                    cont = getattr(it, "content", None) or []
                    for c in cont:
                        t = getattr(c, "text", None) or getattr(c, "value", None)
                        if isinstance(t, str):
                            chunks.append(t)
                text = "\n".join(chunks).strip() or None
        except Exception:
            pass
        text = text or str(sum_resp)
        with open(out_txt, "w", encoding="utf-8") as f:
            f.write(text)