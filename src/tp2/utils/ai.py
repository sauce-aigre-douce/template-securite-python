# -*- coding: utf-8 -*-
import json, httpx, os
from typing import Dict, Any, Optional

try:
    from openai import OpenAI
except Exception:
    OpenAI = None

_OPENAI_DEFAULT_MODEL = "gpt-4.1-mini"

def ask_openai_report(payload: Dict[str, Any], model: str = _OPENAI_DEFAULT_MODEL, api_key: Optional[str] = None) -> str:
    if OpenAI is None:
        raise RuntimeError("Le package 'openai' n'est pas installé.")
    api_key = api_key or os.environ.get("OPENAI_API_KEY")
    if not api_key:
        raise RuntimeError("Clé OpenAI manquante. Utilise --openai-key ou la variable d'env OPENAI_API_KEY.")
    client = OpenAI(api_key=api_key)

    instructions = (
        "Tu es un analyste malware. On te fournit un JSON décrivant un shellcode : "
        "métadonnées, stats, chaînes, désassemblage, émulation. "
        "Produis un **compte-rendu détaillé** (Résumé exécutif, Indicateurs, Analyse, Preuves, "
        "Recommandations, Limites) en citant les indices."
    )
    user_text = json.dumps(payload, ensure_ascii=False, indent=2)

    resp = client.responses.create(
        model=model,
        instructions=instructions,
        input=[{"role": "user", "content": [{"type": "input_text", "text": user_text}]}],
    )

    try:
        out = []
        if hasattr(resp, "output") and resp.output:
            for item in resp.output:
                for c in getattr(item, "content", []) or []:
                    t = getattr(c, "text", None) or getattr(c, "value", None)
                    if isinstance(t, str):
                        out.append(t)
        return "\n".join(out).strip() or str(resp)
    except Exception:
        return str(resp)

def ask_ollama_report(payload: Dict[str, Any], model: str, base_url: str) -> str:
    prompt = (
        "Tu es un analyste malware. Analyse le shellcode décrit par ce JSON et rédige un rapport détaillé "
        "avec résumé, indicateurs, analyse, preuves, recommandations et limites, en citant les indices.\n\n"
        f"{json.dumps(payload, ensure_ascii=False, indent=2)}"
    )
    try:
        r = httpx.post(
            f"{base_url.rstrip('/')}/api/generate",
            json={"model": model, "prompt": prompt, "stream": False},
            timeout=120
        )
        r.raise_for_status()
        data = r.json()
        return data.get("response", "")
    except Exception as e:
        return f"[Erreur Ollama] {e}"