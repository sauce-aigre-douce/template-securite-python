# -*- coding: utf-8 -*-
import argparse, json, logging, os
from pathlib import Path

from tp2.utils.io import read_shellcode
from tp2.utils.strings import shannon_entropy, find_nop_sled, extract_strings
from tp2.utils.disasm import disassemble
from tp2.utils.emulate import emulate_with_pylibemu
from tp2.utils.ai import ask_openai_report, ask_ollama_report
from tp2.utils.model import ShellcodeMeta, ShellcodeReport

logging.basicConfig(level=logging.INFO, format="%(message)s")
log = logging.getLogger("shellcode")

def main():
    ap = argparse.ArgumentParser(description="Analyse de shellcode (strings, capstone, pylibemu, rapport IA)")
    ap.add_argument("--file", help="Fichier contenant le shellcode. Si absent, lecture depuis stdin.")
    ap.add_argument("--arch", default="x86", choices=["x86", "x64"], help="Architecture pour Capstone (défaut: x86)")
    ap.add_argument("--base", default="0x0", help="Adresse de base affichée dans le désassemblage (ex: 0x401000)")
    ap.add_argument("--max-instr", type=int, default=2000, help="Nombre max d'instructions désassemblées")
    ap.add_argument("--ai", choices=["openai", "ollama", "none"], default="none", help="Fournisseur IA (none=désactivé)")
    ap.add_argument("--openai-model", default="gpt-4.1-mini", help="Modèle OpenAI")
    ap.add_argument("--openai-key", default=None, help="Clé OpenAI (sinon OPENAI_API_KEY)")
    ap.add_argument("--ollama-model", default="llama3", help="Modèle Ollama (ex: mistral, qwen2, llama3)")
    ap.add_argument("--ollama-url", default="http://localhost:11434", help="Base URL Ollama")
    ap.add_argument("--json-out", default=None, help="Chemin pour sauvegarder le JSON d'analyse")
    ap.add_argument("--report-out", default=None, help="Chemin pour sauvegarder le rapport texte")
    args = ap.parse_args()

    # base addr
    try:
        base = int(args.base, 16) if isinstance(args.base, str) else int(args.base)
    except Exception:
        base = 0

    sc = read_shellcode(file=args.file)
    size = len(sc)
    log.info(f"[+] Testing shellcode of size {size} bytes")

    ent = shannon_entropy(sc)
    nop = find_nop_sled(sc)
    strings = extract_strings(sc)
    disasm = disassemble(sc, arch=args.arch, base=base, max_instr=args.max_instr)
    emu = emulate_with_pylibemu(sc)

    report = ShellcodeReport(
        meta=ShellcodeMeta(
            size=size,
            entropy=ent,
            arch_assumed=args.arch,
            base=f"0x{base:x}",
            has_nop_sled=bool(nop),
            nop_sled={"offset": nop[0], "length": nop[1]} if nop else None,
        ),
        strings=strings,
        disassembly={
            "arch": disasm["arch"],
            "base": disasm["base"],
            "instruction_count": len(disasm["instructions"]),
            "mnemonic_hist": disasm["mnemonic_hist"],
            "head": disasm["instructions"][:120],
            "tail": disasm["instructions"][-120:],
            "truncated": disasm["truncated"],
        },
        emulation=emu,
    )

    log.info("[+] Shellcode analysed !")

    if args.json_out:
        Path(args.json_out).parent.mkdir(parents=True, exist_ok=True)
        Path(args.json_out).write_text(json.dumps(report.to_dict(), ensure_ascii=False, indent=2), encoding="utf-8")
        log.info(f"[+] JSON => {args.json_out}")

    report_text = None
    if args.ai != "none":
        log.info(f"[+] Demande d'un compte-rendu via IA ({args.ai})...")
        if args.ai == "openai":
            api_key = args.openai_key or os.environ.get("OPENAI_API_KEY")
            report_text = ask_openai_report(report.to_dict(), model=args.openai_model, api_key=api_key)
        else:
            report_text = ask_ollama_report(report.to_dict(), model=args.ollama_model, base_url=args.ollama_url)

    if report_text:
        if args.report_out:
            Path(args.report_out).parent.mkdir(parents=True, exist_ok=True)
            Path(args.report_out).write_text(report_text, encoding="utf-8")
            log.info(f"[+] Rapport IA => {args.report_out}")
        else:
            print("\n" + report_text)

if __name__ == "__main__":
    main()