## TP1 – Capture & Analyse Réseau (Scapy) + Export JSON + PDF local / PDF via IA :

Ce projet capture le trafic réseau pendant une durée donnée, détecte plusieurs protocoles (TCP/UDP/ICMP/ARP, heuristiques QUIC/SSDP/TLS/DNS…), calcule des statistiques, produit un JSON structuré et génère :
- un PDF local (matplotlib), ou
- un PDF via OpenAI (gpt‑4.1‑mini + Code Interpreter) contenant graphiques, tableaux et analyse rédigée.

### Prérequis :

- Windows avec Npcap installé
- Droits Administrateur pour la capture (ouvrir un Terminale en Administrateur)
- Python 3.11+ (ou version utilisée par Poetry).
- Poetry (gestion des dépendances) 
- Pour la génération PDF via IA :
  - Un compte OpenAI avec crédits,
  - Une clé API valide.
 
### Utilisation :

Lister les interfaces capturables :
```bash
poetry run tp1 --list-ifaces
```

Capture locale 60s sur une interface :
```bash
poetry run tp1 --iface "Ethernet 2" --seconds 60 --out reports/local.pdf
```
*Génère : `reports/local.pdf` et `reports/local.json`.*

Capture + PDF via OpenAI :
```bash
poetry run tp1 --iface "Ethernet 2" --seconds 60 \
  --assume-quic-on-udp443 --resolve-dns \
  --ai-pdf reports/ai.pdf --ai-summary-txt reports/ai.txt
```
*Génère : reports/ai.pdf (par l’IA), reports/ai.txt (résumé), reports/ai.json.*

Sous cmd.exe Windows, tu peux utiliser la continuation avec ^:
```bash
poetry run tp1 --iface "Ethernet 2" --seconds 60 ^
  --assume-quic-on-udp443 --resolve-dns ^
  --ai-pdf reports/ai.pdf --ai-summary-txt reports/ai.txt
```

### Option disponibles :

```bash
tp1 [-h]
    [--iface IFACE]
    [--seconds SECONDS]
    [--filter FILTER]
    [--out OUT]
    [--list-ifaces]
    [--pcap PCAP]
    [--assume-quic-on-udp443]
    [--resolve-dns]
    [--top TOP]
    [--ai-pdf AI_PDF]
    [--ai-model AI_MODEL]
    [--ai-summary-txt AI_SUMMARY_TXT]
    [--json-out JSON_OUT]
```
- --list-ifaces : liste les interfaces détectées (nom + device Npcap + IPs) et quitte.
- --iface : nom “friendly” Windows (ex. Ethernet 2, Wi-Fi) ou device \Device\NPF_{GUID}.
- --seconds : durée de capture en secondes (défaut 30).
- --filter : filtre BPF (ex. tcp or udp or icmp or arp).
- --out : chemin du PDF local (matplotlib).
- --pcap : écrit un pcap brut (tous les paquets capturés).
- --assume-quic-on-udp443 : compte UDP/443 comme QUIC si heuristique incertaine (utile pour HTTP/3).
- --resolve-dns : tente un reverse DNS pour enrichir la table “Top destinations”.
- --top : nombre de lignes dans les tableaux Top destinations et Top flows (défaut 10).
Mode IA (OpenAI) :
- --ai-pdf : si fourni → désactive le PDF local et demande à l’IA de générer AI_PDF.
- --ai-model : modèle OpenAI (défaut gpt-4.1-mini).
- --ai-summary-txt : enregistre un résumé (10–15 lignes) du rapport IA.
- --json-out : chemin du JSON d’analyse (sinon déduit de --ai-pdf ou --out).

### Exemple de commande :

1) Capture rapide + PDF local
```bash
poetry run tp1 --iface "Ethernet 2" --seconds 30 --out reports/local.pdf
```
2) Capture + PCAP + JSON nommé
```bash
poetry run tp1 --iface "Wi-Fi" --seconds 90 --pcap reports/cap.pcap --json-out reports/cap.json --out reports/local.pdf
```
3) Capture (assume QUIC) + reverse DNS + PDF IA + résumé
```bash
poetry run tp1 --iface "Ethernet 2" --seconds 60 \
  --assume-quic-on-udp443 --resolve-dns \
  --ai-pdf reports/ai.pdf --ai-summary-txt reports/ai.txt
```
___

