# src/tp1/utils/config.py
from pathlib import Path

# --- Réseau / capture ---
DEFAULT_IFACE = "Ethernet 2"
DEFAULT_SECONDS = 30
DEFAULT_BPF_FILTER = "tcp or udp or icmp or arp"
DEFAULT_TOP = 10

# --- OpenAI ---
OPENAI_API_KEY = "REMPLACEZ_PAR_VOTRE_CLE"      # <<< ta clé ici
DEFAULT_AI_MODEL = "gpt-4.1-mini"               # modèle IA

# --- Sorties ---
REPORTS_DIR = Path("reports")
DEFAULT_LOCAL_PDF_NAME = "tp1-report.pdf"       # si tu veux un nom fixe
# ou laisse le timestamp dans main si tu préfères

# --- Comportement ---
ASSUME_QUIC_ON_UDP443_DEFAULT = False