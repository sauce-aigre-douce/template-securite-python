### Dépendances a installer :

```bash
pip install capstone openai httpx
```

### Commandes :

#### Test a blanc sans utilisation de l'IA :
```bash
poetry run tp2 ^
  --file "src/tp2/shellcode.bin" ^
  --arch x86 ^
  --base 0x401000 ^
  --max-instr 200 ^
  --ai none ^
  --json-out "reports/tp2-shellcode.json" ^
  --report-out "reports/tp2-report.txt"
```
*on remplace : --file "src/tp2/shellcode.bin" par le shellcode a tester*

#### Test avec IA OpenAI (analyse détaillée) :
```bash
poetry run tp2 ^
  --file "src/tp2/shellcode.bin" ^
  --arch x86 ^
  --base 0x401000 ^
  --max-instr 200 ^
  --ai openai ^
  --openai-model "gpt-4.1-mini" ^
  --openai-key "TA_CLE_OPENIA_ICI" ^
  --json-out "reports/tp2-shellcode.json" ^
  --report-out "reports/tp2-ai-report.txt"
```
*on remplace : --file "src/tp2/shellcode.bin" par le shellcode a tester*

#### Test avec IA locale via Ollama :
```bash
poetry run tp2 ^
  --file "src/tp2/shellcode.bin" ^
  --arch x86 ^
  --ai ollama ^
  --ollama-model "llama3" ^
  --ollama-url "http://localhost:11434" ^
  --json-out "reports/tp2-shellcode.json" ^
  --report-out "reports/tp2-ollama-report.txt"
```
*on remplace : --file "src/tp2/shellcode.bin" par le shellcode a tester*