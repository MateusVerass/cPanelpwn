#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
cPanelpwn.py — Scanner de Bypass de Autenticação cPanel & WHM (CVE-2026-41940)
Autor    : cPanelpwn
Versão   : 2.5

CVE-2026-41940: Injeção CRLF no Session-File → Bypass de Autenticação Root WHM
  saveSession() chama filter_sessiondata() DEPOIS de escrever o session file.
  Chars CRLF no header Authorization Basic envenenan a sessão em disco com
  campos controlados pelo atacante (hasroot=1, tfa_verified=1, etc.)

Cadeia de Exploit (4 estágios):
  [0] Auto-descobrir hostname canónico via /openid_connect/cpanelid 307
  [1] POST /login/?login_only=1  creds erradas → cookie de sessão preauth
  [2] GET /  + Authorization: Basic envenenado com CRLF → session file envenenado
  [3] GET /scripts2/listaccts   → dispara o gadget do_token_denied (raw→cache flush)
  [4] GET /{{token}}/json-api/version  → 200 + version = ACESSO ROOT CONFIRMADO

Post-Exploit:
  --action passwd   → Alterar senha root via API WHM
  --action cmd      → Executar comandos arbitrários via /json-api/scripts/exec
  --action adduser  → Criar nova conta cPanel
  --action addadmin → Criar admin reseller backdoor WHM
  --action list     → Listar todas as contas cPanel
  --action readfile → Ler arquivo arbitrário via API WHM
  --action info     → Dump de info do servidor (hostname, load, disco, etc.)
  --action shell    → Shell WHM interativo
  --action dump     → Dump massivo: contas + shadow + chaves SSH + histórico bash

Novo em v2.5 — correções, catálogo de CVEs e hardening:
  Fix crítico     → discovery de CT logs (faltava import json; sempre 0 hostnames)
  Fix crítico     → pesquisa GitHub/WAF no bypass agent (faltava import quote)
  Fix CVE feed    → janela da NVD fatiada em blocos de ≤120 dias (limite da API)
  Catálogo CVEs   → cves.py com 11 CVEs de cPanel/WHM + --list-cves / --cve
  Faixas de versão→ atribuição por versão com intervalos reais dos registros CVE
  Smuggling       → --smuggle-check detecta CL.TE/TE.CL (CVE-2026-58047) via socket cru
  Metadados       → CVSS real (9.8) e branches 138; atribuição de CVEs por versão
  Segurança       → --verify-tls / --cacert; --passwd-file; senha não vai mais ao log
  Robustez        → regex de token/versão flexíveis, IPv6, reuso de opener HTTP
  Limpeza         → ~30 imports mortos removidos; textos 100% PT-BR
  Testes          → novos testes de discovery, cves, smuggling e E2E (mock_whm)

Novo em v2.4 — pacote modular, testes, CI, features de pipeline:
  Refactor        → split em pacote cpanelpwn/ (config, http, waf, exploit,
                    actions, scanner, report, cve_feed, cli, ...)
  --json-lines    → emite cada achado como uma linha NDJSON em stdout (jq-ready)
  --resume        → retomar um scan batch interrompido desde checkpoint
  --no-checkpoint → desativar escritura de checkpoints
  Testes          → suite unittest em tests/ (só stdlib)
  CI              → workflow GitHub Actions (compile + testes em 3.8-3.12)

Novo em v2.3 — feed CVE + verificação de update no arranque:
  Feed CVE       → CVEs recentes de cPanel/WHM desde API NVD (cache 24h)
  --cve-feed     → forçar refresh; --no-cve-feed → desativar
  --cve-days N   → janela do feed em dias (padrão 90)
  Update check   → comparação de releases GitHub (falha silenciosa)
  --check -o     → suporte de saída .csv / .html

Novo em v2.2 — Stealth, customização, fiabilidade:
  --delay/--jitter, --user-agent, --no-research, --wordlist, --no-banner,
  -V/--version, retry 5xx/429, fix de pesquisa GITHUB_TOKEN, refactor de perfil WAF

Uso:
  python3 cPanelpwn.py -u https://alvo.com:2087
  python3 cPanelpwn.py --domain alvo.com -t 20 -q -o resultados.html
  python3 cPanelpwn.py -l alvos.txt --json-lines | jq -r '.target'
  python3 cPanelpwn.py -l alvos.txt -t 20 --resume
  python3 cPanelpwn.py -u https://alvo.com:2087 --check
  python3 cPanelpwn.py -u https://alvo.com:2087 --session <ck> --token /cpsess123 --action list
  cat urls.txt | python3 cPanelpwn.py

Só stdlib — não é preciso pip.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from cpanelpwn.cli import main  # noqa: E402

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\033[91m[!] Interrompido.\033[0m", file=sys.stderr)
        sys.exit(0)