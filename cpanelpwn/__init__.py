"""cPanelpwn — Scanner de Bypass de Autenticação cPanel & WHM (CVE-2026-41940).

Layout do pacote:
  config     — cores, logging, globals de runtime, VERSION
  core       — ScanCtx, payloads CRLF, parse de alvos, verificação de versão
  http       — motor HTTP stdlib (acesso raw a Set-Cookie, retries, delay)
  waf        — detecção WAF, perfiles de bypass, agente de bypass
  discovery  — descobrimento de subdomínios (logs CT, brute DNS, probe de porta)
  parsers    — entrada nmap XML / masscan JSON / Shodan NDJSON / texto plano
  exploit    — cadeia de exploit de 4 estágios + chamador de API WHM
  actions    — ações post-exploit + shell WHM interativo
  store      — store de achados, ctx map, progress, checkpoint de resume
  scanner    — check passivo + orquestração do scan principal
  report     — resumo, saída HTML/CSV/JSON
  cve_feed   — feed CVE de arranque + verificação de update da tool
  cves       — catálogo de CVEs de cPanel/WHM + atribuição por versão
  cli        — parse de argumentos, montagem de alvos, main()
"""

from .config import VERSION

__all__ = ["VERSION"]