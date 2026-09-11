"""Módulo cPanelpwn: report."""

import os, json, csv
import html as _html_mod
from datetime import datetime
from typing import List
from . import config as cfg
from . import core
from . import store
import sys
from .config import C, VERSION, log
from .core import is_version_patched
from .store import STORE

# ══════════════════════════════════════════════════════════════
#  RESUMO
# ══════════════════════════════════════════════════════════════
def print_summary(elapsed: float, total: int):
    findings = STORE.all()
    vuln_n   = len(findings)
    clean_n  = max(0, total - vuln_n)
    W        = 68

    def p(s=""):
        print(s, file=sys.stderr)

    # ── Cabeçalho ────────────────────────────────────────────────────
    if not cfg._NO_BANNER:
        p()
        p(f"{C.RED}{C.BOLD}  {'═'*W}{C.RESET}")
        p(f"{C.RED}{C.BOLD}  ██████╗██████╗  █████╗ ███╗  ██╗███████╗██╗{C.RESET}")
        p(f"{C.RED}{C.BOLD} ██╔════╝██╔══██╗██╔══██╗████╗ ██║██╔════╝██║{C.RESET}")
        p(f"{C.RED}{C.BOLD} ██║     ██████╔╝███████║██╔██╗██║█████╗  ██║{C.RESET}")
        p(f"{C.RED}{C.BOLD} ██║     ██╔═══╝ ██╔══██║██║╚████║██╔══╝  ██║{C.RESET}")
        p(f"{C.RED}{C.BOLD} ╚██████╗██║     ██║  ██║██║ ╚███║███████╗███████╗{C.RESET}")
        p(f"{C.RED}{C.BOLD}  ╚═════╝╚═╝     ╚═╝  ╚═╝╚═╝  ╚══╝╚══════╝╚══════╝{C.RESET}")
        p(f"{C.BOLD}  ██████╗ ██╗    ██╗███╗   ██╗{C.RESET}")
        p(f"{C.BOLD}  ██╔══██╗██║    ██║████╗  ██║{C.RESET}")
        p(f"{C.BOLD}  ██████╔╝██║ █╗ ██║██╔██╗ ██║{C.RESET}")
        p(f"{C.BOLD}  ██╔═══╝ ██║███╗██║██║╚██╗██║{C.RESET}")
        p(f"{C.BOLD}  ██║     ╚███╔███╔╝██║ ╚████║{C.RESET}")
        p(f"{C.BOLD}  ╚═╝      ╚══╝╚══╝ ╚═╝  ╚═══╝{C.RESET}")
        p(f"{C.RED}{C.BOLD}  {'═'*W}{C.RESET}")
        p()

    # ── Barra de estadísticas ─────────────────────────────────────────
    p(f"  {C.DIM}┌─ RESUMO DO SCAN {'─'*50}┐{C.RESET}")
    p(f"  {C.DIM}│{C.RESET}  "
      f"{C.BOLD}Escaneados{C.RESET}  {C.CYAN}{C.BOLD}{total}{C.RESET}"
      f"     {C.BOLD}Vulneráveis{C.RESET}  {C.RED}{C.BOLD}{vuln_n}{C.RESET}"
      f"     {C.BOLD}Limpos{C.RESET}  {C.GREEN}{C.BOLD}{clean_n}{C.RESET}"
      f"     {C.BOLD}Tempo{C.RESET}  {C.DIM}{elapsed:.1f}s{C.RESET}")
    p(f"  {C.DIM}└{'─'*(W+2)}┘{C.RESET}")
    p()

    # ── Sem achados ─────────────────────────────────────────────────
    if not findings:
        p(f"  {C.GREEN}✔  Não se encontraram alvos vulneráveis.{C.RESET}")
        p()
        return

    # ── Contagem de achados ───────────────────────────────────────────
    p(f"  {C.RED}{C.BOLD}{'─'*W}{C.RESET}")
    p(f"  {C.RED}{C.BOLD}⚡  {vuln_n} ALVO(S) COMPROMETIDO(S)  —  CVE-2026-41940  —  CVSS 10.0{C.RESET}")
    p(f"  {C.RED}{C.BOLD}{'─'*W}{C.RESET}")
    p()

    # ── Cartões por achado ───────────────────────────────────────────
    for idx, f in enumerate(findings, 1):
        version = f.get("version", "unknown")
        patched = is_version_patched(version)
        waf     = f.get("waf", "")
        ev      = f.get("evidence", "")[:180].replace("\n", " ").strip()
        ts      = f.get("timestamp", "")[:19].replace("T", " ")
        session = f.get("session", "")
        token   = f.get("token", "")
        target  = f.get("target", "")
        api_url = f.get("api_url", "")

        # Insignia de versão
        if patched is False:
            ver_str = f"{C.RED}{C.BOLD}{version}  ◀ VULNERÁVEL{C.RESET}"
        elif patched is True:
            ver_str = f"{C.YELLOW}{version}  ◀ patch detectado — verificar{C.RESET}"
        else:
            ver_str = f"{C.CYAN}{version}{C.RESET}"

        sep = f"  {C.RED}{C.BOLD}│{C.RESET}"
        p(f"  {C.RED}{C.BOLD}┌─ #{idx} {'─'*(W-5)}{C.RESET}")
        p(f"{sep}  {C.DIM}{'TARGET':10}{C.RESET}  {C.BOLD}{C.CYAN}{target}{C.RESET}")
        p(f"{sep}  {C.DIM}{'VERSÃO':10}{C.RESET}  {ver_str}")
        if waf:
            p(f"{sep}  {C.DIM}{'WAF':10}{C.RESET}  {C.ORANGE}{C.BOLD}{waf}{C.RESET}  "
              f"{C.DIM}(bypass aplicado automaticamente){C.RESET}")
        p(f"{sep}  {C.DIM}{'TOKEN':10}{C.RESET}  {C.GREEN}{C.BOLD}{token}{C.RESET}")
        p(f"{sep}  {C.DIM}{'SESSÃO':10}{C.RESET}  {C.DIM}{session[:55]}...{C.RESET}")
        p(f"{sep}  {C.DIM}{'API URL':10}{C.RESET}  {C.GREEN}{api_url}{C.RESET}")
        if ts:
            p(f"{sep}  {C.DIM}{'QUANDO':10}{C.RESET}  {C.DIM}{ts}{C.RESET}")
        p(sep)
        if ev:
            p(f"{sep}  {C.DIM}{'EVIDÊNCIA':10}{C.RESET}  {C.GREEN}{ev}{C.RESET}")
            p(sep)
        reuse = (f"python3 cPanelpwn.py -u {target} "
                 f"--session '{session[:25]}...' "
                 f"--token {token} --action shell")
        p(f"{sep}  {C.DIM}{'REUSO ▶':10}{C.RESET}  {C.DIM}{reuse}{C.RESET}")
        p(f"  {C.RED}{C.BOLD}└{'─'*W}{C.RESET}")
        p()

    # ── Footer ────────────────────────────────────────────────────────
    p(f"  {C.RED}{C.BOLD}{'═'*W}{C.RESET}")
    p()

# ══════════════════════════════════════════════════════════════
#  INFORME HTML
# ══════════════════════════════════════════════════════════════
def _html_css() -> str:
    return (
        "* { box-sizing: border-box; margin: 0; padding: 0; }"
        "body { background: #0d1117; color: #e6edf3; "
        "font-family: 'Segoe UI', Consolas, monospace; padding: 2rem; }"
        "h1 { color: #ff4444; font-size: 1.8rem; margin-bottom: 0.4rem; }"
        ".subtitle { color: #8b949e; margin-bottom: 2rem; font-size: 0.85rem; }"
        ".stats { display: flex; gap: 1rem; margin-bottom: 2rem; flex-wrap: wrap; }"
        ".stat-box { background: #161b22; border: 1px solid #30363d; "
        "border-radius: 8px; padding: 1rem 1.5rem; min-width: 120px; }"
        ".stat-box .num { font-size: 2rem; font-weight: bold; color: #ff4444; }"
        ".stat-box .label { color: #8b949e; font-size: 0.78rem; text-transform: uppercase; }"
        ".finding { background: #161b22; border: 1px solid #ff4444; "
        "border-radius: 8px; margin-bottom: 1.5rem; overflow: hidden; }"
        ".finding-header { background: #1f0d0d; padding: 1rem 1.5rem; "
        "border-bottom: 1px solid #30363d; }"
        ".finding-title { color: #ff4444; font-weight: bold; font-size: 1rem; }"
        ".finding-target { color: #58a6ff; font-family: monospace; "
        "font-size: 0.85rem; margin-top: 0.3rem; word-break: break-all; }"
        ".finding-body { padding: 1.5rem; display: grid; "
        "grid-template-columns: 1fr 1fr; gap: 1rem; }"
        ".field label { color: #8b949e; font-size: 0.72rem; "
        "text-transform: uppercase; display: block; margin-bottom: 2px; }"
        ".field value { color: #e6edf3; font-family: monospace; "
        "font-size: 0.82rem; word-break: break-all; }"
        ".evidence { grid-column: 1 / -1; }"
        ".evidence pre { background: #0d1117; padding: 0.8rem; border-radius: 4px; "
        "font-size: 0.78rem; color: #7ee787; overflow-x: auto; "
        "white-space: pre-wrap; margin-top: 4px; }"
        ".badge { display: inline-block; padding: 0.15rem 0.5rem; "
        "border-radius: 4px; font-size: 0.7rem; font-weight: bold; margin-right: 4px; }"
        ".badge-crit { background: #ff4444; color: #fff; }"
        ".badge-cvss { background: #e06c00; color: #fff; }"
        ".badge-waf  { background: #1f6feb; color: #fff; }"
        "footer { margin-top: 3rem; color: #3d444d; font-size: 0.75rem; text-align: center; }"
        "a { color: #58a6ff; }"
    )

def save_html_report(findings: list, out_file: str, elapsed: float, total: int):
    e = _html_mod.escape

    def card(f) -> str:
        waf_badge = (f'<span class="badge badge-waf">WAF: {e(f.get("waf",""))}</span>'
                     if f.get("waf") else "")
        return (
            '<div class="finding">'
            '<div class="finding-header">'
            f'<div class="finding-title">'
            f'<span class="badge badge-crit">CRÍTICO</span>'
            f'<span class="badge badge-cvss">CVSS {e(str(f.get("cvss","10.0")))}</span>'
            f'{waf_badge} {e(f.get("title",""))}</div>'
            f'<div class="finding-target">{e(f.get("target",""))}</div>'
            '</div>'
            '<div class="finding-body">'
            f'<div class="field"><label>Versão</label><value>{e(str(f.get("version","")))}</value></div>'
            f'<div class="field"><label>Token</label><value>{e(str(f.get("token","")))}</value></div>'
            f'<div class="field"><label>Canónico</label><value>{e(str(f.get("canonical","")))}</value></div>'
            f'<div class="field"><label>Timestamp</label><value>{e(str(f.get("timestamp","")))}</value></div>'
            f'<div class="field"><label>API URL</label>'
            f'<value><a href="{e(str(f.get("api_url","")))}">{e(str(f.get("api_url","")))}</a></value></div>'
            f'<div class="field"><label>Sessão</label>'
            f'<value>{e(str(f.get("session",""))[:70])}...</value></div>'
            f'<div class="field evidence"><label>Evidencia</label>'
            f'<pre>{e(str(f.get("evidence",""))[:500])}</pre></div>'
            '</div></div>'
        )

    ts_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    cards  = "".join(card(f) for f in findings)
    if not cards:
        cards = "<p style='color:#8b949e;padding:1rem'>Nenhum alvo vulnerável encontrado.</p>"

    page = (
        "<!DOCTYPE html>\n<html lang='pt'>\n<head>\n"
        "<meta charset='UTF-8'>\n"
        "<meta name='viewport' content='width=device-width, initial-scale=1'>\n"
        "<title>cPanelpwn — Reporte CVE-2026-41940</title>\n"
        f"<style>{_html_css()}</style>\n"
        "</head>\n<body>\n"
        "<h1>cPanelpwn — CVE-2026-41940</h1>\n"
        f"<div class='subtitle'>Reporte de Bypass de Autenticação cPanel &amp; WHM &nbsp;|&nbsp; {ts_str}</div>\n"
        "<div class='stats'>\n"
        f"  <div class='stat-box'><div class='num'>{total}</div>"
        f"<div class='label'>Escaneados</div></div>\n"
        f"  <div class='stat-box'><div class='num'>{len(findings)}</div>"
        f"<div class='label'>Vulneráveis</div></div>\n"
        f"  <div class='stat-box'><div class='num'>{elapsed:.1f}s</div>"
        f"<div class='label'>Duração</div></div>\n"
        "</div>\n"
        + cards +
        "\n<footer>cPanelpwn "
        f"v{VERSION} &nbsp;|&nbsp; CVE-2026-41940 &nbsp;|&nbsp; "
        "CVSS 10.0 &nbsp;|&nbsp; Somente para testes de penetração autorizados</footer>\n"
        "</body>\n</html>"
    )

    with open(out_file, "w", encoding="utf-8") as fp:
        fp.write(page)
    log("OK", f"Reporte HTML → {out_file}")

# ══════════════════════════════════════════════════════════════
#  SAÍDA
# ══════════════════════════════════════════════════════════════
def save_output(findings, out_file: str, elapsed: float = 0.0, total: int = 0):
    os.makedirs(os.path.dirname(out_file) if os.path.dirname(out_file) else ".",
                exist_ok=True)
    ext = os.path.splitext(out_file)[1].lower()

    if ext == ".html":
        save_html_report(findings, out_file, elapsed, total)
    elif ext == ".csv":
        fields = ["target", "version", "token", "canonical", "session",
                  "api_url", "cve", "cvss", "waf", "timestamp"]
        with open(out_file, "w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore")
            w.writeheader()
            w.writerows(findings)
        log("OK", f"Resultados → {out_file}")
    else:
        with open(out_file, "w", encoding="utf-8") as f:
            json.dump({
                "scanner":   f"cPanelpwn v{VERSION}",
                "cve":       "CVE-2026-41940",
                "timestamp": datetime.now().isoformat(),
                "findings":  findings,
            }, f, indent=2, ensure_ascii=False)
        log("OK", f"Resultados → {out_file}")

# ══════════════════════════════════════════════════════════════

