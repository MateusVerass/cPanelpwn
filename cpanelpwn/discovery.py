"""Módulo cPanelpwn: discovery."""

import socket, json, threading
from typing import List, Set, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed
from .config import C, log
from .http import _do, R

# ══════════════════════════════════════════════════════════════
#  DESCUBRIMIENTO DE SUBDOMINIOS
# ══════════════════════════════════════════════════════════════
_WHM_SIGNATURES = ("whm", "cpanel", "webhost manager", "cpsess",
                   "login_only", "cpsrvd", "webmail")

def _is_whm_response(resp: R) -> bool:
    """Devolver True se a resposta parece uma página de login cPanel/WHM."""
    if resp.status == 0:
        return False
    body = (resp.body or "").lower()
    return any(sig in body for sig in _WHM_SIGNATURES)

def _parse_ct_entries(body: str, domain: str) -> Set[str]:
    """Parsear entradas JSON de qualquer API de logs CT que devolva name_value/common_name."""
    results: Set[str] = set()
    try:
        entries = json.loads(body)
        for entry in entries:
            for raw in entry.get("name_value", "").split("\n"):
                raw = raw.strip().lower().lstrip("*.")
                if raw == domain or raw.endswith(f".{domain}"):
                    results.add(raw)
            cn = entry.get("common_name", "").strip().lower().lstrip("*.")
            if cn == domain or cn.endswith(f".{domain}"):
                results.add(cn)
    except Exception:
        pass
    return results

def crtsh_subdomains(domain: str, timeout: int = 20) -> Set[str]:
    """
    Consultar logs CT por subdomínios — crt.sh principal, certspotter.com fallback.
    Passivo — não gera ruído no alvo.
    """
    results: Set[str] = set()

    # Principal: crt.sh
    log("DISC", f"Consultando crt.sh para *.{domain} ...")
    try:
        resp = _do(f"https://crt.sh/?q=%.{domain}&output=json", timeout=timeout)
        if resp.status == 200 and resp.body:
            results = _parse_ct_entries(resp.body, domain)
            log("OK", f"crt.sh: {len(results)} hostname(s)")
            return results
        log("WARN", f"crt.sh HTTP {resp.status} — tentando certspotter...")
    except Exception as e:
        log("WARN", f"crt.sh falhou ({e}) — tentando certspotter...")

    # Fallback: certspotter.com
    log("DISC", f"Consultando certspotter.com para *.{domain} ...")
    try:
        resp2 = _do(
            f"https://api.certspotter.com/v1/issuances"
            f"?domain={domain}&include_subdomains=true&expand=dns_names",
            timeout=timeout)
        if resp2.status == 200 and resp2.body:
            try:
                entries = json.loads(resp2.body)
                for entry in entries:
                    for name in entry.get("dns_names", []):
                        name = name.strip().lower().lstrip("*.")
                        if name == domain or name.endswith(f".{domain}"):
                            results.add(name)
                log("OK", f"certspotter: {len(results)} hostname(s)")
            except Exception:
                log("WARN", "certspotter: resposta inválida")
        else:
            log("WARN", f"certspotter HTTP {resp2.status}")
    except Exception as e:
        log("WARN", f"certspotter falhou: {e}")

    return results

def load_wordlist(path: str) -> List[str]:
    """Carregar wordlist DNS customizada (um prefixo por linha, '#' = comentário)."""
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            words = [ln.strip().lower().lstrip("*.")
                     for ln in f if ln.strip() and not ln.strip().startswith("#")]
    except FileNotFoundError:
        log("WARN", f"Wordlist não encontrada: {path}")
        return []
    if not words:
        log("WARN", f"Wordlist vazia: {path} — usando a lista integrada")
        return []
    log("INFO", f"Wordlist customizada: {len(words)} prefixo(s) de {path}")
    return words

def dns_brute(domain: str, wordlist: List[str], threads: int = 100) -> Set[str]:
    """Resolver prefixos de subdomínios via socket. Devolve só hosts que resolvem."""
    results: Set[str] = set()
    lock = threading.Lock()

    def _resolve(prefix: str):
        fqdn = f"{prefix}.{domain}"
        try:
            socket.getaddrinfo(fqdn, None)
            with lock:
                results.add(fqdn)
        except (socket.gaierror, socket.herror):
            pass

    log("DISC", f"DNS brute-force: {len(wordlist)} prefixos, {threads} workers ...")
    with ThreadPoolExecutor(max_workers=threads) as ex:
        futs = [ex.submit(_resolve, w) for w in wordlist]
        for _ in as_completed(futs):
            pass
    log("OK", f"DNS brute: {len(results)} hostname(s) vivos")
    return results

# Portas WHM/cPanel a sondar
WHM_PORTS = [2087, 2083, 2086, 2082]

def probe_whm(host: str, timeout: int = 8) -> Optional[str]:
    """
    Sondar todos os WHM_PORTS em paralelo; devolver a primeira URL com página
    de login cPanel/WHM, ou None. A sondagem paralela evita ficar trabado em portas mortas.
    """
    result: list = []
    result_lock  = threading.Lock()

    def _try(port: int):
        scheme = "https" if port in (2087, 2083) else "http"
        url    = f"{scheme}://{host}:{port}/login"
        log("DISC", f"  probe {host}:{port} ...")
        resp   = _do(url, timeout=timeout, follow=False)
        if _is_whm_response(resp):
            with result_lock:
                if not result:
                    result.append(f"{scheme}://{host}:{port}")

    with ThreadPoolExecutor(max_workers=len(WHM_PORTS)) as ex:
        futs = [ex.submit(_try, p) for p in WHM_PORTS]
        for _ in as_completed(futs):
            pass

    return result[0] if result else None

def discover_subdomains(domain: str, threads: int, timeout: int,
                        timeout_probe: int = 5,
                        wordlist: Optional[List[str]] = None) -> List[str]:
    """
    Pipeline completo de descobrimento de subdomínios:
      1. Logs CT de crt.sh  (passivo)
      2. Brute-force DNS (só DNS ativo, sem HTTP)
      3. Sondeo de portas WHM (2087, 2083, 2086, 2082)

    Devolve lista deduplicada de URLs WHM vivas (scheme://host:port).
    """
    log("DISC", f"{'─'*50}")
    log("DISC", f"Descobrimento de subdomínios para: {C.CYAN}{domain}{C.RESET}")
    log("DISC", f"{'─'*50}")

    ct_hosts    = crtsh_subdomains(domain, timeout=max(timeout, 20))
    brute_hosts = dns_brute(domain, wordlist or WHM_WORDLIST,
                            threads=min(threads * 3, 150))

    all_hosts: Set[str] = ct_hosts | brute_hosts | {domain}
    log("DISC", f"Total de hosts únicos a sondar: {len(all_hosts)}")

    log("DISC", f"Sondando portas WHM em {len(all_hosts)} host(s) ...")
    live: List[str] = []
    live_lock = threading.Lock()

    def _probe(host: str):
        url = probe_whm(host, timeout=timeout_probe)
        if url:
            with live_lock:
                live.append(url)
            log("OK", f"WHM confirmado → {C.GREEN}{url}{C.RESET}")
        else:
            log("SKIP", f"Sem WHM em nenhuma porta: {host}")

    with ThreadPoolExecutor(max_workers=threads) as ex:
        futs = [ex.submit(_probe, h) for h in sorted(all_hosts)]
        for _ in as_completed(futs):
            pass

    log("DISC", f"{'─'*50}")
    log("DISC",
        f"Descobrimento completo: {C.GREEN}{len(live)}{C.RESET} alvo(s) WHM encontrados")
    log("DISC", f"{'─'*50}")
    return live

# ══════════════════════════════════════════════════════════════


# ══════════════════════════════════════════════════════════════
#  WORDLIST DE SUBDOMÍNIOS — enfocada em WHM/cPanel
# ══════════════════════════════════════════════════════════════
WHM_WORDLIST: List[str] = [
    # Paneles directos cPanel / WHM
    "cpanel", "whm", "webmail", "webdisk", "cpcalendars", "cpcontacts",
    "cp", "wm", "panel", "control", "manage", "secure",
    # Hosting tiers
    "host", "host1", "host2", "host3", "host4",
    "server", "server1", "server2", "server3", "server4", "server5",
    "vps", "vps1", "vps2", "vps3",
    "dedicated", "dedi", "dedi1",
    "shared", "shared1", "reseller",
    "node", "node1", "node2",
    # Web
    "www", "www1", "www2",
    "web", "web1", "web2",
    "origin", "direct",
    # Mail
    "mail", "mail1", "mail2", "mail3",
    "smtp", "smtp1", "pop", "pop3", "imap",
    "mx", "mx1", "mx2", "email", "webmail2",
    # FTP / files
    "ftp", "ftp1", "sftp", "files", "backup", "bk",
    # DNS
    "ns1", "ns2", "ns3", "ns4",
    # Admin / auth
    "admin", "admin1", "login", "auth",
    "portal", "customer", "client", "billing", "pay", "invoice",
    "support", "help", "ticket",
    # DB
    "db", "db1", "mysql", "database", "phpmyadmin", "pma",
    # Dev / staging
    "dev", "dev1", "development",
    "staging", "stage", "uat",
    "test", "test1", "testing",
    "demo", "sandbox", "beta", "alpha",
    "prod", "production", "live",
    "new", "old",
    # CMS / apps
    "blog", "wp", "wordpress",
    "shop", "store", "woo", "ecommerce",
    "forum", "community", "board",
    "api", "api2", "api3", "app", "apps",
    "v2", "v3",
    # Media / CDN
    "cdn", "cdn1", "static", "media", "img", "images", "assets",
    # Infra / network
    "vpn", "remote", "gw", "gateway", "proxy",
    "cloud", "aws", "azure",
    "monitor", "stats", "status", "analytics",
    "git", "svn", "ci", "gitlab",
    # Mobile
    "m", "mobile", "wap",
    # Misc
    "intranet", "internal",
    "relay", "bounce",
    "ssl", "tls",
    "home", "main",
]
