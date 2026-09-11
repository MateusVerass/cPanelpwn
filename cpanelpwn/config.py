"""Módulo cPanelpwn: config."""

import sys, os, threading
from datetime import datetime

VERSION = "2.4"

# ══════════════════════════════════════════════════════════════
#  CORES
# ══════════════════════════════════════════════════════════════
class C:
    RED    = "\033[91m"; GREEN  = "\033[92m"; YELLOW = "\033[93m"
    BLUE   = "\033[94m"; PURPLE = "\033[95m"; CYAN   = "\033[96m"
    BOLD   = "\033[1m";  DIM    = "\033[2m";  RESET  = "\033[0m"
    ORANGE = "\033[38;5;208m"

LOG_LOCK   = threading.Lock()
PRINT_LOCK = threading.Lock()

# Globals estabelecidos desde args de CLI antes de começar o scan
_RETRIES       = 2
_QUIET         = False   # suprime todos os logs excepto PWNED/CRIT/HIGH
_PROXY         = None    # e.g. "http://127.0.0.1:8080"
_TIMEOUT_PROBE = 5       # timeout curto para fases de discovery / probe WAF / check
_DELAY         = 0.0     # fixed per-request delay (stealth)
_JITTER        = 0.0     # random ±jitter added to _DELAY
_UA            = None    # custom User-Agent override
_NO_RESEARCH   = False   # skip internet WAF bypass research
_NO_BANNER     = False   # skip ASCII banner
_CVE_FEED_ON   = True    # CVE feed on startup
_CVE_DAYS      = 90      # feed window in days
_UPDATE_CHECK  = True    # GitHub release version check
_JSON_LINES    = False   # emit findings as NDJSON on stdout
_CHECKPOINT    = None    # instância de store.Checkpoint (definida pela CLI em batch)

def ts():
    return datetime.now().strftime("%H:%M:%S")

_QUIET_PASS = {"PWNED", "CRIT", "HIGH"}

def log(level, msg, target=""):
    if _QUIET and level not in _QUIET_PASS:
        return
    icons = {
        "CRIT":  f"{C.RED}{C.BOLD}[CRIT]{C.RESET}",
        "HIGH":  f"{C.RED}[HIGH]{C.RESET}",
        "INFO":  f"{C.BLUE}[INFO]{C.RESET}",
        "OK":    f"{C.GREEN}[  OK]{C.RESET}",
        "ERR":   f"{C.DIM}[ ERR]{C.RESET}",
        "SKIP":  f"{C.DIM}[SKIP]{C.RESET}",
        "SCAN":  f"{C.PURPLE}[SCAN]{C.RESET}",
        "STEP":  f"{C.CYAN}[STEP]{C.RESET}",
        "PWNED": f"{C.RED}{C.BOLD}[PWND]{C.RESET}",
        "WARN":  f"{C.YELLOW}[WARN]{C.RESET}",
        "API":   f"{C.ORANGE}[ API]{C.RESET}",
        "PROG":  f"{C.PURPLE}[PROG]{C.RESET}",
        "DISC":  f"{C.CYAN}[DISC]{C.RESET}",
        "CHECK": f"{C.CYAN}[CHK]{C.RESET}",
    }.get(level, f"[{level:>4}]")
    t = f" {C.DIM}{target}{C.RESET}" if target else ""
    with LOG_LOCK:
        print(f"{C.DIM}{ts()}{C.RESET} {icons} {msg}{t}", file=sys.stderr, flush=True)

def safe_print(msg):
    with PRINT_LOCK:
        print(msg, flush=True)

def banner():
    if _NO_BANNER:
        return
    print(f"""{C.ORANGE}{C.BOLD}
   ██████╗██████╗  █████╗ ███╗  ██╗███████╗██╗
  ██╔════╝██╔══██╗██╔══██╗████╗ ██║██╔════╝██║
  ██║     ██████╔╝███████║██╔██╗██║█████╗  ██║
  ██║     ██╔═══╝ ██╔══██║██║╚████║██╔══╝  ██║
  ╚██████╗██║     ██║  ██║██║ ╚███║███████╗███████╗
   ╚═════╝╚═╝     ╚═╝  ╚═╝╚═╝  ╚══╝╚══════╝╚══════╝{C.RESET}
{C.BOLD}██████╗ ██╗    ██╗███╗   ██╗{C.RESET}
{C.BOLD}██╔══██╗██║    ██║████╗  ██║{C.RESET}
{C.BOLD}██████╔╝██║ █╗ ██║██╔██╗ ██║{C.RESET}
{C.BOLD}██╔═══╝ ██║███╗██║██║╚██╗██║{C.RESET}
{C.BOLD}██║     ╚███╔███╔╝██║ ╚████║{C.RESET}
{C.BOLD}╚═╝      ╚══╝╚══╝ ╚═╝  ╚═══╝{C.RESET}
{C.CYAN}  CVE-2026-41940 — cPanel & WHM Auth Bypass via CRLF Injection{C.RESET}
{C.DIM}  4 estágios: preauth → injeção CRLF → propagação → verificação → post-exploit{C.RESET}
{C.RED}  In-The-Wild | CVSS 10.0{C.RESET}
""", file=sys.stderr)

# ══════════════════════════════════════════════════════════════

