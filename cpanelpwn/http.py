"""Módulo cPanelpwn: http."""

import ssl, threading, time, random
from urllib.parse import urlparse, urlencode
import urllib.request, urllib.error
from . import config as cfg

# ══════════════════════════════════════════════════════════════
#  MOTOR HTTP — stdlib, acesso raw a Set-Cookie preservado
# ══════════════════════════════════════════════════════════════
class _SSLCtx:
    """Contextos TLS cacheados por (verificar, cafile).

    Por padrão não verificamos o certificado (alvos WHM costumam usar
    certificado autoassinado). `--verify-tls` usa as CAs do sistema e
    `--cacert FILE` verifica contra um bundle específico.
    """
    _cache = {}
    _lock  = threading.Lock()

    @classmethod
    def get(cls, verify: bool = False, cafile=None):
        key = (bool(verify), cafile or "")
        with cls._lock:
            ctx = cls._cache.get(key)
            if ctx is not None:
                return ctx
            if verify:
                ctx = ssl.create_default_context(cafile=cafile or None)
            else:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode    = ssl.CERT_NONE
            try:
                ctx.set_ciphers("DEFAULT:@SECLEVEL=1")
            except Exception:
                pass
            cls._cache[key] = ctx
            return ctx

BASE_UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
           "AppleWebKit/537.36 (KHTML, like Gecko) "
           "Chrome/146.0.0.0 Safari/537.36")

class R:
    """Wrapper fino de resposta."""
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

_OPENER_CACHE = {}
_OPENER_LOCK  = threading.Lock()

def _build_opener(follow: bool) -> urllib.request.OpenerDirector:
    """Devolver um opener cacheado por (follow, proxy, verificação TLS).

    Reutilizar o opener evita reconstruir handlers a cada request em scans
    grandes; o cache é invalidado quando a configuração relevante muda.
    """
    key = (bool(follow), cfg._PROXY or "", cfg._CAFILE or "",
           bool(cfg._VERIFY_TLS))
    with _OPENER_LOCK:
        op = _OPENER_CACHE.get(key)
        if op is not None:
            return op
        handlers: list = [urllib.request.HTTPSHandler(
            context=_SSLCtx.get(cfg._VERIFY_TLS, cfg._CAFILE))]
        if cfg._PROXY:
            handlers.append(urllib.request.ProxyHandler(
                {"http": cfg._PROXY, "https": cfg._PROXY}))
        if not follow:
            handlers.append(_NoRedir())
        op = urllib.request.build_opener(*handlers)
        op.addheaders = []
        _OPENER_CACHE[key] = op
        return op

def clear_opener_cache():
    with _OPENER_LOCK:
        _OPENER_CACHE.clear()

def _do(url, method="GET", extra_headers=None, data=None, timeout=15,
        follow=False, canonical_host=None):
    parsed = urlparse(url)
    h = {"User-Agent": cfg._UA or BASE_UA, "Accept": "*/*", "Connection": "close"}
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

    for attempt in range(cfg._RETRIES + 1):
        if cfg._DELAY:
            time.sleep(cfg._DELAY + (random.uniform(0, cfg._JITTER) if cfg._JITTER else 0))
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
                # Erros transitórios do servidor (5xx / 429) → tentar de novo.
                # NOTA: com follow=False, _NoRedir devolve a resposta raw
                # (sem HTTPError), por isso a verificação de status deve viver aqui.
                if (resp.status >= 500 or resp.status == 429) \
                    and attempt < cfg._RETRIES:
                    time.sleep(0.5 * (attempt + 1))
                    continue
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
            # HTTPError só chega aqui com follow=True (handlers por padrão)
            if (e.code >= 500 or e.code == 429) and attempt < cfg._RETRIES:
                time.sleep(0.5 * (attempt + 1))
                continue
            return R(e.code, body, rh, url, "\n".join(raw_ck))
        except Exception as ex:
            last_exc = ex
            if attempt < cfg._RETRIES:
                time.sleep(0.5 * (attempt + 1))

    return R(0, str(last_exc), {}, url, "")

# ══════════════════════════════════════════════════════════════

