"""Módulo cPanelpwn: cve_feed."""

import os, re, json
from datetime import datetime, timedelta, timezone
from typing import Optional, Dict, List
from . import config as cfg
from . import http
import time
from .config import C, VERSION, log
from .http import _do

# ══════════════════════════════════════════════════════════════
#  FEED CVE + COMPROBACIÓN DE ACTUALIZACIÓN — CVEs recientes de cPanel/WHM al inicio
# ══════════════════════════════════════════════════════════════
# Se obtém uma vez de APIs públicas (sem auth), cacheado 24h em
# ~/.cache/cpanelpwn/cve_feed.json para que as execuções repetidas sejam silenciosas.
CVE_FEED_TTL = 24 * 3600
CVE_FEED_MAX = 8

def cve_feed_sources(days: int) -> List[tuple]:
    """Construir lista de fontes do feed para a janela dada (em dias).

    Principal: NVD API v2.0 com pubStartDate/pubEndDate para que só se
    devolvam CVEs publicadas dentro da janela (a pesquisa por keyword
    só ordena por relevância e tira entradas de há décadas).
    Fallback: pesquisa CIRCL (dava 404 ao momento de escrever; se mantém por resiliência).
    """
    end   = datetime.now(timezone.utc).replace(tzinfo=None)
    start = end - timedelta(days=days)
    fmt   = "%Y-%m-%dT%H:%M:%S.000"
    srcs: List[tuple] = []
    for kw in ("cpanel", "whm"):
        srcs.append(("nvd",
            f"https://services.nvd.nist.gov/rest/json/cves/2.0"
            f"?keywordSearch={kw}"
            f"&pubStartDate={start.strftime(fmt)}"
            f"&pubEndDate={end.strftime(fmt)}"
            f"&resultsPerPage=50"))
    srcs += [
        ("circl", "https://cve.circl.lu/api/search/cpanel"),
        ("circl", "https://cve.circl.lu/api/search/whm"),
    ]
    return srcs

def _cve_cache_path() -> str:
    base = os.environ.get("XDG_CACHE_HOME") \
        or os.path.join(os.path.expanduser("~"), ".cache")
    d = os.path.join(base, "cpanelpwn")
    try:
        os.makedirs(d, exist_ok=True)
    except Exception:
        pass
    return os.path.join(d, "cve_feed.json")

def _read_json_cache(path: str) -> Optional[dict]:
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return None

def _write_json_cache(path: str, data: dict):
    try:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f)
    except Exception:
        pass

def _cve_published_ts(c: dict) -> float:
    for k in ("published", "Published", "Modified"):
        v = c.get(k)
        if v:
            try:
                return datetime.fromisoformat(str(v).replace("Z", "+00:00")).timestamp()
            except Exception:
                pass
    return 0.0

def _cve_score(c: dict) -> float:
    cv = c.get("cvss")
    if isinstance(cv, dict):
        try: return float(cv.get("score", 0) or 0)
        except Exception: return 0.0
    try: return float(cv or 0)
    except Exception: return 0.0

def _parse_nvd_cves(body: str) -> List[dict]:
    """Parsear resposta de NVD API v2.0 /rest/json/cves/2.0."""
    out: List[dict] = []
    try:
        data = json.loads(body)
        for item in data.get("vulnerabilities", []):
            cve = item.get("cve", {})
            cid = cve.get("id", "")
            if not cid:
                continue
            desc = ""
            for d in cve.get("descriptions", []):
                if d.get("lang") == "en":
                    desc = d.get("value", "")
                    break
            score = 0.0
            for mkey in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                m = (cve.get("metrics", {}) or {}).get(mkey)
                if m:
                    m0 = m[0]
                    # V3.x anida sob cvssData; V2 tem baseScore no nível superior
                    score = float(m0.get("cvssData", {}).get("baseScore", 0)
                                  or m0.get("baseScore", 0) or 0)
                    break
            out.append({
                "id":        cid,
                "summary":   desc[:220],
                "score":     score,
                "published": cve.get("published", ""),
                "url":       f"https://nvd.nist.gov/vuln/detail/{cid}",
            })
    except Exception:
        pass
    return out

def _parse_circl_cves(body: str) -> List[dict]:
    """Parsear resposta de CIRCL /api/search/<kw> (lista de dicts CVE)."""
    out: List[dict] = []
    try:
        data = json.loads(body)
        items = data if isinstance(data, list) else data.get("results", [])
        for it in items:
            cid = it.get("id") or it.get("cve_id") or ""
            if not cid:
                continue
            out.append({
                "id":        cid,
                "summary":   (it.get("summary") or it.get("description") or "")[:220],
                "score":     _cve_score(it),
                "published": it.get("Published") or it.get("published") or "",
                "url":       f"https://nvd.nist.gov/vuln/detail/{cid}",
            })
    except Exception:
        pass
    return out

def fetch_cve_feed(timeout: int = 12, days: int = 90) -> List[dict]:
    """Obter CVEs de cPanel/WHM publicadas dentro de `days` de APIs públicas
    (NVD principal, sem auth). Deduplica por id de CVE. Devolve [] se todas
    as fontes falham — o chamador degrada com graça (offline / cambios de API).
    """
    seen: Dict[str, dict] = {}
    for kind, url in cve_feed_sources(days):
        try:
            resp = _do(url, timeout=timeout)
            if resp.status != 200 or not resp.body:
                continue
            items = (_parse_nvd_cves(resp.body) if kind == "nvd"
                     else _parse_circl_cves(resp.body))
            for it in items:
                # "whm" keyword also matches WHMCS (a different product) —
                # descartar esses falsos positivos, manter CVEs reais de cPanel/WHM
                if "whmcs" in it["summary"].lower():
                    continue
                seen.setdefault(it["id"], it)
        except Exception:
            continue
    return list(seen.values())

def check_tool_update(timeout: int = 8) -> Optional[str]:
    """Verificar releases de GitHub por uma versão mais nova. Devolve tag ou None (falha silenciosa)."""
    try:
        resp = _do(
            "https://api.github.com/repos/MateusVerass/cPanelpwn/releases/latest",
            timeout=timeout,
            extra_headers={"Accept": "application/vnd.github+json"})
        if resp.status != 200:
            return None
        tag = (json.loads(resp.body).get("tag_name") or "").lstrip("vV")
        return tag or None
    except Exception:
        return None

def _ver_tuple(v: str) -> tuple:
    return tuple(int(x) for x in re.findall(r"\d+", v)[:3]) or (0,)

def print_cve_feed(force: bool = False):
    """Mostrar CVEs recentes de cPanel/WHM + estado de atualização da tool ao início."""
    if cfg._QUIET or not cfg._CVE_FEED_ON:
        return

    path  = _cve_cache_path()
    cache = _read_json_cache(path)
    fresh = cache and cache.get("ts", 0) > time.time() - CVE_FEED_TTL

    if cfg._UPDATE_CHECK:
        if fresh and not force:
            up = cache.get("update")
        else:
            up = check_tool_update()
        if up:
            if _ver_tuple(up) > _ver_tuple(VERSION):
                log("WARN", f"Nova versão do cPanelpwn: v{up} — "
                            f"https://github.com/MateusVerass/cPanelpwn/releases")
            else:
                log("OK", f"cPanelpwn v{VERSION} — versão mais recente")
        else:
            log("OK", f"cPanelpwn v{VERSION}")

    if fresh and not force:
        cves = cache.get("cves", [])
    else:
        cves = fetch_cve_feed(timeout=12, days=cfg._CVE_DAYS)
        _write_json_cache(path, {"ts": time.time(), "update": up if cfg._UPDATE_CHECK else None,
                                 "cves": cves})
        if not cves:
            log("SKIP", "CVE feed: nenhuma CVE obtida (offline?)")
            return

    if not cves:
        return

    cves.sort(key=_cve_published_ts, reverse=True)
    top = cves[:CVE_FEED_MAX]

    log("INFO", f"CVE feed — {C.CYAN}{len(top)}{C.RESET} CVE(s) cPanel/WHM "
                f"publicada(s) nos últimos {cfg._CVE_DAYS}d:")
    for c in top:
        score = c.get("score", 0)
        if score >= 7.0:
            sc = f"{C.RED}{C.BOLD}{score:.1f}{C.RESET}"
        elif score >= 4.0:
            sc = f"{C.YELLOW}{score:.1f}{C.RESET}"
        else:
            sc = f"{C.DIM}{score:.1f}{C.RESET}"
        ts_pub = _cve_published_ts(c)
        pub = (datetime.fromtimestamp(ts_pub).strftime("%Y-%m-%d") if ts_pub else "?")
        log("INFO", f"  {C.CYAN}{c['id']}{C.RESET}  CVSS {sc}  "
                    f"{C.DIM}{pub}{C.RESET}  {c.get('summary','')[:100]}")

# ══════════════════════════════════════════════════════════════

