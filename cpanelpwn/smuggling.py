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
