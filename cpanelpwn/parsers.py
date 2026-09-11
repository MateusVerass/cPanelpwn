"""Módulo cPanelpwn: parsers."""

import os, json
import xml.etree.ElementTree as ET
from typing import List, Set
from . import config as cfg
from . import core
from .config import log
from .core import parse_target

# ══════════════════════════════════════════════════════════════
#  PARSEADORES DE FORMATO DE ENTRADA (nmap XML / masscan JSON / Shodan NDJSON / texto plano)
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
            if ":" in ip and not ip.startswith("["):
                ip = f"[{ip}]"          # IPv6 needs brackets in URLs
            for port_el in host.findall(".//port"):
                port_id = int(port_el.get("portid", 0))
                state   = port_el.find("state")
                if state is not None and state.get("state") == "open" and port_id:
                    targets.append(f"{_port_scheme(port_id)}://{ip}:{port_id}")
    except Exception as e:
        log("WARN", f"erro de parse nmap XML: {e}")
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
        log("WARN", f"erro de parse masscan JSON: {e}")
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
    """Auto-detectar formato de entrada e devolver lista de URLs de alvos."""
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            raw = f.read()
    except FileNotFoundError:
        return []

    stripped = raw.lstrip()
    if path.lower().endswith(".xml") or "<nmaprun" in stripped[:300]:
        log("INFO", "Formato nmap XML detectado")
        return parse_nmap_xml(path)
    if stripped.startswith("["):
        log("INFO", "Formato masscan JSON detectado")
        return parse_masscan_json(stripped)
    if stripped.startswith("{"):
        log("INFO", "Formato Shodan NDJSON detectado")
        return parse_shodan_json(stripped)
    # Texto plano — um alvo por linha
    return [ln.strip() for ln in raw.splitlines()
            if ln.strip() and not ln.strip().startswith("#")]

# ══════════════════════════════════════════════════════════════
#  LISTA DE EXCLUSIÓN
# ══════════════════════════════════════════════════════════════
def load_exclude(path: str) -> Set[str]:
    """Carregar pares host:porta a excluir do scan."""
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
        log("WARN", f"Arquivo de exclusão não encontrado: {path}")
    return excluded

def is_excluded(target: str, excluded: Set[str]) -> bool:
    if not excluded:
        return False
    if "://" not in target:
        target = "https://" + target
    _, h, port = parse_target(target)
    return f"{h}:{port}" in excluded

# ══════════════════════════════════════════════════════════════

