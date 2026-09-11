"""Módulo cPanelpwn: store."""

import json, os, threading
from datetime import datetime
from typing import Dict, List, Set, Optional
from . import config as cfg
from .config import C, log
from .core import ScanCtx

# ══════════════════════════════════════════════════════════════
#  HALLAZGOS + MAPA CTX
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
#  RASTREADOR DE PROGRESO
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
#  CHECKPOINT DE RESUME — persistir estado do scan para --resume
# ══════════════════════════════════════════════════════════════
DEFAULT_CHECKPOINT = os.path.join(
    os.environ.get("XDG_CACHE_HOME") or os.path.join(os.path.expanduser("~"), ".cache"),
    "cpanelpwn", "resume.json")

class Checkpoint:
    """Persiste alvos terminados para que um scan batch interrompido possa ser retomado.

    Estrutura (JSON):
      {
        "version": "2.4",
        "created":  "...",
        "targets":  ["https://a:2087", ...],      # lista completa de alvos
        "done":     {"https://a:2087": {"vuln": bool, ...}},  # terminados
        "ts":       ...
      }
    """

    def __init__(self, path: str = DEFAULT_CHECKPOINT, enabled: bool = True):
        self.path    = path
        self.enabled = enabled
        self._lock   = threading.Lock()
        self._data   = {"version": cfg.VERSION, "created": datetime.now().isoformat(),
                        "targets": [], "done": {}}
        self._dirty  = 0
        if enabled and path and os.path.exists(path):
            try:
                with open(path, encoding="utf-8") as f:
                    loaded = json.load(f)
                if loaded.get("version") == cfg.VERSION:
                    self._data.update(loaded)
            except Exception:
                pass

    def set_targets(self, targets: List[str]):
        with self._lock:
            self._data["targets"] = list(targets)
            self._save()

    def mark_done(self, target: str, result: dict):
        with self._lock:
            self._data["done"][target] = result
            self._dirty += 1
            if self._dirty >= 10:
                self._dirty = 0
                self._save()

    def done(self) -> Set[str]:
        with self._lock:
            return set(self._data.get("done", {}))

    def results(self) -> Dict[str, dict]:
        with self._lock:
            return dict(self._data.get("done", {}))

    def targets(self) -> List[str]:
        with self._lock:
            return list(self._data.get("targets", []))

    def save(self):
        with self._lock:
            self._save()

    def clear(self):
        with self._lock:
            self._data["done"] = {}
            self._save()

    def _save(self):
        if not self.enabled or not self.path:
            return
        try:
            os.makedirs(os.path.dirname(self.path), exist_ok=True)
            self._data["ts"] = datetime.now().isoformat()
            with open(self.path, "w", encoding="utf-8") as f:
                json.dump(self._data, f)
        except Exception:
            pass

# ══════════════════════════════════════════════════════════════

