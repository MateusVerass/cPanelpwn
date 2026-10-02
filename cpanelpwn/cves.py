"""Módulo cPanelpwn: cves.

Catálogo estático das CVEs relevantes de cPanel & WHM / plugins.

Serve três propósitos:
  * metadados (CVSS, componente, referência) usados nos relatórios — evita
    espalhar números mágicos pelo código;
  * atribuição de versão: dado um `11.x.y.z`, dizer quais CVEs do catálogo
    afetam a instalação (`cves_affecting`);
  * registro de exploits: `EXPLOITABLE` marca as CVEs com módulo de exploit
    implementado (hoje só a CVE-2026-41940). É o ponto de extensão para
    novas cadeias.

As faixas de versão vêm dos registros CVE (HackerOne/MITRE) e dos advisories
oficiais do cPanel. Cada CVE afetada é uma lista de intervalos
`(piso_inclusivo, teto_exclusivo)`; `None` significa aberto. As faixas são
ancoradas ao ramo (piso explícito), ex.:
`((110, 0, 0), (110, 0, 137))` = "ramo 110, builds abaixo de 110.0.137".

Sobre o CVSS: quando há score v3.x no NVD, ele é preferido; caso contrário
usa-se o score v4.0 publicado. Como as escalas v3 e v4 não são diretamente
comparáveis, o número serve para ordenar/priorizar no relatório, não como
métrica formal.
"""

from typing import Dict, List, Optional, NamedTuple

from .core import parse_cpanel_version

# Um intervalo (piso_inclusivo, teto_exclusivo); None = aberto.
Range = tuple


class CVE(NamedTuple):
    id: str
    cvss: Optional[float]
    component: str          # "WHM", "cPanel", "LiteSpeed plugin", ...
    auth: str               # "pré-auth", "pós-auth", "conta de e-mail"...
    summary: str
    reference: str
    # Intervalos de versões afetadas (piso inclusivo, teto exclusivo).
    affected_ranges: Optional[List[Range]] = None
    # Tabela {branch_str: (patched_patch, patched_build)} — usada quando a
    # atribuição é por build de ramo (ex.: CVE-2026-41940).
    fixed: Optional[Dict[str, tuple]] = None
    exploitable: bool = False


CVES: List[CVE] = [
    CVE(
        id="CVE-2026-41940",
        cvss=9.8,
        component="WHM",
        auth="pré-auth",
        summary="Bypass de autenticação no fluxo de login via injeção CRLF no "
                "arquivo de sessão — acesso root ao WHM sem credenciais.",
        reference="https://support.cpanel.net/hc/en-us/articles/40073787579671",
        affected_ranges=[
            ((40, 0, 0), (86, 0, 41)),
            ((88, 0, 0), (94, 0, 28)),
            ((96, 0, 0), (102, 0, 39)),
            ((104, 0, 0), (110, 0, 97)),
            ((112, 0, 0), (118, 0, 63)),
            ((120, 0, 0), (124, 0, 35)),
            ((126, 0, 0), (126, 0, 54)),
            ((128, 0, 0), (130, 0, 19)),
            ((132, 0, 0), (132, 0, 29)),
            ((134, 0, 0), (134, 0, 20)),
            ((136, 0, 0), (136, 0, 5)),
        ],
        exploitable=True,
    ),
    CVE(
        id="CVE-2026-58047",
        cvss=5.6,
        component="cPanel",
        auth="pré-auth",
        summary="HTTP request smuggling (CWE-444, CL/TE) no cPanel que pode "
                "vazar credenciais de outros usuários.",
        reference="https://support.cpanel.net/hc/en-us/articles/42285024734743",
        affected_ranges=[
            ((110, 0, 0), (110, 0, 137)),
            ((118, 0, 0), (118, 0, 71)),
            ((126, 0, 0), (126, 0, 78)),
            ((134, 0, 0), (134, 0, 48)),
            ((136, 0, 0), (136, 0, 32)),
            ((137, 0, 0), (137, 9999, 99)),
        ],
    ),
    CVE(
        id="CVE-2026-58048",
        cvss=9.4,
        component="cPanel",
        auth="pós-auth",
        summary="Preservação incorreta do SQL mode ao renomear bancos permite "
                "execução de SQL em contexto root.",
        reference="https://support.cpanel.net/hc/en-us/articles/42285024734743",
        affected_ranges=[
            ((110, 0, 0), (110, 0, 137)),
            ((118, 0, 0), (118, 0, 71)),
            ((126, 0, 0), (126, 0, 78)),
            ((134, 0, 0), (134, 0, 48)),
            ((136, 0, 0), (136, 0, 32)),
            ((137, 0, 0), (137, 9999, 99)),
        ],
    ),
    CVE(
        id="CVE-2026-65643",
        cvss=8.8,
        component="cPanel",
        auth="pós-auth",
        summary="Eval injection na Park API do cPanel permite código "
                "arbitrário como root.",
        reference="https://support.cpanel.net/hc/en-us/articles/42959571221527",
        affected_ranges=[
            ((110, 0, 0), (110, 0, 141)),
            ((112, 0, 0), (134, 0, 53)),
            ((136, 0, 0), (136, 0, 37)),
            ((138, 0, 0), (138, 0, 2)),
            ((138, 1, 0), (138, 1, 7)),
        ],
    ),
    CVE(
        id="CVE-2026-67401",
        cvss=9.9,
        component="cPanel",
        auth="conta de e-mail",
        summary="SQLi na funcionalidade EmailTrack permite RCE como root a "
                "partir de uma conta com e-mail habilitado.",
        reference="https://support.cpanel.net/hc/en-us/articles/43187903921559",
        affected_ranges=[
            ((110, 0, 0), (110, 0, 143)),
            ((134, 0, 0), (134, 0, 55)),
            ((136, 0, 0), (136, 0, 39)),
            ((138, 0, 0), (138, 0, 4)),
            ((138, 1, 0), (138, 1, 9)),
        ],
    ),
    CVE(
        id="CVE-2026-87899",
        cvss=9.4,
        component="cPanel",
        auth="pós-auth",
        summary="Execução com privilégios desnecessários permite código "
                "arbitrário como root.",
        reference="https://support.cpanel.net/hc/en-us/articles/43591715125271",
        affected_ranges=[
            ((120, 0, 0), (134, 0, 57)),
            ((136, 0, 0), (136, 0, 41)),
            ((138, 0, 0), (138, 0, 8)),
        ],
    ),
    CVE(
        id="CVE-2026-93697",
        cvss=9.0,
        component="WHM",
        auth="pós-auth",
        summary="Stored XSS na interface Mass Modify Accounts do WHM permite "
                "execução arbitrária de código.",
        reference="https://docs.cpanel.net/changelogs/138-change-log/#138011",
        affected_ranges=[
            ((110, 0, 0), (110, 0, 148)),
            ((134, 0, 0), (134, 0, 61)),
            ((136, 0, 0), (136, 0, 45)),
            ((138, 0, 0), (138, 0, 11)),
        ],
    ),
    CVE(
        id="CVE-2026-93029",
        cvss=9.0,
        component="WHM",
        auth="pós-auth",
        summary="Stored XSS na interface Manage SSL Hosts do WHM permite "
                "execução arbitrária de código.",
        reference="https://docs.cpanel.net/changelogs/138-change-log/#138011",
        affected_ranges=[
            ((110, 0, 0), (110, 0, 148)),
            ((134, 0, 0), (134, 0, 61)),
            ((136, 0, 0), (136, 0, 45)),
            ((138, 0, 0), (138, 0, 11)),
        ],
    ),
    CVE(
        id="CVE-2026-47365",
        cvss=9.9,
        component="WordPress Toolkit plugin",
        auth="pós-auth",
        summary="Argument injection no WordPress Toolkit < 6.11.0 permite "
                "burlar o isolamento entre tenants.",
        reference="https://support.cpanel.net/hc/en-us/articles/40073787579671",
    ),
    CVE(
        id="CVE-2026-48172",
        cvss=9.8,
        component="LiteSpeed plugin",
        auth="pré-auth",
        summary="LiteSpeed User-End cPanel Plugin pode escalar privilégios "
                "(possivelmente a root). Explorado in-the-wild; consta no "
                "catálogo KEV da CISA.",
        reference="https://blog.litespeedtech.com/2026/05/21/security-update-for-litespeed-cpanel-plugin/",
    ),
    CVE(
        id="CVE-2025-66429",
        cvss=8.8,
        component="cPanel",
        auth="pós-auth",
        summary="Path traversal na Team Manager API permite sobrescrever "
                "arquivo arbitrário.",
        reference="https://nvd.nist.gov/vuln/detail/CVE-2025-66429",
    ),
]

_BY_ID: Dict[str, CVE] = {c.id: c for c in CVES}

# CVEs com módulo de exploit implementado (ponto de extensão).
EXPLOITABLE = {c.id for c in CVES if c.exploitable}

DEFAULT_CVE = "CVE-2026-41940"


def get(cve_id: str) -> Optional[CVE]:
    """Devolver a CVE do catálogo pelo id (case-insensitive), ou None."""
    return _BY_ID.get((cve_id or "").upper().strip())


def list_cves() -> List[CVE]:
    """Devolver o catálogo ordenado por severidade (maior primeiro)."""
    return sorted(CVES, key=lambda c: (c.cvss or 0.0), reverse=True)


def cvss_of(cve_id: str, default: Optional[float] = None) -> Optional[float]:
    c = get(cve_id)
    return c.cvss if (c and c.cvss is not None) else default


def _in_range(v: tuple, lo: Optional[tuple], hi: Optional[tuple]) -> bool:
    if lo is not None and v < lo:
        return False
    if hi is not None and v >= hi:
        return False
    return True


def is_affected(version: str, cve: CVE) -> bool:
    """True se `version` cai em algum intervalo afetado (ou tabela por ramo)."""
    parsed = parse_cpanel_version(version)
    if not parsed:
        return False
    if cve.affected_ranges:
        return any(_in_range(parsed, lo, hi) for lo, hi in cve.affected_ranges)
    if cve.fixed:
        key = str(parsed[0])
        if key in cve.fixed:
            return parsed[1:] < cve.fixed[key]
    return False


def cves_affecting(version: str) -> List[CVE]:
    """CVEs do catálogo que afetam `version`.

    Só devolve CVEs com faixa de versão conhecida; as sem faixa publicada
    (ex.: plugins sem versão mapeável) não entram, para não gerar falso
    positivo.
    """
    if not parse_cpanel_version(version):
        return []
    return [c for c in CVES if is_affected(version, c)]


def print_catalog(log_fn):
    """Imprimir o catálogo de CVEs usando o logger da tool."""
    log_fn("INFO", f"Catálogo de CVEs de cPanel & WHM ({len(CVES)} entradas):")
    for c in list_cves():
        score = f"{c.cvss:.1f}" if c.cvss is not None else " n/d"
        mark = "[EXPLOIT]" if c.exploitable else "[  info ]"
        log_fn("INFO", f"  {c.id:16} CVSS {score:>4}  {mark}  "
                       f"{c.component:24} {c.auth:14} {c.summary[:70]}")
