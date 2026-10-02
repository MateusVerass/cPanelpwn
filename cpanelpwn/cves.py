"""Módulo cPanelpwn: cves.

Catálogo estático das CVEs relevantes de cPanel & WHM / plugins.

Serve três propósitos:
  * metadados (CVSS, componente, referência) usados nos relatórios — evita
    espalhar números mágicos pelo código;
  * atribuição de versão: dado um `11.x.y.z`, dizer quais CVEs do catálogo
    provavelmente afetam a instalação (`cves_affecting`);
  * registro de exploits: `EXPLOITABLE` marca as CVEs com módulo de exploit
    implementado (hoje só a CVE-2026-41940). É o ponto de extensão para
    novas cadeias.

Os dados de versões corrigidas vêm dos advisories oficiais do cPanel
(support.cpanel.net) e do changelog. Quando o advisory não publica faixas
de versão, `fixed` fica `None` e a CVE só é reportada no catálogo
(`--list-cves`), sem atribuição automática.
"""

from typing import Dict, List, Optional, NamedTuple

from .core import parse_cpanel_version


class CVE(NamedTuple):
    id: str
    cvss: Optional[float]
    component: str          # "WHM", "cPanel", "LiteSpeed plugin", ...
    auth: str               # "pré-auth", "pós-auth", "conta de e-mail"...
    summary: str
    reference: str
    # {branch_str: (patched_patch, patched_build)} — None quando desconhecido.
    fixed: Optional[Dict[str, tuple]] = None
    # Versão máxima afetada (inclusive), ex.: (138, 0, 0) para "11.138.0.0 e anteriores".
    max_affected: Optional[tuple] = None
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
        fixed={"110": (0, 97), "118": (0, 63), "126": (0, 54),
               "132": (0, 29), "134": (0, 20), "136": (0, 5),
               "138": (0, 0)},
        exploitable=True,
    ),
    CVE(
        id="CVE-2026-58047",
        cvss=None,
        component="cPanel",
        auth="pré-auth",
        summary="HTTP Request Smuggling no cPanel que pode vazar credenciais.",
        reference="https://support.cpanel.net/hc/en-us/articles/42285024734743",
    ),
    CVE(
        id="CVE-2026-65643",
        cvss=8.8,
        component="cPanel",
        auth="pós-auth",
        summary="Eval injection na Park API do cPanel (≤ 11.138.0.0) permite "
                "código arbitrário como root.",
        reference="https://support.cpanel.net/hc/en-us/articles/42959571221527",
        max_affected=(138, 0, 0),
    ),
    CVE(
        id="CVE-2026-67401",
        cvss=9.9,
        component="cPanel",
        auth="conta de e-mail",
        summary="SQLi na funcionalidade EmailTrack permite RCE como root a "
                "partir de uma conta com e-mail habilitado.",
        reference="https://support.cpanel.net/hc/en-us/articles/43187903921559",
    ),
    CVE(
        id="CVE-2026-87899",
        cvss=None,
        component="cPanel",
        auth="pós-auth",
        summary="Execução com privilégios desnecessários permite código "
                "arbitrário como root.",
        reference="https://support.cpanel.net/hc/en-us/articles/43591715125271",
    ),
    CVE(
        id="CVE-2026-58048",
        cvss=None,
        component="cPanel",
        auth="pós-auth",
        summary="Preservação incorreta do SQL mode ao renomear bancos permite "
                "execução de SQL em contexto root.",
        reference="https://docs.cpanel.net/changelogs/138-change-log",
    ),
    CVE(
        id="CVE-2026-93697",
        cvss=9.0,
        component="WHM",
        auth="pós-auth",
        summary="Stored XSS na interface Mass Modify Accounts do WHM permite "
                "execução arbitrária de código.",
        reference="https://docs.cpanel.net/changelogs/138-change-log/#138011",
    ),
    CVE(
        id="CVE-2026-93029",
        cvss=9.0,
        component="WHM",
        auth="pós-auth",
        summary="Stored XSS na interface Manage SSL Hosts do WHM permite "
                "execução arbitrária de código.",
        reference="https://docs.cpanel.net/changelogs/138-change-log/#138011",
    ),
    CVE(
        id="CVE-2026-48172",
        cvss=9.8,
        component="LiteSpeed plugin",
        auth="pré-auth",
        summary="LiteSpeed User-End cPanel Plugin < 2.4.5 permite escalar "
                "privilégios (possivelmente a root). Explorado in-the-wild; "
                "consta no catálogo KEV da CISA.",
        reference="https://blog.litespeedtech.com/2026/05/21/security-update-for-litespeed-cpanel-plugin/",
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


def cves_affecting(version: str) -> List[CVE]:
    """CVEs do catálogo cujo range de versão indica que `version` é afetada.

    Só devolve CVEs com faixa conhecida (tabela `fixed` ou `max_affected`);
    CVEs sem faixa publicada não entram (apareceriam como falso positivo).
    """
    parsed = parse_cpanel_version(version)
    if not parsed:
        return []
    branch, patch, build = parsed
    hit: List[CVE] = []
    for c in CVES:
        if c.fixed:
            key = str(branch)
            if key in c.fixed and (patch, build) < c.fixed[key]:
                hit.append(c)
        elif c.max_affected is not None:
            if (branch, patch, build) <= c.max_affected:
                hit.append(c)
    return hit


def print_catalog(log_fn):
    """Imprimir o catálogo de CVEs usando o logger da tool."""
    log_fn("INFO", f"Catálogo de CVEs de cPanel & WHM ({len(CVES)} entradas):")
    for c in list_cves():
        score = f"{c.cvss:.1f}" if c.cvss is not None else " n/d"
        mark = "[EXPLOIT]" if c.exploitable else "[  info ]"
        log_fn("INFO", f"  {c.id:16} CVSS {score:>4}  {mark}  "
                       f"{c.component:24} {c.auth:14} {c.summary[:70]}")

