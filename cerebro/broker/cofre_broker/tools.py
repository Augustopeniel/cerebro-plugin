"""Ferramentas do MCP local `cofre`: nenhuma devolve nem recebe o valor de uma credencial.

O valor entra pelo popup mascarado ou é gerado (`generate`); sai só para o destino
(digitar, copiar, o ambiente de um comando, outro MCP pelo canal). As respostas são texto com
metadados, e mesmo assim passam pela máscara com tudo o que foi entregue na chamada.

O que só o dono decide (no portal) e as ferramentas recusam: destino com alvo `*`
(digitar e copiar, por exemplo), a política `livre` e o escopo. O código do pareamento também
não volta ao modelo: só aparece na tela da pessoa.
"""

from __future__ import annotations

import datetime as dt
import time
from collections.abc import Callable
from typing import Any

from . import config as C
from . import platform_io as P
from .broker import KINDS, VIAS, Broker, BrokerError
from .keystore import KeystoreError
from .mask import mask_text
from .protocol import VaultClientError

Handler = Callable[[Broker, dict[str, Any], str | None], str]
LOCAL_ONLY = frozenset({"setup"})  # popups na máquina de quem recebeu a chamada
AGENT_POLICIES = ("sempre", "sessao")  # 'livre' só o dono define (no portal)
OWNER_ONLY = "só o dono define, no portal"


def _ref(args: dict[str, Any], key: str = "ref") -> str:
    found = str(args.get(key) or "").strip().strip("/")
    if not found:
        raise BrokerError(f"faltou '{key}' (caminho da credencial, ex.: 'mcp/zabbix/ZABBIX_PASS')")
    return found


def _when(ts: Any) -> str:
    try:
        return dt.datetime.fromtimestamp(float(ts)).strftime("%Y-%m-%d %H:%M")
    except (TypeError, ValueError, OSError):
        return "-"


def _destinations_text(entry: dict[str, Any]) -> str:
    found = [f"{d.get('via')}:{d.get('alvo')}" for d in entry.get("destinos") or []]
    return ", ".join(found) or "nenhum (não entrega para lugar nenhum)"


def _entry_line(entry: dict[str, Any]) -> str:
    extra = [str(entry.get("tipo", ""))]
    for key in ("usuario", "url", "host"):
        if entry.get(key):
            extra.append(f"{key}: {entry[key]}")
    extra.append(f"v{entry.get('versao', '?')}")
    extra.append(f"destinos: {_destinations_text(entry)}")
    extra.append(f"confirmação: {entry.get('confirmacao', '?')}")
    if entry.get("arquivada"):
        extra.append("ARQUIVADA")
    return f"- {entry.get('caminho')} ({'; '.join(extra)})"


def _agent_destinations(items: Any) -> list[dict[str, str]]:
    """Destinos que o modelo pode pedir: um comando (ambiente) ou um consumidor (mcp) dito pelo
    nome. Alvo `*` (digitar, copiar, qualquer comando) fica para o dono."""
    found = []
    for item in items or []:
        if not isinstance(item, dict):
            raise BrokerError(f"destino inválido: {item!r}")
        target = str(item.get("target") or "").strip()
        if item.get("via") in ("digitar", "copiar") or not target or "*" in target:
            raise BrokerError(
                f"destino {item.get('via')}:{target or '*'}: alvo '*' {OWNER_ONLY}; aqui só "
                "ambiente:<comando> ou mcp:<consumidor>"
            )
        found.append({"via": str(item.get("via")), "target": target})
    return found


def _saved(verb: str, entry: dict[str, Any]) -> str:
    return (
        f"'{entry.get('caminho')}' {verb} (versão {entry.get('versao', '?')}, destinos: "
        f"{_destinations_text(entry)}). O valor não passou por mim."
    )


# ---------------------------------------------------------- handlers -----


def t_status(broker: Broker, args: dict[str, Any], cwd: str | None) -> str:
    s = broker.state()
    lines = [f"{s['name']} {s['version']} | {s['platform']} | servidor {s['server']}"]
    if not s["paired"]:
        lines.append("aparelho: NÃO vinculado — use `pair`")
    else:
        lines.append(f"aparelho: {s.get('device_name') or '-'} ({s.get('device')})")
    lines.append(f"chaves do aparelho: {s['keystore']}")
    if s.get("keystore_warning"):
        lines.append(f"[ALERTA] {s['keystore_warning']}")
    if s.get("account"):
        lines.append(f"conta no portal: {s['account']}")
    if s.get("pairing"):
        lines.append(
            "pareamento pendente: o código e as impressões estão na tela do usuário (popup e "
            "navegador)"
        )
    if s.get("error"):
        lines.append(f"[ERRO] servidor: {s['error']}")
    elif s["paired"]:
        if not s.get("configured"):
            lines.append("cofre: ainda não configurado — use `setup` (só popups)")
        else:
            state = "DESTRAVADO" if s.get("unlocked") else "TRANCADO"
            lines.append(f"cofre: {state}, {s.get('total', 0)} credencial(is) visíveis")
            if s.get("pending_shares"):
                lines.append(
                    f"esperando a aprovação do dono: {s['pending_shares']} (veja `approvals`)"
                )
    lines.append(f"canal dos MCPs locais: {s['channel']}")
    return "\n".join(lines)


def t_unlock(broker: Broker, args: dict[str, Any], cwd: str | None) -> str:
    broker.unlock()
    return (
        "cofre destravado neste aparelho (senha e código entraram pelos popups; eu não os vi). "
        "Tranca sozinho com 2 h sem uso ou ao fechar o Claude."
    )


def t_lock(broker: Broker, args: dict[str, Any], cwd: str | None) -> str:
    broker.lock()
    return "cofre trancado: a sessão foi encerrada no servidor e esquecida aqui."


def t_list(broker: Broker, args: dict[str, Any], cwd: str | None) -> str:
    group = str(args.get("group") or "").strip().strip("/")
    entries = broker.list_entries(group=group, archived=bool(args.get("archived")))
    if not entries:
        return "nenhuma credencial" + (f" no grupo '{group}'." if group else ".")
    lines = [f"{len(entries)} credencial(is) (só metadados, nunca o valor):"]
    lines += [_entry_line(e) for e in sorted(entries, key=lambda e: str(e["caminho"]).lower())]
    return "\n".join(lines)


def t_events(broker: Broker, args: dict[str, Any], cwd: str | None) -> str:
    found = broker.events(int(args.get("limit") or 20))
    if not found:
        return "nenhum evento do cofre registrado."
    lines = [f"últimos {len(found)} evento(s) (sem valores):"]
    for e in found:
        lines.append(
            f"{_when(e.get('quando'))} {e.get('acao')} [{e.get('resultado')}] "
            f"{e.get('motivo') or ''}".rstrip()
        )
    return "\n".join(lines)


def t_approvals(broker: Broker, args: dict[str, Any], cwd: str | None) -> str:
    found = broker.pending()
    shares, teams = found["compartilhamentos"], found["times"]
    if not shares and not teams:
        return "nada esperando a aprovação do dono."
    lines = [f"{len(shares) + len(teams)} pendência(s) esperando o dono (sem valores):"]
    lines += [
        f"- compartilhar {s.get('caminho')} com {s.get('usuario')} (papel {s.get('papel')})"
        for s in shares
    ]
    lines += [f"- chave do time {t.get('nome_time')} para {t.get('usuario')}" for t in teams]
    lines.append(
        "Aprovar é na caixa que aparece logo depois de cada destrave (tranque e destrave para "
        "ver de novo). Cancelar deixa pendente."
    )
    return "\n".join(lines)


def t_store(broker: Broker, args: dict[str, Any], cwd: str | None) -> str:
    path = _ref(args, "path")
    confirm = str(args.get("confirmation") or "sempre")
    if confirm not in AGENT_POLICIES:
        raise BrokerError(f"confirmação '{confirm}' {OWNER_ONLY}; aqui: sempre ou sessao")
    if args.get("scope"):
        raise BrokerError(f"o escopo {OWNER_ONLY}; aqui vale o cérebro do aparelho")
    destinations = _agent_destinations(args.get("destinations"))
    fields = {
        k: args.get(src)
        for k, src in (("usuario", "username"), ("url", "url"), ("descricao", "description"))
    }
    entry = broker.store(
        path,
        generate=bool(args.get("generate")),
        length=int(args.get("length") or 24),
        kind=str(args.get("kind") or "senha"),
        fields={k: str(v) for k, v in fields.items() if v},
        destinations=destinations,
        confirm=confirm,
    )
    how = "com senha forte gerada (ninguém a viu)" if args.get("generate") else "pelo popup"
    return _saved(f"gravada {how}", entry)


def t_update(broker: Broker, args: dict[str, Any], cwd: str | None) -> str:
    entry = broker.replace(
        _ref(args), generate=bool(args.get("generate")), length=int(args.get("length") or 24)
    )
    return _saved("com valor novo", entry)


def t_archive(broker: Broker, args: dict[str, Any], cwd: str | None) -> str:
    entry = broker.archive(_ref(args))
    return f"'{entry.get('caminho')}' arquivada (nada foi apagado; `restore` desfaz)."


def t_restore(broker: Broker, args: dict[str, Any], cwd: str | None) -> str:
    entry = broker.restore(_ref(args))
    return f"'{entry.get('caminho')}' restaurada."


def t_move(broker: Broker, args: dict[str, Any], cwd: str | None) -> str:
    entry = broker.move(_ref(args), _ref(args, "new_path"))
    return (
        f"agora é '{entry.get('caminho')}'. Se é variável de um MCP, o grupo e o nome precisam "
        "continuar batendo com o que ele espera."
    )


def t_import_env(broker: Broker, args: dict[str, Any], cwd: str | None) -> str:
    path = str(args.get("path") or "").strip()
    if not path:
        raise BrokerError("faltou 'path' (caminho do arquivo .env)")
    result = broker.import_env(
        path,
        str(args.get("group") or ""),
        names=args.get("names") or None,
        destinations=_agent_destinations(args.get("destinations")),
        cwd=cwd,
    )
    lines = [
        f"grupo '{result['group']}': {len(result['imported'])} importada(s): "
        f"{', '.join(result['imported']) or '-'}"
    ]
    if result["skipped"]:
        lines.append(f"já existiam (não sobrescrevi): {', '.join(result['skipped'])}")
    for fail in result["failed"]:
        lines.append(f"falhou {fail['name']}: {fail['reason']}")
    lines.append(
        "O .env NÃO foi alterado: esvazie-o depois de conferir que o MCP funciona. Eu não vi "
        "os valores."
    )
    if not args.get("destinations"):
        lines.append(
            "Atenção: sem destinos, nenhuma delas é entregue ainda; o dono diz os destinos no "
            "portal."
        )
    return "\n".join(lines)


def t_inject(broker: Broker, args: dict[str, Any], cwd: str | None) -> str:
    done = broker.inject(_ref(args))
    return f"valor de '{done['path']}' digitado no campo em foco. Eu não vi o valor."


def t_copy(broker: Broker, args: dict[str, Any], cwd: str | None) -> str:
    done = broker.copy(_ref(args))
    return (
        f"valor de '{done['path']}' copiado: cole com {P.paste_shortcut()}. Sai da área de "
        f"transferência em {done['ttl']} s. Eu não vi o valor."
    )


def t_run(broker: Broker, args: dict[str, Any], cwd: str | None) -> str:
    result = broker.run(
        args.get("command") or [],
        group=str(args.get("group") or ""),
        paths=args.get("paths") or [],
        timeout=int(args.get("timeout") or 120),
        cwd=args.get("cwd") or cwd,
    )
    code = "tempo esgotado" if result["timed_out"] else f"código de saída {result['exit_code']}"
    lines = [f"{code} | variáveis do cofre no ambiente: {', '.join(result['variables'])}"]
    lines.append("--- saída (valores do cofre mascarados como ••••) ---")
    lines.append(result["stdout"].rstrip() or "(vazia)")
    if result["stderr"].strip():
        lines.append("--- erros ---")
        lines.append(result["stderr"].rstrip())
    return "\n".join(lines)


def t_ssh_list(broker: Broker, args: dict[str, Any], cwd: str | None) -> str:
    servers = broker.ssh_servers()
    if not servers:
        return (
            "Nenhum servidor no cofre deste cérebro. Servidor é uma credencial do tipo 'ssh' "
            "com host, porta, usuário (e, se precisar, jump e impressão); cadastre pelo portal "
            "ou pelo store com kind='ssh'."
        )
    lines = []
    for e in servers:
        extra = [
            f"salta por {e['jump']}" if e.get("jump") else "",
            "chave do host fixada" if e.get("impressao") else "chave do host NÃO fixada",
            f"regra {e['regra']}" if e.get("regra") and e["regra"] != "livre" else "",
        ]
        lines.append(
            f"- {e['caminho']}: {e.get('usuario', '?')}@{e.get('host', '?')}:"
            f"{e.get('porta', 22)} · " + " · ".join(x for x in extra if x)
        )
    return "\n".join(lines)


def _ssh_text(result: dict[str, Any]) -> str:
    lines = [f"código de saída {result['exit_code']} (chaves dos hosts conferidas)"]
    lines.append("--- saída (valores do cofre mascarados como ••••) ---")
    lines.append(result["stdout"].rstrip() or "(vazia)")
    if result["stderr"].strip():
        lines += ["--- erros ---", result["stderr"].rstrip()]
    return "\n".join(lines)


def t_ssh_run(broker: Broker, args: dict[str, Any], cwd: str | None) -> str:
    return _ssh_text(
        broker.ssh(
            _ref(args, "server"),
            str(args.get("command") or ""),
            stdin=str(args.get("stdin") or ""),
            timeout=int(args.get("timeout") or 60),
        )
    )


def t_ssh_run_script(broker: Broker, args: dict[str, Any], cwd: str | None) -> str:
    from .ssh_connector import script_command

    script = str(args.get("script") or "")
    if not script.strip():
        raise BrokerError("diga o script")
    return _ssh_text(
        broker.ssh(
            _ref(args, "server"),
            script_command(str(args.get("shell") or "sh")),
            stdin=script,
            timeout=int(args.get("timeout") or 120),
            script=True,
        )
    )


def t_pair(broker: Broker, args: dict[str, Any], cwd: str | None) -> str:
    started = broker.pair_start(name=args.get("name") or None, force=bool(args.get("force")))
    if started.get("already"):
        return (
            f"este aparelho já está vinculado ({started.get('name') or '-'}, "
            f"{started.get('device')}). Para vincular de novo, chame com force=true."
        )
    # o código, o link (que leva o código) e as impressões vão só para a tela da pessoa
    # o aviso primeiro e o navegador depois: aberto antes, o navegador cobria o aviso
    broker.ui.show_info("Cofre do cérebro — vincular aparelho", broker.pairing_message(started))
    if started.get("new"):
        time.sleep(1.5)
        broker.ui.open_url(started["link"])
    wait = args.get("wait")
    state = broker.pair_wait(max(0, min(int(300 if wait is None else wait), 600)))
    if state == "aprovado":
        return (
            "aparelho vinculado. Próximo passo: `setup` (1ª vez: senha do cofre e kit por "
            "popup) ou `unlock`."
        )
    if state == "pendente":
        return (
            "aguardando aprovação: código mostrado na tela do usuário, com as impressões das "
            f"chaves para ele comparar com as do portal ({broker.url}/cofre, logado, com MFA). "
            "Chame `pair` de novo para continuar esperando."
        )
    return "o código venceu ou foi recusado: chame `pair` de novo para pedir outro."


def t_setup(broker: Broker, args: dict[str, Any], cwd: str | None) -> str:
    broker.configure()
    return (
        "cofre configurado e destravado: a senha, o kit de recuperação e o código foram só por "
        "popup (eu não vi nenhum). Para cadastrar, use `store` com os dados do chat; o popup pede "
        "só o valor."
    )


HANDLERS: dict[str, Handler] = {
    "status": t_status,
    "unlock": t_unlock,
    "lock": t_lock,
    "list_entries": t_list,
    "events": t_events,
    "store": t_store,
    "update": t_update,
    "archive": t_archive,
    "restore": t_restore,
    "move": t_move,
    "import_env": t_import_env,
    "inject": t_inject,
    "copy": t_copy,
    "run": t_run,
    "ssh_list": t_ssh_list,
    "ssh_run": t_ssh_run,
    "ssh_run_script": t_ssh_run_script,
    "pair": t_pair,
    "setup": t_setup,
    "approvals": t_approvals,
}


def call_tool(broker: Broker, name: str, args: dict[str, Any], cwd: str | None) -> dict[str, Any]:
    """Roda a ferramenta e devolve {text, is_error}; a resposta passa pela máscara."""
    handler = HANDLERS.get(name)
    if handler is None:
        return {"text": f"ferramenta desconhecida: {name}", "is_error": True}
    with broker.capture() as delivered:
        try:
            text, is_error = handler(broker, args, cwd), False
        except (BrokerError, VaultClientError, KeystoreError, P.PlatformError) as exc:
            text, is_error = str(exc), True
        except (ValueError, TypeError) as exc:
            text, is_error = f"argumento inválido: {exc}", True
        except Exception as exc:
            C.log("erro inesperado em", name, ":", type(exc).__name__)
            text, is_error = f"erro interno: {type(exc).__name__}", True
        return {"text": mask_text(text, delivered), "is_error": is_error}


# ----------------------------------------------------------- schemas -----

_REF = {"type": "string", "description": "caminho da credencial, ex.: 'mcp/zabbix/ZABBIX_PASS'"}
_DESTINATIONS = {
    "type": "array",
    "description": "para onde ela pode ir (lista fechada; sem destino não vai a lugar nenhum)",
    "items": {
        "type": "object",
        "properties": {
            "via": {"type": "string", "enum": list(VIAS)},
            "target": {
                "type": "string",
                "description": "nome do comando (ambiente) ou do consumidor (mcp); alvo '*', "
                "digitar e copiar só o dono define (no portal)",
            },
        },
        "required": ["via", "target"],
    },
}
_NO_ARGS = {"type": "object", "properties": {}}

SCHEMAS: list[dict[str, Any]] = [
    {
        "name": "status",
        "inputSchema": _NO_ARGS,
        "description": "Situação do cofre neste aparelho: vinculado, configurado, destravado, "
        "quantas credenciais e o canal dos MCPs locais. Não pede senha. Comece aqui.",
    },
    {
        "name": "unlock",
        "inputSchema": _NO_ARGS,
        "description": "Destrava o cofre: abre um popup NATIVO para o usuário digitar a senha do "
        "cofre (eu nunca a vejo). As ferramentas de entrega destravam sozinhas.",
    },
    {
        "name": "lock",
        "inputSchema": _NO_ARGS,
        "description": "Tranca o cofre agora (encerra a sessão no servidor e esquece aqui).",
    },
    {
        "name": "list_entries",
        "description": "Lista as credenciais visíveis neste aparelho com tipo, usuário, url, "
        "versão e destinos — NUNCA o valor. Use para achar o 'ref' das outras.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "group": {"type": "string", "description": "só este grupo, ex.: 'mcp/zabbix'"},
                "archived": {"type": "boolean", "description": "incluir as arquivadas"},
            },
        },
    },
    {
        "name": "events",
        "description": "Últimos eventos do cofre (gravar, entregar, destravar, recusas), sem "
        "o valor.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "limit": {"type": "integer", "description": "quantos (padrão 20, máx. 200)"}
            },
        },
    },
    {
        "name": "store",
        "description": "Grava uma credencial nova. O valor o usuário digita num popup mascarado "
        "(eu não vejo), ou com generate=true o broker gera uma senha forte que "
        "ninguém vê. NUNCA peça o valor na conversa.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "grupo/NOME, ex.: 'api/GITHUB_PAT'"},
                "kind": {"type": "string", "enum": list(KINDS)},
                "username": {"type": "string"},
                "url": {"type": "string"},
                "description": {"type": "string"},
                "destinations": _DESTINATIONS,
                "confirmation": {
                    "type": "string",
                    "enum": list(AGENT_POLICIES),
                    "description": "caixa de OK a cada uso (padrão) ou nenhuma depois do "
                    "destrave; 'livre' e o escopo só o dono define",
                },
                "generate": {"type": "boolean", "description": "gerar senha forte em vez do popup"},
                "length": {"type": "integer", "description": "tamanho da gerada (padrão 24)"},
            },
            "required": ["path"],
        },
    },
    {
        "name": "update",
        "description": "Troca o valor de uma credencial (vira versão nova): popup mascarado ou "
        "generate=true. Nenhum valor passa por mim.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "ref": _REF,
                "generate": {"type": "boolean"},
                "length": {"type": "integer"},
            },
            "required": ["ref"],
        },
    },
    {
        "name": "archive",
        "description": "Arquiva uma credencial (nada se apaga; deixa de ser entregue). "
        "'restore' desfaz.",
        "inputSchema": {"type": "object", "properties": {"ref": _REF}, "required": ["ref"]},
    },
    {
        "name": "restore",
        "description": "Restaura uma credencial arquivada.",
        "inputSchema": {"type": "object", "properties": {"ref": _REF}, "required": ["ref"]},
    },
    {
        "name": "move",
        "description": "Muda o caminho (grupo e/ou nome) de uma credencial.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "ref": _REF,
                "new_path": {"type": "string", "description": "novo grupo/NOME"},
            },
            "required": ["ref", "new_path"],
        },
    },
    {
        "name": "import_env",
        "description": "Lê um .env local e grava cada variável secreta (nome com KEY, PASS, "
        "SECRET…) como credencial 'grupo/NOME'. O broker lê o arquivo: eu só vejo "
        "os nomes. Não altera o .env nem sobrescreve. Pede confirmação.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "caminho do .env"},
                "group": {"type": "string", "description": "grupo no cofre, ex.: 'mcp/zabbix'"},
                "names": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "só estas variáveis (padrão: as de nome secreto)",
                },
                "destinations": _DESTINATIONS,
            },
            "required": ["path", "group"],
        },
    },
    {
        "name": "inject",
        "description": "Digita o valor no campo em FOCO, sem me devolver. Um popup pede o código "
        "do app autenticador sempre (o usuário põe o cursor no campo e digita o código); terminal "
        "e Claude são recusados. Precisa do destino 'digitar'. Se falhar, use 'copy'.",
        "inputSchema": {"type": "object", "properties": {"ref": _REF}, "required": ["ref"]},
    },
    {
        "name": "copy",
        "description": "Copia o valor para a área de transferência por alguns segundos (limpa "
        "depois). Não me devolve o valor. Precisa do destino 'copiar'; se a política pedir, uma "
        "caixa de OK aparece para o usuário. Nunca leia a área de transferência depois.",
        "inputSchema": {"type": "object", "properties": {"ref": _REF}, "required": ["ref"]},
    },
    {
        "name": "run",
        "description": "Roda um comando (lista de argumentos, sem shell; o programa pelo nome, "
        "achado no PATH, sem pasta) com credenciais no ambiente (um grupo ou caminhos; a "
        "variável é o NOME). Precisa do destino 'ambiente' com o nome do programa. Devolve o "
        "código de saída e a saída com os valores mascarados (••••). Se a política pedir, e "
        "sempre para intérprete/shell, uma caixa de OK aparece para o usuário.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "command": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "programa (só o nome, do PATH) e argumentos, ex.: ['gh', "
                    "'api', 'user']",
                },
                "group": {"type": "string", "description": "todas as entradas diretas do grupo"},
                "paths": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "caminhos das credenciais",
                },
                "timeout": {"type": "integer", "description": "segundos (padrão 120, máx. 600)"},
                "cwd": {
                    "type": "string",
                    "description": "pasta de trabalho (padrão: a do projeto)",
                },
            },
            "required": ["command"],
        },
    },
    {
        "name": "ssh_list",
        "inputSchema": _NO_ARGS,
        "description": "Servidores SSH do cofre neste cérebro (credenciais do tipo 'ssh'): "
        "usuário@host:porta, salto, se a chave do host está fixada e a regra. Sem segredos.",
    },
    {
        "name": "ssh_run",
        "description": "Roda um comando num servidor do cofre. A senha ou a chave (e as dos "
        "saltos) vão direto ao ssh, sem passar por mim; a chave do host é conferida antes e host "
        "sem impressão fixada não recebe segredo (o erro mostra a impressão para gravar). Host "
        "com regra 'routeros-leitura' só aceita `/menu print|export` com palavras simples.",
        "inputSchema": {
            "type": "object",
            "required": ["server", "command"],
            "properties": {
                "server": {"type": "string", "description": "caminho da credencial ssh"},
                "command": {"type": "string", "description": "comando remoto"},
                "stdin": {"type": "string", "description": "entrada do comando (opcional)"},
                "timeout": {"type": "integer", "description": "segundos (padrão 60, máx. 600)"},
            },
        },
    },
    {
        "name": "ssh_run_script",
        "description": "Roda um script (várias linhas) num servidor do cofre, mandado pelo "
        "stdin do shell remoto. Recusado em host só de leitura.",
        "inputSchema": {
            "type": "object",
            "required": ["server", "script"],
            "properties": {
                "server": {"type": "string", "description": "caminho da credencial ssh"},
                "script": {"type": "string", "description": "o script"},
                "shell": {"type": "string", "description": "shell remoto (padrão sh)"},
                "timeout": {"type": "integer", "description": "segundos (padrão 120, máx. 600)"},
            },
        },
    },
    {
        "name": "pair",
        "description": "Vincula este aparelho ao cofre: pede um código, mostra-o na tela do "
        "usuário (popup) com as impressões das chaves, abre o portal para ele aprovar (logado, "
        "com MFA) e espera. O código não volta para mim.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "name": {
                    "type": "string",
                    "description": "nome do aparelho, ex.: 'Mac do Augusto'",
                },
                "wait": {
                    "type": "integer",
                    "description": "segundos esperando (padrão 300, máx. 600)",
                },
                "force": {
                    "type": "boolean",
                    "description": "vincular de novo um aparelho já vinculado",
                },
            },
        },
    },
    {
        "name": "setup",
        "inputSchema": _NO_ARGS,
        "description": "Configura o cofre na 1ª vez, só por popups: a pessoa cria a senha do "
        "cofre (duas vezes), vê o kit de recuperação uma vez e digita o código do autenticador. "
        "Você não recebe nada disso.",
    },
    {
        "name": "approvals",
        "inputSchema": _NO_ARGS,
        "description": "O que espera a aprovação do dono (compartilhamentos e chaves de time "
        "para membros novos), sem segredo. Aprovar é na caixa que aparece depois do destrave.",
    },
]
assert [s["name"] for s in SCHEMAS] == list(HANDLERS)  # noqa: S101 (as duas listas andam juntas)
