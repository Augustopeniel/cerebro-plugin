"""Hook PreToolUse do Bash (plugin `cerebro`): barra comandos que leriam um segredo cru.

O cofre entrega valores sem mostrá-los ao Claude (inject, copy, run). Este hook fecha os atalhos
que contornariam isso pelo terminal: ler o Keychain com `-w`/`-g`, despejar o Keychain, ler as
chaves do broker, pedir o valor ao canal local do broker (qualquer programa que cite
`broker.sock`/`broker.key`), o `keepassxc-cli show -s`, o Gerenciador de Credenciais do Windows,
a área de transferência logo depois de um `copy`, o ambiente de outros processos (`ps eww`,
`ps -E`, `/proc/*/environ`, onde o `run` deixa as credenciais) e clicar em popups pelo
`osascript` com o System Events.

Só biblioteca padrão. Lê o JSON do hook no stdin; barra com código 2 e a explicação no stderr.
É uma camada a mais, não a garantia: a garantia é o valor nunca chegar à conversa.
"""

from __future__ import annotations

import json
import re
import sys

_I = re.IGNORECASE
# quem lê arquivo (o nome solto conta: `cd ~/.claude/cofre && cat broker.key`); quem só busca
# texto (grep, sed…) conta apenas dentro da pasta do broker, para não barrar busca no código
_READERS = (
    r"\b(?:cat|less|more|head|tail|xxd|od|hexdump|base64|strings|cp|mv|scp|rsync|tar|zip|dd|"
    r"nl|tac|openssl|type|gc|Get-Content|Copy-Item)\b[^|;&]*"
)
_SEARCHERS = r"\b(?:grep|egrep|rg|ag|awk|sed|find|xargs)\b[^|;&]*"
_SECURITY = r"\bsecurity\s+(?:-\S+\s+)*"
RULES: tuple[tuple[re.Pattern[str], str], ...] = (
    (
        re.compile(
            _SECURITY + r"find-(?:generic|internet)-password\b.*\s-[A-Za-z]*[wg][A-Za-z]*(?=\s|$)"
        ),
        "o `security find-*-password` com -w/-g imprime a senha guardada no Keychain",
    ),
    (
        re.compile(_SECURITY + r"(?:dump-keychain|export)\b"),
        "o `security dump-keychain`/`export` despeja segredos do Keychain",
    ),
    (
        re.compile(_SECURITY + r"-i\b|\|\s*(?:/usr/bin/)?security\b"),
        "o `security` interativo (comandos pelo stdin) leria senhas do Keychain",
    ),
    (
        re.compile(
            r"[/\\~]broker\.key\b|[/\\~]cofre-device-keys\b|\$\{?COFRE_BROKER_KEY|"
            + _READERS
            + r"(?:\bbroker\.key\b|\bcofre-device-keys\b|\.claude[/\\]cofre\b)|"
            + _SEARCHERS
            + r"\.claude[/\\]cofre\b",
            _I,
        ),
        "esses são os arquivos de chave do broker do cofre",
    ),
    (
        re.compile(
            r"\b(?:nc|ncat|netcat|socat|curl|python[0-9.]*|node|perl|ruby|php|osascript)\b.*"
            r"(?:broker\.sock|\.claude[/\\]cofre\b|pipe[/\\]+cofre-broker)",
            _I,
        ),
        "o canal local do broker entrega valores em claro: só os MCPs falam com ele",
    ),
    (
        re.compile(
            r"\bcofre_run(?:\.py)?\b.*--consumer|\bimport\s+cofre_client\b|"
            r"\bcofre_client\.(?:valor|grupo)\b"
        ),
        "o `cofre_run`/`cofre_client` põe valores do cofre ao alcance do comando",
    ),
    (
        re.compile(r"\bkeepassxc-cli\b.*\b(?:show\b.*(?:\s-s\b|--show-protected)|export|clip)\b"),
        "o `keepassxc-cli` mostraria ou copiaria a senha",
    ),
    (re.compile(r"\bcmdkey(?:\.exe)?\b", _I), "o `cmdkey` mexe no Gerenciador de Credenciais"),
    (
        re.compile(
            r"Get-StoredCredential|\bCredRead|PasswordVault|RetrievePassword|"
            r"GetNetworkCredential|\bGet-Secret\b|\bvaultcmd\b|PtrToStringBSTR|PtrToStringAuto|"
            r"PtrToStringUni|ConvertFrom-SecureString|SecureStringToBSTR",
            _I,
        ),
        "o PowerShell leria uma credencial guardada em claro",
    ),
    (
        re.compile(
            r"\bpbpaste\b|Get-Clipboard|\bxclip\b.*\s-o\b|\bxsel\b.*(?:\s-o\b|--output)|"
            r"\bwl-paste\b|\bosascript\b.*the clipboard",
            _I,
        ),
        "ler a área de transferência pegaria o valor de um `copy` do cofre",
    ),
    (
        re.compile(r"\bkeyring\s+get\b|keyring\.get_password", _I),
        "o `keyring get` imprime a senha guardada no cofre do sistema",
    ),
    (
        # qualquer programa que fale com o canal ou leia a chave dele; buscar o nome no código
        # (grep, rg, git grep…) segue livre
        re.compile(
            r"^(?!\s*(?:grep|egrep|fgrep|rg|ag|ack|git\s+(?:grep|log|diff|show))\b)"
            r".*(?:\bbroker\.(?:sock|key)\b|\$\{?COFRE_SOCKET\b)",
            _I,
        ),
        "o canal local do broker (`broker.sock`/`broker.key`) entrega valores em claro",
    ),
    (
        # BSD: `ps e`, `ps eww`, `ps auxe` (sem traço) e `-E` mostram o ambiente dos processos
        re.compile(
            r"(?:^|[;&|(`]|\$\(|\b(?:sudo|exec|command|env|nohup|watch))\s*(?:\S*/)?ps\s+"
            r"(?:[A-Za-z]*e[A-Za-z]*(?=\s|$|[;&|)])|(?:[^;&|\s]+\s+)*-[A-Za-z]*E[A-Za-z]*\b)"
        ),
        "o `ps` com `e`/`eww`/`-E` mostra o ambiente de outros processos (onde ficam valores do "
        "`run`)",
    ),
    (
        re.compile(r"/proc/\S*environ|/proc/\S*/[^\s/]*[*?\[]"),
        "o `/proc/*/environ` mostra o ambiente de outros processos (onde ficam valores do `run`)",
    ),
)
# vistas no comando inteiro (um script do osascript pode ocupar várias linhas)
WHOLE_RULES: tuple[tuple[re.Pattern[str], str], ...] = (
    (
        re.compile(
            r"\bosascript\b.*System Events.*\bclick\b|\bosascript\b.*\bclick\b.*"
            r"System Events",
            _I | re.S,
        ),
        "clicar pelo System Events aprovaria um popup do cofre no lugar do usuário",
    ),
)

MESSAGE = (
    "Bloqueado pelo cofre do cérebro: {reason}. O Claude nunca lê segredo cru. Use as "
    "ferramentas do MCP `cofre` (`inject` digita, `copy` copia, `run` põe no ambiente de um "
    "comando com a saída mascarada); para cadastrar, `store` (popup) ou a janela (`open_window`)."
)


def check(command: str) -> str | None:
    """Motivo do bloqueio, ou None se o comando pode rodar."""
    joined = command.replace("\\\n", " ")
    for line in joined.splitlines() or [command]:
        for pattern, reason in RULES:
            if pattern.search(line):
                return reason
    for pattern, reason in WHOLE_RULES:
        if pattern.search(joined):
            return reason
    return None


def main() -> int:
    try:
        event = json.loads(sys.stdin.read() or "{}")
    except ValueError:
        return 0  # não é conosco
    tool_input = event.get("tool_input") if isinstance(event, dict) else None
    command = tool_input.get("command") if isinstance(tool_input, dict) else None
    if not isinstance(command, str):
        return 0
    reason = check(command)
    if reason is None:
        return 0
    sys.stderr.write(MESSAGE.format(reason=reason) + "\n")
    return 2


if __name__ == "__main__":
    sys.exit(main())
