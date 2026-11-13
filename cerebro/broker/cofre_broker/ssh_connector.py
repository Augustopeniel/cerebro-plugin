"""Conector SSH do broker: servidores são credenciais do tipo "ssh" no cofre do cérebro.

Cada servidor é uma credencial `ssh` com metadados `host`, `porta`, `usuario`, `jump` (caminho de
outra credencial ssh para saltar), `impressao` (impressão digital da chave do host, `SHA256:…`) e
`regra`. O valor é a senha ou a chave privada (texto começando por `-----BEGIN`). Desde a 2.10,
uma credencial `senha` com a url `ssh://[usuario@]host[:porta]` também é servidor (é como os
servidores foram cadastrados até aqui): host, porta e usuário saem da url.

Como o segredo chega ao `ssh` sem passar pelo Claude, por disco, por argv ou pelo ambiente (o
`ps eww` do mesmo usuário mostra o ambiente):
- senha: o `SSH_ASKPASS` não tem segredo e pergunta ao broker por um socket local: no macOS e
  no Linux, um socket Unix numa pasta 0700 de nome aleatório (o askpass é um script mínimo que
  vira o Python do broker em modo isolado); no Windows, um socket TCP em 127.0.0.1 com um token
  desta conexão (o askpass é o próprio lançador do plugin, `cerebro-plugin.exe`). O broker
  lança o ssh com `Popen` para saber o pid dele e, a cada pedido, pergunta ao sistema quem
  conectou (LOCAL_PEERPID, SO_PEERCRED, a tabela TCP do Windows): só responde a um descendente
  desse ssh (o askpass que ele abriu, ou o do ssh de um salto). Pedido de outro processo:
  desarma, mata o ssh e registra. Passada a conferência, só o prompt EXATO de um salto
  (`usuario@host's password: `) recebe a senha, uma vez por conexão; qualquer outro
  (keyboard-interactive, passphrase, pergunta) não recebe nada. A pasta é apagada no fim;
- chave: um `ssh-agent` próprio e de vida curta recebe a chave pelo stdin (`ssh-add -t … -`) e
  morre no fim; a chave nunca toca o disco;
- conexão: um `ssh_config` temporário (sem segredo) com um bloco por salto, porque opções `-o`
  não chegam ao ssh do salto (`ProxyJump`).

Chave do host: antes de mandar qualquer credencial a um host, uma sonda conecta sem autenticar
(`PreferredAuthentications=none`), grava a chave num known_hosts temporário e confere a impressão
fixada (`impressao`); só então a conexão de verdade roda com `StrictHostKeyChecking=yes`. Host sem
impressão fixada não recebe segredo: a sonda para nele e o erro mostra a impressão vista, para a
pessoa conferir e gravar no campo `impressao` da credencial.

Regra `routeros-leitura`: só comandos de leitura do RouterOS, por lista do que é permitido (o
MikroTik core é só leitura): caminho + `print` ou `export` + palavras de uma lista curta.
"""

from __future__ import annotations

import base64
import contextlib
import ctypes
import ctypes.util
import hmac
import json
import os
import re
import secrets as _secrets
import shlex
import shutil
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time
from collections.abc import Callable, Iterable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import Any

from . import config as C
from . import peer as PEER

KEY_MARK = b"-----BEGIN"
AGENT_TTL_S = 300
DEFAULT_TIMEOUT_S = 60
PROBE_TIMEOUT_S = 25
_HOST = re.compile(r"^[A-Za-z0-9.:_-]{1,253}$")
_USER = re.compile(r"^[A-Za-z0-9._-]{1,64}$")
_FINGERPRINT = re.compile(r"^SHA256:[A-Za-z0-9+/=]{20,}$")
_FOUND_FINGERPRINT = re.compile(r"SHA256:[A-Za-z0-9+/=]+")
IS_WINDOWS = os.name == "nt"

# RouterOS só leitura, por lista do que é permitido: `/caminho do menu` (segmentos separados
# por `/` ou espaço) + `print` ou `export` + só palavras desta lista. Nada de `[`, `]`, `{`, `}`,
# `:`, `$`, `=` (scripts, `find`, `file=`), nem `;` fora do separador, nem `file`.
ROUTEROS_VERBS = frozenset({"print", "export"})
ROUTEROS_WORDS = frozenset(
    {"detail", "terse", "brief", "without-paging", "count-only", "compact", "verbose"}
)
_ROUTEROS_SEGMENT = re.compile(r"[a-z0-9][a-z0-9-]{0,63}")
_ROUTEROS_FORBIDDEN = re.compile(r"[\[\]{}:$=;]")
# comandos que agem: não podem aparecer no caminho do menu, nem abreviados (o RouterOS aceita
# `reb` por `reboot`): `/system reboot print` reiniciaria o roteador
ROUTEROS_ACTIONS = frozenset(
    {
        "add",
        "apply",
        "cancel",
        "check-for-updates",
        "clear",
        "comment",
        "disable",
        "download",
        "downgrade",
        "edit",
        "enable",
        "execute",
        "export-file",
        "fetch",
        "flush",
        "import",
        "install",
        "make-static",
        "move",
        "netinstall",
        "password",
        "ping",
        "reboot",
        "remove",
        "reset",
        "reset-configuration",
        "reset-counters",
        "run",
        "save",
        "send",
        "set",
        "shutdown",
        "uninstall",
        "unset",
        "upgrade",
    }
)
ROUTEROS_MENU_MAX = 5
RULES = ("livre", "routeros-leitura")

Spawner = Callable[..., subprocess.Popen]


class SshError(Exception):
    """Recusa ou falha do conector; a mensagem diz o motivo (sem segredo)."""


@dataclass(frozen=True)
class Target:
    ref: str  # caminho da credencial no cofre
    host: str
    port: int
    user: str
    secret: bytes = field(repr=False)
    jump: Target | None = None
    fingerprint: str = ""
    rule: str = "livre"

    @property
    def uses_key(self) -> bool:
        return self.secret.lstrip().startswith(KEY_MARK)


def from_url(url: str) -> tuple[str, str, str]:
    """(usuário, host, porta) de `ssh://[usuario@]host[:porta]`, ignorando o que vier depois do
    endereço (`ssh://10.1.2.3:22 (servidor X)`). Fora disso, ("", "", "")."""
    text = str(url or "").strip()
    if not text.lower().startswith("ssh://"):
        return "", "", ""
    rest = re.split(r"[\s/(]", text[6:], maxsplit=1)[0]
    user, _, hostport = rest.rpartition("@")
    host, port = hostport, ""
    if hostport.count(":") == 1:
        host, port = hostport.split(":")
    return user, host, port


def is_server(entry: dict[str, object]) -> bool:
    """Credencial que o conector usa: tipo `ssh`, ou `senha` com url `ssh://…`."""
    if entry.get("tipo") == "ssh":
        return True
    return entry.get("tipo") == "senha" and bool(from_url(str(entry.get("url") or ""))[1])


def target_from(entry: dict[str, object], secret: bytes, jump: Target | None = None) -> Target:
    """Monta o alvo a partir dos metadados da credencial (`list_entries`) e do valor entregue."""
    name = entry.get("caminho")
    url_user, url_host, url_port = from_url(str(entry.get("url") or ""))
    host = str(entry.get("host") or url_host or entry.get("url") or "").strip()
    user = str(entry.get("usuario") or url_user or "").strip()
    port_text = str(entry.get("porta") or url_port or "22").strip()
    rule = str(entry.get("regra") or "livre").strip()
    fingerprint = str(entry.get("impressao") or "").strip()
    if not _HOST.match(host):
        raise SshError(f"{name}: host inválido ou ausente ({host!r})")
    if not _USER.match(user):
        raise SshError(f"{name}: usuário inválido ou ausente")
    if not port_text.isdigit() or not 0 < int(port_text) < 65536:
        raise SshError(f"{name}: porta inválida")
    if fingerprint and not _FINGERPRINT.match(fingerprint):
        raise SshError(f"{name}: impressão digital deve ser SHA256:…")
    if rule not in RULES:
        raise SshError(f"{name}: regra desconhecida {rule!r} (use {', '.join(RULES)})")
    return Target(str(name), host, int(port_text), user, secret, jump, fingerprint, rule)


def routeros_read_only(piece: str) -> bool:
    """Um comando (sem `;`) que só lê: `/a/b c print detail`, `/export compact`."""
    text = piece.strip()
    if not text.startswith("/") or _ROUTEROS_FORBIDDEN.search(text):
        return False
    tokens = [t for t in re.split(r"[/\s]+", text[1:]) if t]
    verb = next((i for i, t in enumerate(tokens) if t in ROUTEROS_VERBS), None)
    if verb is None or "file" in tokens:
        return False
    menu, words = tokens[:verb], tokens[verb + 1 :]
    if len(menu) > ROUTEROS_MENU_MAX:
        return False
    if any(action.startswith(t) for t in menu for action in ROUTEROS_ACTIONS):
        return False  # comando de ação (ou abreviação dele) no meio do caminho
    return all(_ROUTEROS_SEGMENT.fullmatch(t) for t in menu) and all(
        w in ROUTEROS_WORDS for w in words
    )


def check_rule(target: Target, command: str, *, script: bool = False) -> None:
    """Aplica a regra do host antes de qualquer conexão."""
    if target.rule == "livre":
        return
    if script:
        raise SshError(f"{target.ref}: host só de leitura não aceita script")
    pieces = [p.strip() for p in re.split(r"[;\r\n]", command) if p.strip()]
    if not pieces:
        raise SshError(f"{target.ref}: comando vazio")
    for piece in pieces:
        if not routeros_read_only(piece):
            raise SshError(
                f"{target.ref}: host só de leitura — comando recusado: {piece[:80]!r} (só "
                f"`/menu print` ou `/menu export` com {', '.join(sorted(ROUTEROS_WORDS))})"
            )


def hops(target: Target) -> list[Target]:
    """Do primeiro salto ao destino."""
    chain, seen = [], set()
    node: Target | None = target
    while node is not None:
        if node.ref in seen:
            raise SshError(f"salto em círculo em {node.ref}")
        seen.add(node.ref)
        chain.append(node)
        node = node.jump
    return chain[::-1]


# ---------- arquivos temporários (nenhum com segredo) ----------


def alias(index: int) -> str:
    return f"cerebro-salto-{index}"


def write_config(
    chain: list[Target],
    folder: str,
    *,
    known_hosts: str,
    strict: list[bool],
    agent_sock: str | None,
    probe: int | None = None,
) -> str:
    """Um bloco `Host` por salto, cada um saltando pelo anterior. Com `probe`, aquele salto só
    pega a chave do host (sem autenticar) e não manda credencial nenhuma."""
    lines = []
    for i, hop in enumerate(chain):
        lines += [
            f"Host {alias(i)}",
            f"  HostName {hop.host}",
            f"  Port {hop.port}",
            f"  User {hop.user}",
            "  ConnectTimeout 15",
            "  LogLevel ERROR",
            "  UpdateHostKeys no",
            f"  UserKnownHostsFile {known_hosts}",
            f"  GlobalKnownHostsFile {os.devnull}",
            f"  StrictHostKeyChecking {'yes' if strict[i] else 'accept-new'}",
        ]
        if i:
            lines.append(f"  ProxyJump {alias(i - 1)}")
        if probe == i:
            lines += ["  PreferredAuthentications none", "  BatchMode yes"]
        elif hop.uses_key:
            lines += ["  PreferredAuthentications publickey", "  BatchMode yes"]
            if agent_sock:
                lines.append(f"  IdentityAgent {agent_sock}")
        else:  # só senha: keyboard-interactive mostraria prompts que o askpass não confere
            lines += [
                "  PreferredAuthentications password",
                "  PubkeyAuthentication no",
                "  NumberOfPasswordPrompts 1",
            ]
    path = os.path.join(folder, "ssh_config")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")
    os.chmod(path, 0o600)
    return path


def password_prompts(hop: Target) -> list[str]:
    """O prompt exato do OpenSSH para a senha deste salto (sem o espaço final); com o host em
    minúsculas também, se for diferente (o ssh pode normalizar o nome)."""
    found = [f"{hop.user}@{hop.host}'s password:", f"{hop.user}@{hop.host.lower()}'s password:"]
    return list(dict.fromkeys(found))


_SAFE_PROMPT = re.compile(r"[A-Za-z0-9._:@'-]+ password:")

# o askpass do macOS/Linux, sem segredo: pergunta ao broker pelo socket Unix da pasta 0700 desta
# conexão e escreve o que vier; resposta vazia ou qualquer erro: sai com 1 e o ssh não recebe nada
ASKPASS_CLIENT = """\
import base64, json, socket, sys
try:
    s = socket.socket(socket.AF_UNIX)
    s.settimeout(10)
    s.connect(sys.argv[1])
    s.sendall(json.dumps({"p": sys.argv[2]}).encode() + b"\\n")
    d = b""
    while not d.endswith(b"\\n") and len(d) < 65536:
        c = s.recv(4096)
        if not c:
            break
        d += c
    b = json.loads(d or b"{}").get("b")
    if not b:
        sys.exit(1)
    sys.stdout.buffer.write(base64.b64decode(b) + b"\\n")
except Exception:
    sys.exit(1)
"""


def write_askpass(folder: str, python: str, sock: str) -> str:
    """Script do SSH_ASKPASS (macOS/Linux), sem segredo: troca-se (`exec`, mesmo pid, filho do
    ssh) pelo Python do broker em modo isolado, que pergunta pelo socket Unix desta conexão. Quem
    decide se há resposta é o broker (`AskpassServer`): ele confere o processo e o prompt."""
    code = " ".join(shlex.quote(a) for a in (python, "-I", "-c", ASKPASS_CLIENT, sock))
    path = os.path.join(folder, "askpass.sh")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(f'#!/bin/sh\nexec {code} "$1"\n')
    os.chmod(path, 0o700)
    return path


def askpass_by_tcp() -> bool:
    """Windows não tem socket Unix para isso: o askpass é o lançador do plugin, pelo socket TCP
    local. Nos outros sistemas, só com CEREBRO_SSH_ASKPASS=tcp (testes)."""
    return IS_WINDOWS or os.environ.get("CEREBRO_SSH_ASKPASS") == "tcp"


# ---------- quem pede a senha: o processo do outro lado do socket ----------

ANCESTORS_MAX = 16  # askpass → ssh do salto (ProxyJump, às vezes com um sh no meio) → … → o ssh
UNIX_PATH_MAX = 100  # sun_path: 104 bytes no macOS, 108 no Linux
WATCH_WAIT_S = 3.0  # o askpass pode conectar antes de o broker anotar o pid do ssh que lançou
PROC_PIDTBSDINFO, PROC_BSDINFO_SIZE, PBI_PPID_OFFSET = 3, 136, 16  # <sys/proc_info.h>


def _parent_darwin(pid: int) -> int | None:
    libc = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)
    buf = ctypes.create_string_buffer(PROC_BSDINFO_SIZE)
    got = libc.proc_pidinfo(
        ctypes.c_int(pid),
        ctypes.c_int(PROC_PIDTBSDINFO),
        ctypes.c_uint64(0),
        buf,
        ctypes.c_int(PROC_BSDINFO_SIZE),
    )
    if got != PROC_BSDINFO_SIZE:
        return None
    return int(struct.unpack_from("I", buf.raw, PBI_PPID_OFFSET)[0])


def _kernel32():
    from ctypes import wintypes

    k32 = ctypes.WinDLL("kernel32", use_last_error=True)  # type: ignore[attr-defined]
    k32.CreateToolhelp32Snapshot.argtypes = (wintypes.DWORD, wintypes.DWORD)
    k32.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
    k32.CloseHandle.argtypes = (wintypes.HANDLE,)
    k32.OpenProcess.argtypes = (wintypes.DWORD, wintypes.BOOL, wintypes.DWORD)
    k32.OpenProcess.restype = wintypes.HANDLE
    filetime = ctypes.POINTER(wintypes.FILETIME)
    k32.GetProcessTimes.argtypes = (wintypes.HANDLE, filetime, filetime, filetime, filetime)
    return k32, wintypes


def _windows_processes() -> dict[int, int]:
    """pid → pid do pai, de um retrato de todos os processos (Toolhelp32)."""
    k32, wintypes = _kernel32()

    class Entry(ctypes.Structure):  # PROCESSENTRY32W
        _fields_ = [
            ("dwSize", wintypes.DWORD),
            ("cntUsage", wintypes.DWORD),
            ("th32ProcessID", wintypes.DWORD),
            ("th32DefaultHeapID", ctypes.c_size_t),
            ("th32ModuleID", wintypes.DWORD),
            ("cntThreads", wintypes.DWORD),
            ("th32ParentProcessID", wintypes.DWORD),
            ("pcPriClassBase", ctypes.c_long),
            ("dwFlags", wintypes.DWORD),
            ("szExeFile", ctypes.c_wchar * 260),
        ]

    k32.Process32FirstW.argtypes = (wintypes.HANDLE, ctypes.POINTER(Entry))
    k32.Process32NextW.argtypes = (wintypes.HANDLE, ctypes.POINTER(Entry))
    snap = k32.CreateToolhelp32Snapshot(0x2, 0)  # TH32CS_SNAPPROCESS
    if not snap or snap == ctypes.c_void_p(-1).value:
        raise OSError("CreateToolhelp32Snapshot")
    try:
        entry = Entry()
        entry.dwSize = ctypes.sizeof(Entry)
        found: dict[int, int] = {}
        more = k32.Process32FirstW(snap, ctypes.byref(entry))
        while more:
            found[int(entry.th32ProcessID)] = int(entry.th32ParentProcessID)
            more = k32.Process32NextW(snap, ctypes.byref(entry))
        return found
    finally:
        k32.CloseHandle(snap)


def _windows_started(pid: int) -> int | None:
    """Quando o processo nasceu (FILETIME): no Windows o pai anotado de um processo pode ser um
    pid que já morreu e foi reaproveitado; o pai de verdade nasceu antes do filho."""
    k32, wintypes = _kernel32()
    handle = k32.OpenProcess(0x1000, False, pid)  # PROCESS_QUERY_LIMITED_INFORMATION
    if not handle:
        return None
    try:
        times = [wintypes.FILETIME() for _ in range(4)]
        if not k32.GetProcessTimes(handle, *(ctypes.byref(t) for t in times)):
            return None
        return (int(times[0].dwHighDateTime) << 32) | int(times[0].dwLowDateTime)
    finally:
        k32.CloseHandle(handle)


def parent_pid(pid: int) -> int | None:
    """O pai de `pid`, pelo sistema; None se não der para ver."""
    try:
        if sys.platform.startswith("linux"):
            with open(f"/proc/{pid}/stat", "rb") as fh:
                stat = fh.read()
            return int(stat[stat.rindex(b")") + 2 :].split()[1])  # "pid (nome) estado ppid …"
        if sys.platform == "darwin":
            return _parent_darwin(pid)
        if IS_WINDOWS:
            return _windows_processes().get(pid)
    except (OSError, ValueError, IndexError, struct.error):
        return None
    return None


def descends_from(
    pid: int,
    root: int,
    *,
    parent_of: Callable[[int], int | None] = parent_pid,
    started: Callable[[int], int | None] | None = None,
) -> bool:
    """`pid` é descendente de `root` (o ssh que o broker lançou)? Sobe pelos pais até achá-lo.
    Com `started` (Windows), cada pai precisa ter nascido antes do filho."""
    node = pid
    for _ in range(ANCESTORS_MAX):
        up = parent_of(node)
        if not up or up == node:
            return False
        if started is not None:
            born_up, born = started(up), started(node)
            if born_up is None or born is None or born_up > born:
                return False
        if up == root:
            return True
        node = up
    return False


def _descends_here(pid: int, root: int) -> bool:
    if IS_WINDOWS:
        try:
            parents = _windows_processes()
        except OSError:
            return False
        return descends_from(pid, root, parent_of=parents.get, started=_windows_started)
    return descends_from(pid, root)


def _ipv4(value: int) -> str:
    return socket.inet_ntoa(struct.pack("<I", value))  # o DWORD guarda os bytes na ordem da rede


def _port(value: int) -> int:
    return int(struct.unpack(">H", struct.pack("<I", value)[:2])[0])  # 16 bits baixos, da rede


def tcp_owner(table: bytes, local: tuple[str, int], remote: tuple[str, int]) -> int | None:
    """O pid dono da conexão TCP `local` → `remote` numa MIB_TCPTABLE_OWNER_PID (IPv4) do
    `GetExtendedTcpTable`: DWORD com o número de linhas e, por linha, 6 DWORDs (estado, endereço
    e porta locais, endereço e porta remotos, pid)."""
    (count,) = struct.unpack_from("<I", table, 0)
    if len(table) < 4 + 24 * count:
        return None
    for i in range(count):
        _, laddr, lport, raddr, rport, pid = struct.unpack_from("<6I", table, 4 + 24 * i)
        if (_ipv4(laddr), _port(lport)) == local and (_ipv4(raddr), _port(rport)) == remote:
            return int(pid)
    return None


def _windows_tcp_table() -> bytes:
    from ctypes import wintypes

    iphlp = ctypes.WinDLL("iphlpapi")  # type: ignore[attr-defined]
    fn = iphlp.GetExtendedTcpTable
    fn.argtypes = (ctypes.c_void_p, ctypes.POINTER(wintypes.DWORD), wintypes.BOOL,
                   wintypes.ULONG, ctypes.c_int, wintypes.ULONG)  # fmt: skip
    fn.restype = wintypes.DWORD
    size = wintypes.DWORD(0)
    fn(None, ctypes.byref(size), False, socket.AF_INET, 5, 0)  # 5: TCP_TABLE_OWNER_PID_ALL
    for _ in range(5):  # a tabela pode crescer entre as chamadas
        buf = ctypes.create_string_buffer(size.value + 4096)
        size = wintypes.DWORD(len(buf))
        result = fn(buf, ctypes.byref(size), False, socket.AF_INET, 5, 0)
        if result == 0:
            return buf.raw
        if result != 122:  # ERROR_INSUFFICIENT_BUFFER
            break
    raise OSError("GetExtendedTcpTable")


def tcp_peer_pid(conn: socket.socket, addr: tuple[str, int]) -> int | None:
    """Quem abriu esta conexão TCP local, pela tabela TCP do Windows (só lá existe)."""
    if not IS_WINDOWS:
        return None
    try:
        server = conn.getsockname()[:2]
        return tcp_owner(_windows_tcp_table(), (addr[0], int(addr[1])), (server[0], server[1]))
    except (OSError, struct.error, ValueError):
        return None


def _unix_peer_pid(conn: socket.socket, _addr: object) -> int | None:
    return PEER.peer_pid(conn)


def _who(pid: int | None) -> str:
    if pid is None:
        return "processo que o sistema não identificou"
    found = PEER.identify(pid)
    return f"pid {pid}" + (f", {found.exe}" if found else "")


class AskpassServer:
    """Entrega a senha ao askpass, e só a ele. Escuta num socket Unix na pasta 0700 desta conexão
    (macOS/Linux; o askpass é o `write_askpass`) ou em 127.0.0.1 com um bilhete (Windows; o
    askpass é o lançador do plugin, `cerebro-plugin askpass`).

    Antes de ler o pedido, pergunta ao sistema quem conectou (LOCAL_PEERPID no macOS,
    SO_PEERCRED no Linux, a tabela TCP no Windows) e só segue se o processo descender do ssh que
    o broker acabou de lançar (`watch`): o askpass que esse ssh abriu, ou o do ssh de um salto
    (ProxyJump). Qualquer outro processo desarma de vez (nada mais sai nesta execução), mata o
    ssh e fica registrado (`intruder` e o stderr do broker). Passada a conferência, responde ao
    prompt exato de um salto armado, uma vez por conexão (`armed`)."""

    def __init__(
        self,
        chain: list[Target],
        password_hops: Iterable[int],
        folder: str,
        *,
        tcp: bool = False,
        launcher: str | None = None,
        python: str | None = None,
        peer_pid: Callable[[socket.socket, Any], int | None] | None = None,
        descends: Callable[[int, int], bool] = _descends_here,
    ) -> None:
        seen: set[str] = set()
        for index in password_hops:
            for prompt in password_prompts(chain[index]):
                if not _SAFE_PROMPT.fullmatch(prompt):
                    raise SshError(f"prompt de senha inesperado: {prompt!r}")
                if prompt in seen:
                    raise SshError(f"dois saltos com o mesmo prompt de senha ({prompt!r})")
                seen.add(prompt)
        self._chain = chain
        self._tcp = tcp
        self._descends = descends
        self._token = _secrets.token_urlsafe(24)
        self._armed: dict[str, bytes] = {}
        self._cond = threading.Condition()
        self._proc: subprocess.Popen | None = None
        self._tripped = False
        self.intruder = ""  # quem pediu sem ser o askpass desta conexão (vazio: ninguém)
        self._path = self._short = ""
        if tcp:
            exe = launcher or os.environ.get("CEREBRO_LANCADOR", "")
            if not exe or not os.path.isfile(exe):
                raise SshError(
                    "a senha do SSH no Windows usa o lançador do plugin 2.10 ou mais novo: "
                    "atualize o plugin e reinicie o Claude"
                )
            self._server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self._server.bind(("127.0.0.1", 0))
            self._peer_pid = peer_pid or tcp_peer_pid
            self.env = {
                "SSH_ASKPASS": exe,
                "SSH_ASKPASS_REQUIRE": "force",
                "CEREBRO_ASKPASS_PORTA": str(self._server.getsockname()[1]),
                "CEREBRO_ASKPASS_BILHETE": self._token,
            }
        else:
            self._path = os.path.join(folder, "askpass.sock")
            if len(os.fsencode(self._path)) > UNIX_PATH_MAX:  # TMPDIR comprido demais
                self._short = tempfile.mkdtemp(prefix="cerebro-ap-", dir="/tmp")  # 0700
                self._path = os.path.join(self._short, "s")
            self._server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            try:
                self._server.bind(self._path)
            except OSError as exc:
                self._server.close()
                self._cleanup()
                raise SshError(f"não consegui abrir o socket do askpass ({exc})") from exc
            os.chmod(self._path, 0o600)
            self._peer_pid = peer_pid or _unix_peer_pid
            askpass = write_askpass(folder, python or sys.executable, self._path)
            self.env = {"SSH_ASKPASS": askpass, "SSH_ASKPASS_REQUIRE": "force"}
        self._server.listen(4)
        self._server.settimeout(0.2)
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()

    @contextmanager
    def armed(self, passwords: dict[int, bytes]) -> Iterator[None]:
        table = {}
        for index, secret in passwords.items():
            for prompt in password_prompts(self._chain[index]):
                table[prompt] = secret
        with self._cond:
            if not self._tripped:  # depois de um intruso, nada mais é armado
                self._armed = table
        try:
            yield
        finally:
            with self._cond:
                self._armed = {}

    def watch(self, proc: subprocess.Popen | None) -> None:
        """O ssh que o broker acabou de lançar (None: nenhum). Só os descendentes dele levam."""
        with self._cond:
            self._proc = proc
            self._cond.notify_all()

    def intruder_message(self) -> str:
        return (
            f"um processo que não é o askpass desta conexão pediu a senha ({self.intruder}): a "
            "conexão foi abortada e nada foi entregue. Confira o que está rodando nesta máquina."
        )

    def _trip(self, pid: int | None, proc: subprocess.Popen | None) -> None:
        who = _who(pid)
        with self._cond:
            self._tripped = True
            self._armed = {}
            self.intruder = self.intruder or who
        if proc is not None:
            with contextlib.suppress(OSError):
                proc.kill()
        print(  # o registro: vai para o log do broker (stderr do MCP ou do broker de fundo)
            f"cofre: pedido de senha do SSH recusado ({who}): não descende do ssh desta "
            "conexão; ssh abortado, nada entregue",
            file=sys.stderr,
            flush=True,
        )

    def _allowed(self, conn: socket.socket, addr: Any) -> bool:
        pid = self._peer_pid(conn, addr)
        with self._cond:
            self._cond.wait_for(lambda: self._proc is not None, timeout=WATCH_WAIT_S)
            proc = self._proc
        if (
            pid is not None
            and proc is not None
            and proc.poll() is None  # vivo: o pid dele não foi reaproveitado
            and self._descends(pid, proc.pid)
        ):
            return True
        self._trip(pid, proc)
        return False

    def _answer(self, raw: bytes) -> bytes:
        try:
            asked = json.loads(raw.decode("utf-8"))
            token, prompt = str(asked.get("t", "")), str(asked["p"]).rstrip()
        except (ValueError, KeyError, TypeError, AttributeError):
            return b"{}"
        if self._tcp and not hmac.compare_digest(token, self._token):
            return b"{}"
        with self._cond:
            secret = self._armed.pop(prompt, None)
            if secret is not None:  # uma vez por conexão: as variantes do mesmo salto saem juntas
                self._armed = {k: v for k, v in self._armed.items() if v is not secret}
        if secret is None:
            return b"{}"
        return json.dumps({"b": base64.b64encode(secret).decode()}).encode()

    def _loop(self) -> None:
        while not self._stop.is_set():
            try:
                conn, addr = self._server.accept()
            except (TimeoutError, OSError):
                continue
            with conn:
                conn.settimeout(5)
                try:
                    if not self._allowed(conn, addr):
                        continue  # nem lê o pedido: fecha sem resposta
                    data = b""
                    while b"\n" not in data and len(data) < 8192:
                        part = conn.recv(4096)
                        if not part:
                            break
                        data += part
                    conn.sendall(self._answer(data.split(b"\n")[0]) + b"\n")
                except OSError:
                    pass

    def close(self) -> None:
        self._stop.set()
        with contextlib.suppress(OSError):
            self._server.close()
        self._thread.join(timeout=2)
        self._cleanup()

    def _cleanup(self) -> None:
        if self._path:
            with contextlib.suppress(OSError):
                os.unlink(self._path)
        if self._short:
            with contextlib.suppress(OSError):
                os.rmdir(self._short)


def fingerprints(known_hosts: str, keygen: str = "ssh-keygen") -> set[str]:
    """Impressões SHA256 das chaves gravadas num known_hosts."""
    if not os.path.exists(known_hosts) or not os.path.getsize(known_hosts):
        return set()
    # argumentos fixos e caminho temporário nosso, sem shell
    p = subprocess.run(  # noqa: S603 (argumentos fixos, arquivo temporário nosso, sem shell)
        [keygen, "-lf", known_hosts],
        capture_output=True,
        **C.NO_WINDOW,
        text=True,
        encoding="utf-8",
        timeout=15,
        check=False,
    )
    return set(_FOUND_FINGERPRINT.findall(p.stdout or ""))


@contextmanager
def agent_with_keys(keys: list[bytes], folder: str) -> Iterator[str | None]:
    """ssh-agent próprio, de vida curta, com as chaves vindas pelo stdin (nunca em disco)."""
    if not keys:
        yield None
        return
    agent, add = shutil.which("ssh-agent"), shutil.which("ssh-add")
    if not agent or not add:
        raise SshError("ssh-agent/ssh-add não encontrados (OpenSSH)")
    sock = os.path.join(folder, "agent.sock")
    proc = subprocess.Popen(  # noqa: S603 (binário do OpenSSH, argumentos fixos, sem shell)
        [agent, "-D", "-a", sock],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        **C.NO_WINDOW,
    )
    try:
        for _ in range(100):
            if os.path.exists(sock):
                break
            time.sleep(0.05)
        env = dict(os.environ, SSH_AUTH_SOCK=sock)
        for key in keys:
            r = subprocess.run(  # noqa: S603 (a chave vai pelo stdin, nunca por argv)
                [add, "-t", str(AGENT_TTL_S), "-"],
                input=key,
                env=env,
                capture_output=True,
                **C.NO_WINDOW,
                timeout=15,
                check=False,
            )
            if r.returncode != 0:
                raise SshError("a chave privada do cofre não foi aceita pelo ssh-add")
        yield sock
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()


# ---------- execução ----------


@dataclass
class Result:
    code: int
    out: str
    err: str
    host_keys: dict[str, str]  # caminho da credencial → impressão vista (para fixar)


def _execute(
    spawn: Spawner,
    args: list[str],
    *,
    env: dict[str, str],
    timeout: float,
    stdin: str,
    server: AskpassServer | None,
    passwords: dict[int, bytes],
) -> subprocess.CompletedProcess:
    """Lança o ssh com `Popen` (para saber o pid dele), mostra o pid ao servidor de senha e
    espera. Se outro processo pediu a senha nesse meio-tempo, o ssh já foi morto: SshError."""
    arm = server.armed(passwords) if server is not None and passwords else contextlib.nullcontext()
    with arm:
        try:
            proc = spawn(
                args,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                encoding="utf-8",
                errors="replace",
                env=env,
                **C.NO_WINDOW,
            )
        except FileNotFoundError as exc:
            raise SshError("ssh (OpenSSH) não encontrado no PATH") from exc
        if server is not None:
            server.watch(proc)
        try:
            out, err = proc.communicate(stdin, timeout=timeout)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.communicate()
            raise
        finally:
            if server is not None:
                server.watch(None)
    if server is not None and server.intruder:
        raise SshError(server.intruder_message())
    return subprocess.CompletedProcess(args, proc.returncode, out, err)


def run(
    target: Target,
    command: str,
    *,
    timeout: int = DEFAULT_TIMEOUT_S,
    stdin: str = "",
    script: bool = False,
    mask: Callable[[str], str] = lambda s: s,
    spawn: Spawner = subprocess.Popen,
    keygen: str = "ssh-keygen",
    sudo: bool = False,
    probe_only: bool = False,
) -> Result:
    """Roda `command` no alvo (com saltos). Saída e erro já passam pela máscara. `sudo`: roda
    como root com a senha do próprio servidor (pelo stdin, nunca na linha de comando).
    `probe_only`: só a sonda até o último salto, para ver a chave dele (sem segredo para ele):
    `host_keys` traz a impressão vista, mesmo sem nenhuma fixada."""
    check_rule(target, command, script=script)
    chain = hops(target)
    # só autentica quem tem segredo: os saltos depois do 1º sem impressão chegam com b"" e a
    # sonda para antes deles
    passwords = {i: h.secret for i, h in enumerate(chain) if h.secret and not h.uses_key}
    if sudo:
        last = chain[-1]
        if not last.secret or last.uses_key:
            raise SshError(f"{last.ref}: sudo usa a senha do servidor, e esta credencial é chave")
        if script or stdin:
            raise SshError("sudo vale para um comando, sem script e sem stdin")
        if target.rule != "livre":
            raise SshError(f"{target.ref}: host só de leitura não aceita sudo")
        # -k: pede a senha sempre (sem o cache do sudo); a senha entra pelo stdin do ssh e o
        # comando roda com o stdin em /dev/null: nem com NOPASSWD a senha chega ao comando
        inner = "exec </dev/null; " + command
        command = f"sudo -k -S -p '' -- sh -c {shlex.quote(inner)}"
        stdin = last.secret.decode("utf-8", "replace") + "\n"
    ssh = shutil.which("ssh") or "ssh"
    with tempfile.TemporaryDirectory(prefix="cerebro-ssh-") as folder:
        os.chmod(folder, 0o700)  # nome aleatório (mkdtemp) e só para este usuário
        known = os.path.join(folder, "known_hosts")
        env = dict(os.environ)
        for name in ("CEREBRO_ASKPASS_BILHETE", "CEREBRO_ASKPASS_PORTA"):
            env.pop(name, None)
        server = None
        try:
            if passwords:
                server = AskpassServer(chain, passwords, folder, tcp=askpass_by_tcp())
                env.update(server.env, DISPLAY=env.get("DISPLAY") or "none:0")
            keys = [h.secret for h in chain if h.uses_key]
            with agent_with_keys(keys, folder) as sock:
                seen = _verify_host_keys(
                    chain, folder, known, ssh, spawn, keygen, env, sock, passwords,
                    server=server, probe_last=probe_only,
                )  # fmt: skip
                if probe_only:
                    return Result(0, "", "", seen)
                config = write_config(
                    chain, folder, known_hosts=known, strict=[True] * len(chain), agent_sock=sock
                )
                args = [ssh, "-F", config, alias(len(chain) - 1), command]
                try:
                    p = _execute(spawn, args, env=env, timeout=timeout, stdin=stdin,
                                 server=server, passwords=passwords)  # fmt: skip
                except subprocess.TimeoutExpired:
                    return Result(124, "", f"tempo esgotado depois de {timeout}s", seen)
        finally:
            if server is not None:
                server.close()
    out, err = mask(p.stdout or ""), mask(p.stderr or "")
    if sudo and target.secret:  # a senha nunca volta, nem se o sudo a ecoar num erro
        secret_text = target.secret.decode("utf-8", "replace")
        out, err = out.replace(secret_text, "••••"), err.replace(secret_text, "••••")
    return Result(p.returncode, out, err, seen)


def _verify_host_keys(
    chain: list[Target],
    folder: str,
    known: str,
    ssh: str,
    spawn: Spawner,
    keygen: str,
    env: dict[str, str],
    sock: str | None,
    passwords: dict[int, bytes] | None = None,
    *,
    server: AskpassServer | None = None,
    probe_last: bool = False,
) -> dict[str, str]:
    """Salto a salto, antes de mandar a credencial de cada host: a sonda passa pelos saltos já
    conferidos (autenticando neles, que é seguro) e chega ao host da vez sem autenticar
    (`PreferredAuthentications=none`), só para gravar a chave dele e conferir a impressão. Host
    sem impressão fixada para tudo aqui: nada vai para ele."""
    seen: dict[str, str] = {}
    passwords = passwords or {}
    for i, hop in enumerate(chain):
        before = fingerprints(known, keygen)
        config = write_config(
            chain[: i + 1],
            folder,
            known_hosts=known,
            strict=[True] * i + [False],
            agent_sock=sock,
            probe=i,
        )
        before_hops = {k: v for k, v in passwords.items() if k < i}  # os já conferidos
        with contextlib.suppress(subprocess.TimeoutExpired):  # sem chave nova: o erro abaixo
            _execute(spawn, [ssh, "-F", config, alias(i), "true"], env=env,
                     timeout=PROBE_TIMEOUT_S, stdin="", server=server,
                     passwords=before_hops)  # fmt: skip
        new = fingerprints(known, keygen) - before
        if not new:
            raise SshError(f"{hop.ref}: não consegui ler a chave do host (rede, porta ou salto?)")
        if probe_last and not hop.fingerprint and i == len(chain) - 1:
            seen[hop.ref] = ", ".join(sorted(new))  # sonda de 1ª conexão: só mostra a impressão
            return seen
        if not hop.fingerprint:
            raise SshError(
                f"{hop.ref}: a chave do host não está fixada, então nenhum segredo foi enviado a "
                f"ele. Vista agora: {', '.join(sorted(new))}. Confira no servidor (ssh-keygen "
                "-lf /etc/ssh/ssh_host_ed25519_key.pub) e grave no campo 'impressao' da "
                "credencial; depois rode de novo."
            )
        if hop.fingerprint not in new:
            raise SshError(
                f"{hop.ref}: a chave do host não bate com a impressão fixada "
                f"({hop.fingerprint}) — possível interceptação; nada foi enviado"
            )
        seen[hop.ref] = hop.fingerprint
    return seen


def script_command(shell: str = "sh") -> str:
    """Comando remoto para rodar um script mandado pelo stdin."""
    return f"{shlex.quote(shell)} -s"
