"""Conector SSH do broker: servidores são credenciais do tipo "ssh" no cofre do cérebro.

Cada servidor é uma credencial `ssh` com metadados `host`, `porta`, `usuario`, `jump` (caminho de
outra credencial ssh para saltar), `impressao` (impressão digital da chave do host, `SHA256:…`) e
`regra`. O valor é a senha ou a chave privada (texto começando por `-----BEGIN`). Desde a 2.10,
uma credencial `senha` com a url `ssh://[usuario@]host[:porta]` também é servidor (é como os
servidores foram cadastrados até aqui): host, porta e usuário saem da url.

Como o segredo chega ao `ssh` sem passar pelo Claude, por disco, por argv ou pelo ambiente (o
`ps eww` do mesmo usuário mostra o ambiente):
- senha (só POSIX): numa pasta 0700 de nome aleatório, um FIFO por salto. O broker escreve a
  senha uma vez por conexão, numa thread; o `SSH_ASKPASS` é um script mínimo, sem segredo, que
  só faz `cat` do FIFO do salto cujo prompt casou EXATAMENTE (`usuario@host's password: `).
  Qualquer outro prompt (keyboard-interactive, passphrase, pergunta) não recebe nada. A pasta é
  apagada no fim. No Windows (sem FIFO), o askpass é o próprio lançador do plugin
  (`cerebro-plugin.exe`, sem segredo), que pede a senha por um socket TCP local (127.0.0.1) com
  um token de uso único desta conexão; o broker só responde ao prompt exato de um salto
  conhecido, uma vez por conexão;
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
import errno
import hmac
import json
import os
import re
import secrets as _secrets
import shlex
import shutil
import socket
import subprocess
import tempfile
import threading
import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field

KEY_MARK = b"-----BEGIN"
AGENT_TTL_S = 300
DEFAULT_TIMEOUT_S = 60
PROBE_TIMEOUT_S = 25
_HOST = re.compile(r"^[A-Za-z0-9.:_-]{1,253}$")
_USER = re.compile(r"^[A-Za-z0-9._-]{1,64}$")
_FINGERPRINT = re.compile(r"^SHA256:[A-Za-z0-9+/=]{20,}$")
_FOUND_FINGERPRINT = re.compile(r"SHA256:[A-Za-z0-9+/=]+")
IS_WINDOWS = os.name == "nt"
FEED_POLL_S = 0.05

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

Runner = Callable[..., subprocess.CompletedProcess]


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


def fifo_path(folder: str, index: int) -> str:
    return os.path.join(folder, f"senha-{index}")


_SAFE_PROMPT = re.compile(r"[A-Za-z0-9._:@'-]+ password:")


def write_askpass(folder: str, choices: list[tuple[list[str], str]]) -> str:
    """Script do SSH_ASKPASS (POSIX), sem segredo: (prompts exatos, FIFO) por salto. Só o prompt
    que casar inteiro, com ou sem o espaço final, ganha o `cat` do FIFO daquele salto; qualquer
    outro (keyboard-interactive, passphrase, pergunta) sai com 1 e não recebe nada."""
    seen: set[str] = set()
    lines = ["#!/bin/sh", 'case "$1" in']
    for prompts, fifo in choices:
        patterns = []
        for prompt in prompts:
            if not _SAFE_PROMPT.fullmatch(prompt):
                raise SshError(f"prompt de senha inesperado: {prompt!r}")
            if prompt in seen:
                raise SshError(f"dois saltos com o mesmo prompt de senha ({prompt!r})")
            seen.add(prompt)
            patterns += [f'"{prompt}"', f'"{prompt} "']
        lines.append(f"  {'|'.join(patterns)}) exec cat {shlex.quote(fifo)} ;;")
    lines += ["  *) exit 1 ;;", "esac"]
    path = os.path.join(folder, "askpass.sh")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")
    os.chmod(path, 0o700)
    return path


def askpass_by_tcp() -> bool:
    """Windows não tem FIFO: o askpass é o lançador do plugin, pelo socket TCP local. Nos outros
    sistemas, só com CEREBRO_SSH_ASKPASS=tcp (testes)."""
    return IS_WINDOWS or os.environ.get("CEREBRO_SSH_ASKPASS") == "tcp"


class TcpAskpass:
    """Servidor de senha para o askpass do lançador (`cerebro-plugin askpass`): escuta só em
    127.0.0.1, numa porta aleatória, e responde a um pedido {"t": token, "p": prompt} com a senha
    do salto cujo prompt casar inteiro, uma vez por `armed` (uma conexão ssh). Token errado,
    prompt desconhecido ou repetido: resposta vazia (o askpass sai com 1)."""

    def __init__(self, chain: list[Target], launcher: str | None = None) -> None:
        exe = launcher or os.environ.get("CEREBRO_LANCADOR", "")
        if not exe or not os.path.isfile(exe):
            raise SshError(
                "a senha do SSH no Windows usa o lançador do plugin 2.10 ou mais novo: "
                "atualize o plugin e reinicie o Claude"
            )
        self._chain = chain
        self._token = _secrets.token_urlsafe(24)
        self._armed: dict[str, bytes] = {}
        self._lock = threading.Lock()
        self._server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._server.bind(("127.0.0.1", 0))
        self._server.listen(4)
        self._server.settimeout(0.2)
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()
        self.env = {
            "SSH_ASKPASS": exe,
            "SSH_ASKPASS_REQUIRE": "force",
            "CEREBRO_ASKPASS_PORTA": str(self._server.getsockname()[1]),
            "CEREBRO_ASKPASS_BILHETE": self._token,
        }

    @contextmanager
    def armed(self, passwords: dict[int, bytes]) -> Iterator[None]:
        table = {}
        for index, secret in passwords.items():
            for prompt in password_prompts(self._chain[index]):
                table[prompt] = secret
        with self._lock:
            self._armed = table
        try:
            yield
        finally:
            with self._lock:
                self._armed = {}

    def _answer(self, raw: bytes) -> bytes:
        try:
            asked = json.loads(raw.decode("utf-8"))
            token, prompt = str(asked["t"]), str(asked["p"]).rstrip()
        except (ValueError, KeyError, TypeError):
            return b"{}"
        if not hmac.compare_digest(token, self._token):
            return b"{}"
        with self._lock:
            secret = self._armed.pop(prompt, None)
            if secret is not None:  # uma vez por conexão: as variantes do mesmo salto saem juntas
                self._armed = {k: v for k, v in self._armed.items() if v is not secret}
        if secret is None:
            return b"{}"
        return json.dumps({"b": base64.b64encode(secret).decode()}).encode()

    def _loop(self) -> None:
        while not self._stop.is_set():
            try:
                conn, _ = self._server.accept()
            except (TimeoutError, OSError):
                continue
            with conn:
                conn.settimeout(5)
                data = b""
                try:
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


def _feed(path: str, secret: bytes, stop: threading.Event) -> None:
    """Espera alguém abrir o FIFO para leitura (o askpass), escreve a senha uma vez e apaga o
    FIFO: um 2º pedido na mesma conexão não acha nada."""
    while not stop.is_set():
        try:
            fd = os.open(path, os.O_WRONLY | os.O_NONBLOCK)
        except OSError as exc:
            if exc.errno != errno.ENXIO:  # ENXIO: ninguém lendo ainda
                return
            stop.wait(FEED_POLL_S)
            continue
        try:
            os.set_blocking(fd, True)
            data = memoryview(secret + b"\n")
            while data:
                data = data[os.write(fd, data) :]
        except OSError:
            pass  # o leitor desistiu
        finally:
            os.close(fd)
            with contextlib.suppress(OSError):
                os.unlink(path)
        return


@contextmanager
def password_feed(folder: str, secrets: dict[int, bytes]) -> Iterator[None]:
    """Um FIFO por salto (0600) e uma thread que escreve a senha dele uma vez. No fim, para as
    threads e apaga o que sobrou."""
    stop = threading.Event()
    threads = []
    for index, secret in secrets.items():
        path = fifo_path(folder, index)
        with contextlib.suppress(FileNotFoundError):
            os.unlink(path)
        os.mkfifo(path, 0o600)
        thread = threading.Thread(target=_feed, args=(path, secret, stop), daemon=True)
        thread.start()
        threads.append(thread)
    try:
        yield
    finally:
        stop.set()
        for thread in threads:
            thread.join(timeout=2)
        for index in secrets:
            with contextlib.suppress(OSError):
                os.unlink(fifo_path(folder, index))


def fingerprints(known_hosts: str, keygen: str = "ssh-keygen") -> set[str]:
    """Impressões SHA256 das chaves gravadas num known_hosts."""
    if not os.path.exists(known_hosts) or not os.path.getsize(known_hosts):
        return set()
    # argumentos fixos e caminho temporário nosso, sem shell
    p = subprocess.run(  # noqa: S603 (argumentos fixos, arquivo temporário nosso, sem shell)
        [keygen, "-lf", known_hosts],
        capture_output=True,
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
        [agent, "-D", "-a", sock], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
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


def run(
    target: Target,
    command: str,
    *,
    timeout: int = DEFAULT_TIMEOUT_S,
    stdin: str = "",
    script: bool = False,
    mask: Callable[[str], str] = lambda s: s,
    runner: Runner = subprocess.run,
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
    tcp = TcpAskpass(chain) if passwords and askpass_by_tcp() else None
    with tempfile.TemporaryDirectory(prefix="cerebro-ssh-") as folder:
        os.chmod(folder, 0o700)  # nome aleatório (mkdtemp) e só para este usuário
        known = os.path.join(folder, "known_hosts")
        env = dict(os.environ)
        env.pop("CEREBRO_ASKPASS_BILHETE", None)
        if tcp is not None:
            env.update(tcp.env, DISPLAY=env.get("DISPLAY") or "none:0")
            feed = tcp.armed
        else:
            if passwords:
                choices = [(password_prompts(chain[i]), fifo_path(folder, i)) for i in passwords]
                env.update(
                    SSH_ASKPASS=write_askpass(folder, choices),
                    SSH_ASKPASS_REQUIRE="force",
                    DISPLAY=env.get("DISPLAY") or "none:0",
                )

            def feed(chosen: dict[int, bytes]):
                return password_feed(folder, chosen)

        keys = [h.secret for h in chain if h.uses_key]
        try:
            with agent_with_keys(keys, folder) as sock:
                seen = _verify_host_keys(
                    chain, folder, known, ssh, runner, keygen, env, sock, passwords, feed=feed,
                    probe_last=probe_only,
                )
                if probe_only:
                    return Result(0, "", "", seen)
                config = write_config(
                    chain, folder, known_hosts=known, strict=[True] * len(chain), agent_sock=sock
                )
                args = [ssh, "-F", config, alias(len(chain) - 1), command]
                try:
                    with feed(passwords):
                        p = runner(
                            args,
                            input=stdin,
                            capture_output=True,
                            text=True,
                            encoding="utf-8",
                            errors="replace",
                            timeout=timeout,
                            env=env,
                            check=False,
                        )
                except subprocess.TimeoutExpired:
                    return Result(124, "", f"tempo esgotado depois de {timeout}s", seen)
                except FileNotFoundError as exc:
                    raise SshError("ssh (OpenSSH) não encontrado no PATH") from exc
        finally:
            if tcp is not None:
                tcp.close()
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
    runner: Runner,
    keygen: str,
    env: dict[str, str],
    sock: str | None,
    passwords: dict[int, bytes] | None = None,
    *,
    feed: Callable[[dict[int, bytes]], contextlib.AbstractContextManager[None]] | None = None,
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
        with (feed or (lambda chosen: password_feed(folder, chosen)))(before_hops):
            runner(
                [ssh, "-F", config, alias(i), "true"],
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=PROBE_TIMEOUT_S,
                env=env,
                check=False,
            )
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
