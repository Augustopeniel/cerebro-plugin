"""Canal local: por onde os outros MCPs e as outras sessões do Claude falam com o broker.

O mesmo endereço e o mesmo protocolo do broker antigo, para o `cofre_client.py` e o `cofre_run.py`
seguirem funcionando sem mudar uma linha:
  macOS/Linux: socket Unix `~/.claude/cofre/broker.sock` (0600);
  Windows: named pipe `\\\\.\\pipe\\cofre-broker-<usuário>` com o handshake HMAC do
  `multiprocessing` e a chave `~/.claude/cofre/broker.key` (testes: `COFRE_CANAL=mp`).

Uma linha JSON por conexão:
  {"op": "env", "group": "mcp/zabbix", "consumer": "zabbix"} → {"ok": true, "env": {...}}
  {"op": "hello"} → {"ok": true, "result": {"broker": "cerebro-cofre", ...}}
  {"op": "admin", "ts", "nonce", "payload", "mac"} → {"ok": true, "result": ...}
  erro → {"ok": false, "error": "..."}

`env` é o de sempre (a entrega com via `mcp` e alvo = consumidor; o servidor decide se vale).
`admin` é o que as outras sessões e a linha de comando usam (estado, vincular, ferramenta…): vai
autenticado com HMAC-SHA256 pela chave do canal, com hora (60 s) e número único (sem repetição).

Só um broker atende: se o endereço já responde (o antigo rodando, ou outra sessão), este não
rouba; tenta de novo a cada 5 s e assume se o outro morrer.
"""

from __future__ import annotations

import contextlib
import getpass
import hashlib
import hmac
import json
import os
import re
import secrets
import socket
import sys
import threading
import time
from collections.abc import Callable
from multiprocessing import AuthenticationError
from multiprocessing.connection import Client as PipeClient
from multiprocessing.connection import Listener
from pathlib import Path
from typing import Any

from . import config as C
from . import peer as PEER
from .broker import Broker, BrokerError
from .protocol import VaultClientError

MAX_REQUEST = 256 * 1024
ADMIN_WINDOW_S = 60
# o que outras sessões e a linha de comando (`pair`, `status`) podem pedir: nada recebe senha nem
# valor, nada devolve kit (a janela, que mandava senha e valor por aqui, saiu na 2.7.0)
ADMIN_ACTIONS = frozenset({"state", "lock", "pair_start", "pair_poll", "tool"})

ToolRunner = Callable[[str, dict[str, Any], str | None], dict[str, Any]]


def use_pipe() -> bool:
    return not hasattr(socket, "AF_UNIX") or C.env("COFRE_CANAL") == "mp"


def pipe_address() -> tuple[str, str]:
    if os.name == "nt":
        user = re.sub(r"[^A-Za-z0-9_.-]", "_", getpass.getuser() or "usuario")
        return r"\\.\pipe\cofre-broker-" + user, "AF_PIPE"
    return str(C.socket_path()) + ".mp", "AF_UNIX"


def channel_key(create: bool = False) -> bytes | None:
    """Chave do canal: o broker cria na 1ª vez (0600); quem fala com ele só lê."""
    path = C.channel_key_path()
    try:
        key = path.read_bytes()
        if len(key) >= 32:
            return key
    except OSError:
        pass
    if not create:
        return None
    path.parent.mkdir(parents=True, exist_ok=True)
    key = os.urandom(32)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as fh:
        fh.write(key)
    return key


def _mac(key: bytes, ts: int, nonce: str, payload: str) -> str:
    return hmac.new(key, f"{ts}\n{nonce}\n{payload}".encode(), hashlib.sha256).hexdigest()


def admin_request(key: bytes, action: str, **args: Any) -> dict[str, Any]:
    payload = json.dumps({"action": action, "args": args})
    ts, nonce = int(time.time()), secrets.token_hex(12)
    return {
        "op": "admin",
        "ts": ts,
        "nonce": nonce,
        "payload": payload,
        "mac": _mac(key, ts, nonce, payload),
    }


def _broker_process(peer: PEER.Peer | None) -> bool:
    """O broker de outra sessão ou a linha de comando: o mesmo Python (de verdade) rodando
    `-m cofre_broker.cli mcp|pair|status`, sem variável que injete código."""
    return bool(
        peer is not None
        and peer.exe == os.path.realpath(sys.executable)
        and peer.is_module("cofre_broker.cli", frozenset({"mcp", "pair", "status"}))
    )


def _alive(path: Path) -> bool:
    probe = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    probe.settimeout(1.0)
    try:
        probe.connect(str(path))
        return True
    except OSError:
        return False
    finally:
        probe.close()


class ChannelServer:
    def __init__(
        self,
        broker: Broker,
        tool_runner: ToolRunner | None = None,
        retry: float = 5.0,
        admin_peer: Callable[[PEER.Peer | None], bool] | None = None,
    ) -> None:
        self.broker, self.tool_runner, self.retry = broker, tool_runner, retry
        self.admin_peer = admin_peer or _broker_process
        self.owner = False
        self._seen: dict[str, float] = {}
        self._seen_lock = threading.Lock()
        self._stop = threading.Event()
        self._lock_fd: int | None = None
        self._listener: Listener | None = None
        self._set("iniciando")

    def _set(self, state: str, owner: bool = False) -> None:
        self.owner = owner
        self.broker.channel_state = state

    # ---------- resposta (igual nos dois canais) ----------

    def respond(self, data: bytes, peer: PEER.Peer | None = None, checked: bool = False) -> bytes:
        """`peer`: o processo do outro lado, visto pelo kernel; `checked`: o canal sabe dizer
        quem é (socket Unix no macOS/Linux). No named pipe do Windows, `checked` é falso."""
        try:
            request = json.loads(data.decode("utf-8"))
            if not isinstance(request, dict):
                raise BrokerError("pedido inválido")
            op = request.get("op")
            if op == "env":
                if checked and peer is None:
                    raise BrokerError("não deu para identificar o processo que pediu")
                program = (
                    (peer.fingerprint(), peer.describe()) if peer is not None
                    else (PEER.NO_CHECK, "sem conferência do processo neste sistema")
                )  # fmt: skip
                env = self.broker.deliver_group(
                    request.get("group"), request.get("consumer"), program=program
                )
                answer = {"ok": True, "env": env}
            elif op == "hello":
                answer = {
                    "ok": True,
                    "result": {"broker": C.NAME, "version": C.VERSION, "pid": os.getpid()},
                }
            elif op == "admin":
                if checked and not self.admin_peer(peer):
                    # a chave do canal fica num arquivo do usuário: além dela, quem pede tem de
                    # ser o broker de outra sessão do Claude ou a linha de comando do plugin
                    raise BrokerError("pedido de administração de um processo não autorizado")
                answer = {"ok": True, "result": self._admin(request)}
            else:
                raise BrokerError("operacao desconhecida.")
        except (BrokerError, VaultClientError) as exc:
            answer = {"ok": False, "error": str(exc)}
        except (ValueError, TypeError, KeyError) as exc:
            answer = {"ok": False, "error": f"pedido inválido: {type(exc).__name__}"}
        except Exception as exc:
            C.log("canal: erro inesperado:", type(exc).__name__)
            answer = {"ok": False, "error": "erro interno do broker."}
        return (json.dumps(answer, ensure_ascii=False) + "\n").encode("utf-8")

    def _admin(self, request: dict[str, Any]) -> Any:
        key = channel_key()
        ts, nonce, payload = (
            request.get("ts"),
            str(request.get("nonce", "")),
            request.get("payload"),
        )
        if key is None or not isinstance(ts, int) or not isinstance(payload, str) or not nonce:
            raise BrokerError("pedido de administração sem autenticação")
        if not hmac.compare_digest(_mac(key, ts, nonce, payload), str(request.get("mac", ""))):
            raise BrokerError("autenticação do canal não confere")
        now = time.time()
        if abs(now - ts) > ADMIN_WINDOW_S:
            raise BrokerError("pedido de administração fora da janela de 60 s")
        with self._seen_lock:
            self._seen = {n: t for n, t in self._seen.items() if t > now}
            if nonce in self._seen:
                raise BrokerError("pedido de administração repetido")
            self._seen[nonce] = now + 2 * ADMIN_WINDOW_S
        body = json.loads(payload)
        action, args = body.get("action"), body.get("args") or {}
        if action not in ADMIN_ACTIONS or not isinstance(args, dict):
            raise BrokerError(f"ação desconhecida: {action!r}")
        if action == "tool":
            if self.tool_runner is None:
                raise BrokerError("este broker não atende ferramentas")
            return self.tool_runner(
                str(args.get("name")), dict(args.get("arguments") or {}), args.get("cwd")
            )
        return getattr(self.broker, action)(**args)

    # ---------- socket Unix ----------

    def _open_socket(self, path: Path) -> socket.socket | None:
        import fcntl

        path.parent.mkdir(parents=True, exist_ok=True)
        if self._lock_fd is None:  # trava entre brokers novos (o antigo não usa)
            fd = os.open(f"{path}.lock", os.O_RDWR | os.O_CREAT, 0o600)
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except OSError:
                os.close(fd)
                self._set("ocupado por outro broker novo (outra sessão do Claude atende)")
                return None
            self._lock_fd = fd
        if path.exists():
            if _alive(path):
                self._set(self._busy_reason())
                return None
            path.unlink()  # sobra de um broker que morreu
        server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        old = os.umask(0o177)
        try:
            server.bind(str(path))
        finally:
            os.umask(old)
        os.chmod(path, 0o600)
        server.listen(16)
        server.settimeout(1.0)
        return server

    def _busy_reason(self) -> str:
        found = ChannelClient(timeout=3).hello()
        if found and found.get("broker") == C.NAME:
            return f"atendido por outro broker novo (processo {found.get('pid')})"
        return (
            "ocupado pelo broker antigo (cofre-mcp): os MCPs seguem falando com ele; feche-o "
            "para este assumir"
        )

    def _serve_socket(self, conn: socket.socket) -> None:
        try:
            conn.settimeout(30)
            data = b""
            while b"\n" not in data and len(data) < MAX_REQUEST:
                part = conn.recv(65536)
                if not part:
                    break
                data += part
            if not data.strip():
                return  # só uma sondagem
            pid = PEER.peer_pid(conn)
            who = PEER.identify(pid) if pid else None
            conn.settimeout(None)
            conn.sendall(self.respond(data, who, checked=True))
        except OSError:
            pass
        finally:
            with contextlib.suppress(OSError):
                conn.close()

    def _socket_loop(self) -> None:
        path = C.socket_path()
        while not self._stop.is_set():
            try:
                server = self._open_socket(path)
            except OSError as exc:
                self._set(f"erro ao abrir {path}: {type(exc).__name__}")
                server = None
            if server is None:
                self._stop.wait(self.retry)
                continue
            self._set(f"atendendo em {path}", owner=True)
            try:
                while not self._stop.is_set():
                    try:
                        conn, _ = server.accept()
                    except TimeoutError:
                        continue
                    threading.Thread(target=self._serve_socket, args=(conn,), daemon=True).start()
            except OSError as exc:
                C.log("canal: socket caiu:", type(exc).__name__)
            finally:
                server.close()
                with contextlib.suppress(OSError):
                    if self._stop.is_set():
                        path.unlink()
                self._set("desligado")

    # ---------- named pipe (Windows) / multiprocessing ----------

    def _open_pipe(self) -> Listener | None:
        address, family = pipe_address()
        if family == "AF_UNIX" and os.path.exists(address):
            if _alive(Path(address)):
                self._set(self._busy_reason())
                return None
            os.unlink(address)
        try:
            # no Windows o 1º pipe sai com FILE_FLAG_FIRST_PIPE_INSTANCE: o 2º broker recebe
            # PermissionError e tenta de novo depois (assume se o 1º morrer)
            return Listener(address, family=family, authkey=channel_key(create=True))
        except OSError:
            self._set(self._busy_reason())
            return None

    def _serve_pipe(self, conn: Any) -> None:
        try:
            if conn.poll(30):
                data = conn.recv_bytes(MAX_REQUEST)
                if data:
                    conn.send_bytes(self.respond(data))
        except (EOFError, OSError):
            pass
        finally:
            with contextlib.suppress(OSError):
                conn.close()

    def _pipe_loop(self) -> None:
        while not self._stop.is_set():
            listener = self._open_pipe()
            if listener is None:
                self._stop.wait(self.retry)
                continue
            self._listener = listener
            self._set(f"atendendo em {pipe_address()[0]}", owner=True)
            try:
                while not self._stop.is_set():
                    try:
                        conn = listener.accept()
                    except (AuthenticationError, EOFError):
                        continue  # sem a chave, ou desistiu no handshake
                    threading.Thread(target=self._serve_pipe, args=(conn,), daemon=True).start()
            except OSError as exc:
                C.log("canal: pipe caiu:", type(exc).__name__)
            finally:
                with contextlib.suppress(OSError):
                    listener.close()
                self._set("desligado")

    # ---------- ciclo de vida ----------

    def start(self) -> threading.Thread:
        channel_key(create=True)
        loop = self._pipe_loop if use_pipe() else self._socket_loop
        thread = threading.Thread(target=loop, name="cofre-canal", daemon=True)
        thread.start()
        return thread

    def wait_owner(self, seconds: float = 3.0) -> bool:
        deadline = time.monotonic() + seconds
        while not self.owner and time.monotonic() < deadline:
            time.sleep(0.05)
        return self.owner

    def stop(self) -> None:
        self._stop.set()
        if self.owner and not use_pipe():  # o processo pode sair antes do laço notar
            with contextlib.suppress(OSError):
                C.socket_path().unlink()
        if self._listener is not None:  # destrava o accept() e apaga o endereço
            with contextlib.suppress(OSError):
                self._listener.close()
            self._listener = None
        if self._lock_fd is not None:
            with contextlib.suppress(OSError):
                os.close(self._lock_fd)
            self._lock_fd = None


class ChannelClient:
    """Quem fala com o broker que atende: outra sessão do Claude, a linha de comando, os testes."""

    def __init__(self, timeout: float = 900) -> None:
        self.timeout = timeout

    def request(self, request: dict[str, Any]) -> dict[str, Any]:
        """Envia um pedido e devolve a resposta. ConnectionError se não houver broker."""
        data = (json.dumps(request) + "\n").encode("utf-8")
        if use_pipe():
            return self._pipe(data)
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(3)
        try:
            sock.connect(str(C.socket_path()))
            sock.settimeout(self.timeout)
            sock.sendall(data)
            answer = b""
            while b"\n" not in answer:
                part = sock.recv(65536)
                if not part:
                    break
                answer += part
        except OSError as exc:
            raise ConnectionError(f"broker indisponível: {type(exc).__name__}") from exc
        finally:
            sock.close()
        if not answer.strip():
            raise ConnectionError("o broker fechou sem responder")
        return json.loads(answer.decode("utf-8"))

    def _pipe(self, data: bytes) -> dict[str, Any]:
        address, family = pipe_address()
        key = channel_key()
        if key is None:
            raise ConnectionError("sem a chave do canal (nenhum broker rodou nesta máquina)")
        try:
            conn = PipeClient(address, family=family, authkey=key)
        except AuthenticationError as exc:
            raise ConnectionError("chave do canal não confere") from exc
        except (OSError, EOFError) as exc:
            raise ConnectionError(f"broker indisponível: {type(exc).__name__}") from exc
        try:
            conn.send_bytes(data)
            if not conn.poll(self.timeout):
                raise ConnectionError("o broker não respondeu a tempo")
            return json.loads(conn.recv_bytes().decode("utf-8"))
        except (EOFError, OSError) as exc:
            raise ConnectionError(f"canal do broker caiu: {type(exc).__name__}") from exc
        finally:
            conn.close()

    def hello(self) -> dict[str, Any] | None:
        """Quem atende: o broker novo (com pid) ou None (ninguém, ou o antigo)."""
        try:
            answer = self.request({"op": "hello"})
        except (ConnectionError, ValueError):
            return None
        result = answer.get("result") if answer.get("ok") else None
        return result if isinstance(result, dict) else {"broker": "antigo"}

    def admin(self, action: str, **args: Any) -> Any:
        key = channel_key()
        if key is None:
            raise ConnectionError("sem a chave do canal")
        answer = self.request(admin_request(key, action, **args))
        if not answer.get("ok"):
            raise BrokerError(str(answer.get("error") or "o broker recusou"))
        return answer.get("result")


class RemoteBroker:
    """O broker de outro processo, pelo canal: a linha de comando usa como se fosse o local."""

    def __init__(self, client: ChannelClient | None = None) -> None:
        self._client = client or ChannelClient()

    def __getattr__(self, action: str) -> Callable[..., Any]:
        if action not in ADMIN_ACTIONS:
            raise AttributeError(action)
        return lambda **args: self._client.admin(action, **args)


def find_remote(client: ChannelClient | None = None) -> RemoteBroker | None:
    """O broker novo que atende o canal (outro processo), se houver e se a chave existir."""
    client = client or ChannelClient()
    found = client.hello()
    if not found or found.get("broker") != C.NAME or found.get("pid") == os.getpid():
        return None
    if channel_key() is None:
        return None
    return RemoteBroker(client)
