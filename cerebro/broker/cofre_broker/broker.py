"""O broker: o único processo da máquina que guarda a sessão destravada do cofre.

Junta o cliente do protocolo (`protocol.py`), a guarda das chaves (`keystore.py`) e os destinos
locais (`platform_io.py`): digitar, copiar, o ambiente de um comando e os outros MCPs pelo canal
local. Quem chama (as ferramentas do MCP, o canal) recebe só metadados; o valor vai
direto ao destino e é esquecido.

Garantias daqui:
- o valor nunca entra por argumento de ferramenta: vem do popup mascarado ou é gerado;
- a entrega usa a via certa e o alvo certo (`run`: o nome do comando, que vem do PATH; `mcp`: o
  consumidor; digitar e copiar: `*`), e quem decide se o destino vale é o servidor: o dono da
  credencial manda para qualquer destino e decide na hora (o código, ou a caixa com "Liberar
  destino" na sessão de confiança); quem recebe (time, compartilhamento) segue a lista do dono;
- a confirmação é exigida pelo SERVIDOR (HTTP 428) e liberada com o código de 6 dígitos do app
  autenticador, digitado num popup mascarado: um OK o agente de IA conseguiria clicar (System
  Events, computer-use), o código ele não tem. Ao digitar e ao rodar um intérprete o broker pede
  o código antes da 1ª entrega, mesmo com a política 'livre';
- compartilhamentos e chaves de time esperando o dono só se completam com o código, num popup
  depois do destrave;
- o que um comando imprime volta mascarado (`mask.py`).
"""

from __future__ import annotations

import os
import platform
import re
import secrets
import shlex
import shutil
import string
import subprocess
import threading
import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from pathlib import Path
from types import ModuleType
from typing import Any

from . import config as C
from . import envfile, ssh_connector
from . import platform_io as P
from .keystore import Keystore, default_keystore
from .mask import masked_output
from .protocol import (
    Client,
    ConfirmationRequired,
    Delivery,
    DeviceKeys,
    Transport,
    VaultClientError,
    b64,
    http_transport,
)
from .protocol import unb64 as _unb64

TITLE = "Cofre do cérebro"
KINDS = ("senha", "token", "ssh", "chave", "nota", "ambiente")
CONFIRM_POLICIES = ("sempre", "sessao", "livre")
VIAS = ("ambiente", "digitar", "copiar", "mcp")
RUN_TIMEOUT_MAX = 600
_GROUP = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}(/[A-Za-z0-9][A-Za-z0-9._-]{0,63}){0,2}")
_CONSUMER = re.compile(r"[A-Za-z0-9_.-]{1,64}")
_SYMBOLS = "-_.!@#%^*+=:,~"
_CODE = re.compile(r"[0-9]{6}")
CODE_ATTEMPTS = 3
POPUP_ITEMS_MAX = 12
# comandos que executam o que receberem: com eles, a credencial no ambiente pode ser lida e
# impressa de qualquer jeito (a máscara não cobre tudo); por isso pedem o código sempre
INTERPRETERS = frozenset(
    {
        "sh",
        "bash",
        "zsh",
        "fish",
        "dash",
        "ksh",
        "csh",
        "tcsh",
        "nu",
        "python",
        "pypy",
        "node",
        "deno",
        "bun",
        "perl",
        "ruby",
        "php",
        "lua",
        "tclsh",
        "osascript",
        "pwsh",
        "powershell",
        "cmd",
        "env",
        "xargs",
        "sudo",
        "nohup",
        "nice",
        "time",
        "timeout",
        "watch",
        "busybox",
        "uv",
        "uvx",
        "npx",
        "pipx",
        "make",
        "awk",
        "gawk",
        "java",
        "jshell",
        "script",
        "expect",
    }
)


SSH_HOPS_MAX = 4


class BrokerError(Exception):
    """Pedido recusado aqui no aparelho; a mensagem diz o motivo."""


def resolve_program(program: str) -> str:
    """Caminho absoluto do programa do `run`, achado no PATH. Recusa pasta no nome: o alvo da
    entrega é o nome, e `./gh` ou `/tmp/x/gh` passariam por `gh` sem ser o `gh` de verdade."""
    seps = {"/", "\\"} | ({":"} if os.name == "nt" else set())
    if any(sep in program for sep in seps) or program in (".", ".."):
        raise BrokerError(
            f"{program!r}: diga só o nome do programa (sem pasta); ele tem de vir do PATH"
        )
    found = shutil.which(program)
    if not found:
        raise BrokerError(f"comando não encontrado no PATH: {program!r}")
    return os.path.abspath(found)


def command_target(program: str) -> str:
    """Alvo da entrega no `run`: o nome do programa, sem pasta (e sem `.exe` no Windows)."""
    name = os.path.basename(program.replace("\\", "/"))
    for suffix in (".exe", ".cmd", ".bat"):
        if name.lower().endswith(suffix):
            return name[: -len(suffix)]
    return name


def is_interpreter(target: str) -> bool:
    return re.sub(r"[0-9.]+$", "", target.lower()) in INTERPRETERS


def generate_secret(length: int = 24) -> str:
    """Senha forte, gerada aqui e gravada direto: ninguém a vê."""
    length = max(16, min(int(length or 24), 128))
    alphabet = string.ascii_letters + string.digits + _SYMBOLS
    while True:
        found = "".join(secrets.choice(alphabet) for _ in range(length))
        kinds = (string.ascii_lowercase, string.ascii_uppercase, string.digits, _SYMBOLS)
        if all(any(ch in kind for ch in found) for kind in kinds):
            return found


def check_group(group: str) -> str:
    clean = str(group or "").strip().strip("/")
    if not _GROUP.fullmatch(clean):
        raise BrokerError(f"grupo inválido: {group!r} (ex.: 'mcp/zabbix')")
    return clean


def default_device_name() -> str:
    return (platform.node() or P.platform_name()).split(".")[0][:40] or "aparelho"


def _destinations(items: Any) -> list[dict[str, str]]:
    """Destinos vindos da ferramenta (`via`, `target`) no formato do fio (`via`, `alvo`)."""
    found = []
    for item in items or []:
        if not isinstance(item, dict) or item.get("via") not in VIAS:
            raise BrokerError(f"destino inválido: {item!r} (via: {', '.join(VIAS)})")
        found.append({"via": item["via"], "alvo": str(item.get("target") or "*")})
    return found


def _listed(entry: dict[str, Any], via: str, target: str) -> bool:
    """O destino está na lista da credencial (liberado, não pergunta)."""
    return any(
        d.get("via") == via and d.get("alvo") in ("*", target) for d in entry.get("destinos") or []
    )


def _owner(entry: dict[str, Any]) -> bool:
    """Credencial sua (ou de um time de que você é dono): vai para qualquer destino."""
    return entry.get("papel") == "dono"


class Broker:
    def __init__(
        self,
        *,
        keystore: Keystore | None = None,
        ui: ModuleType | Any = None,
        folder: Path | None = None,
        url: str | None = None,
        transport_factory: Callable[[str], Transport] = http_transport,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self.keystore = keystore or default_keystore()
        self.ui = ui or P
        self.folder = folder or C.data_dir()
        self.url = (url or C.server_url()).rstrip("/")
        self._transport_factory, self._clock = transport_factory, clock
        self._lock = threading.RLock()  # cliente, sessão e pareamento
        self._deliver_lock = threading.Lock()  # entregas (e seus popups) uma de cada vez
        self._client: Client | None = None
        # sessão (cvs_…) em que o código do autenticador já foi digitado: daí em diante só a
        # caixa de OK das credenciais 'sempre'; vale até trancar, vencer ou fechar o Claude
        self._trusted_session: str | None = None
        self._pending: dict[str, Any] | None = None
        self._seen = threading.local()
        self.channel_state = "desligado"  # o canal local escreve aqui (status)

    # ---------- valores entregues nesta chamada (para mascarar a resposta) ----------

    @contextmanager
    def capture(self) -> Iterator[list[bytes]]:
        seen: list[bytes] = []
        self._seen.values = seen
        try:
            yield seen
        finally:
            self._seen.values = None

    def _note(self, value: bytes) -> None:
        seen = getattr(self._seen, "values", None)
        if seen is not None:
            seen.append(value)

    # ---------- cliente e pareamento ----------

    def _load_client(self) -> Client | None:
        config = C.load_config(self.folder)
        if not config.paired or config.server_url.rstrip("/") != self.url:
            return None
        text = self.keystore.get()
        if not text:
            return None
        return Client(
            self._transport_factory(self.url),
            DeviceKeys.from_text(text),
            device=config.device_id,
            server=_unb64(config.server_key),
            clock=self._clock,
        )

    def client(self) -> Client:
        with self._lock:
            if self._client is None:
                self._client = self._load_client()
            if self._client is None:
                raise BrokerError(
                    "este aparelho ainda não está vinculado ao cofre: use a ferramenta `pair` "
                    "ou o `setup` (1ª vez)"
                )
            return self._client

    def paired(self) -> bool:
        try:
            self.client()
        except BrokerError:
            return False
        return True

    def pair_start(self, name: str | None = None, force: bool = False) -> dict[str, Any]:
        with self._lock:
            pending = self._pending
            if pending and pending["expires"] > self._clock():
                return self._pending_view(new=False)
            if self.paired() and not force:
                config = C.load_config(self.folder)
                return {"already": True, "device": config.device_id, "name": config.device_name}
            keys = DeviceKeys.generate()
            client = Client(self._transport_factory(self.url), keys, clock=self._clock)
            answer = client.pair(name or default_device_name())  # confere as impressões
            self._pending = {
                "client": client,
                "request": answer["pedido"],
                "code": answer["codigo"],
                "link": str(answer.get("link", "")),
                "expires": float(answer.get("expira", self._clock() + 600)),
                "name": name or default_device_name(),
                "fingerprints": dict(answer["impressoes"]),
            }
            return self._pending_view(new=True)

    def _pending_view(self, *, new: bool) -> dict[str, Any]:
        """Código, link e impressões: só para o popup e o aviso nativo. A ferramenta
        `pair` não devolve nada disso ao modelo (ele poderia mandar o código para fora)."""
        pending = self._pending or {}
        link = pending.get("link", "")
        if not link.startswith(self.url + "/"):
            link = f"{self.url}/cofre?parear={pending.get('code', '')}"
        return {
            "code": pending.get("code"),
            "link": link,
            "expires": pending.get("expires"),
            "fingerprints": dict(pending.get("fingerprints") or {}),
            "new": new,
        }

    @staticmethod
    def pairing_message(started: dict[str, Any]) -> str:
        """Texto do popup do pareamento: o código e as duas impressões para comparar."""
        prints = started.get("fingerprints") or {}
        return (
            f"Código: {started.get('code')}\n\n"
            f"Impressão do servidor: {prints.get('servidor', '?')}\n"
            f"Impressão deste aparelho: {prints.get('aparelho', '?')}\n\n"
            "Aprove no portal (logado, com o código do autenticador) só se as duas impressões "
            f"forem as mesmas que o portal mostra:\n{started.get('link')}"
        )

    def pair_poll(self) -> str:
        """`pendente`, `aprovado`, `vencido` ou `nenhum` (sem pareamento em curso)."""
        with self._lock:
            pending = self._pending
            if not pending:
                return "nenhum"
            client: Client = pending["client"]
            state = client.pairing_state(pending["request"])
            if state == "aprovado":
                self.keystore.set(client.keys.to_text())
                C.save_config(
                    C.DeviceConfig(
                        self.url, str(client.device), b64(client.server_key()), pending["name"]
                    ),
                    self.folder,
                )
                self._client, self._pending = client, None
            elif state != "pendente":
                self._pending = None
            return state

    def pair_wait(self, seconds: float, interval: float = 3.0) -> str:
        deadline = time.monotonic() + max(0.0, seconds)
        while True:
            state = self.pair_poll()
            if state != "pendente" or time.monotonic() >= deadline:
                return state
            time.sleep(interval)

    # ---------- senha do cofre ----------

    def configure(self) -> dict[str, Any]:
        """1ª vez, só por popups (sem janela nem formulário): a senha do cofre duas vezes, o kit
        de recuperação mostrado uma vez num aviso, e o código do autenticador. Nada volta ao
        Claude além de "configurado"."""
        ask = "Crie a senha do cofre (mínimo de 12 caracteres; o Claude não vê o que você digitar):"
        for _ in range(3):
            first = self.ui.prompt_secret(TITLE, ask)
            if not first:
                raise BrokerError("configuração cancelada: nada foi criado")
            second = self.ui.prompt_secret(TITLE, "Repita a senha do cofre:")
            if second == first and len(first) >= 12:
                break
            ask = ("As duas senhas não conferem ou têm menos de 12 caracteres. Crie a senha do "
                   "cofre de novo:")  # fmt: skip
        else:
            raise BrokerError("configuração cancelada: a senha não conferiu 3 vezes")
        kit = self.setup(first)
        first = second = ""
        aviso = (
            "Kit de recuperação do cofre (aparece só agora; serve se você esquecer a senha):\n\n"
            f"{kit}\n\nAnote ou guarde longe do computador e do Claude. Clique OK quando tiver "
            "guardado."
        )
        while not self.ui.confirm(TITLE, aviso):
            if self.ui.confirm(TITLE, "O kit não aparece de novo. Fechar mesmo assim?"):
                break
        kit = ""
        self._session_code(self.client())
        return {"configured": True, "unlocked": True}

    def setup(self, password: str) -> str:
        """Cria o cofre da conta e já destrava. Devolve o kit (o `configure` mostra uma vez)."""
        client = self.client()
        with self._lock:
            kit = client.setup(password)
            client.unlock(password)
        return kit

    def unlock(self, password: str | None = None) -> dict[str, Any]:
        client = self.client()
        with self._lock:
            if password is None:
                if client.session:
                    return {"unlocked": True}
                password = self.ui.prompt_secret(
                    TITLE, "Senha do cofre para destravar (o Claude não vê o que você digitar):"
                )
                if not password:
                    raise BrokerError("o cofre segue trancado (popup cancelado)")
            client.unlock(password)
            self._trusted_session = None
            self._session_code(client)
        self.review_pending()
        return {"unlocked": True}

    def _relocking(self, call: Callable[[], Any]) -> Any:
        """Roda `call`; se o servidor disser que a sessão acabou (portal reiniciado, 2 h sem uso),
        destrava de novo (senha + código) e tenta uma vez."""
        try:
            return call()
        except VaultClientError as exc:
            if exc.status != 401 or self.client().session is not None:
                raise
        self.unlock()
        return call()

    def trusted(self) -> bool:
        """A sessão atual já passou pelo código do autenticador (autenticou uma vez)."""
        client = self._client
        return bool(client and client.session and client.session == self._trusted_session)

    def _session_code(self, client: Client) -> None:
        """Logo depois da senha, o código de 6 dígitos uma vez só: o servidor passa a confiar
        nesta sessão até trancar (2 h sem uso ou o Claude fechar). Cancelar não desfaz o
        destrave: o código volta a ser pedido na primeira entrega."""
        try:
            self._with_code(
                "Cofre destravado. Para terminar de autenticar, digite o código de 6 dígitos do "
                "app autenticador (uma vez só: vale até fechar o Claude ou ficar 2 h sem uso; "
                "o Claude não vê).",
                lambda code: client.confirm(code, []),
                "código cancelado: será pedido na primeira entrega",
            )
        except (BrokerError, VaultClientError) as exc:
            C.log(f"sessão sem o código: {exc}")
            return
        self._trusted_session = client.session

    def lock(self) -> dict[str, Any]:
        with self._lock:
            self._trusted_session = None
            if self._client is not None:
                self._client.lock()
        return {"unlocked": False}

    # ---------- código do autenticador (confirmações e aprovações) ----------

    def _with_code(self, message: str, send: Callable[[str], Any], cancelled: str) -> Any:
        """Popup mascarado pedindo o código de 6 dígitos do app autenticador; `send` leva o
        código ao servidor. Código recusado (403) pergunta de novo, até CODE_ATTEMPTS vezes."""
        note = ""
        for _ in range(CODE_ATTEMPTS):
            code = self.ui.prompt_secret(TITLE, note + message)
            if not code:
                raise BrokerError(cancelled)
            code = "".join(str(code).split())
            if not _CODE.fullmatch(code):
                note = "O código tem 6 dígitos.\n\n"
                continue
            try:
                return send(code)
            except VaultClientError as exc:
                if exc.status != 403:
                    raise
                note = f"Código recusado pelo servidor ({exc}).\n\n"
        raise BrokerError(f"código do autenticador recusado {CODE_ATTEMPTS} vezes: nada foi feito")

    @staticmethod
    def _items_text(items: list[dict[str, Any]]) -> str:
        lines = [
            f"• {i.get('caminho') or i.get('id')} (via {i.get('via')}, alvo {i.get('alvo')})"
            for i in items[:POPUP_ITEMS_MAX]
        ]
        if len(items) > POPUP_ITEMS_MAX:
            lines.append(f"… e mais {len(items) - POPUP_ITEMS_MAX}")
        return "\n".join(lines)

    def confirm_with_code(self, items: list[dict[str, Any]], head: str) -> int:
        """Libera no servidor as entregas de `items` (id, caminho, via, alvo) com o código."""
        message = (
            f"{head}\n\nCredenciais:\n{self._items_text(items)}\n\nDigite o código de 6 "
            "dígitos do app autenticador para liberar (o Claude não vê). Cancelar não entrega "
            "nada."
        )
        client = self.client()
        if not client.session:
            self.unlock()
        count = self._with_code(
            message,
            lambda code: client.confirm(code, items),
            "cancelado na confirmação: nada foi entregue",
        )
        self._trusted_session = client.session  # o código certo vale para a sessão inteira
        return count

    def pending(self) -> dict[str, list[dict[str, Any]]]:
        """Compartilhamentos e chaves de time esperando o dono aprovar (sem segredo)."""
        client = self.client()
        if not client.session:
            raise BrokerError(
                "cofre trancado: destrave (`unlock`); se houver pendências, um popup pede o "
                "código do autenticador para aprová-las logo depois"
            )
        return client.pending()

    def review_pending(self) -> int:
        """Depois de cada destrave: se algo espera o dono, um popup lista tudo e pede o código
        do autenticador para aprovar. Cancelar deixa pendente; falha não atrapalha o destrave."""
        try:
            found = self.pending()
        except (BrokerError, VaultClientError) as exc:
            C.log(f"pendências não consultadas: {exc}")
            return 0
        shares, teams = found["compartilhamentos"], found["times"]
        if not shares and not teams:
            return 0
        lines = [
            f"• credencial {s.get('caminho')} para {s.get('usuario')} ({s.get('papel')})"
            for s in shares
        ] + [f"• chave do time {t.get('nome_time')} para {t.get('usuario')}" for t in teams]
        if len(lines) > POPUP_ITEMS_MAX:
            lines = [*lines[:POPUP_ITEMS_MAX], f"… e mais {len(lines) - POPUP_ITEMS_MAX}"]
        message = (
            "Esperando a sua aprovação (quem recebe passa a poder usar; 'usa' quer dizer que o "
            "aparelho da pessoa recebe o valor):\n\n" + "\n".join(lines) + "\n\nDigite o código "
            "de 6 dígitos do app autenticador para aprovar tudo. Cancelar deixa pendente."
        )
        client = self.client()
        share_pairs = [[int(s["id"]), int(s["usuario_id"])] for s in shares]
        team_pairs = [[int(t["time"]), int(t["usuario_id"])] for t in teams]
        # dar acesso a outra pessoa pede o código sempre (uma caixa de OK o agente clicaria)
        try:
            return int(
                self._with_code(
                    message,
                    lambda code: client.approve(code, share_pairs, team_pairs),
                    "aprovação cancelada: segue pendente",
                )
            )
        except (BrokerError, VaultClientError) as exc:
            C.log(f"pendências não aprovadas: {exc}")
            return 0

    def state(self) -> dict[str, Any]:
        config = C.load_config(self.folder)
        found: dict[str, Any] = {
            "name": C.NAME,
            "version": C.VERSION,
            "platform": P.platform_name(),
            "server": self.url,
            "paired": False,
            "device": config.device_id,
            "device_name": config.device_name,
            "keystore": self.keystore.name,
            "keystore_warning": self.keystore.warning,
            "channel": self.channel_state,
            "pid": os.getpid(),
        }
        if self._pending:  # sem o código: ele só aparece no popup
            found["pairing"] = {"pending": True, "expires": self._pending.get("expires")}
        try:
            client = self.client()
        except BrokerError:
            return found
        found["paired"] = True
        try:
            remote = client.state()
        except VaultClientError as exc:
            found["error"] = str(exc)
            return found
        found |= {
            "configured": bool(remote.get("configurado")),
            "unlocked": bool(client.session),
            "total": remote.get("total", 0),
            "pending_shares": remote.get("pendencias", 0),
            "brain": remote.get("cerebro"),
            "account": remote.get("conta"),
        }
        return found

    # ---------- credenciais (metadados) ----------

    def list_entries(self, group: str = "", archived: bool = False) -> list[dict[str, Any]]:
        group = check_group(group) if group else ""
        return self.client().list(group=group, archived=archived)

    def events(self, limit: int = 50) -> list[dict[str, Any]]:
        return self.client().events(max(1, min(int(limit or 50), 200)))

    def _value(self, path: str, value: str | None, generate: bool, length: int) -> str:
        if generate:
            return generate_secret(length)
        if value is not None:  # import do .env e testes; o MCP nunca manda valor
            return value
        found = self.ui.prompt_secret(
            TITLE, f"Valor para '{path}' (o Claude não vê o que você digitar):"
        )
        if not found:
            raise BrokerError("cancelado: nada foi gravado")
        return found

    def store(
        self,
        path: str,
        value: str | None = None,
        generate: bool = False,
        length: int = 24,
        kind: str = "senha",
        fields: dict[str, str] | None = None,
        destinations: list[dict[str, str]] | None = None,
        confirm: str = "sempre",
        scope: list[str] | None = None,
    ) -> dict[str, Any]:
        if kind not in KINDS:
            raise BrokerError(f"tipo: um de {', '.join(KINDS)}")
        if confirm not in CONFIRM_POLICIES:
            raise BrokerError(f"confirmação: um de {', '.join(CONFIRM_POLICIES)}")
        client = self.client()
        wire = _destinations(destinations)
        secret = self._value(path, value, generate, length)
        clean = {k: str(v) for k, v in (fields or {}).items() if v}
        return client.store(
            path,
            secret.encode("utf-8"),
            kind=kind,
            fields=clean,
            scope=list(scope) if scope else None,
            destinations=wire,
            confirm=confirm,
        )

    def replace(
        self, ref: str, value: str | None = None, generate: bool = False, length: int = 24
    ) -> dict[str, Any]:
        client = self.client()
        return client.replace(ref, self._value(ref, value, generate, length).encode("utf-8"))

    def archive(self, ref: str) -> dict[str, Any]:
        return self.client().archive(ref)

    def restore(self, ref: str) -> dict[str, Any]:
        return self.client().restore(ref)

    def move(self, ref: str, path: str) -> dict[str, Any]:
        return self.client().move(ref, path)

    def import_env(
        self,
        path: str,
        group: str,
        names: list[str] | None = None,
        destinations: list[dict[str, str]] | None = None,
        cwd: str | None = None,
    ) -> dict[str, Any]:
        group = check_group(group)
        file = Path(path).expanduser()
        if not file.is_absolute():
            file = Path(cwd or os.getcwd()) / file
        try:
            variables = envfile.parse_env_file(file)
        except (ValueError, OSError) as exc:
            raise BrokerError(f"não consegui ler o .env: {exc}") from exc
        if names:
            missing = [n for n in names if n not in variables]
            if missing:
                raise BrokerError(f"variáveis ausentes no .env: {', '.join(missing)}")
            chosen = [n for n in names if variables[n]]
        else:
            chosen = [n for n, v in variables.items() if v and envfile.is_secret_name(n)]
        if not chosen:
            raise BrokerError(f"nenhuma variável secreta com valor em {file.name}")
        client = self.client()
        wire = _destinations(destinations)
        existing = {e["caminho"].lower() for e in client.list(group=group, archived=True)}
        new = [n for n in chosen if f"{group}/{n}".lower() not in existing]
        skipped = [n for n in chosen if n not in new]
        if new and not self.ui.confirm(
            TITLE,
            f"Importar {len(new)} segredo(s) de {file.parent.name}/{file.name} para o grupo "
            f"'{group}'?\n\n{', '.join(new)}",
        ):
            raise BrokerError("importação cancelada: nada foi gravado")
        done, failed = [], []
        for name in new:
            try:
                client.store(
                    f"{group}/{name}",
                    variables[name].encode("utf-8"),
                    kind="ambiente",
                    destinations=wire,
                )
                done.append(name)
            except VaultClientError as exc:
                failed.append({"name": name, "reason": str(exc)})
        variables.clear()
        return {"group": group, "imported": done, "skipped": skipped, "failed": failed}

    # ---------- entrega (o valor sai daqui direto para o destino) ----------

    def _fetch(self, ref: str, via: str, target: str, program: str | None = None) -> Delivery:
        """Uma entrega. ConfirmationRequired (428) sobe para quem chamou juntar num popup só."""
        client = self.client()
        if not client.session:
            self.unlock()
        try:
            delivery = client.deliver(ref, via, target, program)
        except ConfirmationRequired:
            raise
        except VaultClientError as exc:
            if exc.status != 401 or client.session is not None:
                raise
            self.unlock()  # a sessão venceu no servidor: destrava e tenta uma vez
            delivery = client.deliver(ref, via, target, program)
        self._note(delivery.value)
        return delivery

    def _entries_for(self, refs: list[str], via: str, target: str) -> list[dict[str, Any]]:
        """Metadados das credenciais (para confirmar antes da 1ª entrega). O destino é conferido
        aqui só para não pedir o código à toa: quem decide é o servidor, na entrega. O dono
        manda para qualquer destino; quem recebe, só para os da lista."""
        # sessão que o servidor esqueceu (portal reiniciado): destrava de novo e tenta uma vez
        listed = self._relocking(lambda: self.client().list())
        by_ref = {str(e["caminho"]).lower(): e for e in listed} | {str(e["id"]): e for e in listed}
        found = []
        for ref in refs:
            entry = by_ref.get(str(ref).strip().strip("/").lower())
            if entry is None:
                raise BrokerError(f"credencial {ref!r} não encontrada neste cérebro")
            if not _listed(entry, via, target) and not _owner(entry):
                raise BrokerError(
                    f"destino {via}:{target} não permitido para {entry['caminho']} (a "
                    "credencial não é sua: o dono define os destinos no portal)"
                )
            found.append(entry)
        return found

    def _deliver_all(
        self,
        wanted: dict[str, str],
        via: str,
        target: str,
        head: str,
        *,
        force: bool = False,
        skip_refused: bool = False,
        program: str | None = None,
    ) -> tuple[dict[str, Delivery], list[str]]:
        """Entrega {nome: caminho} pela via e alvo dados. O que o servidor segurar (428) vira um
        popup só, com o código do autenticador, e é pedido de novo uma vez. Com `force`, o
        código vem antes da 1ª entrega, mesmo com a política 'livre'. Depois do código (a
        sessão de confiança, que vale 2 h sem uso e renova a cada uso), o servidor não segura
        mais nada: copiar, digitar, intérprete e 'sempre' mostram só a caixa de autorização,
        uma para o pedido inteiro (decisão do Augusto, 2026-11-12)."""
        client = self.client()
        if not client.session:
            self.unlock()
        if self.trusted():
            self._relocking(lambda: self._authorize(wanted, via, target, head, force=force))
            force = False
        confirmed: set[int] = set()
        if force:
            entries = self._entries_for(list(wanted.values()), via, target)
            items = [
                {"id": int(e["id"]), "caminho": e["caminho"], "via": via, "alvo": target}
                for e in entries
            ]
            self.confirm_with_code(items, head)
            confirmed = {i["id"] for i in items}
        done: dict[str, Delivery] = {}
        refused: list[str] = []
        held: dict[str, dict[str, Any]] = {}
        for name, path in sorted(wanted.items()):
            try:
                done[name] = self._fetch(path, via, target, program)
            except ConfirmationRequired as exc:
                held[name] = exc.request or {"caminho": path}
            except VaultClientError as exc:
                if not skip_refused or "não permitido" not in str(exc):
                    raise
                refused.append(name)
        if not held:
            return done, refused
        items = [
            {
                "id": int(r.get("id") or 0),
                "caminho": r.get("caminho") or wanted[n],
                "via": r.get("via") or via,
                "alvo": r.get("alvo") or target,
            }
            | ({"programa": r["programa"]} if r.get("programa") else {})
            for n, r in held.items()
        ]
        if any(not i["id"] or i["id"] in confirmed for i in items):
            raise BrokerError("o servidor segue pedindo confirmação: nada foi entregue")
        self.confirm_with_code(items, head)
        for name in sorted(held):
            try:
                done[name] = self._fetch(wanted[name], via, target, program)
            except ConfirmationRequired as exc:
                raise BrokerError(
                    "o servidor segue pedindo confirmação depois do código: nada foi entregue"
                ) from exc
        return done, refused

    def _authorize(
        self, wanted: dict[str, str], via: str, target: str, head: str, *, force: bool
    ) -> None:
        """Caixa de autorização (sem código) numa sessão de confiança, antes de copiar, digitar,
        rodar intérprete (`force`), entregar credencial 'sempre' ou mandar uma credencial sua a
        um destino que ainda não está na lista dela. Destino novo ganha três botões: Negar, Só
        desta vez e Liberar destino (põe na lista; da próxima vez não pergunta). Destinos
        recusados (credencial de outro dono) não entram: o servidor recusa na entrega."""
        items: list[dict[str, Any]] = []
        fresh: list[dict[str, Any]] = []  # credenciais suas indo a um destino fora da lista
        if force:  # copiar, digitar e intérprete: destino conferido antes, sem nem perguntar
            entries = self._entries_for(sorted(set(wanted.values())), via, target)
            items = [{"caminho": e["caminho"], "via": via, "alvo": target} for e in entries]
            wanted = {}
        listed = self.client().list() if wanted else []
        by_ref = {str(e["caminho"]).lower(): e for e in listed}
        for path in sorted(set(wanted.values())):
            entry = by_ref.get(str(path).strip().strip("/").lower())
            if entry is None:
                continue
            item = {"id": entry.get("id"), "caminho": entry["caminho"], "via": via, "alvo": target}
            if _listed(entry, via, target):
                if entry.get("confirmacao") == "sempre":
                    items.append(item)
            elif _owner(entry):
                items.append(item)
                fresh.append(item)
        if not items:
            return
        if not fresh:
            message = (
                f"{head}\n\nCredenciais:\n{self._items_text(items)}\n\nAutorizar? (o código já "
                "foi digitado no destrave; o Claude não vê o valor)"
            )
            if not self.ui.confirm(TITLE, message):
                raise BrokerError("cancelado na autorização: nada foi entregue")
            return
        message = (
            f"{head}\n\nCredenciais:\n{self._items_text(items)}\n\n"
            f"Destino novo para {len(fresh)} delas ({via}:{target}): confira se foi você quem "
            "pediu.\n• Só desta vez: entrega agora e pergunta de novo da próxima.\n"
            "• Liberar destino: entrega e, da próxima vez, este destino não pergunta (copiar, "
            "digitar, intérprete e 'sempre' perguntam sempre).\n(O Claude não vê o valor.)"
        )
        choice = getattr(self.ui, "choose", None)
        answer = choice(TITLE, message) if choice else ("uma" if self.ui.confirm(TITLE, message)
                                                        else None)  # fmt: skip
        if answer not in ("uma", "liberar"):
            raise BrokerError("negado na autorização: nada foi entregue")
        if answer == "liberar":
            client = self.client()
            for item in fresh:
                try:
                    client.allow(int(item["id"]), via, target)
                except VaultClientError as exc:  # não liberou: entrega mesmo assim, desta vez
                    C.log(f"liberar {item['caminho']} → {via}:{target}: {exc}")

    def _group_entries(self, group: str) -> dict[str, str]:
        """{NOME: caminho} das entradas diretas do grupo (o nome é o da variável)."""
        found = {}
        for entry in self._relocking(lambda: self.client().list(group=group)):
            path = str(entry["caminho"])
            if not path.lower().startswith(group.lower() + "/"):
                continue
            rest = path[len(group) + 1 :]
            if "/" not in rest and envfile.is_env_name(rest):
                found[rest] = path
        return found

    def deliver_group(
        self, group: str, consumer: str, program: tuple[str, str] | None = None
    ) -> dict[str, str]:
        """O que o `cofre_client`/`cofre_run` pedem pelo canal: NOME→valor do grupo, entregue com
        via `mcp` e alvo = consumidor. Entradas sem esse destino ficam de fora. `program`:
        (impressão, descrição) do processo que pediu, visto pelo kernel; o servidor só entrega
        a um programa que a pessoa aprovou com o código."""
        group = check_group(group)
        consumer = str(consumer or "").strip()
        if not _CONSUMER.fullmatch(consumer):
            raise BrokerError("'consumer' inválido")
        with self._deliver_lock:
            names = self._group_entries(group)
            if not names:
                raise BrokerError(f"grupo '{group}' vazio ou inexistente no cofre")
            desc = program[1] if program else "não identificado"
            deliveries, refused = self._deliver_all(
                names,
                "mcp",
                consumer,
                f"Entregar credenciais do grupo '{group}' ao processo '{consumer}' (outro MCP "
                f"desta máquina).\n\nPrograma: {desc}\nSe não reconhece este programa, cancele.",
                skip_refused=True,
                program=program[0] if program else None,
            )
            if not deliveries:
                raise BrokerError(f"nenhuma credencial de '{group}' tem o destino mcp:{consumer}")
        if refused:
            C.log(f"{consumer}: sem destino mcp:{consumer} em {', '.join(refused)}")
        return {name: d.value.decode("utf-8") for name, d in deliveries.items()}

    def inject(self, ref: str) -> dict[str, Any]:
        """Digita no campo em foco. O código vem sempre antes da entrega: o popup é também o
        "pronto, o cursor está no campo"."""
        with self._deliver_lock:
            front = getattr(self.ui, "frontmost_app", lambda: "")() or "não identificado"
            head = (
                f"Digitar o valor de '{ref}' no campo em foco.\n"
                f"App em foco agora: {front}.\n\n"
                "Ponha o cursor no campo de destino; terminal e Claude são recusados."
            )
            done, _ = self._deliver_all({"valor": ref}, "digitar", "*", head, force=True)
            delivery = done["valor"]
            self.ui.type_text(delivery.value.decode("utf-8"))
        return {"path": delivery.credential.get("caminho", ref)}

    def copy(self, ref: str) -> dict[str, Any]:
        """Copia com o código do autenticador a cada vez: a área de transferência é legível
        por qualquer processo do usuário, inclusive o agente."""
        ttl = C.clip_ttl()
        with self._deliver_lock:
            head = f"Copiar o valor de '{ref}' para a área de transferência por {ttl} s."
            done, _ = self._deliver_all({"valor": ref}, "copiar", "*", head, force=True)
            delivery = done["valor"]
            self.ui.copy_clipboard(delivery.value.decode("utf-8"), ttl)
        return {"path": delivery.credential.get("caminho", ref), "ttl": ttl}

    def run(
        self,
        command: list[str],
        group: str = "",
        paths: list[str] | None = None,
        timeout: int = 120,
        cwd: str | None = None,
    ) -> dict[str, Any]:
        if (
            not isinstance(command, list)
            or not command
            or not all(isinstance(a, str) and a for a in command)
        ):
            raise BrokerError("'command' é a lista do programa e seus argumentos (sem shell)")
        program = resolve_program(command[0])
        target = command_target(command[0])
        wanted: dict[str, str] = self._group_entries(check_group(group)) if group else {}
        for path in paths or []:
            name = str(path).strip().strip("/").rsplit("/", 1)[-1]
            if not envfile.is_env_name(name):
                raise BrokerError(f"'{path}': o nome não serve de variável de ambiente")
            if name in wanted and wanted[name].lower() != str(path).strip("/").lower():
                raise BrokerError(f"duas credenciais virariam a mesma variável {name}")
            wanted[name] = str(path).strip().strip("/")
        if not wanted:
            raise BrokerError("diga as credenciais: 'group' ou 'paths'")
        workdir = Path(cwd or os.getcwd()).expanduser()
        if not workdir.is_dir():
            raise BrokerError(f"pasta de trabalho não existe: {workdir}")
        real = os.path.realpath(program)
        # .bat/.cmd no Windows passa pelo cmd.exe: os argumentos viram linguagem de shell; e um
        # nome inocente pode ser um atalho para um intérprete (o nome real também conta)
        risky = (
            is_interpreter(target)
            or is_interpreter(command_target(real))
            or program.lower().endswith((".bat", ".cmd"))
        )
        head = (
            f"Rodar um comando com {', '.join(sorted(wanted))} no ambiente.\n\n"
            f"Programa: {program}" + (f" (→ {real})" if real != program else "") + "\n"
            f"Argumentos: {shlex.join(command[1:])[:400] or '(nenhum)'}\n"
            f"Pasta: {workdir}"
        )
        if risky:
            head += f"\n\nAtenção: '{target}' executa o que receber e pode ler e mostrar o valor."
        with self._deliver_lock:
            deliveries, _ = self._deliver_all(wanted, "ambiente", target, head, force=risky)
        values = [d.value for d in deliveries.values()]
        env = dict(os.environ) | {n: d.value.decode("utf-8") for n, d in deliveries.items()}
        limit = max(1, min(int(timeout or 120), RUN_TIMEOUT_MAX))
        timed_out = False
        try:
            proc = subprocess.run(  # noqa: S603 (lista de argumentos, sem shell)
                [program, *command[1:]],
                env=env,
                cwd=workdir,
                stdin=subprocess.DEVNULL,
                capture_output=True,
                timeout=limit,
                check=False,
            )
            code, out, err = proc.returncode, proc.stdout, proc.stderr
        except FileNotFoundError as exc:
            raise BrokerError(f"comando não encontrado: {command[0]!r}") from exc
        except subprocess.TimeoutExpired as exc:
            timed_out, code = True, None
            out, err = exc.stdout or b"", exc.stderr or b""
        finally:
            env.clear()
        return {
            "exit_code": code,
            "timed_out": timed_out,
            "variables": sorted(deliveries),
            "stdout": masked_output(out, values),
            "stderr": masked_output(err, values),
        }

    # ---------- ssh (servidores = credenciais do tipo 'ssh') ----------

    def ssh_servers(self) -> list[dict[str, Any]]:
        return [e for e in self.client().list() if e.get("tipo") == "ssh"]

    def _ssh_chain(self, server: str) -> list[dict[str, Any]]:
        by_path = {str(e["caminho"]).lower(): e for e in self.ssh_servers()}
        chain, ref = [], str(server).strip().strip("/").lower()
        while ref:
            entry = by_path.get(ref)
            if entry is None:
                raise BrokerError(f"servidor {ref!r} não está no cofre (tipo ssh) deste cérebro")
            if entry in chain or len(chain) >= SSH_HOPS_MAX:
                raise BrokerError(f"saltos demais ou em círculo a partir de {server!r}")
            chain.append(entry)
            ref = str(entry.get("jump") or "").strip().strip("/").lower()
        return chain[::-1]  # do primeiro salto ao destino

    def ssh(
        self, server: str, command: str, *, stdin: str = "", timeout: int = 60, script: bool = False
    ) -> dict[str, Any]:
        """Roda um comando no servidor; as senhas e chaves dos saltos vão ao ssh sem passar pelo
        Claude (destino exigido em cada credencial: ambiente:ssh). A regra do host é conferida
        antes de buscar qualquer segredo, e host sem impressão fixada não recebe segredo: só a
        sonda roda até ele, e o erro mostra a impressão vista para gravar."""
        if not isinstance(command, str) or not command.strip():
            raise BrokerError("diga o comando")
        chain = self._ssh_chain(server)
        dry = None
        for entry in chain:  # regra e metadados, ainda sem segredo nenhum
            dry = ssh_connector.target_from(entry, b"", dry)
        assert dry is not None  # noqa: S101 (a cadeia tem ao menos o destino)
        try:
            ssh_connector.check_rule(dry, command, script=script)
        except ssh_connector.SshError as exc:
            raise BrokerError(str(exc)) from exc
        # só os saltos antes do 1º sem impressão fixada recebem segredo (para a sonda chegar nele)
        reach = next((i for i, e in enumerate(chain) if not e.get("impressao")), len(chain))
        last = chain[-1]
        what = "script" if script else "comando"
        head = (
            f"Rodar no servidor {last['caminho']} ({last.get('usuario')}@{last.get('host')}) o "
            f"{what}:\n{command[:300]}"
        )
        if reach < len(chain):
            head += (
                f"\n\n{chain[reach]['caminho']} não tem a chave do host fixada: só a sonda vai "
                "até ele, sem segredo."
            )
        wanted = {str(i): str(e["caminho"]) for i, e in enumerate(chain[:reach])}
        deliveries: dict[str, Delivery] = {}
        with self._deliver_lock:
            if wanted:
                deliveries, _ = self._deliver_all(wanted, "ambiente", "ssh", head)
            target = None
            for i, entry in enumerate(chain):
                secret = deliveries[str(i)].value if str(i) in deliveries else b""
                target = ssh_connector.target_from(entry, secret, target)
        try:
            result = ssh_connector.run(
                target, command, timeout=max(1, min(int(timeout), 600)), stdin=stdin, script=script
            )
        except ssh_connector.SshError as exc:
            raise BrokerError(str(exc)) from exc
        return {
            "exit_code": result.code,
            "stdout": result.out,
            "stderr": result.err,
            "host_keys": result.host_keys,
        }
