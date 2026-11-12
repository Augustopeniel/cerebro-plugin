"""Cliente do cofre do cérebro: o lado do aparelho no protocolo do broker.

- As chaves do aparelho nascem aqui (Ed25519 para assinar, X25519 para receber) e as privadas
  nunca saem da máquina (ficam no cofre do sistema, ver `keystore.py`).
- Cada pedido vai assinado (método, caminho, hora e hash do corpo).
- O que é secreto vai selado para a chave do servidor (HPKE) e o que volta vem selado para a chave
  do aparelho: além do TLS, uma segunda camada que a inspeção SSL de um firewall não abre.
- A senha do cofre vira chave aqui mesmo (Argon2id); só a chave derivada viaja, selada.

Nada daqui devolve valor ao Claude: quem chama é o broker, que injeta no destino.
O formato do fio (chaves JSON em pt-BR, contextos e assinatura) é o de `cerebro.core.vault`.
"""

from __future__ import annotations

import base64
import contextlib
import hashlib
import json
import secrets
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
import warnings
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from argon2.low_level import Type, hash_secret_raw
from cryptography import x509
from cryptography.hazmat.primitives import hpke
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)

FORMAT = "v1"  # o mesmo do servidor (cerebro.core.vault.FORMAT)
API = "/api/cofre/aparelho/"
SUITE = hpke.Suite(hpke.KEM.X25519, hpke.KDF.HKDF_SHA256, hpke.AEAD.AES_256_GCM)
PASSWORD_MIN = 12

Transport = Callable[[str, str, dict[str, str], bytes], tuple[int, dict[str, Any]]]


CONFIRM_STATUS = 428  # o mesmo do servidor (cerebro.core.vault.CONFIRM_STATUS)


class VaultClientError(Exception):
    """Recusa do servidor ou falha local; a mensagem diz o motivo."""

    def __init__(self, message: str, status: int = 0) -> None:
        super().__init__(message)
        self.status = status


class ConfirmationRequired(VaultClientError):
    """`entregar` sem confirmação válida (HTTP 428): o broker pede o código do autenticador,
    chama `confirm` e repete a entrega uma vez. `request` traz id, caminho, via, alvo, política."""

    def __init__(self, message: str, request: dict[str, Any]) -> None:
        super().__init__(message, CONFIRM_STATUS)
        self.request = request


def b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode()


def unb64(text: str) -> bytes:
    return base64.b64decode(text)


def _raw(key: Any, public: bool) -> bytes:
    if public:
        return key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    return key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())


@dataclass
class DeviceKeys:
    sign: bytes  # privada Ed25519
    receive: bytes  # privada X25519

    @classmethod
    def generate(cls) -> DeviceKeys:
        return cls(
            _raw(Ed25519PrivateKey.generate(), False), _raw(X25519PrivateKey.generate(), False)
        )

    @property
    def sign_public(self) -> bytes:
        return _raw(Ed25519PrivateKey.from_private_bytes(self.sign), True)

    @property
    def receive_public(self) -> bytes:
        return _raw(X25519PrivateKey.from_private_bytes(self.receive), True)

    def to_text(self) -> str:
        return json.dumps({"sign": b64(self.sign), "receive": b64(self.receive)})

    @classmethod
    def from_text(cls, text: str) -> DeviceKeys:
        data = json.loads(text)
        return cls(unb64(data["sign"]), unb64(data["receive"]))


def fingerprint(*keys: bytes) -> str:
    """Igual a `cerebro.core.vault.key_fingerprint`: impressão curta (`ABCD-EF01-…`) das chaves
    públicas, para a pessoa comparar a do aparelho e a do portal no pareamento."""
    digest = hashlib.sha256(b"".join(keys)).hexdigest()[:16].upper()
    return "-".join(digest[i : i + 4] for i in range(0, 16, 4))


def signed_payload(method: str, path: str, timestamp: int, body: bytes) -> bytes:
    """Igual a `cerebro.core.vault.signing_payload` (o teste de integração confere)."""
    digest = hashlib.sha256(body).hexdigest()
    return f"cofre/{FORMAT}/pedido\n{method.upper()}\n{path}\n{timestamp}\n{digest}".encode()


def derive(password: str, salt: bytes, params: dict[str, Any]) -> bytes:
    """Chave da senha do cofre (Argon2id), no aparelho. A senha nunca sai daqui."""
    if params.get("algoritmo") != "argon2id":
        raise VaultClientError(f"derivação desconhecida: {params.get('algoritmo')!r}")
    return hash_secret_raw(
        password.encode("utf-8"),
        salt,
        time_cost=int(params["tempo"]),
        memory_cost=int(params["memoria_kib"]),
        parallelism=int(params["paralelismo"]),
        hash_len=int(params["tamanho"]),
        type=Type.ID,
    )


def tls_context() -> ssl.SSLContext:
    """Contexto HTTPS que confere o certificado do servidor com as raízes do sistema.

    No Windows o Python carrega os repositórios ROOT e CA do sistema e, ao montar a cadeia,
    prefere o certificado que está neles ao que o servidor manda. Um intermediário vencido
    esquecido no repositório (caso real em 2026-11-11: o cruzamento antigo "ISRG Root X2
    emitido por ISRG Root X1", vencido em 15/09/2025) derruba a conexão com "certificate has
    expired" mesmo com a cadeia do servidor válida. Por isso, no Windows, os certificados do
    sistema entram um a um e os vencidos ficam de fora; nos outros sistemas vale o padrão.
    """
    if not hasattr(ssl, "enum_certificates"):
        return ssl.create_default_context()
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)  # confere nome e cadeia por padrão
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    agora = datetime.now(UTC)
    for loja in ("ROOT", "CA"):
        for der, codificacao, uso in ssl.enum_certificates(loja):
            if codificacao != "x509_asn":
                continue
            if uso is not True and ssl.Purpose.SERVER_AUTH.oid not in uso:
                continue  # mesmo filtro do Python: só o que serve para autenticar servidor
            try:
                with warnings.catch_warnings():  # certificados antigos com número de série negativo
                    warnings.simplefilter("ignore")
                    if x509.load_der_x509_certificate(der).not_valid_after_utc < agora:
                        continue
            except ValueError:
                pass  # ilegível para o cryptography: o OpenSSL decide
            with contextlib.suppress(ssl.SSLError):  # o que o OpenSSL não aceita fica de fora
                context.load_verify_locations(cadata=der)
    return context


def http_transport(base: str, *, timeout: float = 20.0) -> Transport:
    """HTTPS com verificação de certificado (raízes do sistema, sem as vencidas)."""
    context = tls_context()

    def send(
        method: str, path: str, headers: dict[str, str], body: bytes
    ) -> tuple[int, dict[str, Any]]:
        parts = urllib.parse.urlsplit(base)
        local = parts.scheme == "http" and parts.hostname in ("localhost", "127.0.0.1")
        if parts.scheme != "https" and not local:
            raise VaultClientError("o cofre só fala com o servidor por HTTPS")
        url = base.rstrip("/") + path  # https conferido acima: nada de file: nem outro esquema
        request = urllib.request.Request(url, data=body or None, method=method, headers=headers)  # noqa: S310
        try:
            with urllib.request.urlopen(request, timeout=timeout, context=context) as r:  # noqa: S310
                return r.status, json.loads(r.read() or b"{}")
        except urllib.error.HTTPError as exc:
            try:
                return exc.code, json.loads(exc.read() or b"{}")
            except json.JSONDecodeError:
                return exc.code, {"erro": f"HTTP {exc.code}"}
        except urllib.error.URLError as exc:
            raise VaultClientError(f"servidor do cofre fora do ar: {exc.reason}") from exc

    return send


@dataclass(frozen=True)
class Delivery:
    value: bytes
    credential: dict[str, Any]


class Client:
    def __init__(
        self,
        transport: Transport,
        keys: DeviceKeys,
        *,
        device: str | None = None,
        server: bytes | None = None,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self._send, self.keys, self.device = transport, keys, device
        self._server, self._clock = server, clock
        self.session: str | None = None  # só na memória do broker

    # ---------- pareamento (sem assinatura: ainda não há aparelho) ----------

    def _public_call(self, method: str, path: str, data: dict[str, Any] | None = None) -> dict:
        body = json.dumps(data or {}).encode() if data is not None else b""
        headers = {"content-type": "application/json"} if data is not None else {}
        status, answer = self._send(method, path, headers, body)
        if status >= 400:
            raise VaultClientError(str(answer.get("erro", f"HTTP {status}")), status)
        return answer

    def server_key(self) -> bytes:
        if self._server is None:
            self._server = unb64(self._public_call("GET", "/api/cofre/servidor")["chave_publica"])
        return self._server

    def pair(self, name: str) -> dict[str, Any]:
        """Pede o pareamento. Confere as impressões que o servidor diz ter visto com as
        calculadas aqui (recusa se não baterem) e devolve as daqui em `impressoes`, para a
        pessoa comparar com as do portal: é o que pega uma troca de chaves no caminho."""
        answer = self._public_call(
            "POST",
            "/api/cofre/parear",
            {
                "nome": name,
                "assinatura_publica": b64(self.keys.sign_public),
                "caixa_publica": b64(self.keys.receive_public),
            },
        )
        server = unb64(answer["servidor"])
        mine = {
            "servidor": fingerprint(server),
            "aparelho": fingerprint(self.keys.sign_public, self.keys.receive_public),
        }
        seen = answer.get("impressoes") if isinstance(answer.get("impressoes"), dict) else {}
        if any(seen.get(k) != mine[k] for k in mine):
            raise VaultClientError(
                "as impressões das chaves no pareamento não batem com as calculadas neste "
                "aparelho (alguém pode ter trocado as chaves no caminho): pareamento recusado"
            )
        self._server = server
        return answer | {"impressoes": mine}

    def pairing_state(self, request: str) -> str:
        answer = self._public_call("POST", "/api/cofre/parear/estado", {"pedido": request})
        if answer.get("estado") == "aprovado":
            self.device = answer["aparelho"]
        return str(answer.get("estado"))

    # ---------- pedidos assinados ----------

    def _seal(self, op: str, timestamp: int, data: bytes) -> str:
        info = f"cofre/{FORMAT}/para-servidor/{self.device}/{op}/{timestamp}".encode()
        public = X25519PublicKey.from_public_bytes(self.server_key())
        return b64(SUITE.encrypt(data, public, info))

    def _open(self, item: int, timestamp: int, sealed: str) -> bytes:
        info = f"cofre/{FORMAT}/para-aparelho/{self.device}/{item}/{timestamp}".encode()
        private = X25519PrivateKey.from_private_bytes(self.keys.receive)
        try:
            return SUITE.decrypt(unb64(sealed), private, info)
        except Exception as exc:
            raise VaultClientError("resposta selada não abre neste aparelho") from exc

    def _call(
        self, op: str, build: Callable[[int], dict[str, Any]], *, session: bool = False
    ) -> tuple[int, dict[str, Any]]:
        if not self.device:
            raise VaultClientError("aparelho não pareado: rode o pareamento")
        if session and not self.session:
            raise VaultClientError("cofre trancado: destrave primeiro")
        timestamp = int(self._clock())
        # a assinatura Ed25519 é determinística: o número único impede que dois pedidos iguais
        # no mesmo segundo pareçam repetição
        body = json.dumps(build(timestamp) | {"unico": secrets.token_hex(8)}).encode()
        path = API + op
        signature = Ed25519PrivateKey.from_private_bytes(self.keys.sign).sign(
            signed_payload("POST", path, timestamp, body)
        )
        headers = {
            "content-type": "application/json",
            "x-cofre-aparelho": self.device,
            "x-cofre-tempo": str(timestamp),
            "x-cofre-assinatura": b64(signature),
        }
        if self.session:
            headers["x-cofre-sessao"] = self.session
        status, answer = self._send("POST", path, headers, body)
        if status == CONFIRM_STATUS:
            request = answer.get("confirmar")
            raise ConfirmationRequired(
                str(answer.get("erro", "confirmação exigida")),
                request if isinstance(request, dict) else {},
            )
        if status >= 400:
            if status == 401 and "trancado" in str(answer.get("erro", "")):
                self.session = None
            raise VaultClientError(str(answer.get("erro", f"HTTP {status}")), status)
        return timestamp, answer

    # ---------- senha do cofre ----------

    def kdf(self) -> dict[str, Any]:
        return self._call("kdf", lambda t: {})[1]

    def setup(self, password: str) -> str:
        """Cria o cofre da pessoa; devolve o kit de recuperação (mostrar uma vez, imprimir)."""
        _check_password(password)
        info = self.kdf()
        if info.get("configurado"):
            raise VaultClientError("o cofre desta conta já está configurado")
        salt = secrets.token_bytes(16)
        key = derive(password, salt, info["parametros"])
        timestamp, answer = self._call(
            "configurar", lambda t: {"sal": b64(salt), "selado": self._seal("configurar", t, key)}
        )
        return self._open(0, timestamp, answer["kit_selado"]).decode()

    def unlock(self, password: str) -> None:
        info = self.kdf()
        if not info.get("configurado"):
            raise VaultClientError("cofre ainda não configurado nesta conta")
        key = derive(password, unb64(info["sal"]), info["parametros"])
        self.session = self._call(
            "destravar", lambda t: {"selado": self._seal("destravar", t, key)}
        )[1]["sessao"]

    def change_password(self, new: str) -> None:
        _check_password(new)
        salt = secrets.token_bytes(16)
        key = derive(new, salt, self.kdf()["parametros"])
        self._call(
            "senha",
            lambda t: {"sal": b64(salt), "selado": self._seal("senha", t, key)},
            session=True,
        )

    def recover(self, kit: str, new: str) -> None:
        _check_password(new)
        salt = secrets.token_bytes(16)
        key = derive(new, salt, self.kdf()["parametros"])
        inner = json.dumps({"kit": kit, "chave": b64(key)}).encode()
        self._call(
            "recuperar", lambda t: {"sal": b64(salt), "selado": self._seal("recuperar", t, inner)}
        )

    def lock(self) -> None:
        if self.session:
            try:
                self._call("trancar", lambda t: {}, session=True)
            finally:
                self.session = None

    # ---------- credenciais ----------

    def state(self) -> dict[str, Any]:
        return self._call("estado", lambda t: {})[1]

    def list(self, group: str = "", archived: bool = False) -> list[dict[str, Any]]:
        return self._call("listar", lambda t: {"grupo": group, "arquivadas": archived})[1][
            "entradas"
        ]

    def store(
        self,
        path: str,
        value: bytes,
        *,
        kind: str = "senha",
        fields: dict[str, str] | None = None,
        scope: list[str] | None = None,
        destinations: list[dict[str, str]] | None = None,
        confirm: str = "sempre",
        owner: dict[str, str] | None = None,
    ) -> dict[str, Any]:
        def build(t: int) -> dict[str, Any]:
            data = {
                "caminho": path,
                "tipo": kind,
                "campos": fields or {},
                "destinos": destinations or [],
                "confirmacao": confirm,
                "valor_selado": self._seal("gravar", t, value),
            }
            if scope:
                data["escopo"] = scope
            if owner:
                data["dono"] = owner
            return data

        return self._call("gravar", build)[1]["credencial"]

    def replace(self, ref: str, value: bytes) -> dict[str, Any]:
        return self._call(
            "trocar", lambda t: {"ref": ref, "valor_selado": self._seal("trocar", t, value)}
        )[1]["credencial"]

    def archive(self, ref: str) -> dict[str, Any]:
        return self._call("arquivar", lambda t: {"ref": ref})[1]["credencial"]

    def restore(self, ref: str) -> dict[str, Any]:
        return self._call("restaurar", lambda t: {"ref": ref})[1]["credencial"]

    def move(self, ref: str, path: str) -> dict[str, Any]:
        return self._call("mover", lambda t: {"ref": ref, "caminho": path})[1]["credencial"]

    def events(self, limit: int = 50) -> list[dict[str, Any]]:
        return self._call("eventos", lambda t: {"limite": limit})[1]["eventos"]

    def confirm(self, code: str, items: list[dict[str, Any]]) -> int:
        """Libera entregas com o código do autenticador que a pessoa digitou no popup: cada item
        é o par (credencial, via, alvo). 'sempre' vale para a entrega seguinte; 'sessao', até
        trancar. Código errado: VaultClientError com status 403."""
        wire = [
            {"id": int(i["id"]), "via": str(i["via"]), "alvo": str(i["alvo"])}
            | ({"programa": str(i["programa"])} if i.get("programa") else {})  # aprova o programa
            for i in items
        ]
        answer = self._call("confirmar", lambda t: {"codigo": code, "itens": wire}, session=True)[1]
        return int(answer.get("confirmadas", 0))

    def allow(self, item_id: int, via: str, target: str) -> dict[str, Any]:
        """Liberar destino: o dono põe (via, alvo) na lista da credencial; da próxima vez não
        pergunta. Só na sessão de confiança (o servidor confere)."""
        data = {"id": int(item_id), "via": str(via), "alvo": str(target)}
        return self._call("liberar", lambda t: data, session=True)[1]["credencial"]

    def pending(self) -> dict[str, list[dict[str, Any]]]:
        """O que espera a aprovação do dono: compartilhamentos e chaves de time (sem segredo)."""
        answer = self._call("pendencias", lambda t: {}, session=True)[1]
        return {
            "compartilhamentos": list(answer.get("compartilhamentos") or []),
            "times": list(answer.get("times") or []),
        }

    def approve(self, code: str, shares: list[list[int]], teams: list[list[int]]) -> int:
        """Aprova pendências com o código do autenticador; pares (item, usuário) e (time,
        usuário). Código errado: VaultClientError com status 403."""
        answer = self._call(
            "aprovar",
            lambda t: {"codigo": code, "compartilhamentos": shares, "times": teams},
            session=True,
        )[1]
        return int(answer.get("aprovadas", 0))

    def deliver(self, ref: str, via: str, target: str, program: str | None = None) -> Delivery:
        """O valor de uma credencial, aberto aqui; quem chama injeta no destino e esquece.
        Sem confirmação válida no servidor: ConfirmationRequired (HTTP 428). `program`: na via
        `mcp`, a impressão do processo que pediu (o servidor confere com as aprovadas)."""
        # "dono decide": este broker (2.8.0+) mostra a caixa de destino novo; sem isso o servidor
        # mantém a lista fechada também para o dono (broker antigo entregaria sem perguntar)
        body: dict[str, Any] = {"ref": ref, "via": via, "alvo": target, "dono_decide": True}
        if program:
            body["programa"] = program
        timestamp, answer = self._call("entregar", lambda t: dict(body), session=True)
        item = int(answer["credencial"]["id"])
        return Delivery(self._open(item, timestamp, answer["valor_selado"]), answer["credencial"])


def _check_password(password: str) -> None:
    if len(password) < PASSWORD_MIN:
        raise VaultClientError(f"a senha do cofre precisa de pelo menos {PASSWORD_MIN} caracteres")
