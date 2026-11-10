"""Migração do cofre antigo (KeePass `.kdbx` + allowlist local) para o cofre do cérebro.

Roda no aparelho, pelo broker: lê o `.kdbx` com o motor do broker antigo (`keepassxc-cli`), monta
o plano (caminho, tipo, usuário, url, destinos) e, com `apply`, grava cada credencial pelo cliente
do cofre — o valor vai selado para o servidor e nunca é impresso, logado nem devolvido.

Depois confere: pede cada credencial de volta pelo destino permitido e compara o hash SHA-256 com
o do `.kdbx`, aqui mesmo, e descarta. O original fica intacto (congelado como reserva).

Regras de segurança da migração:
- notas do KeePass NÃO viram metadado (metadado o Claude enxerga; nota pode ter segredo, como
  códigos de recuperação): ficam listadas para migrar à mão como credencial do tipo "nota";
- `Arquivo/…` entra e é arquivada logo em seguida (nada se perde, nada fica em uso);
- nome que não cabe nas regras de caminho do cofre é relatado e pulado (renomeie no KeePass).
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from typing import Any, Protocol

ARCHIVE_GROUP = "Arquivo"
_SEGMENT = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
_TOKEN_HINT = re.compile(r"(TOKEN|API_?KEY|_KEY$|SECRET|BEARER)", re.IGNORECASE)
_SSH_HINT = re.compile(r"(SSH|_PEM$|PRIVATE_KEY|ID_RSA|ID_ED25519)", re.IGNORECASE)


class OldBackend(Protocol):
    """O que a migração usa do `KeePassXCBackend` do broker antigo."""

    def list_meta(self, master: str) -> list[dict[str, str]]: ...

    def get_secret(self, master: str, ref: str) -> str: ...


@dataclass
class Planned:
    old_ref: str
    path: str
    kind: str
    fields: dict[str, str]
    destinations: list[dict[str, str]]
    archived: bool
    has_notes: bool

    def public(self) -> dict[str, Any]:
        return {
            "caminho": self.path,
            "tipo": self.kind,
            "destinos": self.destinations,
            "arquivada": self.archived,
            "usuario": self.fields.get("usuario", ""),
            "url": self.fields.get("url", ""),
        }  # sem valor e sem notas


@dataclass
class Plan:
    items: list[Planned] = field(default_factory=list)
    skipped: list[dict[str, str]] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)  # caminhos com notas a migrar à mão

    def report(self) -> dict[str, Any]:
        return {
            "credenciais": len(self.items),
            "arquivadas": sum(1 for i in self.items if i.archived),
            "puladas": self.skipped,
            "com_notas": self.notes,
            "entradas": [i.public() for i in self.items],
        }


def _kind(name: str) -> str:
    if _SSH_HINT.search(name):
        return "ssh"
    return "token" if _TOKEN_HINT.search(name) else "senha"


def destinations_from(allowlist: Iterable[tuple[str, str]], ref: str) -> list[dict[str, str]]:
    """Traduz os pares da allowlist antiga (`ref` ou grupo → destino) para destinos novos, só o
    necessário: `env:<consumidor>` → `mcp:<consumidor>` (os MCPs pelo socket); rótulos livres de
    app/site/campo → `digitar:*`. O que mais precisar (copiar, ambiente) o dono acrescenta."""
    found: dict[tuple[str, str], None] = {}
    for source, target in allowlist:
        applies = source == ref or ref.startswith(source.rstrip("/") + "/")
        if not applies:
            continue
        if target.startswith("env:"):
            found[("mcp", target.removeprefix("env:"))] = None
        else:
            found[("digitar", "*")] = None
    return [{"via": via, "alvo": alvo} for via, alvo in found]


def plan(backend: OldBackend, master: str, allowlist: Iterable[tuple[str, str]]) -> Plan:
    pairs = list(allowlist)
    result = Plan()
    for meta in backend.list_meta(master):
        ref = meta["ref"].strip("/")
        archived = ref == ARCHIVE_GROUP or ref.startswith(ARCHIVE_GROUP + "/")
        path = ref.removeprefix(ARCHIVE_GROUP + "/") if archived else ref
        parts = path.split("/")
        if len(parts) < 2 or len(parts) > 4 or not all(_SEGMENT.match(p) for p in parts):
            result.skipped.append(
                {
                    "caminho": ref,
                    "motivo": "nome fora das regras do cofre "
                    "(grupo/NOME, letras, números, '.', '_' e '-')",
                }
            )
            continue
        fields = {
            k: " ".join(meta.get(src, "").split())[:300]
            for k, src in (("usuario", "username"), ("url", "url"))
            if meta.get(src)
        }
        has_notes = bool((meta.get("notes") or "").strip())
        if has_notes:
            result.notes.append(ref)
        result.items.append(
            Planned(
                ref,
                path,
                _kind(parts[-1]),
                fields,
                destinations_from(pairs, ref),
                archived,
                has_notes,
            )
        )
    return result


Store = Callable[[Planned, bytes], dict[str, Any]]  # grava; devolve a credencial (metadados)
Archive = Callable[[str], Any]
Fetch = Callable[[str, str, str], bytes]  # (caminho, via, alvo) → valor, no aparelho


def apply(
    backend: OldBackend, master: str, migration: Plan, *, store: Store, archive: Archive
) -> list[dict[str, Any]]:
    """Grava cada credencial do plano; devolve, por credencial, o resultado (sem valor) e o
    hash do valor original para a conferência."""
    done = []
    for item in migration.items:
        try:
            secret = backend.get_secret(master, item.old_ref).encode("utf-8")
            stored = store(item, secret)
            if item.archived:
                archive(item.path)
            done.append(
                {
                    "caminho": item.path,
                    "id": stored.get("id"),
                    "resultado": "gravada",
                    "_hash": hashlib.sha256(secret).hexdigest(),
                }
            )
        except Exception as exc:  # uma falha não para as outras; o motivo vai no relatório
            done.append({"caminho": item.path, "resultado": "falhou", "motivo": str(exc)[:200]})
    return done


def verification_items(results: list[dict[str, Any]], migration: Plan) -> list[dict[str, Any]]:
    """O que a conferência vai pedir de volta (id, caminho, via, alvo), para liberar tudo com
    um código do autenticador só, em vez de um por credencial."""
    by_path = {i.path: i for i in migration.items}
    found = []
    for row in results:
        item = by_path.get(row["caminho"])
        if row["resultado"] != "gravada" or item is None or item.archived:
            continue
        if not item.destinations or row.get("id") is None:
            continue
        first = item.destinations[0]
        found.append(
            {"id": int(row["id"]), "caminho": item.path, "via": first["via"], "alvo": first["alvo"]}
        )
    return found


def verify(results: list[dict[str, Any]], migration: Plan, fetch: Fetch) -> list[dict[str, Any]]:
    """Confere pelo hash: pede o valor de volta pelo primeiro destino permitido e compara aqui.
    Sem destino (ou arquivada) não dá para pedir: fica 'não conferida', e o relatório diz."""
    by_path = {i.path: i for i in migration.items}
    checked = []
    for row in results:
        item = by_path.get(row["caminho"])
        outcome = dict(row)
        expected = outcome.pop("_hash", None)
        if row["resultado"] != "gravada" or item is None:
            checked.append(outcome)
            continue
        if item.archived or not item.destinations:
            outcome["conferida"] = "não (sem destino permitido ou arquivada)"
            checked.append(outcome)
            continue
        first = item.destinations[0]
        try:
            value = fetch(item.path, first["via"], first["alvo"])
            same = hashlib.sha256(value).hexdigest() == expected
            outcome["conferida"] = "sim" if same else "DIFERENTE"
        except Exception as exc:
            outcome["conferida"] = f"erro: {str(exc)[:120]}"
        checked.append(outcome)
    return checked


# ---------- linha de comando (cerebro-cofre migrate-kdbx) ----------

DEFAULT_OLD_BROKER = "~/Projetos/MCP/global/cofre-mcp"
DEFAULT_KDBX = "~/Library/CloudStorage/OneDrive-Pessoal/Cofre/claude.kdbx"
DEFAULT_KEYFILE = "~/.claude/cofre/claude.keyx"
DEFAULT_ALLOWLIST = "~/.claude/cofre/allowlist.json"
CLI_CANDIDATES = ("keepassxc-cli", "/Applications/KeePassXC.app/Contents/MacOS/keepassxc-cli")


def load_allowlist(path: str) -> list[tuple[str, str]]:
    import json
    import os

    full = os.path.expanduser(path)
    if not os.path.isfile(full):
        return []
    with open(full, encoding="utf-8") as fh:
        data = json.load(fh)
    return [(str(p.get("ref", "")), str(p.get("destino", ""))) for p in data.get("pairs", [])]


def old_backend(old_broker: str, kdbx: str, keyfile: str) -> OldBackend:
    """O motor KeePass do broker antigo (só leitura aqui: a migração não grava no .kdbx)."""
    import os
    import shutil
    import sys

    folder = os.path.expanduser(old_broker)
    if not os.path.isdir(os.path.join(folder, "cofre")):
        raise RuntimeError(f"broker antigo não encontrado em {folder}")
    sys.path.insert(0, folder)
    from cofre.backend import KeePassXCBackend  # o pacote do broker antigo

    cli = next(
        (
            c
            for c in (shutil.which(x) or (x if os.path.isfile(x) else None) for x in CLI_CANDIDATES)
            if c
        ),
        None,
    )
    if cli is None:
        raise RuntimeError("keepassxc-cli não encontrado (instale o KeePassXC)")
    return KeePassXCBackend(cli, os.path.expanduser(kdbx), os.path.expanduser(keyfile))


def main_cli(args: Any) -> int:
    """Ensaio por padrão (só o plano, sem valores); `--apply` grava e confere pelo hash."""
    import json

    from . import platform_io as P
    from .broker import Broker

    backend = old_backend(args.old_broker, args.kdbx, args.keyfile)
    master = P.prompt_secret(
        "Migração do cofre antigo", "Senha-mestra do cofre KeePass antigo (o .kdbx fica intacto):"
    )
    if not master:
        print("cancelado")
        return 1
    migration = plan(backend, master, load_allowlist(args.allowlist))
    report = migration.report()
    if not args.apply:
        print(json.dumps(report | {"modo": "ensaio (nada gravado)"}, ensure_ascii=False, indent=1))
        return 0
    broker = Broker()
    client = broker.client()
    scope = [s.strip() for s in args.scope.split(",") if s.strip()] or ["*"]

    def store(item: Planned, value: bytes) -> dict[str, Any]:
        return client.store(
            item.path,
            value,
            kind=item.kind,
            fields=item.fields,
            scope=scope,
            destinations=item.destinations,
            confirm=args.confirm,
        )

    done = apply(backend, master, migration, store=store, archive=client.archive)
    master = ""
    broker.unlock()  # a conferência precisa do cofre destravado (popup da senha do cofre)
    items = verification_items(done, migration)
    if items:  # um código do autenticador libera a conferência inteira
        broker.confirm_with_code(
            items, f"Conferir a migração: pedir de volta {len(items)} credencial(is) e comparar"
        )

    def fetch(path: str, via: str, target: str) -> bytes:
        return client.deliver(path, via, target).value  # aberto aqui, comparado e descartado

    checked = verify(done, migration, fetch)
    print(
        json.dumps(
            {
                "migradas": checked,
                "puladas": report["puladas"],
                "com_notas_para_migrar_a_mao": report["com_notas"],
            },
            ensure_ascii=False,
            indent=1,
        )
    )
    return 0 if all(r["resultado"] == "gravada" for r in checked) else 1
