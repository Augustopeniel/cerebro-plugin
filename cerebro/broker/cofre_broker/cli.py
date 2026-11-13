"""`cerebro-cofre`: o broker local do cofre do cérebro.

cerebro-cofre mcp      servidor MCP stdio (o que o plugin registra como `cofre`)
cerebro-cofre fundo    broker de fundo: segura o cofre aberto o dia todo (o MCP sobe sozinho)
cerebro-cofre pair     vincula este aparelho (código e impressões num aviso na tela; espera)
cerebro-cofre status   situação do cofre neste aparelho, sem segredo
cerebro-cofre migrate-kdbx [--apply]   migra o cofre KeePass antigo (ensaio por padrão)
"""

from __future__ import annotations

import argparse
import sys
from typing import Any

from . import config as C
from . import tools as T
from .broker import Broker, BrokerError
from .channel import find_remote
from .keystore import KeystoreError
from .protocol import VaultClientError


def _pair(args: argparse.Namespace) -> int:
    from . import platform_io as P

    broker: Any = find_remote() or Broker()
    started = broker.pair_start(name=args.name, force=args.force)
    if started.get("already"):
        print(f"já vinculado: {started.get('name')} ({started.get('device')}); use --force")
        return 0
    # o código e as impressões só na tela (o terminal pode estar ao alcance do Claude)
    P.open_url(started["link"])
    P.show_info("Cofre do cérebro — vincular aparelho", Broker.pairing_message(started))
    print(
        "Código e impressões das chaves mostrados num aviso na tela: confira as impressões com "
        "as do portal antes de aprovar.\nEsperando a aprovação…",
        flush=True,
    )
    import time

    deadline = time.monotonic() + args.wait
    state = "pendente"
    while state == "pendente" and time.monotonic() < deadline:
        time.sleep(3)
        state = broker.pair_poll()
    print(
        {"aprovado": "aparelho vinculado.", "pendente": "ainda pendente: rode de novo."}.get(
            state, "código vencido: rode de novo."
        )
    )
    return 0 if state == "aprovado" else 1


def _status(args: argparse.Namespace) -> int:
    remote = find_remote()
    if remote is not None:
        print(remote.tool(name="status", arguments={}, cwd=None)["text"])
        return 0
    print(T.call_tool(Broker(), "status", {}, None)["text"])
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="cerebro-cofre", description=__doc__.splitlines()[0])
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("mcp", help="servidor MCP stdio")
    sub.add_parser("fundo", help="broker de fundo (o MCP sobe sozinho)")
    pair = sub.add_parser("pair", help="vincular este aparelho")
    pair.add_argument("--name", default=None, help="nome do aparelho")
    pair.add_argument("--wait", type=int, default=600, help="segundos esperando (padrão 600)")
    pair.add_argument("--force", action="store_true", help="vincular de novo")
    sub.add_parser("status", help="situação do cofre")
    from . import migrate_kdbx as M

    mig = sub.add_parser("migrate-kdbx", help="migra o cofre KeePass antigo (ensaio por padrão)")
    mig.add_argument("--apply", action="store_true", help="grava de verdade e confere")
    mig.add_argument("--kdbx", default=M.DEFAULT_KDBX)
    mig.add_argument("--keyfile", default=M.DEFAULT_KEYFILE)
    mig.add_argument("--allowlist", default=M.DEFAULT_ALLOWLIST)
    mig.add_argument("--old-broker", default=M.DEFAULT_OLD_BROKER)
    mig.add_argument("--scope", default="*", help="cérebros, separados por vírgula ('*' = todos)")
    mig.add_argument("--confirm", default="sempre", choices=("sempre", "sessao", "livre"))
    mig.add_argument(
        "--confirm-mcp",
        default="sessao",
        choices=("sempre", "sessao", "livre"),
        help="confirmação das credenciais que os MCPs buscam (destino mcp:)",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.command == "mcp":
            from .mcp_server import main as serve

            serve()
            return 0
        if args.command == "fundo":
            from .fundo import run

            return run()
        if args.command == "pair":
            return _pair(args)
        if args.command == "migrate-kdbx":
            from . import migrate_kdbx as M

            return M.main_cli(args)
        return _status(args)
    except (BrokerError, VaultClientError, KeystoreError, ConnectionError, RuntimeError) as exc:
        C.log(str(exc))
        return 1
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    sys.exit(main())
