"""Servidor MCP local `cofre` (JSON-RPC 2.0 por stdio, só com a biblioteca padrão).

Cada sessão do Claude sobe um destes. Só um guarda a sessão destravada: o que atende o canal
local. Os outros repassam as ferramentas a ele pelo canal (autenticado), para o usuário destravar
uma vez só; se quem atende o canal é o broker antigo, este trabalha sozinho e o `status` avisa.
"""

from __future__ import annotations

import json
import os
import sys
from typing import Any, TextIO

from . import config as C
from . import tools as T
from .broker import Broker, BrokerError
from .channel import ChannelServer, find_remote


def _result(mid: Any, result: dict[str, Any]) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": mid, "result": result}


def _error(mid: Any, code: int, message: str) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": mid, "error": {"code": code, "message": message}}


class McpServer:
    def __init__(self, broker: Broker, channel: ChannelServer | None = None) -> None:
        self.broker, self.channel = broker, channel

    def call_tool(self, name: str, args: dict[str, Any]) -> dict[str, Any] | None:
        if name not in T.HANDLERS:
            return None
        cwd = os.getcwd()
        outcome = None
        if name not in T.LOCAL_ONLY and self.channel is not None and not self.channel.owner:
            remote = find_remote()
            if remote is not None:
                try:
                    outcome = remote.tool(name=name, arguments=args, cwd=cwd)
                except ConnectionError:
                    outcome = None  # o outro caiu: atende aqui mesmo
                except BrokerError as exc:
                    outcome = {"text": str(exc), "is_error": True}
        if outcome is None:
            outcome = T.call_tool(self.broker, name, args, cwd)
        text = str(outcome.get("text", ""))
        return {"content": [{"type": "text", "text": text}], "isError": bool(outcome["is_error"])}

    def handle(self, msg: Any) -> dict[str, Any] | None:
        if not isinstance(msg, dict):
            return None
        method, mid = msg.get("method"), msg.get("id")
        if method == "initialize":
            version = (msg.get("params") or {}).get("protocolVersion") or C.PROTOCOL_FALLBACK
            return _result(
                mid,
                {
                    "protocolVersion": version,
                    "capabilities": {"tools": {"listChanged": False}},
                    "serverInfo": {"name": "cofre", "version": C.VERSION},
                },
            )
        if method in ("notifications/initialized", "initialized"):
            return None
        if method == "ping":
            return _result(mid, {})
        if method == "tools/list":
            return _result(mid, {"tools": T.SCHEMAS})
        if method == "tools/call":
            params = msg.get("params") or {}
            args = params.get("arguments") or {}
            payload = self.call_tool(
                str(params.get("name")), args if isinstance(args, dict) else {}
            )
            if payload is None:
                return _error(mid, -32602, f"ferramenta desconhecida: {params.get('name')}")
            return _result(mid, payload)
        if "id" not in msg:
            return None
        return _error(mid, -32601, f"método não suportado: {method}")

    def serve(self, stdin: TextIO, stdout: TextIO) -> None:
        for line in stdin:
            line = line.strip()
            if not line:
                continue
            try:
                msg = json.loads(line)
            except ValueError:
                C.log("JSON inválido no stdin")
                continue
            try:
                answer = self.handle(msg)
            except Exception as exc:
                C.log("handle() estourou:", type(exc).__name__)
                mid = msg.get("id") if isinstance(msg, dict) else None
                answer = _error(mid, -32603, "erro interno") if mid is not None else None
            if answer is not None:
                stdout.write(json.dumps(answer, ensure_ascii=False) + "\n")
                stdout.flush()


def main() -> None:
    for stream in (sys.stdin, sys.stdout):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is not None:
            reconfigure(encoding="utf-8")
    broker = Broker()
    channel = ChannelServer(broker, lambda n, a, cwd: T.call_tool(broker, n, a, cwd))
    channel.start()
    channel.wait_owner(1.0)  # o status já sai com o papel certo
    C.log(f"v{C.VERSION} pronto | {len(T.SCHEMAS)} ferramentas | servidor {broker.url}")
    McpServer(broker, channel).serve(sys.stdin, sys.stdout)
    channel.stop()
    C.log("stdin fechado, saindo.")
