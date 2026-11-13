"""Broker de fundo: o que mantém o cofre aberto o dia inteiro, mesmo fechando o Claude.

Até a 2.9, cada janela do Claude subia o seu broker, e a sessão do cofre morava no primeiro que
pegava o canal local: fechar aquela janela trancava o cofre. Agora o MCP `cofre` de cada sessão
garante, ao subir, um broker de fundo da mesma versão (`cerebro-cofre fundo`), solto do Claude, e
repassa a ele as ferramentas pelo canal autenticado. A sessão (e a chave da senha que a reabre
depois de um reinício do portal) fica só na memória desse processo: nada vai para o disco.
Reiniciar o computador, trancar de propósito ou passar o dia pedem senha e código de novo.

Versão nova do plugin: o MCP novo pede ao fundo antigo para sair (`stop`) e sobe o seu; a senha
é pedida uma vez. Se o fundo não subir (sistema que não deixa), o MCP atende sozinho, como antes.
"""

from __future__ import annotations

import os
import subprocess
import sys
import threading
import time
from pathlib import Path

from . import config as C
from . import tools as T
from .broker import Broker
from .channel import ChannelClient, ChannelServer

START_WAIT_S = 8.0
CHECK_S = 5.0


def _hello() -> dict | None:
    found = ChannelClient(timeout=5).hello()
    return found if found and found.get("broker") == C.NAME else None


def _wait(predicate, seconds: float) -> bool:
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(0.1)
    return predicate()


def spawn() -> None:
    """Sobe `python -m cofre_broker.cli fundo` solto do Claude (outra sessão de processo, sem
    console no Windows), com o mesmo ambiente; o log vai para a pasta de dados do plugin."""
    log = C.data_dir() / "cofre-fundo.log"
    log.parent.mkdir(parents=True, exist_ok=True)
    extra: dict = {}
    if os.name == "nt":
        flags = 0x00000008 | 0x00000200 | 0x08000000  # DETACHED, NEW_PROCESS_GROUP, NO_WINDOW
        extra["creationflags"] = flags
    else:
        extra["start_new_session"] = True
    with open(log, "ab") as out:
        subprocess.Popen(  # o próprio Python do broker, módulo fixo
            [sys.executable, "-m", "cofre_broker.cli", "fundo"],
            stdin=subprocess.DEVNULL,
            stdout=out,
            stderr=out,
            cwd=str(Path.home()),
            close_fds=True,
            **extra,
        )


def _version(text: object) -> tuple[int, ...]:
    try:
        return tuple(int(x) for x in str(text).split("."))
    except ValueError:
        return (0,)


def ensure() -> bool:
    """Garante um broker de fundo desta versão (ou mais nova) atendendo o canal. Devolve False
    quando quem atende é o broker de uma sessão (versão antiga, sem fundo): aí fica como antes.
    Duas versões abertas não brigam: só o fundo de versão menor é trocado."""
    found = _hello()
    if found and found.get("fundo"):
        if _version(found.get("version")) >= _version(C.VERSION):
            return True
        try:  # fundo de versão menor: sai e este sobe o da versão nova
            ChannelClient(timeout=10).admin("stop")
        except Exception as exc:  # sem o stop, o novo espera o canal vagar
            C.log(f"fundo antigo não parou: {exc}")
        _wait(lambda: not (_hello() or {}).get("fundo"), START_WAIT_S)
    elif found:
        return False  # o broker de outra sessão (2.9 ou antes) atende: não rouba
    try:
        spawn()
    except OSError as exc:
        C.log(f"fundo não subiu: {exc}")
        return False
    ok = _wait(
        lambda: bool(
            (h := _hello())
            and h.get("fundo")
            and _version(h.get("version")) >= _version(C.VERSION)
        ),
        START_WAIT_S,
    )
    if not ok:
        C.log("fundo não respondeu a tempo: este MCP atende sozinho")
    return ok


def _harden() -> None:
    """A chave da senha mora na memória deste processo o dia todo: sem dump de núcleo e sem
    depurador anexando (o mesmo usuário leria a memória). Falhou: segue, só registra."""
    import ctypes
    import ctypes.util

    try:
        import resource

        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    except (ImportError, ValueError, OSError):
        pass
    try:
        libc = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)
        if sys.platform.startswith("linux"):
            libc.prctl(4, 0, 0, 0, 0)  # PR_SET_DUMPABLE = 0
        elif sys.platform == "darwin":
            libc.ptrace(31, 0, None, 0)  # PT_DENY_ATTACH
    except (OSError, AttributeError, TypeError) as exc:
        C.log(f"fundo: sem endurecer a memória ({exc})")


def run(stop: threading.Event | None = None) -> int:
    """O processo de fundo: atende o canal até receber `stop` ou perder o canal."""
    if stop is None:
        _harden()
    stopping = stop or threading.Event()
    broker = Broker()
    channel = ChannelServer(
        broker, lambda n, a, cwd: T.call_tool(broker, n, a, cwd), on_stop=stopping.set
    )
    channel.start()
    if not channel.wait_owner(START_WAIT_S):
        C.log("fundo: outro broker já atende o canal; saindo")
        channel.stop()
        return 0
    C.log(f"fundo v{C.VERSION} pronto (pid {os.getpid()}) | servidor {broker.url}")
    try:
        while not stopping.wait(CHECK_S):
            if not channel.owner:
                C.log("fundo: perdeu o canal; saindo")
                break
    finally:
        channel.stop()
    C.log("fundo: saindo")
    return 0
