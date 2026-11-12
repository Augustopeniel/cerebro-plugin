"""Quem está do outro lado do canal local, pelo kernel (não pelo que o pedido diz).

O socket é 0600, mas isso só separa usuários: o Bash do Claude roda como o mesmo usuário e
falaria com o broker como qualquer MCP. Aqui o broker pergunta ao sistema qual processo conectou
(LOCAL_PEERPID no macOS, SO_PEERCRED no Linux) e monta a identidade dele: o executável de verdade
e o hash dele, os argumentos, o hash dos arquivos que aparecem nos argumentos (o script do MCP) e
as variáveis que injetam código (PYTHONPATH, PYTHONSTARTUP, DYLD_*, LD_PRELOAD…). Mudou o script,
o interpretador ou a injeção, muda a impressão: o servidor só entrega a um programa que a pessoa
aprovou com o código do autenticador.

Não é uma barreira absoluta contra quem roda código como o mesmo usuário (ele pode, por exemplo,
mudar um módulo importado pelo script): é uma camada que tira o atalho de "conectar no socket e
pedir". O Windows (named pipe) ainda não tem a conferência: a impressão sai "sem-conferencia".
"""

from __future__ import annotations

import ctypes
import ctypes.util
import hashlib
import json
import os
import socket
import struct
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

NO_CHECK = "sem-conferencia"
HASH_MAX_BYTES = 64 * 1024 * 1024
FILES_MAX = 4
# variáveis que fazem um interpretador (ou o carregador) rodar código além do script
INJECTION_PREFIXES = ("PYTHON", "DYLD_", "LD_", "NODE_OPTIONS", "NODE_PATH", "PERL5", "RUBYOPT",
                      "RUBYLIB", "BASH_ENV", "ENV", "ZDOTDIR")  # fmt: skip
_HASHES: dict[tuple[str, int, int], str] = {}


@dataclass(frozen=True)
class Peer:
    pid: int
    exe: str
    argv: tuple[str, ...]
    env: tuple[tuple[str, str], ...]
    files: tuple[tuple[str, str], ...]  # (caminho, sha256) dos arquivos citados nos argumentos
    exe_sha256: str

    def fingerprint(self) -> str:
        data = {
            "exe": self.exe,
            "exe_sha256": self.exe_sha256,
            "argv": list(self.argv[1:]),  # argv[0] varia ("python3", caminho…); o exe não
            "env": [list(kv) for kv in self.env],
            "arquivos": [list(f) for f in self.files],
        }
        raw = json.dumps(data, sort_keys=True, ensure_ascii=False).encode()
        return hashlib.sha256(raw).hexdigest()

    def describe(self) -> str:
        args = " ".join(self.argv[1:])
        extra = f" (+{', '.join(k for k, _ in self.env)})" if self.env else ""
        return f"{self.exe} {args}{extra}"[:300]

    def is_module(self, module: str, commands: frozenset[str]) -> bool:
        """`<python> -m <módulo> <comando>`, sem injeção: outro broker ou a linha de comando."""
        a = list(self.argv[1:])
        return (len(a) >= 3 and a[0] == "-m" and a[1] == module and a[2] in commands
                and not self.env)  # fmt: skip


def peer_pid(conn: socket.socket) -> int | None:
    try:
        if sys.platform == "darwin":
            sol_local, local_peerpid = 0, 0x002
            raw = conn.getsockopt(sol_local, local_peerpid, 4)
            return int.from_bytes(raw, sys.byteorder)
        if sys.platform.startswith("linux"):
            raw = conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i"))
            return struct.unpack("3i", raw)[0]
    except OSError:
        return None
    return None


def _sha256(path: str) -> str:
    st = os.stat(path)
    key = (path, st.st_size, st.st_mtime_ns)
    if key in _HASHES:
        return _HASHES[key]
    if st.st_size > HASH_MAX_BYTES:
        return f"grande:{st.st_size}"
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for block in iter(lambda: fh.read(1 << 20), b""):
            h.update(block)
    _HASHES[key] = h.hexdigest()
    return _HASHES[key]


def _procargs_darwin(pid: int) -> tuple[str, list[str], list[str]]:
    libc = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)
    ctl_kern, kern_argmax, kern_procargs2 = 1, 8, 49
    argmax = ctypes.c_int(0)
    size = ctypes.c_size_t(ctypes.sizeof(argmax))
    mib = (ctypes.c_int * 2)(ctl_kern, kern_argmax)
    if libc.sysctl(mib, 2, ctypes.byref(argmax), ctypes.byref(size), None, 0) != 0:
        raise OSError(ctypes.get_errno(), "sysctl KERN_ARGMAX")
    buf = ctypes.create_string_buffer(argmax.value)
    size = ctypes.c_size_t(argmax.value)
    mib3 = (ctypes.c_int * 3)(ctl_kern, kern_procargs2, pid)
    if libc.sysctl(mib3, 3, buf, ctypes.byref(size), None, 0) != 0:
        raise OSError(ctypes.get_errno(), "sysctl KERN_PROCARGS2")
    raw = buf.raw[: size.value]
    argc = struct.unpack_from("i", raw)[0]
    pos = struct.calcsize("i")
    end = raw.index(b"\0", pos)
    exe = raw[pos:end].decode("utf-8", "replace")
    pos = end
    while pos < len(raw) and raw[pos] == 0:
        pos += 1
    parts = raw[pos:].split(b"\0")
    argv = [p.decode("utf-8", "replace") for p in parts[:argc]]
    env = [p.decode("utf-8", "replace") for p in parts[argc:] if p]
    return exe, argv, env


def _procargs_linux(pid: int) -> tuple[str, list[str], list[str]]:
    base = Path(f"/proc/{pid}")
    exe = os.readlink(base / "exe")
    argv = [a.decode("utf-8", "replace") for a in (base / "cmdline").read_bytes().split(b"\0") if a]
    env = [e.decode("utf-8", "replace") for e in (base / "environ").read_bytes().split(b"\0") if e]
    return exe, argv, env


def identify(pid: int) -> Peer | None:
    """A identidade do processo `pid`; None se o sistema não deixar ver (outro usuário etc.)."""
    try:
        if sys.platform == "darwin":
            exe, argv, env = _procargs_darwin(pid)
        elif sys.platform.startswith("linux"):
            exe, argv, env = _procargs_linux(pid)
        else:
            return None
        exe = os.path.realpath(exe)
        injected = []
        for item in env:
            name, _, value = item.partition("=")
            if name.startswith(INJECTION_PREFIXES) and name != "PYTHONDONTWRITEBYTECODE":
                injected.append((name, value))
        files = []
        for arg in argv[1:]:
            candidate = arg.partition("=")[2] if arg.startswith("--") and "=" in arg else arg
            if len(files) >= FILES_MAX or not os.path.isabs(candidate):
                continue
            if os.path.isfile(candidate):
                real = os.path.realpath(candidate)
                files.append((real, _sha256(real)))
        return Peer(pid, exe, tuple(argv), tuple(sorted(injected)), tuple(files), _sha256(exe))
    except (OSError, ValueError, struct.error, IndexError):
        return None


def describe_unknown() -> dict[str, Any]:
    return {"programa": NO_CHECK, "programa_desc": "sem conferência do processo neste sistema"}
