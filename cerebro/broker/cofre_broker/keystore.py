"""Guarda das chaves privadas do aparelho no cofre do sistema.

- macOS: Keychain, pelo `security`. O segredo vai pelo **stdin** (`security -i`), nunca por argv
  (argv aparece no `ps`); a leitura usa `find-generic-password -w`, que só imprime para nós.
- Windows: Gerenciador de Credenciais (`CredWriteW`/`CredReadW`, via `ctypes`), credencial
  genérica do usuário.
- Linux: sem cofre do sistema garantido, um arquivo 0600 na pasta de dados do plugin, com aviso.

O segredo guardado é texto (o JSON das chaves em base64): só letras, números e `+/=`, o que
dispensa aspas na linha do `security -i`.
"""

from __future__ import annotations

import base64
import os
import subprocess
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Protocol

from . import config as C

SERVICE = "cerebro-cofre"
ACCOUNT = "aparelho"

Runner = Callable[..., subprocess.CompletedProcess]


class KeystoreError(Exception):
    """O cofre do sistema recusou guardar ou ler."""


class Keystore(Protocol):
    name: str
    warning: str

    def get(self) -> str | None: ...

    def set(self, secret: str) -> None: ...

    def delete(self) -> None: ...


def _pack(secret: str) -> str:
    return base64.b64encode(secret.encode("utf-8")).decode()


def _unpack(stored: str) -> str:
    return base64.b64decode(stored.strip()).decode("utf-8")


class MemoryKeystore:
    """Para testes: nada sai do processo."""

    name, warning = "memória", ""

    def __init__(self) -> None:
        self.stored: str | None = None

    def get(self) -> str | None:
        return _unpack(self.stored) if self.stored else None

    def set(self, secret: str) -> None:
        self.stored = _pack(secret)

    def delete(self) -> None:
        self.stored = None


class MacKeychain:
    name, warning = "Keychain do macOS", ""

    def __init__(self, runner: Runner = subprocess.run, account: str = ACCOUNT) -> None:
        self._run, self._account = runner, account

    def get(self) -> str | None:
        r = self._run(
            ["security", "find-generic-password", "-a", self._account, "-s", SERVICE, "-w"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            timeout=30,
        )
        if r.returncode != 0:
            return None  # 44: não existe
        return _unpack(r.stdout)

    def set(self, secret: str) -> None:
        packed = _pack(secret)
        line = f"add-generic-password -U -a {self._account} -s {SERVICE} -w {packed}\n"
        r = self._run(
            ["security", "-i"],
            input=line,
            capture_output=True,
            text=True,
            encoding="utf-8",
            timeout=30,
        )
        del line, packed
        if r.returncode != 0 or "error" in (r.stderr or "").lower():
            raise KeystoreError("o Keychain recusou guardar as chaves do aparelho")
        if self.get() != secret:
            raise KeystoreError("as chaves gravadas no Keychain não conferem")

    def delete(self) -> None:
        self._run(
            ["security", "delete-generic-password", "-a", self._account, "-s", SERVICE],
            capture_output=True,
            text=True,
            encoding="utf-8",
            timeout=30,
        )


class WindowsCredentials:
    name, warning = "Gerenciador de Credenciais do Windows", ""
    _GENERIC, _PERSIST_LOCAL, _NOT_FOUND = 1, 2, 1168

    def __init__(self, target: str = f"{SERVICE}/{ACCOUNT}") -> None:
        self._target = target

    @staticmethod
    def _api():  # ctypes.WinDLL só existe no Windows: carregar só aqui
        import ctypes
        from ctypes import wintypes

        class Credential(ctypes.Structure):
            _fields_ = [
                ("Flags", wintypes.DWORD),
                ("Type", wintypes.DWORD),
                ("TargetName", wintypes.LPWSTR),
                ("Comment", wintypes.LPWSTR),
                ("LastWritten", wintypes.FILETIME),
                ("CredentialBlobSize", wintypes.DWORD),
                ("CredentialBlob", ctypes.POINTER(ctypes.c_ubyte)),
                ("Persist", wintypes.DWORD),
                ("AttributeCount", wintypes.DWORD),
                ("Attributes", ctypes.c_void_p),
                ("TargetAlias", wintypes.LPWSTR),
                ("UserName", wintypes.LPWSTR),
            ]

        advapi = ctypes.WinDLL("advapi32", use_last_error=True)  # type: ignore[attr-defined]
        pointer = ctypes.POINTER(Credential)
        advapi.CredWriteW.argtypes = [pointer, wintypes.DWORD]
        advapi.CredWriteW.restype = wintypes.BOOL
        advapi.CredReadW.argtypes = [
            wintypes.LPCWSTR,
            wintypes.DWORD,
            wintypes.DWORD,
            ctypes.POINTER(pointer),
        ]
        advapi.CredReadW.restype = wintypes.BOOL
        advapi.CredDeleteW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD]
        advapi.CredDeleteW.restype = wintypes.BOOL
        advapi.CredFree.argtypes = [ctypes.c_void_p]
        return ctypes, Credential, pointer, advapi

    def get(self) -> str | None:
        ctypes, _, pointer, advapi = self._api()
        found = pointer()
        if not advapi.CredReadW(self._target, self._GENERIC, 0, ctypes.byref(found)):
            if ctypes.get_last_error() == self._NOT_FOUND:  # type: ignore[attr-defined]
                return None
            raise KeystoreError("o Gerenciador de Credenciais recusou a leitura")
        try:
            blob = ctypes.string_at(
                found.contents.CredentialBlob, found.contents.CredentialBlobSize
            )
        finally:
            advapi.CredFree(ctypes.cast(found, ctypes.c_void_p))
        return _unpack(blob.decode("ascii"))

    def set(self, secret: str) -> None:
        ctypes, credential, _, advapi = self._api()
        blob = _pack(secret).encode("ascii")
        buffer = (ctypes.c_ubyte * len(blob)).from_buffer_copy(blob)
        item = credential()
        item.Type = self._GENERIC
        item.TargetName = self._target
        item.UserName = ACCOUNT
        item.Comment = "Chaves do aparelho do cofre do cérebro (plugin cerebro)"
        item.CredentialBlobSize = len(blob)
        item.CredentialBlob = ctypes.cast(buffer, ctypes.POINTER(ctypes.c_ubyte))
        item.Persist = self._PERSIST_LOCAL
        ok = advapi.CredWriteW(ctypes.byref(item), 0)
        ctypes.memset(buffer, 0, len(blob))
        if not ok:
            raise KeystoreError("o Gerenciador de Credenciais recusou guardar as chaves")

    def delete(self) -> None:
        _, _, _, advapi = self._api()
        advapi.CredDeleteW(self._target, self._GENERIC, 0)


class FileKeystore:
    """Linux: arquivo 0600 na pasta de dados do plugin. Protege só contra outros usuários."""

    name = "arquivo local (0600)"
    warning = (
        "sem cofre do sistema: as chaves do aparelho ficam num arquivo 0600 na pasta de dados "
        "do plugin; qualquer programa seu consegue lê-lo"
    )

    def __init__(self, folder: Path | None = None) -> None:
        self.path = (folder or C.data_dir()) / C.KEY_FILE

    def get(self) -> str | None:
        try:
            return _unpack(self.path.read_text(encoding="ascii"))
        except (OSError, ValueError):
            return None

    def set(self, secret: str) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="ascii") as fh:
            fh.write(_pack(secret))
        os.chmod(self.path, 0o600)

    def delete(self) -> None:
        self.path.unlink(missing_ok=True)


def default_keystore() -> Keystore:
    if sys.platform == "darwin":
        return MacKeychain()
    if os.name == "nt":
        return WindowsCredentials()
    return FileKeystore()
