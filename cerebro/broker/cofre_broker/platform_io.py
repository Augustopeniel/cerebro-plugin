"""O que muda entre macOS e Windows: popups nativos, digitar, área de transferência.

Regra de segurança: valor sensível (senha do cofre, valor de credencial) chega ao sistema pelo
**stdin** do subprocesso ou por chamada direta da API (`SendInput`), nunca por argv (aparece no
`ps`) e, no que dura mais que um instante, nem por variável de ambiente (o `ps eww` do mesmo
usuário mostra o ambiente). Título e mensagem dos popups, que não são segredo, vão por ambiente.
Todo subprocesso com texto usa `encoding="utf-8"` explícito (o padrão do Windows é cp1252).

- macOS: `osascript` (diálogos; digitar com o System Events, em JavaScript lendo o stdin) e
  `pbcopy`/`pbpaste` com `LANG` UTF-8.
- Windows: PowerShell para os diálogos e a área de transferência (texto em base64 pelo stdin),
  `SendInput` com `KEYEVENTF_UNICODE` via `ctypes` para digitar — nunca `SendKeys`, que tem
  linguagem própria (`{~}` vira ENTER) e erra a senha sem ninguém perceber.
"""

from __future__ import annotations

import base64
import hashlib
import os
import shutil
import subprocess
import sys
import threading
import time
import unicodedata
import webbrowser

from . import config as C

IS_MAC = sys.platform == "darwin"
IS_WINDOWS = os.name == "nt"
IS_LINUX = sys.platform.startswith("linux")
POPUP_TIMEOUT_S = 300

# o foco não pode estar num terminal ou no próprio Claude: o valor iria parar na conversa
TYPING_DENYLIST = frozenset(
    {
        "terminal",
        "iterm2",
        "iterm",
        "warp",
        "ghostty",
        "kitty",
        "alacritty",
        "wezterm",
        "wezterm-gui",
        "hyper",
        "tabby",
        "claude",
        "code",
        "code - insiders",
        "cursor",
        "windsurf",
        "windowsterminal",
        "cmd",
        "powershell",
        "pwsh",
        "conhost",
        "mintty",
        "electron",
    }
)


class PlatformError(Exception):
    """O sistema não fez o que pedimos (popup, digitar, copiar)."""


def platform_name() -> str:
    if IS_MAC:
        return "macOS"
    return "Windows" if IS_WINDOWS else ("Linux" if IS_LINUX else sys.platform)


def _unsupported(what: str) -> PlatformError:
    hint = (" (instale o zenity ou o kdialog, e o xclip/wl-clipboard e o xdotool/wtype)"
            if IS_LINUX else "")  # fmt: skip
    return PlatformError(f"{what} não suportado neste sistema ({platform_name()}){hint}")


def _run(
    args: list[str],
    *,
    stdin: str = "",
    extra_env: dict[str, str] | None = None,
    timeout: float = POPUP_TIMEOUT_S,
) -> subprocess.CompletedProcess | None:
    env = dict(os.environ) | (extra_env or {})
    try:
        return subprocess.run(  # noqa: S603 (programas fixos do sistema, sem shell)
            args,
            input=stdin,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            env=env,
            timeout=timeout,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        C.log(f"{args[0]} falhou:", type(exc).__name__)
        return None


# ---------------------------------------------------------------- macOS -----

# O texto do diálogo chega pelo ambiente (nunca por argv) e é lido por `do shell script`:
# `system attribute` decodifica como MacRoman e estraga os acentos ("c√©rebro").
_OSA_PROMPT = (
    "activate\n"
    'set t to (do shell script "printf %s \\"$COFRE_DLG_TITLE\\"" without altering line endings)\n'
    'set m to (do shell script "printf %s \\"$COFRE_DLG_MSG\\"" without altering line endings)\n'
    'set r to display dialog m with title t default answer "" '
    'with hidden answer buttons {"Cancelar", "OK"} '
    'default button "OK" cancel button "Cancelar"\n'
    "return text returned of r\n"
)
_OSA_CONFIRM = (
    "activate\n"
    'set t to (do shell script "printf %s \\"$COFRE_DLG_TITLE\\"" without altering line endings)\n'
    'set m to (do shell script "printf %s \\"$COFRE_DLG_MSG\\"" without altering line endings)\n'
    'display dialog m with title t buttons {"Cancelar", "OK"} '
    'default button "OK" cancel button "Cancelar"\n'
    'return "OK"\n'
)
_OSA_INFO = (
    "activate\n"
    'set t to (do shell script "printf %s \\"$COFRE_DLG_TITLE\\"" without altering line endings)\n'
    'set m to (do shell script "printf %s \\"$COFRE_DLG_MSG\\"" without altering line endings)\n'
    'display dialog m with title t buttons {"OK"} default button "OK" giving up after 600\n'
)
# JavaScript (JXA) porque lê o valor do stdin: nada de argv nem de ambiente. A pausa deixa o foco
# voltar ao campo depois do diálogo; quem está na frente é conferido antes de digitar.
_JXA_KEYSTROKE = """
ObjC.import("Foundation");
var data = $.NSFileHandle.fileHandleWithStandardInput.readDataToEndOfFile;
var text = $.NSString.alloc.initWithDataEncoding(data, $.NSUTF8StringEncoding).js;
delay(0.4);
var events = Application("System Events");
var front = events.processes.whose({frontmost: true})[0].name();
var deny = $.NSProcessInfo.processInfo.environment.objectForKey("COFRE_DENY").js.split(",");
if (deny.indexOf(front.toLowerCase()) >= 0) { "BLOCKED:" + front; }
else { events.keystroke(text); "OK"; }
"""
# o app na frente, sem pedir permissão de Acessibilidade (o popup do código mostra qual é)
_JXA_FRONTMOST = (
    'ObjC.import("AppKit"); $.NSWorkspace.sharedWorkspace.frontmostApplication.localizedName.js'
)
_UTF8 = {"LANG": "en_US.UTF-8", "LC_ALL": "en_US.UTF-8"}


def _osascript(script: str, extra_env: dict[str, str], stdin: str = "") -> str | None:
    r = _run(["osascript", "-e", script], stdin=stdin, extra_env=extra_env)
    if r is None or r.returncode != 0:
        return None  # cancelou ou deu erro
    return r.stdout.rstrip("\n")


def _osascript_js(script: str, extra_env: dict[str, str], stdin: str = "") -> str | None:
    r = _run(["osascript", "-l", "JavaScript", "-e", script], stdin=stdin, extra_env=extra_env)
    if r is None or r.returncode != 0:
        return None
    return r.stdout.rstrip("\n")


# -------------------------------------------------------------- Windows -----

_PS_UTF8 = "[Console]::OutputEncoding = [System.Text.Encoding]::UTF8; "
_PS_PROMPT = _PS_UTF8 + (
    "$c = Get-Credential -UserName cofre -Message $env:COFRE_DLG_MSG; "
    "if ($c -eq $null) { exit 1 }; "
    "[Console]::Out.Write($c.GetNetworkCredential().Password)"
)
_PS_CONFIRM = (
    "Add-Type -AssemblyName System.Windows.Forms; "
    "$r = [System.Windows.Forms.MessageBox]::Show($env:COFRE_DLG_MSG, "
    "$env:COFRE_DLG_TITLE, 'OKCancel', 'Question'); "
    "if ($r -eq 'OK') { 'OK' } else { exit 1 }"
)
_PS_INFO = (
    "Add-Type -AssemblyName System.Windows.Forms; "
    "[void][System.Windows.Forms.MessageBox]::Show($env:COFRE_DLG_MSG, $env:COFRE_DLG_TITLE)"
)
# texto em base64 pelo stdin: imune à página de código do console
_PS_COPY = (
    "$b = [Convert]::FromBase64String([Console]::In.ReadToEnd().Trim()); "
    "Set-Clipboard -Value ([System.Text.Encoding]::UTF8.GetString($b))"
)
_PS_PASTE = (
    "$t = Get-Clipboard -Raw; if ($t -ne $null) { "
    "[Console]::Out.Write([Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($t))) }"
)
_PS_CLEAR = "Set-Clipboard -Value ' '"


def _powershell(
    script: str, extra_env: dict[str, str] | None = None, stdin: str = ""
) -> str | None:
    args = ["powershell", "-NoProfile", "-NonInteractive", "-Command", script]
    r = _run(args, stdin=stdin, extra_env=extra_env)
    if r is None or r.returncode != 0:
        return None
    return r.stdout.rstrip("\r\n")


def _win_frontmost() -> str:
    import ctypes
    from ctypes import wintypes

    user32 = ctypes.WinDLL("user32", use_last_error=True)  # type: ignore[attr-defined]
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)  # type: ignore[attr-defined]
    # tipos explícitos: o padrão (int de 32 bits) truncaria HANDLE e HWND no Windows de 64 bits
    user32.GetForegroundWindow.restype = wintypes.HWND
    user32.GetWindowThreadProcessId.argtypes = [wintypes.HWND, ctypes.POINTER(wintypes.DWORD)]
    kernel32.OpenProcess.restype = wintypes.HANDLE
    kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    kernel32.QueryFullProcessImageNameW.argtypes = [
        wintypes.HANDLE,
        wintypes.DWORD,
        wintypes.LPWSTR,
        ctypes.POINTER(wintypes.DWORD),
    ]
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    hwnd = user32.GetForegroundWindow()
    pid = wintypes.DWORD()
    user32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
    handle = kernel32.OpenProcess(0x1000, False, pid.value)  # QUERY_LIMITED_INFORMATION
    if not handle:
        return ""
    try:
        size = wintypes.DWORD(1024)
        buffer = ctypes.create_unicode_buffer(size.value)
        if not kernel32.QueryFullProcessImageNameW(handle, 0, buffer, ctypes.byref(size)):
            return ""
        return os.path.basename(buffer.value).removesuffix(".exe").removesuffix(".EXE")
    finally:
        kernel32.CloseHandle(handle)


def _win_type(text: str, deny: frozenset[str] = TYPING_DENYLIST) -> None:
    import ctypes
    from ctypes import wintypes

    ulong_ptr = ctypes.c_size_t

    class KeyboardInput(ctypes.Structure):
        _fields_ = [
            ("wVk", wintypes.WORD),
            ("wScan", wintypes.WORD),
            ("dwFlags", wintypes.DWORD),
            ("time", wintypes.DWORD),
            ("dwExtraInfo", ulong_ptr),
        ]

    class MouseInput(ctypes.Structure):
        _fields_ = [
            ("dx", wintypes.LONG),
            ("dy", wintypes.LONG),
            ("mouseData", wintypes.DWORD),
            ("dwFlags", wintypes.DWORD),
            ("time", wintypes.DWORD),
            ("dwExtraInfo", ulong_ptr),
        ]

    class InputUnion(ctypes.Union):
        _fields_ = [("ki", KeyboardInput), ("mi", MouseInput)]

    class Input(ctypes.Structure):
        _fields_ = [("type", wintypes.DWORD), ("u", InputUnion)]

    unicode_flag, keyup_flag, keyboard = 0x0004, 0x0002, 1
    units = text.encode("utf-16-le")  # acento e emoji: par surrogate vira dois eventos
    codes = [int.from_bytes(units[i : i + 2], "little") for i in range(0, len(units), 2)]
    events = (Input * (len(codes) * 2))()
    for i, code in enumerate(codes):
        for j, flags in enumerate((unicode_flag, unicode_flag | keyup_flag)):
            event = events[i * 2 + j]
            event.type = keyboard
            event.u.ki.wScan = code
            event.u.ki.dwFlags = flags
    time.sleep(0.4)  # o foco volta ao campo depois do diálogo
    user32 = ctypes.WinDLL("user32", use_last_error=True)  # type: ignore[attr-defined]
    user32.SendInput.argtypes = [wintypes.UINT, ctypes.POINTER(Input), ctypes.c_int]
    user32.SendInput.restype = wintypes.UINT
    # o foco é conferido aqui, logo antes de mandar as teclas (depois da pausa, não antes dela)
    front = _win_frontmost().lower()
    if not front or front in deny:
        ctypes.memset(events, 0, ctypes.sizeof(events))
        raise PlatformError(
            f"o foco está em {front or 'um app não identificado'!r}: clique no campo de destino "
            "e repita"
        )
    sent = user32.SendInput(len(events), events, ctypes.sizeof(Input))
    ctypes.memset(events, 0, ctypes.sizeof(events))
    if sent != len(events):
        raise PlatformError("o Windows não entregou todas as teclas (campo em foco bloqueou?)")


# ------------------------------------------------------- interface comum ----


def _dialog_env(title: str, message: str) -> dict[str, str]:
    # NFC: caminhos do macOS vêm com acento decomposto ("Financ¸as" no diálogo)
    return {
        "COFRE_DLG_TITLE": unicodedata.normalize("NFC", title),
        "COFRE_DLG_MSG": unicodedata.normalize("NFC", message),
    }


# ---------------------------------------------------------------- Linux -----
# zenity (GNOME e a maioria) ou kdialog (KDE): o texto vai por argumento, o segredo volta pelo
# stdout do diálogo (nunca por argumento de outro programa)


def _linux_dialog() -> str | None:
    return next((t for t in ("zenity", "kdialog") if shutil.which(t)), None)


def _linux(kind: str, title: str, message: str) -> tuple[bool, str]:
    tool = _linux_dialog()
    if tool is None:
        raise _unsupported("popup")
    if tool == "zenity":
        flags = {
            "senha": ["--entry", "--hide-text", f"--text={message}"],
            "ok": ["--question", f"--text={message}"],
            "aviso": ["--info", f"--text={message}"],
        }[kind]
        args = ["zenity", *flags, f"--title={title}"]
    else:
        flags = {"senha": ["--password", message], "ok": ["--yesno", message],
                 "aviso": ["--msgbox", message]}[kind]  # fmt: skip
        args = ["kdialog", "--title", title, *flags]
    r = _run(args, timeout=POPUP_TIMEOUT_S)
    if r is None:
        return False, ""
    return r.returncode == 0, r.stdout.rstrip("\n")


def prompt_secret(title: str, message: str) -> str | None:
    """Diálogo nativo com campo mascarado. Devolve o texto ou None (cancelou)."""
    if IS_MAC:
        return _osascript(_OSA_PROMPT, _dialog_env(title, message))
    if IS_WINDOWS:
        return _powershell(_PS_PROMPT, _dialog_env(title, message))
    if IS_LINUX:
        ok, out = _linux("senha", title, message)
        return out if ok and out else None
    raise _unsupported("popup")


def confirm(title: str, message: str) -> bool:
    """OK/Cancelar nativo. True só no OK."""
    if IS_MAC:
        return _osascript(_OSA_CONFIRM, _dialog_env(title, message)) == "OK"
    if IS_WINDOWS:
        return _powershell(_PS_CONFIRM, _dialog_env(title, message)) == "OK"
    if IS_LINUX:
        return _linux("ok", title, message)[0]
    raise _unsupported("popup")


def show_info(title: str, message: str) -> None:
    """Aviso nativo que não prende quem chamou (o código do pareamento, por exemplo)."""
    if IS_MAC:
        job = (_osascript, (_OSA_INFO, _dialog_env(title, message)))
    elif IS_WINDOWS:
        job = (_powershell, (_PS_INFO, _dialog_env(title, message)))
    elif IS_LINUX and _linux_dialog():
        job = (_linux, ("aviso", title, message))
    else:
        C.log(f"{title}: {message}")
        return
    threading.Thread(target=job[0], args=job[1], daemon=True).start()


def open_url(url: str) -> bool:
    if not url.startswith(("https://", "http://localhost", "http://127.0.0.1")):
        return False
    try:
        return webbrowser.open(url)
    except webbrowser.Error:
        return False


def frontmost_app() -> str:
    """Nome do app em foco agora ("" se não der para saber)."""
    if IS_WINDOWS:
        return _win_frontmost()
    if IS_MAC:
        r = _run(["osascript", "-l", "JavaScript", "-e", _JXA_FRONTMOST], timeout=10)
        return r.stdout.strip() if r is not None and r.returncode == 0 else ""
    return ""


def type_text(secret: str) -> None:
    """Digita no campo em foco. Recusa se o foco estiver num terminal ou no Claude.
    macOS: exige a permissão de Acessibilidade para o app que roda o broker."""
    deny = ",".join(sorted(TYPING_DENYLIST))
    if IS_MAC:
        r = _osascript_js(_JXA_KEYSTROKE, {"COFRE_DENY": deny}, stdin=secret)
        if r is None:
            raise PlatformError(
                "não consegui digitar: confira a permissão de Acessibilidade do app que roda o "
                "broker (Ajustes → Privacidade e Segurança → Acessibilidade) ou use 'copy'"
            )
        if r.startswith("BLOCKED:"):
            raise PlatformError(f"o foco está em {r[8:]!r}: clique no campo de destino e repita")
        return
    if IS_WINDOWS:
        _win_type(secret)  # confere o foco logo antes do SendInput
        return
    if IS_LINUX:  # o texto vai pelo stdin (nunca por argumento, que o `ps` mostraria)
        if os.environ.get("WAYLAND_DISPLAY") and shutil.which("wtype"):
            r = _run(["wtype", "-"], stdin=secret, timeout=30)
        elif shutil.which("xdotool"):
            r = _run(["xdotool", "type", "--clearmodifiers", "--file", "-"], stdin=secret,
                     timeout=30)  # fmt: skip
        else:
            raise _unsupported("digitar")
        if r is None or r.returncode != 0:
            raise PlatformError("não consegui digitar; use 'copy'")
        return
    raise _unsupported("digitar")


def _digest(text: str) -> str:
    return hashlib.sha256(text.rstrip("\r\n").encode("utf-8")).hexdigest()


def _paste() -> str | None:
    if IS_MAC:
        r = _run(["pbpaste"], extra_env=_UTF8, timeout=10)
        return r.stdout if r and r.returncode == 0 else None
    if IS_WINDOWS:
        out = _powershell(_PS_PASTE)
        return base64.b64decode(out).decode("utf-8", "replace") if out else None
    if IS_LINUX and (cmd := _linux_clip(copy=False)):
        r = _run(cmd, timeout=10)
        return r.stdout if r and r.returncode == 0 else None
    return None


def _linux_clip(*, copy: bool) -> list[str] | None:
    """Comando da área de transferência no Linux (Wayland ou X11): copiar, ou ler para conferir
    antes de limpar."""
    if os.environ.get("WAYLAND_DISPLAY") and shutil.which("wl-copy"):
        return ["wl-copy"] if copy else ["wl-paste", "--no-newline"]
    if shutil.which("xclip"):
        return ["xclip", "-selection", "clipboard"] + ([] if copy else ["-o"])
    return None


def _clear_if(expected: str) -> None:
    """Limpa só se a área de transferência ainda tiver o que copiamos (compara o hash)."""
    current = _paste()
    if current is None or _digest(current) != expected:
        return
    if IS_MAC:
        _run(["pbcopy"], stdin="", extra_env=_UTF8, timeout=10)
    elif IS_WINDOWS:
        _powershell(_PS_CLEAR)
    elif IS_LINUX and (cmd := _linux_clip(copy=True)):
        _run(cmd, stdin="", timeout=10)


def copy_clipboard(secret: str, ttl: int) -> None:
    """Copia e agenda a limpeza depois de `ttl` s, neste processo (o valor não vai para outro
    processo nem fica no ambiente de ninguém). Se a pessoa copiar outra coisa antes, não mexe."""
    if IS_MAC:
        r = _run(["pbcopy"], stdin=secret, extra_env=_UTF8, timeout=10)
        ok = r is not None and r.returncode == 0
    elif IS_WINDOWS:
        packed = base64.b64encode(secret.encode("utf-8")).decode()
        ok = _powershell(_PS_COPY, stdin=packed) is not None
    elif IS_LINUX and (cmd := _linux_clip(copy=True)):
        r = _run(cmd, stdin=secret, timeout=10)
        ok = r is not None and r.returncode == 0
    else:
        raise _unsupported("área de transferência")
    if not ok:
        raise PlatformError("não consegui copiar para a área de transferência")
    timer = threading.Timer(ttl, _clear_if, args=(_digest(secret),))
    timer.daemon = False  # ao sair, o processo espera a limpeza (no máximo `ttl` segundos)
    timer.start()


def paste_shortcut() -> str:
    return "Cmd+V" if IS_MAC else "Ctrl+V"
