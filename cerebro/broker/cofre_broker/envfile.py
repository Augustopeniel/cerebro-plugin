"""Leitura de um `.env` local e a escolha de quais variáveis são segredo (para o `import_env`).

Os valores vivem só na memória do broker: nada daqui volta ao Claude.
"""

from __future__ import annotations

import re
from pathlib import Path

# nome de variável que indica segredo; URL, flags e tempos ficam no .env
_SECRET_NAME = re.compile(r"(key|token|pass|password|passwd|secret|credential)", re.IGNORECASE)
_VAR = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
MAX_BYTES = 64 * 1024


def is_secret_name(name: str) -> bool:
    return bool(_SECRET_NAME.search(name))


def is_env_name(name: str) -> bool:
    return bool(_VAR.fullmatch(name))


def parse_env_file(path: Path) -> dict[str, str]:
    """{VAR: valor} de um .env simples (KEY=VALUE, aspas opcionais, `#` comentário, `export`)."""
    path = path.expanduser().resolve()
    if not path.is_file():
        raise ValueError(f"arquivo não encontrado: {path}")
    if path.stat().st_size > MAX_BYTES:
        raise ValueError("arquivo grande demais para ser um .env (mais de 64 KB)")
    found: dict[str, str] = {}
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        if line.startswith("export "):
            line = line[7:].lstrip()
        name, value = (part.strip() for part in line.split("=", 1))
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
        if is_env_name(name):
            found[name] = value
    return found
