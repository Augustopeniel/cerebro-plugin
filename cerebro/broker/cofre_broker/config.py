"""Configuração do broker: caminhos, variáveis de ambiente e o JSON não secreto do aparelho.

Nada daqui é segredo. As chaves privadas do aparelho moram no cofre do sistema (`keystore.py`);
aqui ficam só o endereço do servidor, a id do aparelho e a chave pública do servidor.

Variáveis reconhecidas:
  CEREBRO_URL          servidor do cofre (padrão https://cerebro.ogidoc.com)
  CLAUDE_PLUGIN_DATA   pasta de dados do plugin (padrão ~/.claude/plugins/data/cerebro-cerebro-vivo)
  COFRE_SOCKET         socket local dos MCPs (padrão ~/.claude/cofre/broker.sock, o do antigo)
  COFRE_BROKER_KEY     chave do canal local (padrão ~/.claude/cofre/broker.key, a do antigo)
  COFRE_CANAL          mp = força o canal multiprocessing (named pipe no Windows; testes)
  COFRE_CLIP_TTL       segundos até limpar a área de transferência (padrão 15)
"""

from __future__ import annotations

import contextlib
import json
import os
import sys
from dataclasses import asdict, dataclass
from pathlib import Path

NAME = "cerebro-cofre"
VERSION = "2.3.1"
PROTOCOL_FALLBACK = "2025-06-18"
DEFAULT_URL = "https://cerebro.ogidoc.com"
CONFIG_FILE = "cofre.json"
KEY_FILE = "cofre-device-keys"  # só no Linux (sem cofre do sistema); o hook do Bash barra
OLD_DIR = Path.home() / ".claude" / "cofre"  # a do broker antigo: socket e chave do canal


def log(*parts: object) -> None:
    sys.stderr.write("[cerebro-cofre] " + " ".join(str(p) for p in parts) + "\n")
    with contextlib.suppress(OSError, ValueError):
        sys.stderr.flush()


def env(name: str, default: str | None = None) -> str | None:
    value = os.environ.get(name)
    return value.strip() if value and value.strip() else default


def _path(text: str) -> Path:
    return Path(os.path.expandvars(os.path.expanduser(text)))


def server_url() -> str:
    return (env("CEREBRO_URL") or DEFAULT_URL).rstrip("/")


def data_dir() -> Path:
    default = Path.home() / ".claude" / "plugins" / "data" / "cerebro-cerebro-vivo"
    found = env("CLAUDE_PLUGIN_DATA")
    return _path(found) if found else default


def socket_path() -> Path:
    found = env("COFRE_SOCKET")
    return _path(found) if found else OLD_DIR / "broker.sock"


def channel_key_path() -> Path:
    found = env("COFRE_BROKER_KEY")
    return _path(found) if found else OLD_DIR / "broker.key"


def clip_ttl() -> int:
    try:
        return max(5, int(env("COFRE_CLIP_TTL") or 15))
    except ValueError:
        return 15


@dataclass
class DeviceConfig:
    """O que o broker lembra do aparelho entre uma sessão e outra (nada secreto)."""

    server_url: str = ""
    device_id: str = ""
    server_key: str = ""  # base64 da chave pública do servidor
    device_name: str = ""

    @property
    def paired(self) -> bool:
        return bool(self.device_id and self.server_key)


def load_config(folder: Path | None = None) -> DeviceConfig:
    path = (folder or data_dir()) / CONFIG_FILE
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return DeviceConfig()
    known = DeviceConfig.__dataclass_fields__
    return DeviceConfig(**{k: str(v) for k, v in data.items() if k in known})


def save_config(config: DeviceConfig, folder: Path | None = None) -> Path:
    folder = folder or data_dir()
    folder.mkdir(parents=True, exist_ok=True)
    path = folder / CONFIG_FILE
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(asdict(config), indent=2) + "\n", encoding="utf-8")
    os.replace(tmp, path)
    return path
