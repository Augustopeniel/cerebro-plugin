"""Máscara da saída: todo valor entregue vira `••••` antes de qualquer texto voltar ao Claude.

Além do valor cru, cobre as formas em que um comando costuma ecoá-lo: base64 (padrão e de URL,
com e sem `=`, e o do `echo $X | base64`, que leva a quebra de linha), o miolo do base64 quando o
valor vem no meio de outro texto (o `usuario:senha` do Basic), URL-encode (`%XX` e `+`) e o
escape de JSON. Não cobre transformações arbitrárias (inverter, hex, cifrar): um comando com
liberdade para isso pode revelar o valor, e por isso intérprete pede confirmação no `run`.
"""

from __future__ import annotations

import base64
import json
import re
import urllib.parse
from collections.abc import Iterable

MASK = "••••"
_CORE_MIN = 8  # miolo de base64 menor que isto mascararia texto qualquer


def _b64_forms(raw: bytes) -> set[bytes]:
    forms = set()
    for encode in (base64.b64encode, base64.urlsafe_b64encode):
        for data in (raw, raw + b"\n"):
            full = encode(data)
            forms |= {full, full.rstrip(b"=")}
        # o valor no meio de um texto maior: a parte do base64 que só depende dele, para cada
        # alinhamento possível (o início do valor cai em qualquer posição do grupo de 3 bytes)
        for pad in range(3):
            encoded = encode(b"\0" * pad + raw)
            core = encoded[-(-8 * pad // 6) : (8 * (pad + len(raw))) // 6]
            if len(core) >= _CORE_MIN:
                forms.add(core)
    return forms


def forms_of(value: bytes) -> set[bytes]:
    """As formas de `value` que a máscara procura."""
    if not value:
        return set()
    forms = {value} | _b64_forms(value)
    for quote in (
        lambda v: urllib.parse.quote(v, safe=""),
        urllib.parse.quote,
        lambda v: urllib.parse.quote_plus(v, safe=""),
    ):
        forms.add(quote(value).encode("ascii"))
    text = value.decode("utf-8", "replace")
    forms.add(json.dumps(text)[1:-1].encode("utf-8"))
    forms.add(json.dumps(text, ensure_ascii=False)[1:-1].encode("utf-8"))
    return {f for f in forms if f}


def mask_bytes(data: bytes, values: Iterable[bytes]) -> bytes:
    forms: set[bytes] = set()
    for value in values:
        forms |= forms_of(value)
    if not forms or not data:
        return data
    pattern = re.compile(b"|".join(re.escape(f) for f in sorted(forms, key=len, reverse=True)))
    return pattern.sub(MASK.encode("utf-8"), data)


def mask_text(text: str, values: Iterable[bytes]) -> str:
    return mask_bytes(text.encode("utf-8"), values).decode("utf-8", "replace")


def masked_output(data: bytes, values: Iterable[bytes], limit: int = 20_000) -> str:
    """Saída de um comando, mascarada antes de cortar (o corte nunca deixa meio valor à mostra)."""
    text = mask_bytes(data, list(values)).decode("utf-8", "replace")
    if len(text) > limit:
        return f"[… {len(text) - limit} caracteres cortados]\n" + text[-limit:]
    return text
