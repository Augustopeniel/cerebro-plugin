#!/bin/sh
# Compila o lançador para todos os sistemas (do Mac, com o Go). Compilação reprodutível: o mesmo
# código gera os mesmos bytes, e o git não cresce quando nada mudou.
set -eu
cd "$(dirname "$0")"
PLUGIN=..
# o MCP do cofre responde sozinho até o 1º uso (preguica.go): leva a versão e a lista de
# ferramentas do broker embutidas, geradas daqui (sem o broker ao lado, usa o arquivo como está;
# tests/plugin/test_script.py confere que ele bate com o broker)
if [ -d "$PLUGIN/broker" ]; then
  (cd "$PLUGIN/broker" && uv run --quiet --no-dev --frozen python -c 'import json
from cofre_broker import config, tools
print(json.dumps({"versao": config.VERSION, "tools": tools.SCHEMAS}, ensure_ascii=False, indent=1))') \
    > ferramentas_cofre.json.tmp
  mv ferramentas_cofre.json.tmp ferramentas_cofre.json
fi
mkdir -p "$PLUGIN/nativo"
for alvo in darwin/arm64 darwin/amd64 linux/amd64 linux/arm64 windows/amd64; do
  so=${alvo%/*}; arq=${alvo#*/}
  if [ "$so" = windows ]; then saida="$PLUGIN/bin/cerebro-plugin.exe"
  else saida="$PLUGIN/nativo/cerebro-plugin-$so-$arq"; fi
  CGO_ENABLED=0 GOOS=$so GOARCH=$arq go build -trimpath -buildvcs=false \
    -ldflags "-s -w -buildid=" -o "$saida" .
  echo "$saida"
done
