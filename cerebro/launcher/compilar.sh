#!/bin/sh
# Compila o lançador para todos os sistemas (do Mac, com o Go). Compilação reprodutível: o mesmo
# código gera os mesmos bytes, e o git não cresce quando nada mudou.
set -eu
cd "$(dirname "$0")"
PLUGIN=..
mkdir -p "$PLUGIN/nativo"
for alvo in darwin/arm64 darwin/amd64 linux/amd64 linux/arm64 windows/amd64; do
  so=${alvo%/*}; arq=${alvo#*/}
  if [ "$so" = windows ]; then saida="$PLUGIN/bin/cerebro-plugin.exe"
  else saida="$PLUGIN/nativo/cerebro-plugin-$so-$arq"; fi
  CGO_ENABLED=0 GOOS=$so GOARCH=$arq go build -trimpath -buildvcs=false \
    -ldflags "-s -w -buildid=" -o "$saida" .
  echo "$saida"
done
