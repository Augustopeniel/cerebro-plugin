---
name: exportar
description: Exporta o cérebro inteiro em .zip — notas que abrem no Obsidian, histórico (diário e versões) e manifesto com o SHA-256 de cada arquivo. Use quando o usuário quiser uma cópia, levar o cérebro para outro lugar ou guardar um backup.
disable-model-invocation: true
---
Exportar tudo pede o código do app autenticador, por isso o download é feito pelo usuário no portal, e não por você. Explique:

- **Um cérebro:** https://cerebro.ogidoc.com/cerebros → no cartão do cérebro, **Exportar** → marcar ou não "Levar o histórico" → **Baixar o .zip** → código do autenticador.
- **Todos os cérebros e os dados da conta** (portabilidade): Configurações → Conta → **Exportar todos os meus dados**.

Depois do download, explique em até 4 linhas o que vem no arquivo:
- `notas/` abre como vault no Obsidian;
- `historico/` tem o diário e as versões;
- `MANIFESTO.json` confere cada arquivo pelo SHA-256;
- `LEIA-ME.md` explica o resto.
