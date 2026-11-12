---
name: help
description: Mostra a tabela com todos os comandos do cérebro (/cerebro:*), o que cada um faz e quando usar. Use quando o usuário pedir ajuda, a lista de comandos ou o que o cérebro sabe fazer.
---
Responda no idioma do usuário com esta tabela, exatamente nesta ordem, e nada mais além de uma linha final dizendo que `/cerebro:help` mostra a tabela de novo.

| Comando | O que faz | Quando usar |
|---|---|---|
| `/cerebro:comecar` | carrega o cérebro com o assunto da tarefa | no início de uma conversa, antes de trabalhar |
| `/cerebro:memoria` | fecha a etapa: grava o que falta e devolve o relatório de fechamento | ao terminar uma etapa e antes de compactar ou encerrar |
| `/cerebro:estado` | o que já foi gravado desde o último fechamento e se é seguro compactar | para conferir se dá para parar sem perder nada |
| `/cerebro:reprocessar` | faxina do cérebro: retenção, índices e saúde | de tempos em tempos, ou quando a Saúde do portal acusar problemas |
| `/cerebro:sincronia` | fila de sincronia desta máquina | ao abrir uma máquina que ficou para trás em configuração |
| `/cerebro:exportar` | exporta o cérebro inteiro em .zip (notas, histórico e manifesto) | para guardar uma cópia sua ou levar para o Obsidian |
| `/cerebro:instalar` | prepara este Claude para o cérebro (bloco no CLAUDE.md, com backup e ok) | na primeira vez num Claude, ou para revisar outras memórias |
| `/cerebro:desinstalar` | desfaz o que o instalar fez | para tirar o cérebro deste Claude |
| `/cerebro:cofre` | cofre de senhas só com popups: vincular, configurar, destravar; valor nunca na conversa | para vincular este aparelho, criar a senha do cofre ou cadastrar credenciais |
| `/cerebro:help` | esta tabela: todos os comandos do cérebro e o que cada um faz | quando quiser lembrar o que existe |
