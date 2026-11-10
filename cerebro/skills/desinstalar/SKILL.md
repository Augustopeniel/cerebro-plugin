---
name: desinstalar
description: Desfaz o que o /cerebro:instalar fez neste Claude — tira o bloco do CLAUDE.md global e, com ok, devolve as configurações.
disable-model-invocation: true
---
Desfaça a preparação do cérebro neste Claude, com o ok do usuário.

1. Rode `cerebro-plugin diagnostico "${CLAUDE_PLUGIN_DATA}"` e mostre o estado atual.
2. Proponha:
   - tirar o bloco do cérebro do CLAUDE.md global;
   - e, se o usuário quiser, voltar as configurações: religar a memória automática e tirar as permissões `mcp__plugin_cerebro_cerebro__*` do `settings.json`.
3. Aplique o que foi aprovado:
   - o bloco: `cerebro-plugin desinstalar-bloco "${CLAUDE_PLUGIN_DATA}"`, que faz backup antes;
   - o `settings.json`: rode `cerebro-plugin backup "${CLAUDE_PLUGIN_DATA}"` e edite preservando o resto. Os backups do `/cerebro:instalar` estão em `${CLAUDE_PLUGIN_DATA}/backup/`, se o usuário preferir voltar uma cópia inteira.
4. Diga o que foi desfeito e onde ficou o backup. Para tirar o plugin de vez: `claude plugin uninstall cerebro`.
