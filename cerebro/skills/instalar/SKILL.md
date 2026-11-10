---
name: instalar
description: Revisa a preparação deste Claude para o cérebro — o início de sessão já aplica sozinho, com backup, o bloco do CLAUDE.md, as leituras liberadas e a atualização automática; aqui fica o inventário do que pode competir com o cérebro (importar, conviver ou desligar) e a memória automática, com o ok do usuário. Rodar de novo atualiza o bloco.
disable-model-invocation: true
---
Prepare este Claude para usar o cérebro. Fale com o usuário no idioma dele. O início de sessão do plugin já aplicou sozinho, com backup em `${CLAUDE_PLUGIN_DATA}/backup`, o que é seguro e reversível: os itens a), c) e d) do passo 3. **O resto não muda sem o ok do usuário, item por item, e nada é apagado.** O plugin não depende de nada instalado antes (nem `uv`, nem Python, nem shell): o lançador `cerebro-plugin` é nativo e o cofre baixa sozinho o que usa.

1. **Diagnóstico.** Rode `cerebro-plugin diagnostico` e chame `load_context` do MCP `cerebro`. Mostre o resultado em poucas linhas.
   - Se o servidor pedir login, explique: `/mcp` → `plugin:cerebro:cerebro` → Authenticate. O navegador abre o portal (login, código do autenticador, escolha do cérebro) e volta sozinho. Depois, rode `/cerebro:instalar` de novo e pare aqui.
2. **Inventário do que já existe.** Rode `cerebro-plugin inventario`. Ele lista só nomes, sem valores.
   - Nunca abra por inteiro o `~/.claude.json` nem arquivos `.env`: eles guardam tokens de outros servidores.
   - Some ao que o comando mostrou o `CLAUDE.md` do projeto atual, que já está no seu contexto.
   - Mostre ao usuário o que pode competir com o cérebro, por exemplo:
     - regras de memória ou imports (`@…`) no CLAUDE.md;
     - memória automática ligada, ou com arquivos;
     - servidores MCP e plugins de memória ou notas (Obsidian, Notion, mem0, "memory"…);
     - hooks que põem contexto no início da sessão;
     - comandos e skills de memória.
   - Para **cada** item parecido, ofereça três caminhos e peça a escolha:
     - **Importar para o cérebro:** você lê o conteúdo e grava no cérebro com as ferramentas de gravação, no formato dele (`create_note`, `record_decision`, `record_learning`…), em lotes, mostrando antes a lista do que vai virar o quê. O original fica intacto. Se for grande (um vault inteiro, um workspace do Notion), proponha um plano à parte em vez de importar agora.
     - **Conviver:** os dois ficam. O cérebro é a memória principal, e o outro vira fonte de consulta. Registre a escolha no cérebro com `record_decision` (o que é o outro sistema, para que continua servindo, quem prevalece em conflito). Assim o próximo Claude sabe.
     - **Desligar:** só o que for reversível (tirar do `enabledPlugins`, comentar ou tirar a linha do CLAUDE.md), com o backup do passo 4. Nunca apague arquivos de memória ou notas.
   - Nada parecido encontrado: diga em uma linha e siga.
3. **Mostre o estado de cada item.** a), c) e d) normalmente já estão aplicados (confira no `settings.json` e no diagnóstico): diga em uma linha. Peça o ok só do que faltar:
   a) **Bloco do cérebro no CLAUDE.md global.** Mostre o texto de `${CLAUDE_PLUGIN_ROOT}/bloco.md`. Ele entra entre os marcadores `<!-- cerebro:inicio … -->` e `<!-- cerebro:fim -->`; nada fora deles é tocado.
   b) **Memória automática do Claude Code desligada** (`"autoMemoryEnabled": false` no `settings.json` do usuário). Motivo: a memória passa a ser o cérebro, e duas memórias se contradizem. Se o usuário escolheu conviver com a memória automática no passo 2, não proponha este item.
   c) **Leituras do cérebro sem pedir permissão a cada vez.** Entram em `permissions.allow` do `settings.json` só estas ferramentas:
      `mcp__plugin_cerebro_cerebro__load_context`, `mcp__plugin_cerebro_cerebro__read_index`, `mcp__plugin_cerebro_cerebro__read_note`, `mcp__plugin_cerebro_cerebro__search`, `mcp__plugin_cerebro_cerebro__guia`, `mcp__plugin_cerebro_cerebro__session_status`, `mcp__plugin_cerebro_cerebro__note_history` e `mcp__plugin_cerebro_cerebro__recent_changes`.
   d) **Atualização automática do plugin.** Em `extraKnownMarketplaces` do `settings.json`, a entrada `cerebro-vivo` ganha `"autoUpdate": true`, ao lado de `source`. Se a entrada não existir, crie-a com `"source": {"source": "github", "repo": "Augustopeniel/cerebro-plugin"}`. Motivo: marketplace de terceiro vem sem atualização automática. Com ela, o Claude baixa a versão nova sozinho, alguns minutos depois da primeira mensagem, e a versão vale na sessão seguinte. Não é preciso vincular o aparelho nem entrar no portal de novo.
4. **Aplique só o que foi aprovado (passos 2 e 3):**
   - antes de mexer no `settings.json` ou no CLAUDE.md fora do bloco, rode `cerebro-plugin backup "${CLAUDE_PLUGIN_DATA}"` e guarde a pasta que ele imprime;
   - a) `cerebro-plugin instalar-bloco "${CLAUDE_PLUGIN_DATA}"`, que faz o próprio backup e troca só o bloco;
   - b), c), d) e o que for desligar: edite o `settings.json` do usuário (`~/.claude/settings.json`, ou o da pasta em `CLAUDE_CONFIG_DIR`). Preserve todo o resto, mantenha o JSON válido e não duplique entradas. O Claude Code pede a aprovação do usuário para editar esse arquivo: explique antes que o pedido vai aparecer;
   - importações e decisões de convivência: com as ferramentas do cérebro, como combinado no passo 2.
5. **Confira:** rode o diagnóstico de novo.
6. **Termine** com, por item:
   - o que foi aplicado, importado, mantido em convivência ou recusado;
   - onde ficou o backup.

   Avise que o efeito completo vale a partir da próxima sessão e que `/cerebro:desinstalar` desfaz o bloco e as configurações. Se gravou algo no cérebro (importações e decisões), chame `close_session` (resumo: "instalação do plugin") e termine com o texto do campo `fechamento`; se não gravou nada, termine com `CEREBRO: nada gravado` e `🟢 Ponto de parada seguro`.
