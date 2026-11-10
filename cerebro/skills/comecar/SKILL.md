---
name: comecar
description: Carrega o cérebro do usuário para a tarefa atual. Use no início de toda conversa em que o load_context do cérebro ainda não foi chamado, e quando o usuário pedir para usar o cérebro.
argument-hint: "[assunto]"
---
Carregue o cérebro para esta conversa. Responda no idioma do cérebro (as regras dele dizem qual).

1. Se ainda não chamou nesta conversa: chame `load_context` do MCP `cerebro` (`mcp__plugin_cerebro_cerebro__load_context`).
   - Se o servidor pedir login, explique ao usuário: `/mcp` → `plugin:cerebro:cerebro` → Authenticate. O navegador abre o portal (login, código do autenticador, escolha do cérebro) e volta sozinho.
2. Siga as regras que vieram na carga: elas valem para a conversa inteira.
   - **Conexão de vários cérebros** (existe a ferramenta `mcp__plugin_cerebro_cerebro__list_brains`): diga em uma linha em qual cérebro está. Se o assunto for de outro, chame `mcp__plugin_cerebro_cerebro__use_brain` com o nome dele e depois `load_context` de novo. Grave sempre no cérebro do assunto; na dúvida, pergunte ao usuário.
3. Assunto: $ARGUMENTS
   - Com assunto: `search` com as palavras dele, e `read_note` só no Resumo das 1 a 3 notas mais próximas. Desça para uma seção ou para a nota inteira só se o Resumo não bastar.
   - Sem assunto: não procure nada ainda.
4. Diga em até 3 linhas o que encontrou e por onde vai seguir.
