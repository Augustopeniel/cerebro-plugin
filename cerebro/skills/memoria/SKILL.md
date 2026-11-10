---
name: memoria
description: Fecha a etapa no cérebro — grava o que mudou (decisões, aprendizados, andamento, ideias do usuário), registra a sessão e termina com o relatório de fechamento e o sinal de parada segura. Use no fim de cada etapa de trabalho e antes de compactar.
---
Feche esta etapa no cérebro, só sobre o que esta etapa mudou (sem varrer o cérebro nem reler notas inteiras). Se o cérebro tiver um guia de memória (`read_note('memoria')`), siga a seção de fechamento dele.

1. Liste para você o que esta etapa produziu e ainda não foi gravado: decisões, aprendizados (o que custou tentativa), andamento de projeto, ideias e preferências do usuário.
2. Grave cada item com as ferramentas do MCP `cerebro`:
   - `record_decision`, `record_learning`, `append_dated`, `create_note`, `update_section`, `update_fields`, `link_notes`;
   - dúvida de formato: `guia('gravar')`;
   - recusa: a mensagem diz a regra e como acertar; corrija e grave de novo.
3. Confira com `session_status` o que já está salvo desde o último fechamento.
4. Nos repositórios que esta etapa mexeu: diga o que ficou sem commit (ofereça o commit; não faça sem o "sim" do usuário).
5. Chame `close_session(summary, next_steps)`.
6. Termine sua mensagem com o texto do campo `fechamento` da resposta, exatamente como veio (a linha `CEREBRO: …` e o `🟢 Ponto de parada seguro`). Se algo de valor não pôde ser gravado, diga o quê no lugar do 🟢.
