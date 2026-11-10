---
name: reprocessar
description: Faxina do cérebro (retenção, arquivo, saúde, memória, índices) — simula, mostra e aplica só com ok.
disable-model-invocation: true
---
Faça a faxina do cérebro, em passos, sempre simulando antes e aplicando só com o ok do usuário.

1. Leia o procedimento com `read_note('_reprocessamento')`.
2. Junte o que dá para ver pelo MCP:
   - `recent_changes` (o que mudou desde a última faxina);
   - `read_index` (sub-índices, procurando notas sem "quando ler");
   - a caixa de entrada com `read_note('memoria/MEMORY.md')`;
   - os avisos da página Saúde do portal (peça ao usuário, se precisar).
3. Monte um relatório de até 25 linhas: notas para arquivar, índices para corrigir, memórias para consolidar e notas acima do teto.
4. Com o ok, aplique: `archive_note` (com motivo, nada se apaga), `update_section` e `update_fields`.
5. Registre a rodada em "Histórico de execuções" com `append_dated`.
- Os scripts (`reprocessar.py`) não rodam no servidor ainda: o que exigir script fica listado como pendente.
