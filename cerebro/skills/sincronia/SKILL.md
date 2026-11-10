---
name: sincronia
description: Confere e aplica a fila de sincronia desta máquina (o "temporário do cérebro"): mudanças de configuração feitas numa máquina que a outra precisa repetir.
disable-model-invocation: true
---
Identifique esta máquina (macOS = mac, Windows = windows). Fale com o usuário no idioma dele. Nada é aplicado sem o ok dele.

1. **Ler a fila:** `read_note('_index')` (seção "Sincronia pendente"), depois `read_note('<item>')` de cada item com destino nesta máquina.
2. Para cada item `pendente` desta máquina: mostre o plano de aplicação e peça o ok. Aplique um passo por vez, seguindo "Ao aplicar" de `_sincronia` (backup antes de editar configuração, conferência no fim).
3. **Fechar cada item:**
   - `update_fields(item, {'status': 'aplicado', 'aplicado_em': '<hoje>'})`;
   - `append_dated(item, 'Aplicação', '<máquina>: <resultado da conferência>')`;
   - `update_section` na Fila de `_sincronia` e na linha do `_index`.
4. Sem pendências: diga em 1 linha.
