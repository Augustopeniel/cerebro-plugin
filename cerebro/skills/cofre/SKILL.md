---
name: cofre
description: Cofre de senhas deste aparelho (MCP local `cofre` do plugin) — abrir a janela, vincular o aparelho, configurar a senha do cofre e usar credenciais sem que o valor passe pela conversa. Use quando o usuário falar de senha, credencial, chave de API, .env ou do cofre.
---
O cofre guarda as credenciais no servidor do cérebro, cifradas. O valor só sai pelo broker local (o MCP `cofre`, deste plugin) e vai direto ao destino: digitar num campo, copiar, o ambiente de um comando ou outro MCP local. **Você nunca vê um valor, e nunca deve vê-lo.**

## Regras que valem sempre
- **Nunca peça uma senha, chave ou valor na conversa**, nem para "testar". Para gravar, use `store` (o usuário digita num popup mascarado), `store` com `generate=true` ou a janela.
- Se o usuário colar um segredo na conversa, avise que ele ficou na transcrição, não o repita, e sugira trocá-lo e gravar o novo pelo popup.
- Nunca leia a área de transferência depois de um `copy`, nem o Keychain, o Gerenciador de Credenciais ou os arquivos do broker: o hook do Bash barra esses comandos, e contorná-lo é quebrar a regra.
- Nunca clique, digite ou responda por ele um popup do cofre (System Events, computer-use, `osascript`): quem confirma é o usuário, com o código do app autenticador. O hook barra o atalho.
- Para usar uma credencial num comando, use `run` (lista de argumentos, sem shell; o programa só pelo nome, achado no PATH, sem pasta); a saída volta com os valores trocados por `••••`. Não use `env`, `printenv`, `echo`, `ps eww`, `/proc/*/environ` nem intérpretes para "ver se chegou".
- Servidores: `ssh_list` mostra os do cofre (credenciais do tipo `ssh`); `ssh_run` e `ssh_run_script` rodam no servidor com a senha ou a chave entregues direto ao ssh (cada credencial precisa do destino `ambiente:ssh`). Host com regra `routeros-leitura` só aceita `/menu print` ou `/menu export` com palavras simples (`detail`, `terse`, `without-paging`…); nada de `[find]`, `:foreach`, `file=`. Servidor sem a chave do host fixada não recebe segredo: o erro traz a impressão vista; mostre-a ao usuário e peça que confira no servidor e grave no campo `impressao` da credencial.
- Credencial sem destino não vai a lugar nenhum. Destinos com alvo `*` (digitar, copiar, qualquer comando), a política `livre` e o escopo são do dono, no portal ou na janela: o `store` e o `import_env` só aceitam `ambiente:<comando>` e `mcp:<consumidor>` e as políticas `sempre` ou `sessao`.

## Confirmação pelo código do autenticador
- Quem exige a confirmação é o servidor, pela política da credencial (`sempre`: a cada uso; `sessao`: uma vez até trancar; `livre`: não pede). O broker abre um popup mascarado e o usuário digita o código de 6 dígitos do app autenticador. Você não vê nem pede o código.
- O popup mostra a credencial, a via e o alvo; no `run`, o caminho completo do programa e os argumentos; no `inject`, o app em foco; no `ssh_run`, o servidor e o comando. Peça ao usuário que confira antes de digitar.
- `inject` e `run` de intérprete, shell ou `.bat` pedem o código sempre, mesmo com `livre`.
- Cancelado ou código recusado: nada foi entregue. Não insista; pergunte ao usuário.

## Compartilhar e times
- Compartilhamentos e chaves de time para membros novos ficam pendentes até o dono aprovar: depois de cada destrave, um popup lista tudo e pede o código do autenticador (cancelar deixa pendente). `approvals` mostra o que espera, sem valores.
- O papel **usa** quer dizer que o aparelho da pessoa recebe o valor para usá-lo: o cofre protege o valor do Claude e de quem não tem acesso, não de quem recebeu. Lembre o usuário disso antes de compartilhar.

## Primeira vez neste aparelho
1. `status` do MCP `cofre`. Se o MCP `cofre` não estiver disponível, provavelmente falta o `uv`: peça para instalar (https://docs.astral.sh/uv/) e reiniciar o Claude.
2. **Vincular:** `pair` (ou a janela, aba Aparelho). O código e as impressões das chaves aparecem só na tela do usuário (você não recebe o código: não o peça). O navegador abre o portal; o usuário entra, confirma com o autenticador, confere se as impressões são as mesmas do portal e aprova. O `pair` espera a aprovação.
3. **Configurar:** abra a janela (`open_window`), aba Configurar. O usuário cria a senha do cofre (duas vezes, mínimo 12 caracteres). O kit de recuperação aparece uma vez: ele guarda longe do Claude e marca "guardei o kit". Você não pede nem vê o kit.
4. **Destravar:** `unlock` (popup) ou a janela. Tranca sozinho depois de 2 h sem uso; `lock` tranca na hora.

## Uso
- `list_entries` e `events` mostram só metadados.
- `inject` digita no campo em foco (o usuário põe o cursor no campo e digita o código no popup); `copy` copia por alguns segundos.
- `import_env` lê um `.env` e grava cada variável secreta; depois o usuário esvazia o `.env`.
- `update` troca o valor (popup ou gerado); `archive`, `restore` e `move` organizam. Nada se apaga.
- Os MCPs antigos que usam `cofre_client`/`cofre_run` continuam funcionando: o broker atende o mesmo socket, com a via `mcp` e o alvo igual ao consumidor.
