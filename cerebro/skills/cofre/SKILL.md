---
name: cofre
description: Cofre de senhas deste aparelho (MCP local `cofre` do plugin) — vincular o aparelho, configurar, destravar e usar credenciais sem que o valor passe pela conversa, só com popups (sem janela nem formulário). Use quando o usuário falar de senha, credencial, chave de API, .env ou do cofre.
---
O cofre guarda as credenciais no servidor do cérebro, cifradas. O valor só sai pelo broker local (o MCP `cofre`, deste plugin) e vai direto ao destino: digitar num campo, copiar, o ambiente de um comando ou outro MCP local. **Você nunca vê um valor, e nunca deve vê-lo.**

## Simples para o usuário: os dados vêm do chat, o popup só pede o segredo
- Não existe janela nem formulário. Tudo o que não é segredo (caminho, tipo, usuário, URL, descrição) **você tira da conversa** e passa nos argumentos da ferramenta. Faltou algo, pergunte no chat; **nunca** abra nada para o usuário preencher.
- O broker só abre um popup para o que é segredo ou pontual: o valor da credencial, a senha do cofre, o código do autenticador e a caixa de autorização.
- Exemplo: "guarda a senha do roteador da casa, usuário admin, http://192.168.0.1" → `store` com `path="casa/roteador"`, `username="admin"`, `url="http://192.168.0.1"`; o popup pede só a senha.

## Regras que valem sempre
- **Nunca peça uma senha, chave ou valor na conversa**, nem para "testar". Para gravar, use `store` (o usuário digita o valor num popup mascarado) ou `store` com `generate=true`.
- Se o usuário colar um segredo na conversa, avise que ele ficou na transcrição, não o repita, e sugira trocá-lo e gravar o novo pelo popup.
- Nunca leia a área de transferência depois de um `copy`, nem o Keychain, o Gerenciador de Credenciais ou os arquivos do broker: a guarda do plugin barra esses atalhos (no terminal e nas ferramentas de arquivo), e contorná-la é quebrar a regra.
- Nunca clique, digite ou responda por ele um popup do cofre (System Events, computer-use, `osascript`): quem confirma é o usuário. A guarda barra o atalho.
- Para usar uma credencial num comando, use `run` (lista de argumentos, sem shell; o programa só pelo nome, achado no PATH, sem pasta); a saída volta com os valores trocados por `••••`. Não use `env`, `printenv`, `echo`, `ps eww`, `/proc/*/environ` nem intérpretes para "ver se chegou".
- Servidores: `ssh_list` mostra os do cofre (credenciais do tipo `ssh`); `ssh_run` e `ssh_run_script` rodam no servidor com a senha ou a chave entregues direto ao ssh (na primeira vez, o usuário autoriza o destino `ambiente:ssh` no popup). Host com regra `routeros-leitura` só aceita `/menu print` ou `/menu export` com palavras simples (`detail`, `terse`, `without-paging`…); nada de `[find]`, `:foreach`, `file=`. Servidor sem a chave do host fixada não recebe segredo: o erro traz a impressão vista; mostre-a ao usuário e peça que confira no servidor e grave no campo `impressao` da credencial.
- Destinos não se cadastram. A credencial do usuário (ou de um time de que ele é dono) vai para qualquer destino, e **ele decide na hora**: fora das 2 h, no popup do código; dentro delas, numa caixa com Negar / Só desta vez / Liberar destino (liberado não pergunta mais, salvo copiar, digitar, intérprete e 'sempre'). Credencial compartilhada ou de time em que ele não é dono segue a lista que o dono definiu no portal. Use a credencial pelo caminho certo para o pedido dele e diga no chat o que o popup vai mostrar. A política `livre` e o escopo são do dono, no portal: o `store` só aceita `sempre` ou `sessao`.

## Código uma vez, cofre aberto 2 h (renova a cada uso)
- O usuário destrava com a senha do cofre e o código de 6 dígitos do app autenticador, em popups mascarados. Você não vê nem pede nenhum dos dois.
- Depois disso o cofre fica aberto por **2 h sem uso**; cada uso renova por mais 2 h. Passou disso (ou o Claude fechou), tranca e pede senha e código de novo. `lock` tranca na hora.
- Dentro das 2 h, `copy`, `inject`, `run` de intérprete/shell/`.bat` e credenciais `sempre` mostram **só a caixa de autorização** (uma por pedido); `sessao` (os MCPs) não pede nada; `livre` não pede.
- A caixa mostra a credencial, a via e o alvo; no `run`, o caminho completo do programa e os argumentos; no `inject`, o app em foco; no `ssh_run`, o servidor e o comando; nos MCPs, o programa que pediu. Peça ao usuário que confira antes de aprovar.
- Um MCP novo (ou um programa mudado) pede o código uma vez para ser aprovado naquele aparelho.
- Cancelado: nada foi entregue. Não insista; pergunte ao usuário.

## Compartilhar e times
- Compartilhamentos e chaves de time para membros novos ficam pendentes até o dono aprovar: depois de cada destrave, um popup lista tudo e pede o código para aprovar (cancelar deixa pendente). `approvals` mostra o que espera, sem valores.
- O papel **usa** quer dizer que o aparelho da pessoa recebe o valor para usá-lo: o cofre protege o valor do Claude e de quem não tem acesso, não de quem recebeu. Lembre o usuário disso antes de compartilhar.

## Primeira vez neste aparelho
1. `status` do MCP `cofre`. Na 1ª abertura num aparelho, o plugin baixa sozinho o que o cofre usa (uv e Python, uns 120 MB, só na pasta do plugin; nada é instalado no sistema): se o MCP `cofre` aparecer como falho, rode `cerebro-plugin diagnostico`, espere o "cofre local: pronto" e reconecte em `/mcp`. Sem internet para baixar, rode `cerebro-plugin preparar` quando houver. No Linux, os popups usam o `zenity` ou o `kdialog`; copiar, o `wl-clipboard` ou o `xclip`; digitar, o `wtype` ou o `xdotool`.
2. **Vincular:** `pair`. O código e as impressões das chaves aparecem só na tela do usuário (você não recebe o código: não o peça). O navegador abre o portal; o usuário entra, confirma com o autenticador, confere se as impressões são as mesmas do portal e aprova. O `pair` espera a aprovação.
3. **Configurar:** `setup`. Popups pedem a senha do cofre duas vezes (mínimo 12 caracteres), mostram o kit de recuperação uma vez (o usuário guarda longe do Claude e clica OK) e pedem o código. Você não pede nem vê o kit.
4. **Destravar:** `unlock` (popups da senha e do código).

## Uso
- `list_entries` e `events` mostram só metadados.
- `inject` digita no campo em foco (o usuário põe o cursor no campo e autoriza); `copy` copia por alguns segundos.
- `import_env` lê um `.env` e grava cada variável secreta; depois o usuário esvazia o `.env`.
- `update` troca o valor (popup ou gerado); `archive`, `restore` e `move` organizam. Nada se apaga.
- Os MCPs antigos que usam `cofre_client`/`cofre_run` continuam funcionando: o broker atende o mesmo socket, com a via `mcp` e o alvo igual ao consumidor.
