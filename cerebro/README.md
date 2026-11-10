# Plugin `cerebro`

Conecta o Claude ao seu cérebro (Cérebro Vivo). Sem token: o login é feito pelo próprio Claude (OAuth), com a sua conta do portal.

## Requisito: `uv`
O plugin passa a exigir o [`uv`](https://docs.astral.sh/uv/) no PATH: ele roda o broker local do cofre (o MCP `cofre`) e o hook que protege o Bash. Instale uma vez (macOS: `brew install uv`; Windows: `winget install astral-sh.uv`) e reinicie o Claude. Sem o `uv`, a memória funciona, mas o cofre não.

## Instalar (Claude Code)
1. No portal (https://cerebro.ogidoc.com), em Meus cérebros, clique em **Vincular com o Claude**. O Claude Code abre com o comando pronto; aperte Enter. Ou cole no Claude Code:
   ```
   /plugin install cerebro --marketplace Augustopeniel/cerebro-plugin
   ```
   (Claude Code anterior à 2.1.275: `/plugin marketplace add Augustopeniel/cerebro-plugin` e depois `/plugin install cerebro@cerebro-vivo`.)
2. Na primeira sessão, o Claude avisa que o cérebro precisa de login: `/mcp` → `plugin:cerebro:cerebro` → **Authenticate**. O navegador abre o portal, onde você entra, confirma com o código do autenticador e escolhe o cérebro. Depois ele volta sozinho.
3. Rode `/cerebro:instalar`. Ele prepara este Claude com backup e o seu ok, item por item.

## claude.ai (web, desktop e celular)
Customize → Connectors → **Add custom connector** → endereço `https://cerebro.ogidoc.com/mcp/eu`. O login é o mesmo.

## Comandos
- `/cerebro:comecar`, `/cerebro:memoria`, `/cerebro:estado`, `/cerebro:exportar`;
- `/cerebro:reprocessar`, `/cerebro:sincronia`;
- `/cerebro:instalar`, `/cerebro:desinstalar`;
- `/cerebro:cofre`: o cofre de senhas deste aparelho.

## Cofre de senhas (MCP local `cofre`)
O valor de uma credencial nunca passa pela conversa: o broker local entrega direto ao destino (digitar, copiar, o ambiente de um comando, outro MCP) e o Claude vê só os nomes.
- **Vincular o aparelho:** `/cerebro:cofre` (ou a ferramenta `pair`). O código aparece num aviso na sua tela (e na janela), nunca na conversa, junto com duas impressões das chaves (`ABCD-EF01-…`), uma do servidor e uma do aparelho. O portal abre; aprove logado, com o autenticador, **só se as impressões forem as mesmas que o portal mostra**.
- **Configurar e destravar:** na janela do cofre (`open_window`). A senha do cofre não sai do aparelho; o kit de recuperação aparece uma vez. O `status` mostra a conta do portal a que o aparelho está ligado.
- **Confirmação pelo código do autenticador:** quando a política da credencial pede (`sempre`: a cada uso; `sessao`: uma vez até trancar; `livre`: não pede), quem exige é o servidor, e o broker abre um popup mascarado pedindo o código de 6 dígitos do seu app autenticador. O popup mostra a credencial, a via e o alvo; no `run`, o caminho completo do programa e os argumentos; no `inject`, o app em foco; no `ssh_run`, o servidor e o comando. Digitar num campo e rodar um intérprete ou shell pedem o código sempre, mesmo com `livre`. Um OK o Claude conseguiria clicar sozinho; o código, não: ele não tem a semente do autenticador.
- **Só o dono decide** destinos com alvo `*` (digitar, copiar, qualquer comando), a política `livre` e o escopo: no portal ou na janela. O `store` e o `import_env` do Claude não definem nada disso.
- **Compartilhar e times:** compartilhar uma credencial, ou dar a chave de um time a um membro novo, fica pendente até você aprovar. Depois de cada destrave, se houver pendência, um popup lista tudo e pede o código do autenticador; cancelar deixa pendente. A ferramenta `approvals` mostra o que espera (sem valores). Quem recebe com o papel **usa** tem o aparelho dele recebendo o valor para usar: o cofre o protege do Claude e de quem não tem acesso, não dessa pessoa. Só compartilhe com quem pode ver o valor.
- **SSH:** a senha chega ao `ssh` por um FIFO de uso único, só no prompt de senha exato do servidor certo (nada no ambiente, nada em disco). Servidor sem a impressão da chave do host fixada não recebe segredo: o erro mostra a impressão vista, para você conferir e gravar no campo `impressao`. No Windows, por enquanto, só chave.
- **Chaves do aparelho:** no Keychain (macOS) ou no Gerenciador de Credenciais (Windows). No Linux, num arquivo 0600 na pasta de dados do plugin.
- **MCPs que já usam o cofre antigo** (`cofre_client`/`cofre_run`): continuam funcionando pelo mesmo socket. Se o broker antigo ainda estiver rodando, o novo não toma o lugar dele e avisa no `status`.
- Um hook do Bash barra comandos que leriam segredo cru: Keychain com `-w`, área de transferência, arquivos e canal do broker (qualquer programa que cite `broker.sock` ou `broker.key`), o ambiente de outros processos (`ps eww`, `ps -E`, `/proc/*/environ`) e clicar em popups pelo `osascript` com o System Events.

## Desfazer
O `/cerebro:desinstalar` tira o bloco do CLAUDE.md global e, com o seu ok, devolve as configurações. Para tirar o plugin de vez: `claude plugin uninstall cerebro`.
