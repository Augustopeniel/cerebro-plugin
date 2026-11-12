# Plugin `cerebro`

Conecta o Claude ao seu cérebro (Cérebro Vivo). Sem token: o login é feito pelo próprio Claude (OAuth), com a sua conta do portal.

## Nada a instalar antes
O plugin começa tudo sozinho, em macOS, Windows e Linux, no app desktop ou no terminal. O lançador `cerebro-plugin` é um binário nativo, compilado de `launcher/` (Go, só a biblioteca padrão) com compilação reprodutível. Os ganchos rodam sem shell. Na 1ª abertura, o cofre baixa uma cópia fixa do [`uv`](https://docs.astral.sh/uv/), conferida pelo SHA-256 gravado no lançador, e o uv baixa o Python e as bibliotecas do broker. Tudo fica na pasta de dados do plugin, uns 120 MB, nada no sistema nem no PATH. Também na 1ª abertura, o plugin prepara este Claude sozinho, com backup: o bloco no CLAUDE.md global, as leituras do cérebro liberadas e a atualização automática.

## Instalar (Claude Code)
1. No portal (https://cerebro.ogidoc.com), em Meus cérebros, clique em **Vincular com o Claude** e copie o pedido. Cole numa conversa do Claude Code (app desktop ou terminal): o próprio Claude instala o plugin (`claude plugin marketplace add Augustopeniel/cerebro-plugin` e `claude plugin install cerebro@cerebro-vivo`) e abre o login (`claude mcp login plugin:cerebro:cerebro`).
2. O navegador abre o portal, onde você entra, confirma com o código do autenticador e escolhe o cérebro. Depois ele volta sozinho.
3. Reinicie o Claude. Na abertura seguinte, o plugin se prepara sozinho, com backup. `/cerebro:instalar` revisa o que pode competir com o cérebro (outras memórias, plugins de notas).

## claude.ai (web, desktop e celular)
Customize → Connectors → **Add custom connector** → endereço `https://cerebro.ogidoc.com/mcp/eu`. O login é o mesmo.

## Comandos
- `/cerebro:comecar`, `/cerebro:memoria`, `/cerebro:estado`, `/cerebro:exportar`;
- `/cerebro:reprocessar`, `/cerebro:sincronia`;
- `/cerebro:instalar`, `/cerebro:desinstalar`;
- `/cerebro:cofre`: o cofre de senhas deste aparelho.

## Cofre de senhas (MCP local `cofre`)
O valor de uma credencial nunca passa pela conversa: o broker local entrega direto ao destino (digitar, copiar, o ambiente de um comando, outro MCP) e o Claude vê só os nomes.
- **Vincular o aparelho:** `/cerebro:cofre` (ou a ferramenta `pair`). O código aparece num aviso na sua tela, nunca na conversa, junto com duas impressões das chaves (`ABCD-EF01-…`), uma do servidor e uma do aparelho. O portal abre; aprove logado, com o autenticador, **só se as impressões forem as mesmas que o portal mostra**.
- **Configurar e destravar:** só por popups (`setup` na 1ª vez, depois `unlock`). A senha do cofre não sai do aparelho; o kit de recuperação aparece uma vez. Depois do código, o cofre fica aberto 2 h e renova a cada uso. O `status` mostra a conta do portal a que o aparelho está ligado.
- **Confirmação pelo código do autenticador:** quando a política da credencial pede (`sempre`: a cada uso; `sessao`: uma vez até trancar; `livre`: não pede), quem exige é o servidor, e o broker abre um popup mascarado pedindo o código de 6 dígitos do seu app autenticador. O popup mostra a credencial, a via e o alvo; no `run`, o caminho completo do programa e os argumentos; no `inject`, o app em foco; no `ssh_run`, o servidor e o comando. Digitar num campo e rodar um intérprete ou shell pedem o código sempre, mesmo com `livre`. Um OK o Claude conseguiria clicar sozinho; o código, não: ele não tem a semente do autenticador.
- **Você decide na hora** para onde vai cada credencial sua: o popup do código, ou, dentro das 2 h, a caixa com Negar / Só desta vez / Liberar destino. Credencial de time ou compartilhada com você segue os destinos do dono. A política `livre` e o escopo só o dono define, no portal.
- **Compartilhar e times:** compartilhar uma credencial, ou dar a chave de um time a um membro novo, fica pendente até você aprovar. Depois de cada destrave, se houver pendência, um popup lista tudo e pede o código do autenticador; cancelar deixa pendente. A ferramenta `approvals` mostra o que espera (sem valores). Quem recebe com o papel **usa** tem o aparelho dele recebendo o valor para usar: o cofre o protege do Claude e de quem não tem acesso, não dessa pessoa. Só compartilhe com quem pode ver o valor.
- **SSH:** a senha chega ao `ssh` por um FIFO de uso único, só no prompt de senha exato do servidor certo (nada no ambiente, nada em disco). Servidor sem a impressão da chave do host fixada não recebe segredo: o erro mostra a impressão vista, para você conferir e gravar no campo `impressao`. No Windows, por enquanto, só chave.
- **Chaves do aparelho:** no Keychain (macOS) ou no Gerenciador de Credenciais (Windows). No Linux, num arquivo 0600 na pasta de dados do plugin.
- **MCPs que já usam o cofre antigo** (`cofre_client`/`cofre_run`): continuam funcionando pelo mesmo socket. Se o broker antigo ainda estiver rodando, o novo não toma o lugar dele e avisa no `status`.
- Um hook do Bash barra comandos que leriam segredo cru: Keychain com `-w`, área de transferência, arquivos e canal do broker (qualquer programa que cite `broker.sock` ou `broker.key`), o ambiente de outros processos (`ps eww`, `ps -E`, `/proc/*/environ`) e clicar em popups pelo `osascript` com o System Events.

## Desfazer
O `/cerebro:desinstalar` tira o bloco do CLAUDE.md global e, com o seu ok, devolve as configurações. Para tirar o plugin de vez: `claude plugin uninstall cerebro`.
