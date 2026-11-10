# Plugin `cerebro`

Conecta o Claude ao seu cérebro (Cérebro Vivo). Sem token: o login é feito pelo próprio Claude (OAuth), com a sua conta do portal.

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
- `/cerebro:instalar`, `/cerebro:desinstalar`.

## Desfazer
O `/cerebro:desinstalar` tira o bloco do CLAUDE.md global e, com o seu ok, devolve as configurações. Para tirar o plugin de vez: `claude plugin uninstall cerebro`.
