// Lançador do plugin `cerebro` (contrato 2.2): um binário só, sem dependências, para macOS,
// Linux e Windows. Faz o início de sessão, o bloco do CLAUDE.md global, o inventário, o
// diagnóstico, a guarda do terminal e sobe o cofre local baixando sozinho o que ele precisa
// (uv e Python), sem nada instalado antes na máquina.
//
// Uso:
//
//	cerebro-plugin sessao [pasta-dados]           (hook de início de sessão)
//	cerebro-plugin guarda                          (hook PreToolUse do terminal)
//	cerebro-plugin cofre <args…>                   (MCP e comandos do cofre local)
//	cerebro-plugin preparar [pasta-dados]          (baixa o que o cofre precisa)
//	cerebro-plugin diagnostico | inventario
//	cerebro-plugin instalar-bloco|desinstalar-bloco|backup <pasta-dados>
package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// versão do contrato que este plugin conhece (cerebro.core.contract)
const contrato = "2.2"

func main() {
	os.Exit(rodar(os.Args[1:]))
}

func rodar(args []string) int {
	cmd := "sessao"
	if len(args) > 0 {
		cmd, args = args[0], args[1:]
	}
	// só estes recebem a pasta de dados como 1º argumento; os outros a leem do ambiente
	dados := ""
	switch cmd {
	case "sessao", "preparar", "instalar-bloco", "desinstalar-bloco", "backup":
		dados = primeiro(args)
	}
	p := novoPerfil(dados)
	switch cmd {
	case "sessao":
		return p.sessao()
	case "guarda":
		return guarda(os.Stdin, os.Stderr)
	case "cofre":
		return p.cofre(args)
	case "preparar":
		return p.preparar()
	case "diagnostico":
		return p.diagnostico()
	case "inventario":
		return p.inventario()
	case "instalar-bloco", "desinstalar-bloco", "backup":
		if primeiro(args) == "" {
			fmt.Println("Diga a pasta de dados do plugin.")
			return 1
		}
		switch cmd {
		case "instalar-bloco":
			return p.instalarBloco()
		case "desinstalar-bloco":
			return p.desinstalarBloco()
		default:
			pasta, err := p.backup()
			if err != nil {
				fmt.Fprintln(os.Stderr, "backup falhou:", err)
				return 1
			}
			fmt.Println(pasta)
			return 0
		}
	}
	fmt.Println("uso: cerebro-plugin sessao | guarda | cofre <args> | preparar | diagnostico | inventario | instalar-bloco|desinstalar-bloco|backup <pasta-dados>")
	return 2
}

func primeiro(args []string) string {
	if len(args) > 0 {
		return args[0]
	}
	return ""
}

// perfil: onde ficam o plugin, o Claude do usuário e os dados do plugin
type perfil struct {
	raiz      string // pasta do plugin (a que tem bloco.md e inicio.md)
	claudeDir string
	claudeMD  string
	settings  string
	dados     string
}

func novoPerfil(dados string) *perfil {
	home, _ := os.UserHomeDir()
	claudeDir := os.Getenv("CLAUDE_CONFIG_DIR")
	if claudeDir == "" {
		claudeDir = filepath.Join(home, ".claude")
	}
	if naoExpandida(dados) {
		dados = os.Getenv("CLAUDE_PLUGIN_DATA")
	}
	if naoExpandida(dados) {
		dados = filepath.Join(claudeDir, "plugins", "data", "cerebro-cerebro-vivo")
	}
	return &perfil{
		raiz:      raizDoPlugin(),
		claudeDir: claudeDir,
		claudeMD:  filepath.Join(claudeDir, "CLAUDE.md"),
		settings:  filepath.Join(claudeDir, "settings.json"),
		dados:     dados,
	}
}

// o binário mora em <raiz>/bin (Windows) ou <raiz>/nativo (macOS e Linux)
func raizDoPlugin() string {
	if r := os.Getenv("CEREBRO_PLUGIN_ROOT"); r != "" {
		return r
	}
	exe, err := os.Executable()
	if err == nil {
		if real, err := filepath.EvalSymlinks(exe); err == nil {
			exe = real
		}
		return filepath.Dir(filepath.Dir(exe))
	}
	return os.Getenv("CLAUDE_PLUGIN_ROOT")
}

// vazio, ou uma variável que o Claude Code não expandiu (ex.: "${CLAUDE_PLUGIN_DATA}" no env do MCP)
func naoExpandida(v string) bool {
	return v == "" || strings.Contains(v, "${") || v[0] == '$'
}
