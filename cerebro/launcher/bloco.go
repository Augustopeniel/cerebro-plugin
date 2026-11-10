package main

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

const (
	inicioBloco = "<!-- cerebro:inicio v"
	fimBloco    = "<!-- cerebro:fim -->"
	semBloco    = "sem-bloco" // marca deixada pelo desinstalar: não repor o bloco sozinho
)

// ---------- início de sessão ----------

// Hook de início de sessão: o que sai no stdout entra no contexto do Claude. Prepara este
// Claude sozinho (bloco do CLAUDE.md, com backup) e adianta o download do que o cofre usa.
func (p *perfil) sessao() int {
	v := p.versaoDoBloco()
	_, err := os.Stat(filepath.Join(p.dados, semBloco))
	tirado := err == nil
	switch {
	case v == contrato:
	case tirado:
		fmt.Println("> O bloco do cérebro foi tirado do CLAUDE.md (/cerebro:desinstalar). Para pôr de volta: /cerebro:instalar.")
		fmt.Println()
	default:
		if pasta, err := p.gravarBloco(); err != nil {
			fmt.Printf("> Não consegui gravar o bloco do cérebro em %s (%v): proponha /cerebro:instalar.\n\n", p.claudeMD, err)
		} else if v == "ausente" {
			fmt.Printf("> Preparei este Claude para o cérebro: bloco v%s gravado em %s (backup em %s).\n", contrato, p.claudeMD, pasta)
			fmt.Println("> Na 1ª resposta, avise o usuário em uma linha e proponha /cerebro:instalar para revisar o que pode competir com o cérebro (outras memórias, plugins de notas).")
			fmt.Println()
		} else {
			fmt.Printf("> Bloco do cérebro atualizado de v%s para v%s em %s (backup em %s).\n\n", v, contrato, p.claudeMD, pasta)
		}
	}
	if !tirado {
		mudou, pasta, err := p.prepararSettingsDoUsuario()
		if err != nil {
			fmt.Printf("> Não preparei o %s (%v): proponha /cerebro:instalar.\n\n", p.settings, err)
		} else if len(mudou) > 0 {
			fmt.Printf("> Preparei o %s: %s (backup em %s).\n\n", p.settings, strings.Join(mudou, "; "), pasta)
		}
	}
	p.prepararEmSegundoPlano()
	texto, err := os.ReadFile(filepath.Join(p.raiz, "inicio.md"))
	if err != nil {
		fmt.Println("Chame `load_context` do MCP `cerebro` antes de responder.")
		return 0
	}
	os.Stdout.Write(texto)
	return 0
}

// ---------- bloco do CLAUDE.md global ----------

func (p *perfil) versaoDoBloco() string {
	texto, err := os.ReadFile(p.claudeMD)
	if err != nil {
		return "ausente"
	}
	for _, linha := range strings.Split(string(texto), "\n") {
		if strings.HasPrefix(linha, inicioBloco) {
			v := strings.TrimPrefix(linha, inicioBloco)
			if i := strings.Index(v, " -->"); i >= 0 {
				v = v[:i]
			}
			return strings.TrimSpace(v)
		}
	}
	return "ausente"
}

// copia CLAUDE.md e settings.json antes de qualquer mudança; devolve a pasta
func (p *perfil) backup() (string, error) {
	base := filepath.Join(p.dados, "backup")
	if err := os.MkdirAll(base, 0o700); err != nil {
		return "", err
	}
	// uma pasta por backup, mesmo no mesmo segundo
	pasta, err := os.MkdirTemp(base, time.Now().Format("20060102-150405")+"-")
	if err != nil {
		return "", err
	}
	for _, f := range []string{p.claudeMD, p.settings} {
		if dado, err := os.ReadFile(f); err == nil {
			if err := os.WriteFile(filepath.Join(pasta, filepath.Base(f)), dado, 0o600); err != nil {
				return "", err
			}
		}
	}
	return pasta, nil
}

// Reescreve o CLAUDE.md trocando (ou tirando, com novo == "") só o bloco entre os marcadores.
func (p *perfil) trocarBloco(novo string) error {
	if err := os.MkdirAll(p.claudeDir, 0o700); err != nil {
		return err
	}
	atual, err := os.ReadFile(p.claudeMD)
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	texto := string(atual)
	quebra := "\n"
	if strings.Contains(texto, "\r\n") {
		quebra = "\r\n"
		texto = strings.ReplaceAll(texto, "\r\n", "\n")
	}
	novo = strings.TrimRight(strings.ReplaceAll(novo, "\r\n", "\n"), "\n")
	var linhas []string
	if texto != "" {
		linhas = strings.Split(strings.TrimSuffix(texto, "\n"), "\n")
	}
	var saida []string
	dentro, feito := false, false
	for _, l := range linhas {
		switch {
		case strings.HasPrefix(l, inicioBloco):
			dentro = true
			if novo != "" && !feito {
				saida = append(saida, novo)
				feito = true
			}
		case dentro:
			if strings.HasPrefix(l, fimBloco) {
				dentro = false
			}
		default:
			saida = append(saida, l)
		}
	}
	if novo != "" && !feito {
		if len(linhas) > 0 {
			saida = append(saida, "")
		}
		saida = append(saida, novo)
	}
	resultado := strings.Join(saida, "\n")
	if resultado != "" {
		resultado += "\n"
	}
	resultado = strings.ReplaceAll(resultado, "\n", quebra)
	tmp := p.claudeMD + ".cerebro-tmp"
	if err := os.WriteFile(tmp, []byte(resultado), 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, p.claudeMD)
}

func (p *perfil) gravarBloco() (string, error) {
	bloco, err := os.ReadFile(filepath.Join(p.raiz, "bloco.md"))
	if err != nil {
		return "", err
	}
	pasta, err := p.backup()
	if err != nil {
		return "", err
	}
	if err := p.trocarBloco(string(bloco)); err != nil {
		return "", err
	}
	os.Remove(filepath.Join(p.dados, semBloco))
	return pasta, nil
}

func (p *perfil) instalarBloco() int {
	pasta, err := p.gravarBloco()
	if err != nil {
		fmt.Fprintln(os.Stderr, "não consegui gravar o bloco:", err)
		return 1
	}
	fmt.Printf("Bloco do cérebro v%s gravado em %s (backup em %s).\n", p.versaoDoBloco(), p.claudeMD, pasta)
	return 0
}

func (p *perfil) desinstalarBloco() int {
	pasta, err := p.backup()
	if err == nil {
		err = p.trocarBloco("")
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "não consegui tirar o bloco:", err)
		return 1
	}
	_ = os.WriteFile(filepath.Join(p.dados, semBloco), []byte("tirado pelo /cerebro:desinstalar\n"), 0o600)
	fmt.Printf("Bloco do cérebro retirado de %s (backup em %s).\n", p.claudeMD, pasta)
	return 0
}

// ---------- inventário: só nomes, nunca valores (o .claude.json guarda tokens de outros MCPs) ----------

var parecido = regexp.MustCompile(`(?i)memor|mem0|brain|cerebro|cérebro|obsidian|vault|notion|knowledge|rag|notes|notas|second`)

func lerJSON(caminho string) map[string]any {
	dado, err := os.ReadFile(caminho)
	if err != nil {
		return nil
	}
	var m map[string]any
	if json.Unmarshal(dado, &m) != nil {
		return nil
	}
	return m
}

func chaves(m map[string]any, nome string) []string {
	sub, _ := m[nome].(map[string]any)
	var out []string
	for k := range sub {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// o próprio plugin (cerebro@<marketplace>) não conta; um MCP do usuário chamado "cerebro" conta
func parecidos(nomes []string) string {
	var out []string
	for _, n := range nomes {
		if parecido.MatchString(n) && !strings.HasPrefix(strings.ToLower(n), "cerebro@") {
			out = append(out, n)
		}
	}
	return strings.Join(out, " ")
}

func (p *perfil) memoriaDesligada(s map[string]any) bool {
	v, ok := s["autoMemoryEnabled"].(bool)
	return ok && !v
}

func (p *perfil) inventario() int {
	jsonClaude := filepath.Join(filepath.Dir(p.claudeDir), ".claude.json")
	if os.Getenv("CLAUDE_CONFIG_DIR") != "" {
		jsonClaude = filepath.Join(p.claudeDir, ".claude.json")
	}
	s := lerJSON(p.settings)
	fmt.Println("Inventário deste Claude (o que já existe e pode competir com o cérebro)")
	if texto, err := os.ReadFile(p.claudeMD); err == nil {
		var fora []string
		dentro := false
		for _, l := range strings.Split(strings.ReplaceAll(string(texto), "\r\n", "\n"), "\n") {
			switch {
			case strings.HasPrefix(l, inicioBloco):
				dentro = true
			case dentro && strings.HasPrefix(l, fimBloco):
				dentro = false
			case !dentro:
				fora = append(fora, l)
			}
		}
		n := 0
		for _, l := range fora {
			if l != "" {
				n++
			}
		}
		fmt.Printf("- CLAUDE.md global: %d linha(s) fora do bloco do cérebro\n", n)
		marca := regexp.MustCompile(`(?i)^@|` + parecido.String()[4:] + `|memória|memory`)
		achadas := 0
		for i, l := range fora {
			if achadas < 15 && marca.MatchString(l) {
				linha := fmt.Sprintf("%d:%s", i+1, l)
				if r := []rune(linha); len(r) > 140 {
					linha = string(r[:140])
				}
				fmt.Println("    " + linha)
				achadas++
			}
		}
	} else {
		fmt.Println("- CLAUDE.md global: não existe")
	}
	if p.memoriaDesligada(s) {
		fmt.Println("- memória automática: desligada")
	} else {
		fmt.Println("- memória automática: ligada")
	}
	if pasta, _ := s["autoMemoryDirectory"].(string); pasta != "" {
		real := pasta
		if strings.HasPrefix(real, "~") {
			home, _ := os.UserHomeDir()
			real = home + real[1:]
		}
		fmt.Printf("  pasta própria da memória automática: %s (%d arquivos)\n", pasta, contarMD(real, false))
	}
	fmt.Printf("  arquivos de memória automática em %s: %d\n", filepath.Join(p.claudeDir, "projects"),
		contarMD(filepath.Join(p.claudeDir, "projects"), true))
	mcp := chaves(lerJSON(jsonClaude), "mcpServers")
	fmt.Printf("- servidores MCP do usuário: %s\n", ouNenhum(mcp))
	if len(mcp) > 0 {
		fmt.Printf("  parecidos com memória ou notas: %s\n", parecidos(mcp))
	}
	plugins := chaves(s, "enabledPlugins")
	fmt.Printf("- plugins ligados: %s\n", ouNenhum(plugins))
	if len(plugins) > 0 {
		fmt.Printf("  parecidos com memória ou notas: %s\n", parecidos(plugins))
	}
	fmt.Printf("- hooks no settings.json: %s\n", strings.Join(chaves(s, "hooks"), " "))
	locais := map[string]bool{}
	for _, d := range []string{"skills", "commands"} {
		itens, _ := os.ReadDir(filepath.Join(p.claudeDir, d))
		for _, it := range itens {
			n := strings.TrimSuffix(it.Name(), ".md")
			if !strings.Contains(n, ".bak") && n != "synced" {
				locais[n] = true
			}
		}
	}
	var nomes []string
	for n := range locais {
		nomes = append(nomes, n)
	}
	sort.Strings(nomes)
	fmt.Printf("- skills e comandos próprios: %s\n", ouNenhum(nomes))
	if len(nomes) > 0 {
		fmt.Printf("  parecidos com memória ou notas: %s\n", parecidos(nomes))
	}
	fmt.Println("(o CLAUDE.md do projeto, se houver, já está no contexto do Claude: confira também)")
	return 0
}

func ouNenhum(nomes []string) string {
	if len(nomes) == 0 {
		return "nenhum"
	}
	return strings.Join(nomes, " ")
}

// conta os .md (em */memory/ quando soMemoria)
func contarMD(raiz string, soMemoria bool) int {
	n := 0
	_ = filepath.WalkDir(raiz, func(caminho string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(caminho, ".md") {
			return nil
		}
		if !soMemoria || filepath.Base(filepath.Dir(caminho)) == "memory" ||
			strings.Contains(filepath.ToSlash(caminho), "/memory/") {
			n++
		}
		return nil
	})
	return n
}

func (p *perfil) diagnostico() int {
	fmt.Printf("Plugin cerebro — contrato v%s, endereço fixo https://cerebro.ogidoc.com/mcp/eu\n", contrato)
	fmt.Println("- login: pelo próprio Claude (OAuth). Confira em /mcp se plugin:cerebro:cerebro está conectado")
	fmt.Printf("- CLAUDE.md global: %s (bloco do cérebro: %s; o do plugin: v%s)\n", p.claudeMD, p.versaoDoBloco(), contrato)
	if p.memoriaDesligada(lerJSON(p.settings)) {
		fmt.Println("- memória automática do Claude Code: desligada")
	} else {
		fmt.Println("- memória automática do Claude Code: ligada (o cérebro pede para desligar)")
	}
	fmt.Printf("- cofre local: %s\n", p.estadoDoCofre())
	return 0
}
