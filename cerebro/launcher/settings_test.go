package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSettingsPreservaOrdemEOResto(t *testing.T) {
	dir := t.TempDir()
	p := &perfil{claudeDir: dir, claudeMD: filepath.Join(dir, "CLAUDE.md"),
		settings: filepath.Join(dir, "settings.json"), dados: filepath.Join(dir, "dados")}
	original := "{\n  \"zeta\": 1.50,\n  \"permissions\": {\n    \"allow\": [\"Read(*)\"],\n    \"deny\": []\n  },\n  \"alfa\": \"<a&b>\"\n}\n"
	os.WriteFile(p.settings, []byte(original), 0o644)
	mudou, pasta, err := p.prepararSettingsDoUsuario()
	if err != nil || len(mudou) != 2 || pasta == "" {
		t.Fatalf("mudou=%v pasta=%q err=%v", mudou, pasta, err)
	}
	dado, _ := os.ReadFile(p.settings)
	s := string(dado)
	if strings.Index(s, "zeta") > strings.Index(s, "permissions") || strings.Index(s, "permissions") > strings.Index(s, "alfa") {
		t.Fatalf("ordem perdida:\n%s", s)
	}
	for _, quer := range []string{`"zeta": 1.50`, `"<a&b>"`, `"Read(*)"`, `"deny": []`, `"autoUpdate": true`,
		`"repo": "Augustopeniel/cerebro-plugin"`, "mcp__plugin_cerebro_cerebro__recent_changes"} {
		if !strings.Contains(s, quer) {
			t.Fatalf("faltou %s em:\n%s", quer, s)
		}
	}
	if backup, _ := os.ReadFile(filepath.Join(pasta, "settings.json")); string(backup) != original {
		t.Fatal("backup diferente do original")
	}
	// segunda vez: nada a fazer, nada gravado
	mudou, _, err = p.prepararSettingsDoUsuario()
	if err != nil || len(mudou) != 0 {
		t.Fatalf("segunda vez mudou=%v err=%v", mudou, err)
	}
}

func TestSettingsIlegivelNaoMexe(t *testing.T) {
	dir := t.TempDir()
	p := &perfil{claudeDir: dir, settings: filepath.Join(dir, "settings.json"), dados: dir}
	ruim := "{ // comentário\n}"
	os.WriteFile(p.settings, []byte(ruim), 0o644)
	if _, _, err := p.prepararSettingsDoUsuario(); err == nil {
		t.Fatal("deveria recusar")
	}
	if dado, _ := os.ReadFile(p.settings); string(dado) != ruim {
		t.Fatal("mexeu no arquivo ilegível")
	}
}

func TestGuardaDeixaBuscarONomeDoCanalNoCodigo(t *testing.T) {
	canal := "broker" + ".sock"
	if conferir("grep -n "+canal+" plugin") != "" {
		t.Fatal("buscar o nome no código deve passar")
	}
	if conferir("nc -U ~/.claude/cofre/"+canal) == "" {
		t.Fatal("falar com o canal deve ser barrado")
	}
}

func TestPastaDeDadosIgnoraVariavelNaoExpandida(t *testing.T) {
	t.Setenv("CLAUDE_CONFIG_DIR", t.TempDir())
	t.Setenv("CLAUDE_PLUGIN_DATA", "${CLAUDE_PLUGIN_DATA}")
	p := novoPerfil("${CLAUDE_PLUGIN_DATA}")
	if strings.Contains(p.dados, "$") || !filepath.IsAbs(p.dados) {
		t.Fatalf("pasta de dados errada: %q", p.dados)
	}
}
