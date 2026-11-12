package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestGuardaBarraFerramentasDeArquivoNaPastaDoCofre(t *testing.T) {
	barrar := []string{
		`{"tool_name":"Read","tool_input":{"file_path":"/Users/x/.claude/cofre/broker.key"}}`,
		`{"tool_name":"Grep","tool_input":{"pattern":"a","path":"/Users/x/.claude/cofre"}}`,
		`{"tool_name":"Glob","tool_input":{"pattern":"/Users/x/.claude/cofre/*"}}`,
		`{"tool_name":"Read","tool_input":{"file_path":"C:\\Users\\x\\.claude\\cofre\\broker.key"}}`,
		`{"tool_name":"Edit","tool_input":{"file_path":"/Users/x/.claude/plugins/cache/cerebro-vivo/cerebro/2.5.2/broker/cofre_broker/broker.py"}}`,
		`{"tool_name":"Write","tool_input":{"file_path":"/Users/x/.claude/plugins/data/cerebro-cerebro-vivo/runtime/venv-cofre-x/lib/sitecustomize.py"}}`,
	}
	for _, e := range barrar {
		var erro bytes.Buffer
		if guarda(strings.NewReader(e), &erro) != 2 {
			t.Errorf("devia barrar: %s", e)
		}
	}
	liberar := []string{
		`{"tool_name":"Read","tool_input":{"file_path":"/Users/x/.claude/plugins/cache/cerebro-vivo/cerebro/2.5.2/broker/cofre_broker/broker.py"}}`,
		`{"tool_name":"Edit","tool_input":{"file_path":"/Users/x/Projetos/cerebro-vivo/plugin/cerebro/broker/cofre_broker/broker.py"}}`,
		`{"tool_name":"Grep","tool_input":{"pattern":"broker","path":"/Users/x/Projetos"}}`,
	}
	for _, e := range liberar {
		var erro bytes.Buffer
		if guarda(strings.NewReader(e), &erro) != 0 {
			t.Errorf("devia liberar: %s (%s)", e, erro.String())
		}
	}
}
