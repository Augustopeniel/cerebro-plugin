package main

// Preparação automática do settings.json do usuário: leituras do cérebro sem pedir permissão e
// atualização automática do plugin. Mexe só nessas duas chaves, preserva a ordem e todo o resto do
// arquivo, faz backup antes e não grava nada se já estiver tudo certo.

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
)

const (
	marketplace = "cerebro-vivo"
	repositorio = "Augustopeniel/cerebro-plugin"
)

// leituras do cérebro (cerebro.core.contract.READ_TOOLS): liberadas sem pedir a cada vez
var leiturasDoCerebro = []string{
	"mcp__plugin_cerebro_cerebro__load_context",
	"mcp__plugin_cerebro_cerebro__read_index",
	"mcp__plugin_cerebro_cerebro__read_note",
	"mcp__plugin_cerebro_cerebro__search",
	"mcp__plugin_cerebro_cerebro__guia",
	"mcp__plugin_cerebro_cerebro__session_status",
	"mcp__plugin_cerebro_cerebro__note_history",
	"mcp__plugin_cerebro_cerebro__recent_changes",
}

// ---------- JSON com a ordem das chaves preservada ----------

type objeto struct {
	chaves  []string
	valores map[string]any
}

func novoObjeto() *objeto { return &objeto{valores: map[string]any{}} }

func (o *objeto) pegar(k string) (any, bool) { v, ok := o.valores[k]; return v, ok }

func (o *objeto) por(k string, v any) {
	if _, ok := o.valores[k]; !ok {
		o.chaves = append(o.chaves, k)
	}
	o.valores[k] = v
}

// objeto filho (cria se faltar); erro se a chave existir com outro tipo
func (o *objeto) filho(k string) (*objeto, error) {
	v, ok := o.valores[k]
	if !ok {
		f := novoObjeto()
		o.por(k, f)
		return f, nil
	}
	f, ok := v.(*objeto)
	if !ok {
		return nil, fmt.Errorf("%q não é um objeto", k)
	}
	return f, nil
}

func lerValor(d *json.Decoder) (any, error) {
	t, err := d.Token()
	if err != nil {
		return nil, err
	}
	switch t := t.(type) {
	case json.Delim:
		switch t {
		case '{':
			o := novoObjeto()
			for d.More() {
				k, err := d.Token()
				if err != nil {
					return nil, err
				}
				v, err := lerValor(d)
				if err != nil {
					return nil, err
				}
				o.por(k.(string), v)
			}
			_, err := d.Token()
			return o, err
		case '[':
			var lista []any
			for d.More() {
				v, err := lerValor(d)
				if err != nil {
					return nil, err
				}
				lista = append(lista, v)
			}
			_, err := d.Token()
			return lista, err
		}
		return nil, errors.New("JSON inválido")
	default:
		return t, nil // string, json.Number, bool ou nil
	}
}

func lerObjeto(dado []byte) (*objeto, error) {
	if len(bytes.TrimSpace(dado)) == 0 {
		return novoObjeto(), nil
	}
	d := json.NewDecoder(bytes.NewReader(dado))
	d.UseNumber()
	v, err := lerValor(d)
	if err != nil {
		return nil, err
	}
	if _, err := d.Token(); err != io.EOF {
		return nil, errors.New("sobra conteúdo depois do JSON")
	}
	o, ok := v.(*objeto)
	if !ok {
		return nil, errors.New("o settings.json não é um objeto")
	}
	return o, nil
}

func escrever(b *strings.Builder, v any, recuo string) {
	switch v := v.(type) {
	case *objeto:
		if len(v.chaves) == 0 {
			b.WriteString("{}")
			return
		}
		b.WriteString("{\n")
		for i, k := range v.chaves {
			b.WriteString(recuo + "  ")
			escalar(b, k)
			b.WriteString(": ")
			escrever(b, v.valores[k], recuo+"  ")
			if i < len(v.chaves)-1 {
				b.WriteString(",")
			}
			b.WriteString("\n")
		}
		b.WriteString(recuo + "}")
	case []any:
		if len(v) == 0 {
			b.WriteString("[]")
			return
		}
		b.WriteString("[\n")
		for i, x := range v {
			b.WriteString(recuo + "  ")
			escrever(b, x, recuo+"  ")
			if i < len(v)-1 {
				b.WriteString(",")
			}
			b.WriteString("\n")
		}
		b.WriteString(recuo + "]")
	default:
		escalar(b, v)
	}
}

func escalar(b *strings.Builder, v any) {
	var buf bytes.Buffer
	e := json.NewEncoder(&buf)
	e.SetEscapeHTML(false)
	_ = e.Encode(v)
	b.WriteString(strings.TrimSuffix(buf.String(), "\n"))
}

// ---------- o que entra ----------

// aplica as duas preparações; devolve o que mudou (vazio = nada a fazer)
func prepararSettings(s *objeto) ([]string, error) {
	var mudou []string
	perm, err := s.filho("permissions")
	if err != nil {
		return nil, err
	}
	atual, _ := perm.pegar("allow")
	lista, ok := atual.([]any)
	if atual != nil && !ok {
		return nil, errors.New(`"permissions.allow" não é uma lista`)
	}
	tem := map[string]bool{}
	for _, x := range lista {
		if t, ok := x.(string); ok {
			tem[t] = true
		}
	}
	novas := 0
	for _, t := range leiturasDoCerebro {
		if !tem[t] {
			lista = append(lista, t)
			novas++
		}
	}
	if novas > 0 {
		perm.por("allow", lista)
		mudou = append(mudou, fmt.Sprintf("%d leitura(s) do cérebro liberada(s) sem pedir permissão", novas))
	}
	mercados, err := s.filho("extraKnownMarketplaces")
	if err != nil {
		return nil, err
	}
	m, err := mercados.filho(marketplace)
	if err != nil {
		return nil, err
	}
	if _, ok := m.pegar("source"); !ok {
		fonte := novoObjeto()
		fonte.por("source", "github")
		fonte.por("repo", repositorio)
		m.por("source", fonte)
	}
	if v, _ := m.pegar("autoUpdate"); v != true {
		m.por("autoUpdate", true)
		mudou = append(mudou, "atualização automática do plugin ligada")
	}
	return mudou, nil
}

func (p *perfil) prepararSettingsDoUsuario() ([]string, string, error) {
	dado, err := os.ReadFile(p.settings)
	if err != nil && !os.IsNotExist(err) {
		return nil, "", err
	}
	s, err := lerObjeto(dado)
	if err != nil {
		return nil, "", fmt.Errorf("settings.json ilegível (%v): nada mudou", err)
	}
	mudou, err := prepararSettings(s)
	if err != nil || len(mudou) == 0 {
		return nil, "", err
	}
	pasta, err := p.backup()
	if err != nil {
		return nil, "", err
	}
	var b strings.Builder
	escrever(&b, s, "")
	b.WriteString("\n")
	modo := os.FileMode(0o600)
	if info, err := os.Stat(p.settings); err == nil {
		modo = info.Mode().Perm()
	}
	tmp := p.settings + ".cerebro-tmp"
	if err := os.WriteFile(tmp, []byte(b.String()), modo); err != nil {
		return nil, "", err
	}
	return mudou, pasta, os.Rename(tmp, p.settings)
}
