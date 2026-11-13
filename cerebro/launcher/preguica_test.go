package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// broker de mentira: responde o initialize, conta quantas vezes o recebeu e ecoa cada ferramenta
func TestMain(m *testing.M) {
	if os.Getenv("CEREBRO_BROKER_FALSO") == "1" {
		inits := 0
		avisado := false
		esc := bufio.NewScanner(os.Stdin)
		for esc.Scan() {
			var msg map[string]any
			if json.Unmarshal(esc.Bytes(), &msg) != nil {
				continue
			}
			switch msg["method"] {
			case "initialize":
				inits++
				fmt.Printf(`{"jsonrpc":"2.0","id":%q,"result":{"serverInfo":{"name":"cofre"}}}`+"\n", msg["id"])
			case "notifications/initialized":
				avisado = true
			case "tools/call":
				nome := msg["params"].(map[string]any)["name"]
				id, _ := json.Marshal(msg["id"])
				fmt.Printf(`{"jsonrpc":"2.0","id":%s,"result":{"content":[{"type":"text","text":"broker:%s inits=%d avisado=%t"}]}}`+"\n",
					id, nome, inits, avisado)
			}
		}
		os.Exit(0)
	}
	os.Exit(m.Run())
}

func brokerFalso() *exec.Cmd {
	c := exec.Command(os.Args[0])
	c.Env = append(os.Environ(), "CEREBRO_BROKER_FALSO=1")
	return c
}

type conversa struct {
	escrever *io.PipeWriter
	ler      *bufio.Reader
	fim      chan int
}

func abrir(t *testing.T, preparar func() error, iniciar func() *exec.Cmd) *conversa {
	t.Helper()
	entR, entW := io.Pipe()
	saiR, saiW := io.Pipe()
	c := &conversa{escrever: entW, ler: bufio.NewReader(saiR), fim: make(chan int, 1)}
	go func() { c.fim <- servirPreguicoso(entR, saiW, preparar, iniciar); saiW.Close() }()
	return c
}

func (c *conversa) pedir(t *testing.T, linha string) map[string]any {
	t.Helper()
	if _, err := c.escrever.Write([]byte(linha + "\n")); err != nil {
		t.Fatal(err)
	}
	pronto := make(chan []byte, 1)
	go func() { l, _ := c.ler.ReadBytes('\n'); pronto <- l }()
	select {
	case l := <-pronto:
		var m map[string]any
		if err := json.Unmarshal(l, &m); err != nil {
			t.Fatalf("resposta inválida %q: %v", l, err)
		}
		return m
	case <-time.After(10 * time.Second):
		t.Fatal("sem resposta")
	}
	return nil
}

func texto(m map[string]any) string {
	r := m["result"].(map[string]any)
	return r["content"].([]any)[0].(map[string]any)["text"].(string)
}

func TestAtendeSemBaixarAteAPrimeiraFerramenta(t *testing.T) {
	preparos := 0
	c := abrir(t, func() error { preparos++; return nil }, brokerFalso)
	ini := c.pedir(t, `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26"}}`)
	r := ini["result"].(map[string]any)
	if r["protocolVersion"] != "2025-03-26" || r["serverInfo"].(map[string]any)["name"] != "cofre" {
		t.Fatalf("initialize: %v", r)
	}
	lista := c.pedir(t, `{"jsonrpc":"2.0","id":2,"method":"tools/list"}`)
	tools := lista["result"].(map[string]any)["tools"].([]any)
	if len(tools) < 5 || tools[0].(map[string]any)["name"] != "status" {
		t.Fatalf("tools/list: %d ferramentas", len(tools))
	}
	c.pedir(t, `{"jsonrpc":"2.0","id":3,"method":"ping"}`)
	if preparos != 0 {
		t.Fatal("baixou antes da 1ª ferramenta")
	}
	// 1ª ferramenta: prepara uma vez, o broker recebe um initialize só e o aviso de pronto
	r1 := c.pedir(t, `{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"status","arguments":{}}}`)
	if r1["id"].(float64) != 4 || texto(r1) != "broker:status inits=1 avisado=true" {
		t.Fatalf("1ª chamada: %v", r1)
	}
	r2 := c.pedir(t, `{"jsonrpc":"2.0","id":"x","method":"tools/call","params":{"name":"unlock"}}`)
	if r2["id"] != "x" || !strings.HasPrefix(texto(r2), "broker:unlock inits=1") {
		t.Fatalf("2ª chamada: %v", r2)
	}
	if preparos != 1 {
		t.Fatalf("preparou %d vezes", preparos)
	}
	c.escrever.Close() // o Claude fecha o MCP: o broker sai e o lançador junto
	select {
	case cod := <-c.fim:
		if cod != 0 {
			t.Fatalf("saiu com %d", cod)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("não terminou ao fechar o stdin")
	}
}

func TestSemInternetRespondeErroESegueAtendendo(t *testing.T) {
	falhar := true
	c := abrir(t, func() error {
		if falhar {
			return errors.New("sem rede")
		}
		return nil
	}, brokerFalso)
	c.pedir(t, `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`)
	r := c.pedir(t, `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"status"}}`)
	if r["result"].(map[string]any)["isError"] != true || !strings.Contains(texto(r), "sem rede") {
		t.Fatalf("erro esperado: %v", r)
	}
	falhar = false // a rede voltou: a próxima ferramenta abre o broker
	r = c.pedir(t, `{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"status"}}`)
	if texto(r) != "broker:status inits=1 avisado=true" {
		t.Fatalf("depois da rede: %v", r)
	}
	c.escrever.Close()
	<-c.fim
}

func TestBrokerQueNaoAbreViraErroDaFerramenta(t *testing.T) {
	c := abrir(t, func() error { return nil }, func() *exec.Cmd { return exec.Command("false") })
	c.pedir(t, `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`)
	r := c.pedir(t, `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"status"}}`)
	if r["result"].(map[string]any)["isError"] != true {
		t.Fatalf("erro esperado: %v", r)
	}
	if m := c.pedir(t, `{"jsonrpc":"2.0","id":3,"method":"nada"}`); m["error"] == nil {
		t.Fatalf("método desconhecido: %v", m)
	}
	c.escrever.Close()
	<-c.fim
}
