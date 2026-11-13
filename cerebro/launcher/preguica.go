package main

// Cofre preguiçoso: enquanto o uv e o Python não foram baixados, o MCP `cofre` é atendido aqui
// mesmo (initialize, ping e tools/list, com a lista de ferramentas do broker embutida). O download
// (uv, Python e bibliotecas, ~120 MB) só acontece na 1ª chamada de ferramenta do cofre; daí em
// diante o broker atende e este processo só repassa as linhas. Quem nunca usa o cofre (conta sem
// cofre no plano, ou quem só quer a memória) nunca baixa nada.

import (
	"bufio"
	"bytes"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"sync"
	"time"
)

// gerado pelo compilar.sh a partir do broker (versão e tools.SCHEMAS); um teste confere
//
//go:embed ferramentas_cofre.json
var ferramentasCofre []byte

const (
	idIniciar       = "cerebro-plugin-iniciar" // o initialize que este processo manda ao broker
	protocoloPadrao = "2025-06-18"
	esperaBroker    = time.Minute
)

type catalogo struct {
	Versao string          `json:"versao"`
	Tools  json.RawMessage `json:"tools"`
}

type mensagem struct {
	ID     json.RawMessage `json:"id,omitempty"`
	Method string          `json:"method,omitempty"`
	Params json.RawMessage `json:"params,omitempty"`
}

// saída do MCP: uma mensagem JSON por linha, de um escritor por vez
type saida struct {
	mu sync.Mutex
	w  io.Writer
}

func (s *saida) linha(b []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	b = bytes.TrimRight(b, "\r\n")
	if _, err := s.w.Write(append(append([]byte{}, b...), '\n')); err != nil {
		return err
	}
	if f, ok := s.w.(interface{ Sync() error }); ok {
		_ = f.Sync()
	}
	return nil
}

func (s *saida) json(v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	return s.linha(b)
}

func resposta(id json.RawMessage, result any) map[string]any {
	return map[string]any{"jsonrpc": "2.0", "id": id, "result": result}
}

func erroDeFerramenta(id json.RawMessage, texto string) map[string]any {
	return resposta(id, map[string]any{
		"content": []map[string]string{{"type": "text", "text": texto}},
		"isError": true,
	})
}

// servirPreguicoso atende o MCP até a 1ª ferramenta; então chama `preparar` (o download), sobe o
// broker com `iniciar` e passa a só repassar. Devolve o código de saída do processo.
func servirPreguicoso(in io.Reader, out io.Writer, preparar func() error, iniciar func() *exec.Cmd) int {
	var cat catalogo
	if err := json.Unmarshal(ferramentasCofre, &cat); err != nil || len(cat.Tools) == 0 {
		fmt.Fprintln(os.Stderr, "cofre: lista de ferramentas embutida inválida:", err)
		return 1
	}
	leitor := bufio.NewReaderSize(in, 1<<20)
	o := &saida{w: out}
	var initParams json.RawMessage
	for {
		linha, errLeitura := leitor.ReadBytes('\n')
		var m mensagem
		if len(bytes.TrimSpace(linha)) > 0 && json.Unmarshal(linha, &m) == nil {
			switch m.Method {
			case "initialize":
				initParams = m.Params
				var p struct {
					ProtocolVersion string `json:"protocolVersion"`
				}
				_ = json.Unmarshal(m.Params, &p)
				if p.ProtocolVersion == "" {
					p.ProtocolVersion = protocoloPadrao
				}
				_ = o.json(resposta(m.ID, map[string]any{
					"protocolVersion": p.ProtocolVersion,
					"capabilities":    map[string]any{"tools": map[string]any{"listChanged": false}},
					"serverInfo":      map[string]string{"name": "cofre", "version": cat.Versao},
				}))
			case "ping":
				_ = o.json(resposta(m.ID, map[string]any{}))
			case "tools/list":
				_ = o.json(resposta(m.ID, map[string]any{"tools": cat.Tools}))
			case "tools/call":
				if err := preparar(); err != nil {
					_ = o.json(erroDeFerramenta(m.ID, "O cofre precisa baixar o que usa (uv e Python, "+
						"cerca de 120 MB, uma vez só) e não conseguiu agora: "+err.Error()+
						". Confira a internet e tente de novo; o resto do Claude e a memória seguem funcionando."))
					break
				}
				codigo, err := repassar(leitor, o, linha, initParams, iniciar)
				if err == nil {
					return codigo
				}
				_ = o.json(erroDeFerramenta(m.ID, "O cofre não abriu: "+err.Error()+". Tente de novo."))
			default:
				if m.Method != "" && len(m.ID) > 0 {
					_ = o.json(map[string]any{"jsonrpc": "2.0", "id": m.ID,
						"error": map[string]any{"code": -32601, "message": "método não suportado: " + m.Method}})
				}
			}
		}
		if errLeitura != nil {
			return 0 // o Claude fechou o MCP
		}
	}
}

// repassar sobe o broker, refaz com ele o initialize que o Claude já fez com este processo,
// entrega a chamada pendente e daí em diante só copia as linhas nos dois sentidos. Erro só antes
// de o broker ficar pronto (aí quem chamou responde a ferramenta e segue atendendo).
func repassar(leitor *bufio.Reader, o *saida, pendente []byte, initParams json.RawMessage,
	iniciar func() *exec.Cmd) (int, error) {
	c := iniciar()
	entrada, err := c.StdinPipe()
	if err != nil {
		return 1, err
	}
	saidaBroker, err := c.StdoutPipe()
	if err != nil {
		return 1, err
	}
	if err := c.Start(); err != nil {
		return 1, err
	}
	repassarSinais(c)
	desistir := func(e error) (int, error) {
		entrada.Close()
		_ = c.Process.Kill()
		_ = c.Wait()
		return 1, e
	}
	if len(initParams) == 0 {
		initParams = json.RawMessage(`{"protocolVersion":"` + protocoloPadrao +
			`","capabilities":{},"clientInfo":{"name":"cerebro-plugin","version":"0"}}`)
	}
	ini, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": idIniciar, "method": "initialize",
		"params": initParams})
	if _, err := entrada.Write(append(ini, '\n')); err != nil {
		return desistir(err)
	}
	br := bufio.NewReaderSize(saidaBroker, 1<<20)
	pronto := make(chan error, 1)
	go func() { // a resposta ao nosso initialize não vai para o Claude
		for {
			l, err := br.ReadBytes('\n')
			var m mensagem
			if json.Unmarshal(l, &m) == nil && string(m.ID) == `"`+idIniciar+`"` {
				pronto <- nil
				return
			}
			if err != nil {
				pronto <- errors.New("o broker do cofre fechou ao abrir")
				return
			}
		}
	}()
	select {
	case err := <-pronto:
		if err != nil {
			return desistir(err)
		}
	case <-time.After(esperaBroker):
		return desistir(errors.New("o broker do cofre não respondeu a tempo"))
	}
	avisado := []byte(`{"jsonrpc":"2.0","method":"notifications/initialized"}` + "\n")
	if _, err := entrada.Write(append(avisado, append(bytes.TrimRight(pendente, "\r\n"), '\n')...)); err != nil {
		return desistir(err)
	}
	copiado := make(chan struct{})
	go func() { // broker → Claude
		defer close(copiado)
		for {
			l, err := br.ReadBytes('\n')
			if len(bytes.TrimSpace(l)) > 0 {
				if o.linha(l) != nil {
					return
				}
			}
			if err != nil {
				return
			}
		}
	}()
	_, _ = io.Copy(entrada, leitor) // Claude → broker, até o Claude fechar
	entrada.Close()
	<-copiado
	if err := c.Wait(); err != nil {
		var saiu *exec.ExitError
		if errors.As(err, &saiu) {
			return saiu.ExitCode(), nil
		}
		return 1, nil
	}
	return 0, nil
}
