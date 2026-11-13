package main

// SSH_ASKPASS do conector SSH do cofre onde não há FIFO (Windows): o ssh chama este binário com
// o prompt ("usuario@host's password: ") e o ambiente que o broker pôs só para aquela conexão
// (porta de um socket TCP em 127.0.0.1 e um token de uso único). Este processo não guarda nem
// sabe segredo nenhum: pergunta ao broker, que só responde ao prompt exato de um salto conhecido,
// uma vez por conexão. Resposta vazia (ou qualquer erro): sai com 1 e o ssh não recebe nada.
//
// Quem decide é o broker, não este processo: antes de ler o pedido, ele acha pela tabela TCP do
// Windows o pid de quem conectou e só segue se for descendente do ssh que ele acabou de lançar.
// Um processo de fora, mesmo com a porta e o bilhete (o ambiente do ssh é legível pelo mesmo
// usuário), não recebe nada: o broker desarma, mata o ssh e registra.

import (
	"bufio"
	"encoding/base64"
	"encoding/json"
	"net"
	"os"
	"strings"
	"time"
)

// só com a variável E um argumento único com cara de prompt de senha: a guarda (hook) e os
// outros comandos não caem neste modo por uma variável que vazou para o ambiente
func emModoAskpass() bool {
	if os.Getenv("CEREBRO_ASKPASS_BILHETE") == "" || len(os.Args) != 2 {
		return false
	}
	p := strings.TrimSpace(os.Args[1])
	return strings.HasSuffix(p, "password:") && strings.Contains(p, "@")
}

func askpass(args []string) int {
	porta, token := os.Getenv("CEREBRO_ASKPASS_PORTA"), os.Getenv("CEREBRO_ASKPASS_BILHETE")
	if porta == "" || token == "" || len(args) == 0 {
		return 1
	}
	conn, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", porta), 5*time.Second)
	if err != nil {
		return 1
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	pedido, _ := json.Marshal(map[string]string{"t": token, "p": strings.Join(args, " ")})
	if _, err := conn.Write(append(pedido, '\n')); err != nil {
		return 1
	}
	linha, err := bufio.NewReader(conn).ReadBytes('\n')
	if err != nil && len(linha) == 0 {
		return 1
	}
	var resposta struct {
		B string `json:"b"`
	}
	if json.Unmarshal(linha, &resposta) != nil || resposta.B == "" {
		return 1
	}
	segredo, err := base64.StdEncoding.DecodeString(resposta.B)
	if err != nil {
		return 1
	}
	_, err = os.Stdout.Write(append(segredo, '\n'))
	if err != nil {
		return 1
	}
	return 0
}
