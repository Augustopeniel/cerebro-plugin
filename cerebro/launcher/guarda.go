package main

// Hook PreToolUse do terminal (Bash e PowerShell): barra comandos que leriam um segredo cru.
//
// O cofre entrega valores sem mostrá-los ao Claude (inject, copy, run). Esta guarda fecha os
// atalhos que contornariam isso pelo terminal: ler o Keychain com -w/-g, despejar o Keychain,
// ler as chaves do broker, pedir o valor ao canal local do broker, o `keepassxc-cli show -s`, o
// Gerenciador de Credenciais do Windows, a área de transferência logo depois de um `copy`, o
// ambiente de outros processos (`ps eww`, `ps -E`, /proc/*/environ) e clicar em popups pelo
// osascript com o System Events. É uma camada a mais, não a garantia: a garantia é o valor
// nunca chegar à conversa.

import (
	"encoding/json"
	"fmt"
	"io"
	"regexp"
	"strings"
)

type regra struct {
	padrao *regexp.Regexp
	exceto *regexp.Regexp // linha que casa com esta não é barrada pela regra
	motivo string
}

const (
	// quem lê arquivo (o nome solto conta); quem só busca texto conta só dentro da pasta do broker
	leitores   = `\b(?:cat|less|more|head|tail|xxd|od|hexdump|base64|strings|cp|mv|scp|rsync|tar|zip|dd|nl|tac|openssl|type|gc|Get-Content|Copy-Item)\b[^|;&]*`
	buscadores = `\b(?:grep|egrep|rg|ag|awk|sed|find|xargs)\b[^|;&]*`
	security   = `\bsecurity\s+(?:-\S+\s+)*`
)

var regras = []regra{
	{padrao: regexp.MustCompile(security + `find-(?:generic|internet)-password\b.*\s-[A-Za-z]*[wg][A-Za-z]*(?:\s|$)`),
		motivo: "o `security find-*-password` com -w/-g imprime a senha guardada no Keychain"},
	{padrao: regexp.MustCompile(security + `(?:dump-keychain|export)\b`),
		motivo: "o `security dump-keychain`/`export` despeja segredos do Keychain"},
	{padrao: regexp.MustCompile(security + `-i\b|\|\s*(?:/usr/bin/)?security\b`),
		motivo: "o `security` interativo (comandos pelo stdin) leria senhas do Keychain"},
	{padrao: regexp.MustCompile(`(?i)[/\\~]broker\.key\b|[/\\~]cofre-device-keys\b|\$\{?COFRE_BROKER_KEY|` +
		leitores + `(?:\bbroker\.key\b|\bcofre-device-keys\b|\.claude[/\\]cofre\b)|` +
		buscadores + `\.claude[/\\]cofre\b`),
		motivo: "esses são os arquivos de chave do broker do cofre"},
	{padrao: regexp.MustCompile(`(?i)\b(?:nc|ncat|netcat|socat|curl|python[0-9.]*|node|perl|ruby|php|osascript)\b.*(?:broker\.sock|\.claude[/\\]cofre\b|pipe[/\\]+cofre-broker)`),
		motivo: "o canal local do broker entrega valores em claro: só os MCPs falam com ele"},
	{padrao: regexp.MustCompile(`\bcofre_run(?:\.py)?\b.*--consumer|\bimport\s+cofre_client\b|\bcofre_client\.(?:valor|grupo)\b`),
		motivo: "o `cofre_run`/`cofre_client` põe valores do cofre ao alcance do comando"},
	{padrao: regexp.MustCompile(`\bkeepassxc-cli\b.*\b(?:show\b.*(?:\s-s\b|--show-protected)|export|clip)\b`),
		motivo: "o `keepassxc-cli` mostraria ou copiaria a senha"},
	{padrao: regexp.MustCompile(`(?i)\bcmdkey(?:\.exe)?\b`),
		motivo: "o `cmdkey` mexe no Gerenciador de Credenciais"},
	{padrao: regexp.MustCompile(`(?i)Get-StoredCredential|\bCredRead|PasswordVault|RetrievePassword|GetNetworkCredential|\bGet-Secret\b|\bvaultcmd\b|PtrToStringBSTR|PtrToStringAuto|PtrToStringUni|ConvertFrom-SecureString|SecureStringToBSTR`),
		motivo: "o PowerShell leria uma credencial guardada em claro"},
	{padrao: regexp.MustCompile(`(?i)\bpbpaste\b|Get-Clipboard|\bxclip\b.*\s-o\b|\bxsel\b.*(?:\s-o\b|--output)|\bwl-paste\b|\bosascript\b.*the clipboard`),
		motivo: "ler a área de transferência pegaria o valor de um `copy` do cofre"},
	{padrao: regexp.MustCompile(`(?i)\bkeyring\s+get\b|keyring\.get_password`),
		motivo: "o `keyring get` imprime a senha guardada no cofre do sistema"},
	// qualquer programa que fale com o canal ou leia a chave dele; buscar o nome no código
	// (grep, rg, git grep…) segue livre
	{padrao: regexp.MustCompile(`(?i)\bbroker\.(?:sock|key)\b|\$\{?COFRE_SOCKET\b`),
		exceto: regexp.MustCompile(`(?i)^\s*(?:grep|egrep|fgrep|rg|ag|ack|git\s+(?:grep|log|diff|show))\b`),
		motivo: "o canal local do broker (`broker.sock`/`broker.key`) entrega valores em claro"},
	// BSD: `ps e`, `ps eww`, `ps auxe` (sem traço) e `-E` mostram o ambiente dos processos
	{padrao: regexp.MustCompile("(?:^|[;&|(`]|\\$\\(|\\b(?:sudo|exec|command|env|nohup|watch))\\s*(?:\\S*/)?ps\\s+" +
		`(?:[A-Za-z]*e[A-Za-z]*(?:\s|$|[;&|)])|(?:[^;&|\s]+\s+)*-[A-Za-z]*E[A-Za-z]*\b)`),
		motivo: "o `ps` com `e`/`eww`/`-E` mostra o ambiente de outros processos (onde ficam valores do `run`)"},
	{padrao: regexp.MustCompile(`/proc/\S*environ|/proc/\S*/[^\s/]*[*?\[]`),
		motivo: "o `/proc/*/environ` mostra o ambiente de outros processos (onde ficam valores do `run`)"},
}

// vistas no comando inteiro (um script do osascript pode ocupar várias linhas)
var regrasDoTodo = []regra{
	{padrao: regexp.MustCompile(`(?is)\bosascript\b.*System Events.*\b(?:click|keystroke|key code|perform action)\b|\bosascript\b.*\b(?:click|keystroke|key code|perform action)\b.*System Events|Application\(\s*["']System Events`),
		motivo: "clicar ou teclar pelo System Events aprovaria um popup do cofre no lugar do usuário"},
	// a caixa de OK do cofre (um destrave por dia) só vale se quem clica é a pessoa: simular
	// teclado ou mouse pelo terminal aprovaria no lugar dela
	{padrao: regexp.MustCompile(`(?i)\bcliclick\b|\bxdotool\s+(?:\S+\s+)*(?:key|click|type|mousedown|mouseup)\b|\bydotool\b|SendKeys|\bSendWait\b|\bmouse_event\b|\bkeybd_event\b|\bSendInput\b|InvokePattern|\bAppActivate\b`),
		motivo: "simular teclado ou clique aprovaria uma caixa do cofre no lugar do usuário"},
}

const mensagemDaGuarda = "Bloqueado pelo cofre do cérebro: %s. O Claude nunca lê segredo cru. Use as " +
	"ferramentas do MCP `cofre` (`inject` digita, `copy` copia, `run` põe no ambiente de um " +
	"comando com a saída mascarada); para cadastrar, `store` (os dados do chat, o valor no popup).\n"

// motivo do bloqueio, ou "" se o comando pode rodar
func conferir(comando string) string {
	junto := strings.ReplaceAll(strings.ReplaceAll(comando, "\r\n", "\n"), "\\\n", " ")
	for _, linha := range strings.Split(junto, "\n") {
		for _, r := range regras {
			if r.padrao.MatchString(linha) && (r.exceto == nil || !r.exceto.MatchString(linha)) {
				return r.motivo
			}
		}
	}
	for _, r := range regrasDoTodo {
		if r.padrao.MatchString(junto) {
			return r.motivo
		}
	}
	return ""
}

// as ferramentas de arquivo do Claude (Read, Grep, Edit, Write…) não passam pelo terminal: a
// guarda também confere o caminho delas
var (
	pastaDoCofre   = regexp.MustCompile(`(?i)[/\\]\.claude[/\\]cofre(?:[/\\]|$)|broker\.(?:key|sock)\b|cofre-device-keys\b`)
	codigoDoPlugin = regexp.MustCompile(`(?i)[/\\]\.claude[/\\]plugins[/\\](?:cache[/\\]cerebro-vivo|data[/\\]cerebro-)`)
	escritores     = map[string]bool{"Edit": true, "Write": true, "MultiEdit": true, "NotebookEdit": true}
)

// motivo do bloqueio de uma ferramenta de arquivo, ou ""
func conferirArquivo(ferramenta string, caminhos ...string) string {
	for _, c := range caminhos {
		if c == "" {
			continue
		}
		if pastaDoCofre.MatchString(c) {
			return "a pasta do broker do cofre guarda a chave do canal e o socket (entregam valores em claro)"
		}
		if escritores[ferramenta] && codigoDoPlugin.MatchString(c) {
			return "o código e o ambiente do broker instalado não se alteram por aqui (um broker alterado pularia a confirmação)"
		}
	}
	return ""
}

// lê o JSON do hook; barra com código 2 e a explicação no stderr
func guarda(entrada io.Reader, erro io.Writer) int {
	dado, err := io.ReadAll(entrada)
	if err != nil {
		return 0
	}
	var evento struct {
		ToolName  string `json:"tool_name"`
		ToolInput struct {
			Command      any    `json:"command"`
			FilePath     string `json:"file_path"`
			NotebookPath string `json:"notebook_path"`
			Path         string `json:"path"`
			Pattern      string `json:"pattern"`
			Glob         string `json:"glob"`
		} `json:"tool_input"`
	}
	if json.Unmarshal(dado, &evento) != nil {
		return 0 // não é conosco
	}
	in := evento.ToolInput
	if motivo := conferirArquivo(evento.ToolName, in.FilePath, in.NotebookPath, in.Path,
		map[bool]string{true: in.Pattern}[evento.ToolName == "Glob"], in.Glob); motivo != "" {
		fmt.Fprintf(erro, mensagemDaGuarda, motivo)
		return 2
	}
	comando, ok := in.Command.(string)
	if !ok {
		return 0
	}
	if motivo := conferir(comando); motivo != "" {
		fmt.Fprintf(erro, mensagemDaGuarda, motivo)
		return 2
	}
	return 0
}
