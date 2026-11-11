package main

// Cofre local sem nada instalado antes: o lançador baixa uma cópia fixa do uv (conferida pelo
// SHA-256 gravado aqui), e o uv baixa o Python e as bibliotecas do broker. Tudo fica na pasta de
// dados do plugin; nada vai para o sistema nem para o PATH.

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

const (
	versaoUV     = "0.13.7"
	versaoPython = "3.13"
)

// SHA-256 dos pacotes oficiais do uv (github.com/astral-sh/uv/releases), por sistema
var somasUV = map[string]string{
	"aarch64-apple-darwin.tar.gz":      "81b811b57e4624df7ed3aac148e0359100d9962f3d9dce00aec533dc2e086731",
	"x86_64-apple-darwin.tar.gz":       "20c47e4c1f630b8abaff8c291fa9b9aa300fef92c4fbff95adf198b55287cda7",
	"aarch64-pc-windows-msvc.zip":      "505d9e65e7692bac3ddf98c66754aa26c5050c409c184af30a881a0a72cc85e3",
	"x86_64-pc-windows-msvc.zip":       "0cdc5b38fe5a8168ed6a25814f5ba43c21d313dd3187314fccb37b7cec46e021",
	"aarch64-unknown-linux-gnu.tar.gz": "71279f8d3c67241e807b9d8db872d1bf541579fb9f08b7d1eb1682196d1e57dc",
	"x86_64-unknown-linux-gnu.tar.gz":  "c5221ff41b7892bfc223543883600125f6a47fe845093e0f5bdff4f359196d83",
}

func pacoteUV() (string, error) {
	arq := map[string]string{"arm64": "aarch64", "amd64": "x86_64"}[runtime.GOARCH]
	sis := map[string]string{
		"darwin": "apple-darwin.tar.gz", "windows": "pc-windows-msvc.zip", "linux": "unknown-linux-gnu.tar.gz",
	}[runtime.GOOS]
	nome := arq + "-" + sis
	if arq == "" || sis == "" || somasUV[nome] == "" {
		return "", fmt.Errorf("sistema sem suporte: %s/%s", runtime.GOOS, runtime.GOARCH)
	}
	return nome, nil
}

func exe(nome string) string {
	if runtime.GOOS == "windows" {
		return nome + ".exe"
	}
	return nome
}

func (p *perfil) pastaRuntime() string { return filepath.Join(p.dados, "runtime") }
func (p *perfil) caminhoUV() string {
	return filepath.Join(p.pastaRuntime(), "uv-"+versaoUV, exe("uv"))
}
func (p *perfil) broker() string { return filepath.Join(p.raiz, "broker") }

// ambiente do uv: Python e bibliotecas só na pasta do plugin
func (p *perfil) ambienteUV() []string {
	rt := p.pastaRuntime()
	env := []string{
		"UV_CACHE_DIR=" + filepath.Join(rt, "cache"),
		"UV_PYTHON_INSTALL_DIR=" + filepath.Join(rt, "python"),
		"UV_PROJECT_ENVIRONMENT=" + filepath.Join(rt, "venv-cofre"),
		"UV_PYTHON=" + versaoPython,
		"UV_PYTHON_PREFERENCE=only-managed",
		"UV_PYTHON_DOWNLOADS=automatic",
		"UV_NATIVE_TLS=1", // certificados do sistema (redes com inspeção de TLS)
		"UV_NO_PROGRESS=1",
		"UV_NO_CONFIG=1",
		"CLAUDE_PLUGIN_DATA=" + p.dados,
	}
	var fora []string
	for _, kv := range os.Environ() {
		if !strings.HasPrefix(kv, "UV_") && !strings.HasPrefix(kv, "VIRTUAL_ENV=") {
			fora = append(fora, kv)
		}
	}
	return append(fora, env...)
}

func (p *perfil) argsDoUV(cmd ...string) []string {
	args := []string{"run", "--quiet", "--project", p.broker(), "--no-dev"}
	if _, err := os.Stat(filepath.Join(p.broker(), "uv.lock")); err == nil {
		args = append(args, "--frozen")
	}
	return append(args, cmd...)
}

// ---------- trava entre processos (hook e MCP podem preparar ao mesmo tempo) ----------

func (p *perfil) travar(espera time.Duration) (func(), error) {
	if err := os.MkdirAll(p.pastaRuntime(), 0o700); err != nil {
		return nil, err
	}
	trava := filepath.Join(p.pastaRuntime(), ".preparando")
	fim := time.Now().Add(espera)
	for {
		f, err := os.OpenFile(trava, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if err == nil {
			fmt.Fprintf(f, "%d\n", os.Getpid())
			f.Close()
			return func() { os.Remove(trava) }, nil
		}
		if info, e := os.Stat(trava); e == nil && time.Since(info.ModTime()) > 10*time.Minute {
			os.Remove(trava) // sobra de um processo que morreu
			continue
		}
		if time.Now().After(fim) {
			return nil, errors.New("outro processo ainda está preparando o cofre")
		}
		time.Sleep(300 * time.Millisecond)
	}
}

// ---------- uv ----------

func (p *perfil) garantirUV() (string, error) {
	uv := p.caminhoUV()
	if _, err := os.Stat(uv); err == nil {
		return uv, nil
	}
	nome, err := pacoteUV()
	if err != nil {
		return "", err
	}
	url := fmt.Sprintf("https://github.com/astral-sh/uv/releases/download/%s/uv-%s", versaoUV, nome)
	cliente := &http.Client{Timeout: 5 * time.Minute}
	resp, err := cliente.Get(url)
	if err != nil {
		return "", fmt.Errorf("baixar o uv: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("baixar o uv: HTTP %d", resp.StatusCode)
	}
	pacote, err := io.ReadAll(io.LimitReader(resp.Body, 200<<20))
	if err != nil {
		return "", fmt.Errorf("baixar o uv: %w", err)
	}
	soma := sha256.Sum256(pacote)
	if hex.EncodeToString(soma[:]) != somasUV[nome] {
		return "", errors.New("o pacote do uv baixado não confere com o SHA-256 esperado; nada foi instalado")
	}
	binario, err := extrairUV(pacote, strings.HasSuffix(nome, ".zip"))
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(filepath.Dir(uv), 0o700); err != nil {
		return "", err
	}
	tmp := uv + ".tmp"
	if err := os.WriteFile(tmp, binario, 0o700); err != nil {
		return "", err
	}
	return uv, os.Rename(tmp, uv)
}

func extrairUV(pacote []byte, ehZip bool) ([]byte, error) {
	alvo := exe("uv")
	if ehZip {
		z, err := zip.NewReader(bytes.NewReader(pacote), int64(len(pacote)))
		if err != nil {
			return nil, err
		}
		for _, f := range z.File {
			if filepath.Base(f.Name) == alvo {
				r, err := f.Open()
				if err != nil {
					return nil, err
				}
				defer r.Close()
				return io.ReadAll(io.LimitReader(r, 200<<20))
			}
		}
		return nil, errors.New("uv não encontrado no pacote")
	}
	gz, err := gzip.NewReader(bytes.NewReader(pacote))
	if err != nil {
		return nil, err
	}
	t := tar.NewReader(gz)
	for {
		h, err := t.Next()
		if err != nil {
			return nil, errors.New("uv não encontrado no pacote")
		}
		if h.Typeflag == tar.TypeReg && filepath.Base(h.Name) == alvo {
			return io.ReadAll(io.LimitReader(t, 200<<20))
		}
	}
}

// ---------- preparar e rodar ----------

// baixa uv, Python e bibliotecas do broker; repetir é barato (o uv confere e não refaz)
func (p *perfil) prepararAgora(espera time.Duration) error {
	soltar, err := p.travar(espera)
	if err != nil {
		return err
	}
	defer soltar()
	uv, err := p.garantirUV()
	if err != nil {
		return err
	}
	c := exec.Command(uv, p.argsDoUV("python", "-c", "import cofre_broker")...)
	c.Env = p.ambienteUV()
	saida, err := c.CombinedOutput()
	if err != nil {
		return fmt.Errorf("preparar o Python do cofre: %v: %s", err, strings.TrimSpace(string(saida)))
	}
	return os.WriteFile(p.marcaPronto(), []byte(versaoUV+" "+versaoPython+"\n"), 0o600)
}

func (p *perfil) marcaPronto() string { return filepath.Join(p.pastaRuntime(), "pronto-"+versaoUV) }

func (p *perfil) preparar() int {
	if err := p.prepararAgora(10 * time.Minute); err != nil {
		fmt.Fprintln(os.Stderr, "cofre:", err)
		return 1
	}
	fmt.Println("cofre local pronto (uv " + versaoUV + ", Python " + versaoPython + ")")
	return 0
}

// do hook de início: adianta o download sem segurar a sessão
func (p *perfil) prepararEmSegundoPlano() {
	if _, err := os.Stat(p.marcaPronto()); err == nil || os.Getenv("CEREBRO_SEM_DOWNLOAD") == "1" {
		return
	}
	eu, err := os.Executable()
	if err != nil {
		return
	}
	c := exec.Command(eu, "preparar", p.dados)
	c.Env = append(os.Environ(), "CEREBRO_PLUGIN_ROOT="+p.raiz)
	soltarDoPai(c)
	if c.Start() == nil {
		_ = c.Process.Release()
	}
}

func (p *perfil) estadoDoCofre() string {
	if _, err := os.Stat(p.marcaPronto()); err == nil {
		return "pronto (uv " + versaoUV + " e Python " + versaoPython + " em " + p.pastaRuntime() + ")"
	}
	return "ainda não preparado (baixa sozinho na próxima abertura, ou rode `cerebro-plugin preparar`)"
}

// MCP e comandos do cofre: prepara se faltar e entrega stdin/stdout ao broker
func (p *perfil) cofre(args []string) int {
	if _, err := os.Stat(p.marcaPronto()); err != nil {
		if err := p.prepararAgora(3 * time.Minute); err != nil {
			fmt.Fprintln(os.Stderr, "cofre:", err)
			return 1
		}
	}
	// pelo python do venv, não pelo cerebro-cofre.exe que o uv gera: políticas de empresa
	// (AppLocker/WDAC, antivírus) barram esse executável no Windows e o MCP cai ao subir
	modulo := append([]string{"python", "-m", "cofre_broker.cli"}, args...)
	c := exec.Command(p.caminhoUV(), p.argsDoUV(modulo...)...)
	c.Env = p.ambienteUV()
	c.Stdin, c.Stdout, c.Stderr = os.Stdin, os.Stdout, os.Stderr
	repassarSinais(c)
	if err := c.Run(); err != nil {
		var saiu *exec.ExitError
		if errors.As(err, &saiu) {
			return saiu.ExitCode()
		}
		fmt.Fprintln(os.Stderr, "cofre:", err)
		return 1
	}
	return 0
}
