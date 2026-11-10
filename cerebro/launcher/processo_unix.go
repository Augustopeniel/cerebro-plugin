//go:build !windows

package main

import (
	"os"
	"os/exec"
	"os/signal"
	"syscall"
)

// o preparo em segundo plano sobrevive ao fim do hook
func soltarDoPai(c *exec.Cmd) {
	c.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
}

// o Claude Code encerra o MCP com SIGTERM/SIGINT: repassa ao broker para ele trancar o cofre
func repassarSinais(c *exec.Cmd) {
	sinais := make(chan os.Signal, 4)
	signal.Notify(sinais, syscall.SIGTERM, syscall.SIGINT, syscall.SIGHUP)
	go func() {
		for s := range sinais {
			if c.Process != nil {
				_ = c.Process.Signal(s)
			}
		}
	}()
}
