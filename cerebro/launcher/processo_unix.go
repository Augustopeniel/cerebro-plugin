//go:build !windows

package main

import (
	"os"
	"os/exec"
	"os/signal"
	"syscall"
)

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
