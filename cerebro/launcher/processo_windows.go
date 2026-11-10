//go:build windows

package main

import (
	"os"
	"os/exec"
	"os/signal"
	"syscall"
)

const (
	detachedProcess       = 0x00000008
	createNewProcessGroup = 0x00000200
	createNoWindow        = 0x08000000
)

// o preparo em segundo plano sobrevive ao fim do hook, sem abrir janela de console
func soltarDoPai(c *exec.Cmd) {
	c.SysProcAttr = &syscall.SysProcAttr{
		CreationFlags: detachedProcess | createNewProcessGroup | createNoWindow,
		HideWindow:    true,
	}
}

// no Windows o broker termina quando o stdin fecha; o Ctrl+C chega ao grupo inteiro
func repassarSinais(c *exec.Cmd) {
	signal.Ignore(os.Interrupt)
}
