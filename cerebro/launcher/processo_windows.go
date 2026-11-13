//go:build windows

package main

import (
	"os"
	"os/exec"
	"os/signal"
)

// no Windows o broker termina quando o stdin fecha; o Ctrl+C chega ao grupo inteiro
func repassarSinais(c *exec.Cmd) {
	signal.Ignore(os.Interrupt)
}
