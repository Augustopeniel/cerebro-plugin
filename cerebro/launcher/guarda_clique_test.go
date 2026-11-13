package main

import "testing"

// a caixa de OK do cofre (um destrave por dia) só vale se quem clica é a pessoa
func TestGuardaBarraCliqueETecladoSimulados(t *testing.T) {
	barrados := []string{
		`osascript -e 'tell application "System Events" to click button "OK" of window 1'`,
		`osascript -e 'tell application "System Events" to keystroke return'`,
		"osascript <<'EOF'\ntell application \"System Events\"\n  key code 36\nend tell\nEOF",
		`osascript -l JavaScript -e 'Application("System Events").keystroke("\r")'`,
		`cliclick c:500,300`,
		`xdotool search --name Cofre key Return`,
		`ydotool key 28:1 28:0`,
		`powershell -c "[System.Windows.Forms.SendKeys]::SendWait('{ENTER}')"`,
		`$wsh.AppActivate('Cofre'); $wsh.SendKeys('~')`,
	}
	for _, c := range barrados {
		if conferir(c) == "" {
			t.Errorf("deveria barrar: %s", c)
		}
	}
	livres := []string{
		`osascript -e 'display notification "pronto"'`,
		`echo "System Events"`,
		`xdotool getactivewindow getwindowname`,
	}
	for _, c := range livres {
		if m := conferir(c); m != "" {
			t.Errorf("não deveria barrar %q: %s", c, m)
		}
	}
}
