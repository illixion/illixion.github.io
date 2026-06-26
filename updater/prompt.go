package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

// One shared reader so successive prompts don't drop buffered stdin.
var stdinReader = bufio.NewReader(os.Stdin)

// interactive reports whether we may prompt the user — i.e. stdin is a real
// terminal. Scheduled (cron/launchd/systemd/schtasks) runs are not, so they
// never block on a prompt.
func interactive() bool {
	fi, err := os.Stdin.Stat()
	return err == nil && fi.Mode()&os.ModeCharDevice != 0
}

// ask prints an SSH-style prompt to stderr and returns the trimmed line.
func ask(label string) string {
	fmt.Fprint(os.Stderr, label)
	line, _ := stdinReader.ReadString('\n')
	return strings.TrimSpace(line)
}

// confirm asks a [Y/n] question (default yes).
func confirm(label string) bool {
	a := strings.ToLower(ask(label + " [Y/n]: "))
	return a == "" || a == "y" || a == "yes"
}
