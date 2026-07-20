package main

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"
)

// label identifies the scheduled job across all platforms.
const label = "com.illixion.ssh-keys-updater"

// runArgs reconstructs the argv the scheduler should invoke, using `exe` as the
// binary path. The scheduled run takes no domain/URL: it reads the saved location
// from the sidecar next to authorized_keys, re-fetches discovery, and applies the
// saved splay. We only need to pin the file paths and the TLS flag. `system-install`
// passes the installed system path so the unit references a stable location.
func runArgs(cfg Config, exe string) []string {
	args := []string{exe, "run", "-scheduled",
		"-authorized-keys", cfg.AuthorizedKeys,
		"-local-file", cfg.LocalFile,
	}
	if cfg.InsecureTLS {
		args = append(args, "-insecure-tls")
	}
	return args
}

// currentExe is the running binary's path, used by `install` so the scheduler
// references wherever the binary currently sits.
func currentExe() (string, error) { return os.Executable() }

func validateInterval(d time.Duration) error {
	if d < time.Minute {
		return fmt.Errorf("interval must be at least 1m, got %s", d)
	}
	return nil
}

// cronSpec returns the "min hour dom mon dow" fields for the given interval.
// Sub-hour intervals that divide 60 use minute stepping (e.g. 15m -> */15);
// otherwise it falls back to hourly stepping.
func cronSpec(d time.Duration) string {
	m := int(d.Minutes())
	switch {
	case m >= 1 && m < 60 && 60%m == 0:
		return fmt.Sprintf("*/%d * * * *", m)
	case m == 60:
		return "0 * * * *"
	default:
		h := int(d.Hours())
		if h < 1 {
			h = 1
		}
		return fmt.Sprintf("0 */%d * * *", h)
	}
}

// Generic crontab install/removal, shared by any platform whose native
// scheduler is unavailable or explicitly overridden (-scheduler cron) — e.g.
// a macOS account with no GUI login session, where launchd's gui/<uid>
// domain never comes into existence.
const cronMarker = "# ssh-keys-updater"

func installCrontab(args []string, interval time.Duration) error {
	line := fmt.Sprintf("%s %s %s", cronSpec(interval), shellJoin(args), cronMarker)
	existing, _ := exec.Command("crontab", "-l").Output()
	var kept []string
	for _, l := range strings.Split(string(existing), "\n") {
		if l != "" && !strings.Contains(l, cronMarker) {
			kept = append(kept, l)
		}
	}
	kept = append(kept, line)
	cmd := exec.Command("crontab", "-")
	cmd.Stdin = strings.NewReader(strings.Join(kept, "\n") + "\n")
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("crontab install: %v: %s", err, out)
	}
	logf("installed crontab entry (%s)", cronSpec(interval))
	return nil
}

func removeCrontab() error {
	existing, err := exec.Command("crontab", "-l").Output()
	if err != nil {
		return nil // no crontab
	}
	var kept []string
	for _, l := range strings.Split(string(existing), "\n") {
		if l != "" && !strings.Contains(l, cronMarker) {
			kept = append(kept, l)
		}
	}
	cmd := exec.Command("crontab", "-")
	cmd.Stdin = strings.NewReader(strings.Join(kept, "\n") + "\n")
	return cmd.Run()
}

// shellJoin quotes args for embedding in a crontab/systemd ExecStart line.
func shellJoin(args []string) string {
	q := make([]string, len(args))
	for i, a := range args {
		if a == "" || strings.ContainsAny(a, " \t\"'\\$`") {
			q[i] = "'" + strings.ReplaceAll(a, "'", `'\''`) + "'"
		} else {
			q[i] = a
		}
	}
	return strings.Join(q, " ")
}
