//go:build linux

package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

func isOpenWRT() bool {
	_, err := os.Stat("/etc/openwrt_release")
	return err == nil
}

func hasSystemd() bool {
	_, err := os.Stat("/run/systemd/system")
	return err == nil
}

func installSchedule(cfg Config, interval time.Duration) error {
	if err := validateInterval(interval); err != nil {
		return err
	}
	args, err := runArgs(cfg)
	if err != nil {
		return err
	}
	switch {
	case isOpenWRT():
		return installOpenWRTCron(args, interval)
	case hasSystemd():
		return installSystemd(args, interval)
	default:
		return installCrontab(args, interval)
	}
}

func uninstallSchedule() error {
	switch {
	case isOpenWRT():
		return removeOpenWRTCron()
	case hasSystemd():
		return removeSystemd()
	default:
		return removeCrontab()
	}
}

// --- systemd ---

func systemdPaths() (unitDir string, user bool) {
	if os.Geteuid() == 0 {
		return "/etc/systemd/system", false
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".config", "systemd", "user"), true
}

func installSystemd(args []string, interval time.Duration) error {
	unitDir, user := systemdPaths()
	if err := os.MkdirAll(unitDir, 0o755); err != nil {
		return err
	}
	service := fmt.Sprintf(`[Unit]
Description=Verify and install signed SSH authorized_keys

[Service]
Type=oneshot
ExecStart=%s
`, shellJoin(args))
	// In-binary splay handles desync, so no RandomizedDelaySec here. The timer
	// fires shortly after boot, then on the requested cadence.
	timer := fmt.Sprintf(`[Unit]
Description=Periodic SSH authorized_keys update

[Timer]
OnBootSec=2min
OnUnitActiveSec=%d
Persistent=true

[Install]
WantedBy=timers.target
`, int(interval.Seconds()))

	if err := os.WriteFile(filepath.Join(unitDir, "ssh-keys-updater.service"), []byte(service), 0o644); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(unitDir, "ssh-keys-updater.timer"), []byte(timer), 0o644); err != nil {
		return err
	}

	sc := func(a ...string) *exec.Cmd {
		if user {
			a = append([]string{"--user"}, a...)
		}
		return exec.Command("systemctl", a...)
	}
	_ = sc("daemon-reload").Run()
	if out, err := sc("enable", "--now", "ssh-keys-updater.timer").CombinedOutput(); err != nil {
		return fmt.Errorf("systemctl enable: %v: %s", err, out)
	}
	if user {
		logf("note: for the timer to run while you are logged out, enable lingering: loginctl enable-linger %s", os.Getenv("USER"))
	}
	logf("installed systemd timer (every %s)", interval)
	return nil
}

func removeSystemd() error {
	unitDir, user := systemdPaths()
	sc := func(a ...string) *exec.Cmd {
		if user {
			a = append([]string{"--user"}, a...)
		}
		return exec.Command("systemctl", a...)
	}
	_ = sc("disable", "--now", "ssh-keys-updater.timer").Run()
	_ = os.Remove(filepath.Join(unitDir, "ssh-keys-updater.timer"))
	_ = os.Remove(filepath.Join(unitDir, "ssh-keys-updater.service"))
	_ = sc("daemon-reload").Run()
	return nil
}

// --- generic crontab ---

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

// --- OpenWRT (busybox cron) ---

func installOpenWRTCron(args []string, interval time.Duration) error {
	const path = "/etc/crontabs/root"
	line := fmt.Sprintf("%s %s %s", cronSpec(interval), shellJoin(args), cronMarker)
	data, _ := os.ReadFile(path)
	var kept []string
	for _, l := range strings.Split(string(data), "\n") {
		if l != "" && !strings.Contains(l, cronMarker) {
			kept = append(kept, l)
		}
	}
	kept = append(kept, line)
	if err := os.MkdirAll("/etc/crontabs", 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(path, []byte(strings.Join(kept, "\n")+"\n"), 0o600); err != nil {
		return err
	}
	_ = exec.Command("/etc/init.d/cron", "enable").Run()
	_ = exec.Command("/etc/init.d/cron", "restart").Run()
	logf("installed OpenWRT cron entry in %s (%s)", path, cronSpec(interval))
	return nil
}

func removeOpenWRTCron() error {
	const path = "/etc/crontabs/root"
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var kept []string
	for _, l := range strings.Split(string(data), "\n") {
		if l != "" && !strings.Contains(l, cronMarker) {
			kept = append(kept, l)
		}
	}
	if err := os.WriteFile(path, []byte(strings.Join(kept, "\n")+"\n"), 0o600); err != nil {
		return err
	}
	_ = exec.Command("/etc/init.d/cron", "restart").Run()
	return nil
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
