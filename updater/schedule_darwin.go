//go:build darwin

package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// On macOS we use launchd by default. A per-user LaunchAgent when running as
// a normal user, or a LaunchDaemon when running as root (so root's
// authorized_keys is maintained even with no GUI session). A per-user
// LaunchAgent needs the gui/<uid> launchd domain, which only exists once that
// user has an active Aqua (loginwindow) session — an account used only over
// SSH (e.g. a dedicated key-management user on a shared Mac) never gets one,
// and `launchctl bootstrap` fails with "Domain does not support specified
// action". Pass -scheduler cron to installSchedule/system-install to use a
// plain crontab entry instead, which runs regardless of GUI login state.
func plistPath() (string, bool, error) {
	if os.Geteuid() == 0 {
		return filepath.Join("/Library/LaunchDaemons", label+".plist"), true, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", false, err
	}
	return filepath.Join(home, "Library", "LaunchAgents", label+".plist"), false, nil
}

func installSchedule(cfg Config, interval time.Duration, exe string, useCron bool) error {
	if err := validateInterval(interval); err != nil {
		return err
	}
	args := runArgs(cfg, exe)
	if useCron {
		return installCrontab(args, interval)
	}
	path, isDaemon, err := plistPath()
	if err != nil {
		return err
	}

	var progArgs strings.Builder
	for _, a := range args {
		fmt.Fprintf(&progArgs, "    <string>%s</string>\n", xmlEscape(a))
	}
	logPath := filepath.Join(filepath.Dir(cfg.AuthorizedKeys), ".ssh-keys-updater.log")

	plist := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>%s</string>
  <key>ProgramArguments</key>
  <array>
%s  </array>
  <key>StartInterval</key><integer>%d</integer>
  <key>RunAtLoad</key><false/>
  <key>StandardOutPath</key><string>%s</string>
  <key>StandardErrorPath</key><string>%s</string>
</dict>
</plist>
`, label, progArgs.String(), int(interval.Seconds()), xmlEscape(logPath), xmlEscape(logPath))

	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(path, []byte(plist), 0o644); err != nil {
		return err
	}

	// Reload: bootout (ignore error if not loaded) then bootstrap.
	domain := "gui/" + fmt.Sprint(os.Getuid())
	if isDaemon {
		domain = "system"
	}
	_ = exec.Command("launchctl", "bootout", domain+"/"+label).Run()
	if out, err := exec.Command("launchctl", "bootstrap", domain, path).CombinedOutput(); err != nil {
		return fmt.Errorf("launchctl bootstrap: %v: %s", err, out)
	}
	logf("installed launchd job %s (every %s) -> %s", label, interval, path)
	return nil
}

func uninstallSchedule() error {
	path, isDaemon, err := plistPath()
	if err != nil {
		return err
	}
	domain := "gui/" + fmt.Sprint(os.Getuid())
	if isDaemon {
		domain = "system"
	}
	_ = exec.Command("launchctl", "bootout", domain+"/"+label).Run()
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return err
	}
	// installSchedule may have used cron even though a plist also exists from
	// a prior run (-scheduler cron); remove any crontab entry too, best-effort.
	return removeCrontab()
}

func xmlEscape(s string) string {
	r := strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;")
	return r.Replace(s)
}
