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

func installSchedule(cfg Config, interval time.Duration, exe string, useCron bool) error {
	if err := validateInterval(interval); err != nil {
		return err
	}
	args := runArgs(cfg, exe)
	switch {
	case useCron:
		return installCrontab(args, interval)
	case isOpenWRT():
		return installOpenWRTCron(args, interval)
	case hasSystemd():
		return installSystemd(args, interval)
	default:
		return installCrontab(args, interval)
	}
}

func uninstallSchedule() error {
	// Remove whichever backend is native, then also remove any crontab entry
	// best-effort — installSchedule may have used cron even when a native
	// backend is present (-scheduler cron), and removeCrontab is a no-op if
	// there's no marked entry.
	switch {
	case isOpenWRT():
		return removeOpenWRTCron()
	case hasSystemd():
		if err := removeSystemd(); err != nil {
			return err
		}
		return removeCrontab()
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
	// fires shortly after the timer UNIT itself is (re)started, then on the
	// requested cadence. OnActiveSec (not OnBootSec, and not OnStartupSec)
	// deliberately, after getting both of those wrong first:
	//   - OnBootSec is relative to the actual machine boot. A --user manager
	//     can restart independent of a reboot (e.g. the installing SSH
	//     session's PAM scope tearing down before `loginctl enable-linger`
	//     takes effect, or a manager crash). Once that boot-relative deadline
	//     has passed — true for any manager restart hours/days into an
	//     uptime — OnUnitActiveSec has no prior activation of its own to
	//     count from and the timer never re-arms: stuck at infinity,
	//     silently, with no error anywhere. Reproduced on a live host: the
	//     timer fired exactly once at install and then never again for two
	//     months.
	//   - OnStartupSec looked like the fix (relative to the manager's own
	//     start instead of boot) but it's a single timestamp captured once
	//     per manager process lifetime — restarting the *timer unit* later
	//     (e.g. re-running install to roll out this very fix) does not move
	//     it, so a deadline already in the past stays in the past forever.
	//     Verified this does NOT self-heal a stuck install.
	//   - OnActiveSec is relative to when the timer UNIT was last activated,
	//     which happens both at initial install and at every later
	//     start/restart (including whatever brings a fresh manager back up
	//     after a crash, since it starts all WantedBy=timers.target units).
	//     Verified live: switching to it produced an immediate, real
	//     NextElapseUSec instead of infinity.
	timer := fmt.Sprintf(`[Unit]
Description=Periodic SSH authorized_keys update

[Timer]
OnActiveSec=2min
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
	if out, err := sc("enable", "ssh-keys-updater.timer").CombinedOutput(); err != nil {
		return fmt.Errorf("systemctl enable: %v: %s", err, out)
	}
	// `restart`, not `start`: an install re-run against an already-active timer
	// (e.g. re-installing after this file changed) needs its schedule actually
	// recomputed. `start` on a unit systemd already considers active is a
	// no-op, so a stale timer stuck at infinity (see OnStartupSec comment
	// above) would stay stuck even after a fresh install unless the timer is
	// unconditionally stopped and restarted.
	if out, err := sc("restart", "ssh-keys-updater.timer").CombinedOutput(); err != nil {
		return fmt.Errorf("systemctl restart: %v: %s", err, out)
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
