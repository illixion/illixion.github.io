//go:build windows

package main

import (
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// On Windows we register a recurring Scheduled Task via schtasks. The task runs as
// the current user. Windows 10 1809+ ships OpenSSH, so authorized_keys lives at
// %USERPROFILE%\.ssh\authorized_keys by default (resolved in main).
const taskName = "ssh-keys-updater"

func installSchedule(cfg Config, interval time.Duration, exe string, useCron bool) error {
	if useCron {
		return fmt.Errorf("-scheduler cron is not supported on Windows; use the default Scheduled Task backend")
	}
	if err := validateInterval(interval); err != nil {
		return err
	}
	args := runArgs(cfg, exe)
	// schtasks /tr takes a single command string; quote each argument.
	tr := winJoin(args)
	mins := int(interval.Minutes())
	if mins < 1 {
		mins = 1
	}
	schArgs := []string{"/Create", "/F",
		"/TN", taskName,
		"/SC", "MINUTE",
		"/MO", fmt.Sprintf("%d", mins),
		"/TR", tr,
	}
	// Writing the admin keys file requires privilege the interactive user may
	// only hold when elevated; run the task as SYSTEM so the daily run always
	// has access to %ProgramData%\ssh.
	if strings.EqualFold(filepath.Base(cfg.AuthorizedKeys), "administrators_authorized_keys") {
		schArgs = append(schArgs, "/RU", "SYSTEM", "/RL", "HIGHEST")
	}
	out, err := exec.Command("schtasks", schArgs...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("schtasks create: %v: %s", err, out)
	}
	logf("installed scheduled task %q (every %d min)", taskName, mins)
	return nil
}

func uninstallSchedule() error {
	out, err := exec.Command("schtasks", "/Delete", "/F", "/TN", taskName).CombinedOutput()
	if err != nil && !strings.Contains(string(out), "cannot find") {
		return fmt.Errorf("schtasks delete: %v: %s", err, out)
	}
	return nil
}

// winJoin builds the /TR command line. Plain double quotes only: exec.Command
// already escapes embedded quotes when it builds schtasks' own command line, so
// writing \" here stored a literal backslash in the task (\"C:\...exe\"), which
// then failed every run with 0x80070002 (file not found).
func winJoin(args []string) string {
	q := make([]string, len(args))
	for i, a := range args {
		if a == "" || strings.ContainsAny(a, " \t") {
			q[i] = `"` + a + `"`
		} else {
			q[i] = a
		}
	}
	return strings.Join(q, " ")
}
