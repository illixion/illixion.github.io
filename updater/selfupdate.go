package main

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// selfUpdate atomically replaces the installed binary — wherever `install` or
// `system-install` put it, whether that was a user-scope or system-scope path
// — with the binary at newBinaryPath, then runs the swapped-in binary once
// (unscheduled, so it never splays) to confirm it works and to apply any
// pending manifest immediately instead of waiting for the next scheduled
// tick.
//
// The installed path comes from the sidecar's exe_path, recorded by install/
// system-install (see main.go). A sidecar written before that field existed,
// or an explicit exeOverride, falls back to the currently running binary's
// own path — correct because self-update is normally invoked as the already-
// installed binary (e.g. `/usr/local/bin/ssh-keys-updater self-update
// /tmp/new`), and self-heals by recording that path for next time.
//
// Windows caveat: os.Rename cannot replace a currently-executing image on
// Windows, so self-update there must be run when no scheduled tick is
// in-flight. Unix has no such restriction — replacing a running binary's
// path just relinks the name to a new inode; the process already running
// keeps executing off the old one.
func selfUpdate(cfg Config, newBinaryPath, exeOverride string) error {
	sc, err := loadSidecar(cfg.AuthorizedKeys)
	if err != nil {
		return fmt.Errorf("loading sidecar: %w", err)
	}

	target := sc.ExePath
	if exeOverride != "" {
		target = exeOverride
	}
	if target == "" {
		target, err = currentExe()
		if err != nil {
			return fmt.Errorf("no recorded exe_path in the sidecar and could not resolve the running binary's own path: %w; pass -exe to name it explicitly", err)
		}
	}

	data, err := os.ReadFile(newBinaryPath)
	if err != nil {
		return fmt.Errorf("reading new binary: %w", err)
	}
	if len(data) == 0 {
		return fmt.Errorf("%s is empty", newBinaryPath)
	}

	// Sanity-check the new binary actually runs before clobbering the live
	// one. Distribution is out-of-band by design (see release.sh) — this is a
	// corruption/wrong-arch guard, not a trust boundary.
	out, err := exec.Command(newBinaryPath, "version").CombinedOutput()
	if err != nil {
		return fmt.Errorf("new binary at %s failed to run (%v): %s", newBinaryPath, err, strings.TrimSpace(string(out)))
	}
	logf("new binary reports: %s", strings.TrimSpace(string(out)))

	if err := atomicWrite(target, data, 0o755); err != nil {
		return fmt.Errorf("installing new binary to %s: %w", target, err)
	}
	logf("swapped in new binary at %s", target)

	if sc.ExePath != target {
		sc.ExePath = target
		if err := saveSidecar(cfg.AuthorizedKeys, sc); err != nil {
			return fmt.Errorf("recording exe_path in sidecar: %w", err)
		}
	}

	args := []string{"run",
		"-authorized-keys", cfg.AuthorizedKeys,
		"-local-file", cfg.LocalFile,
	}
	if cfg.InsecureTLS {
		args = append(args, "-insecure-tls")
	}
	out, err = exec.Command(target, args...).CombinedOutput()
	logf("post-update verification run: %s", strings.TrimSpace(string(out)))
	if err != nil {
		return fmt.Errorf("binary swap succeeded but the verification run failed: %w — investigate before trusting the schedule", err)
	}
	return nil
}

// printStatus prints everything self-update and a human need to know about
// this install without hunting the filesystem: where the binary actually is
// (user-scope or system-scope), what it's tracking, and what serial it's at.
func printStatus(cfg Config) error {
	sc, err := loadSidecar(cfg.AuthorizedKeys)
	if err != nil {
		return err
	}

	exe := sc.ExePath
	note := ""
	if exe == "" {
		if e, err := currentExe(); err == nil {
			exe, note = e, "  (not recorded in sidecar; inferred from this invocation)"
		} else {
			exe, note = "(unknown)", "  (not recorded, and could not resolve the current binary's own path)"
		}
	}

	fmt.Printf("version:          %s (%s)\n", version, manifestSchemaInfo())
	fmt.Printf("binary:           %s%s\n", exe, note)
	fmt.Printf("authorized_keys:  %s\n", cfg.AuthorizedKeys)
	fmt.Printf("local file:       %s\n", cfg.LocalFile)
	if sc.Location != nil {
		fmt.Printf("manifest url:     %s\n", sc.Location.ManifestURL)
		fmt.Printf("interval/splay:   %s / %s\n", sc.Location.interval(), sc.Location.splay())
	} else {
		fmt.Println("location:         not configured (run `install`)")
	}
	fmt.Printf("installed serial: %d\n", sc.State.Serial)
	if n := len(sc.State.Disabled); n > 0 {
		fmt.Printf("revoked signers:  %d\n", n)
	}
	return nil
}
