package main

import (
	"fmt"
	"os"
	"time"
)

// label identifies the scheduled job across all platforms.
const label = "com.illixion.ssh-keys-updater"

// runArgs reconstructs the argv the scheduler should invoke: the absolute path
// to this binary, "run", and any non-default flags so the scheduled run behaves
// identically to the install-time invocation.
func runArgs(cfg Config) ([]string, error) {
	exe, err := os.Executable()
	if err != nil {
		return nil, err
	}
	args := []string{exe, "run"}
	if cfg.ManifestURL != defaultManifestURL {
		args = append(args, "-url", cfg.ManifestURL)
	}
	args = append(args, "-authorized-keys", cfg.AuthorizedKeys)
	args = append(args, "-local-file", cfg.LocalFile)
	if cfg.InsecureTLS {
		args = append(args, "-insecure-tls")
	}
	if cfg.Splay > 0 {
		args = append(args, "-splay", cfg.Splay.String())
	}
	return args, nil
}

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
