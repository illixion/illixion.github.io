package main

import (
	"fmt"
	"os"
	"time"
)

// label identifies the scheduled job across all platforms.
const label = "com.illixion.ssh-keys-updater"

// runArgs reconstructs the argv the scheduler should invoke. The scheduled run
// takes no domain/URL: it reads the saved location (.ssh-keys-updater.conf next
// to authorized_keys), re-fetches discovery, and applies the saved splay. We
// only need to pin the file paths and the TLS flag.
func runArgs(cfg Config) ([]string, error) {
	exe, err := os.Executable()
	if err != nil {
		return nil, err
	}
	args := []string{exe, "run", "-scheduled",
		"-authorized-keys", cfg.AuthorizedKeys,
		"-local-file", cfg.LocalFile,
	}
	if cfg.InsecureTLS {
		args = append(args, "-insecure-tls")
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
