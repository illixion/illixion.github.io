//go:build !linux && !windows

package main

import (
	"os"
	"path/filepath"
)

// defaultAuthorizedKeys resolves the standard per-user location (macOS, BSD, etc.).
func defaultAuthorizedKeys() (ak string) {
	home, _ := os.UserHomeDir()
	ak = filepath.Join(home, ".ssh", "authorized_keys")
	return ak
}

// systemBinPath is the canonical install location for `system-install`.
func systemBinPath() (string, error) {
	return "/usr/local/bin/ssh-keys-updater", nil
}
