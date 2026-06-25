//go:build !linux && !windows

package main

import (
	"os"
	"path/filepath"
)

// defaultKeyPaths resolves the standard per-user location (macOS, BSD, etc.).
func defaultKeyPaths() (ak, local string) {
	home, _ := os.UserHomeDir()
	ak = filepath.Join(home, ".ssh", "authorized_keys")
	return ak, filepath.Join(filepath.Dir(ak), "authorized_keys_local")
}
