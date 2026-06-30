//go:build linux

package main

import (
	"os"
	"path/filepath"
)

// defaultKeyPaths resolves where to install on Linux. On OpenWRT the SSH server
// is dropbear, which reads /etc/dropbear/authorized_keys (a plain file — the
// LuCI "SSH-Keys" page is just an editor for it; there is no uci entry for key
// content). Elsewhere we use the standard per-user location.
func defaultKeyPaths() (ak, local string) {
	if isOpenWRT() {
		ak = "/etc/dropbear/authorized_keys"
	} else {
		home, _ := os.UserHomeDir()
		ak = filepath.Join(home, ".ssh", "authorized_keys")
	}
	return ak, filepath.Join(filepath.Dir(ak), "authorized_keys_local")
}

// systemBinPath is the canonical install location for `system-install`. On
// OpenWRT /usr/local may be absent, so use /usr/bin (on the overlay, persistent).
func systemBinPath() (string, error) {
	if isOpenWRT() {
		return "/usr/bin/ssh-keys-updater", nil
	}
	return "/usr/local/bin/ssh-keys-updater", nil
}
