//go:build windows

package main

import (
	"os"
	"path/filepath"
)

// defaultKeyPaths resolves where to install on Windows. Windows OpenSSH sshd
// uses a SINGLE file, %ProgramData%\ssh\administrators_authorized_keys, for
// every account in the Administrators group and IGNORES per-user
// %USERPROFILE%\.ssh\authorized_keys for those accounts. So if the OpenSSH
// server data directory exists, we target the admin file (the common case for
// an admin workstation). For a non-admin user account, override with
// -authorized-keys to point at the per-user file.
func defaultKeyPaths() (ak, local string) {
	pd := os.Getenv("ProgramData")
	if pd == "" {
		pd = `C:\ProgramData`
	}
	adminDir := filepath.Join(pd, "ssh")
	if fi, err := os.Stat(adminDir); err == nil && fi.IsDir() {
		ak = filepath.Join(adminDir, "administrators_authorized_keys")
	} else {
		home, _ := os.UserHomeDir()
		ak = filepath.Join(home, ".ssh", "authorized_keys")
	}
	return ak, filepath.Join(filepath.Dir(ak), "authorized_keys_local")
}

// systemBinPath is the canonical install location for `system-install`.
func systemBinPath() (string, error) {
	pf := os.Getenv("ProgramFiles")
	if pf == "" {
		pf = `C:\Program Files`
	}
	return filepath.Join(pf, "ssh-keys-updater", "ssh-keys-updater.exe"), nil
}
