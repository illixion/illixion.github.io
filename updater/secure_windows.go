//go:build windows

package main

import (
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"
)

// secureKeyFile enforces the ACL that Windows OpenSSH sshd requires on the
// administrators_authorized_keys file: it must be owned by Administrators (or
// SYSTEM) and writable only by SYSTEM and the Administrators group. If any
// other principal can write it, sshd silently refuses the file and all
// key-based logins for admin accounts fail. We reset inheritance and grant only
// those two principals. (The per-user ~/.ssh file needs no special ACL.)
func secureKeyFile(path string) error {
	if !strings.EqualFold(filepath.Base(path), "administrators_authorized_keys") {
		return nil
	}
	steps := [][]string{
		{"/setowner", "BUILTIN\\Administrators"},
		{"/inheritance:r"},
		{"/grant:r", "SYSTEM:F"},
		{"/grant:r", "BUILTIN\\Administrators:F"},
	}
	for _, args := range steps {
		full := append([]string{path}, args...)
		if out, err := exec.Command("icacls", full...).CombinedOutput(); err != nil {
			return fmt.Errorf("icacls %v: %v: %s", args, err, strings.TrimSpace(string(out)))
		}
	}
	return nil
}
