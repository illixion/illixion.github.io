package main

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
)

// selfInstallBinary copies the running executable to dest (the canonical system
// path) so the scheduler can reference a stable location instead of a throwaway
// download path. Idempotent: if already running from dest, it is a no-op. On Unix
// it requires root to write a system directory; on Windows it surfaces any ACL
// error from the attempted write.
func selfInstallBinary(dest string) error {
	src, err := os.Executable()
	if err != nil {
		return err
	}
	if r, err := filepath.EvalSymlinks(src); err == nil {
		src = r
	}
	if d, err := filepath.EvalSymlinks(dest); (err == nil && d == src) || src == dest {
		logf("binary already installed at %s", dest)
		return nil
	}
	if runtime.GOOS != "windows" && os.Geteuid() != 0 {
		return fmt.Errorf("system-install needs root to write %s; re-run with sudo", dest)
	}
	if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil {
		return fmt.Errorf("creating %s: %w", filepath.Dir(dest), err)
	}
	data, err := os.ReadFile(src)
	if err != nil {
		return fmt.Errorf("reading current binary: %w", err)
	}
	if err := atomicWrite(dest, data, 0o755); err != nil {
		return fmt.Errorf("installing binary to %s: %w", dest, err)
	}
	logf("installed binary -> %s", dest)
	return nil
}
