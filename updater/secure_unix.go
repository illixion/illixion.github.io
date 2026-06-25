//go:build !windows

package main

// secureKeyFile is a no-op on Unix: atomicWrite already creates the file with
// mode 0600, which is what sshd/dropbear require.
func secureKeyFile(path string) error { return nil }
