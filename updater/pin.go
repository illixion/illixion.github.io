package main

import (
	"bufio"
	_ "embed"
	"fmt"
	"strings"
)

// pinnedSignersData is the trust anchor: the public keys allowed to sign
// manifests, baked into the binary at build time. This is the whole point of
// the design — the anchor is delivered out-of-band (compiled in, then preloaded
// over a trusted channel), so a compromised website cannot introduce a new
// signer. Edit pinned_signers and rebuild to change it.
//
//go:embed pinned_signers
var pinnedSignersData string

// loadPinnedSigners parses the embedded trust anchor.
func loadPinnedSigners() ([]*PinnedKey, error) {
	var keys []*PinnedKey
	sc := bufio.NewScanner(strings.NewReader(pinnedSignersData))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, err := parseAuthorizedKey(line)
		if err != nil {
			return nil, fmt.Errorf("pinned_signers: %w", err)
		}
		keys = append(keys, k)
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	if len(keys) == 0 {
		return nil, fmt.Errorf("no pinned signers embedded in binary")
	}
	return keys, nil
}

// resolveSigner finds the pinned key referenced by a disable_signer string,
// which may be either a comment label ("ixion@YubiKey5-gpg") or a fingerprint
// ("SHA256:...").
func resolveSigner(ref string, pinned []*PinnedKey) (*PinnedKey, error) {
	ref = strings.TrimSpace(ref)
	for _, k := range pinned {
		if ref == k.Comment || ref == k.Fingerprint {
			return k, nil
		}
	}
	return nil, fmt.Errorf("disable_signer %q matches no pinned signer", ref)
}
