package main

import (
	"bufio"
	"encoding/base64"
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
	// An empty embedded set is allowed: a "neutral" build that an adopter pins to
	// their own signer at install time. The non-empty requirement is enforced on
	// the *effective* set (embedded ∪ locally-accepted) at run time.
	return keys, nil
}

// loadLocalPins parses signer keys the operator accepted at install time, stored
// in the sidecar's `pins` (authorized_keys line format). Absent → empty.
func loadLocalPins(authorizedKeys string) ([]*PinnedKey, error) {
	s, err := loadSidecar(authorizedKeys)
	if err != nil {
		return nil, err
	}
	var keys []*PinnedKey
	for _, line := range s.Pins {
		k, err := parseAuthorizedKey(line)
		if err != nil {
			return nil, fmt.Errorf("local pin: %w", err)
		}
		keys = append(keys, k)
	}
	return keys, nil
}

// effectiveSigners is the trust set used by every verification: the embedded
// pinned signers unioned with the locally-accepted pins, deduped by fingerprint.
func effectiveSigners(authorizedKeys string) ([]*PinnedKey, error) {
	embedded, err := loadPinnedSigners()
	if err != nil {
		return nil, err
	}
	local, err := loadLocalPins(authorizedKeys)
	if err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	var all []*PinnedKey
	for _, k := range append(embedded, local...) {
		if seen[k.Fingerprint] {
			continue
		}
		seen[k.Fingerprint] = true
		all = append(all, k)
	}
	return all, nil
}

// appendLocalPin records a signer in the sidecar's local pin set (idempotent by
// fingerprint). Called only after an interactive, OOB-verified acceptance.
func appendLocalPin(authorizedKeys string, key *PinnedKey) error {
	s, err := loadSidecar(authorizedKeys)
	if err != nil {
		return err
	}
	for _, line := range s.Pins {
		if k, err := parseAuthorizedKey(line); err == nil && k.Fingerprint == key.Fingerprint {
			return nil // already pinned
		}
	}
	line := "ssh-ed25519 " + base64.StdEncoding.EncodeToString(key.Wire)
	if key.Comment != "" {
		line += " " + key.Comment
	}
	s.Pins = append(s.Pins, line)
	return saveSidecar(authorizedKeys, s)
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
