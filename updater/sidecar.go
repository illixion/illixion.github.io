package main

import (
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
)

// Sidecar is the single per-user JSON file kept next to authorized_keys. It
// unifies what used to live in three separate dotfiles (location, state, pins)
// into one record, isolated per identity by directory + ownership. Trust still
// never comes from here over the network: `pins` is only ever written by an
// interactive, OOB-verified install acceptance, and `state`/`location` are the
// client's own bookkeeping.
type Sidecar struct {
	Location *Location `json:"location,omitempty"`
	State    *State    `json:"state"`
	// Pins are adopter-accepted signer public keys in authorized_keys line
	// format. Empty for first-party hosts relying solely on embedded pinned
	// signers. Populated by install-time acceptance (OOB-verified).
	Pins []string `json:"pins,omitempty"`
	// ManagedHash is the SHA-256 (hex) of the managed key block as last written,
	// used for tamper-evidence drift logging. Not a security control.
	ManagedHash string `json:"managed_hash,omitempty"`
}

func sidecarPath(authorizedKeys string) string {
	return filepath.Join(filepath.Dir(authorizedKeys), ".ssh-keys-updater.json")
}

// Legacy single-purpose files superseded by the unified sidecar. Kept here so
// loadSidecar can migrate and remove them in one transparent step.
func legacyLocationPath(authorizedKeys string) string {
	return filepath.Join(filepath.Dir(authorizedKeys), ".ssh-keys-updater.conf")
}
func legacyStatePath(authorizedKeys string) string {
	return filepath.Join(filepath.Dir(authorizedKeys), ".ssh-keys-updater.state")
}

// loadSidecar reads the unified sidecar, always returning a non-nil Sidecar with
// a non-nil State (fresh if nothing is stored). If the unified file is absent but
// legacy .conf/.state files exist, it migrates them: the merged sidecar is written
// and the legacy files are removed.
func loadSidecar(authorizedKeys string) (*Sidecar, error) {
	b, err := os.ReadFile(sidecarPath(authorizedKeys))
	if err == nil {
		var s Sidecar
		if err := json.Unmarshal(b, &s); err != nil {
			return nil, err
		}
		if s.State == nil {
			s.State = &State{}
		}
		if s.State.Disabled == nil {
			s.State.Disabled = map[string]bool{}
		}
		return &s, nil
	}
	if !errors.Is(err, fs.ErrNotExist) {
		return nil, err
	}

	// No unified file — attempt a one-time migration from legacy dotfiles.
	s := &Sidecar{State: &State{Disabled: map[string]bool{}}}
	migrated := false
	if lb, lerr := os.ReadFile(legacyLocationPath(authorizedKeys)); lerr == nil {
		var l Location
		if json.Unmarshal(lb, &l) == nil {
			s.Location = &l
			migrated = true
		}
	}
	if sb, serr := os.ReadFile(legacyStatePath(authorizedKeys)); serr == nil {
		var st State
		if json.Unmarshal(sb, &st) == nil {
			if st.Disabled == nil {
				st.Disabled = map[string]bool{}
			}
			s.State = &st
			migrated = true
		}
	}
	if migrated {
		if err := saveSidecar(authorizedKeys, s); err != nil {
			return nil, err
		}
		// Best-effort cleanup; the unified file is now authoritative.
		_ = os.Remove(legacyLocationPath(authorizedKeys))
		_ = os.Remove(legacyStatePath(authorizedKeys))
		logf("migrated legacy config to %s", sidecarPath(authorizedKeys))
	}
	return s, nil
}

func saveSidecar(authorizedKeys string, s *Sidecar) error {
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	return atomicWrite(sidecarPath(authorizedKeys), append(b, '\n'), 0o600)
}
