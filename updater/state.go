package main

import (
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
)

// State is the small per-user record kept next to authorized_keys. It enforces
// anti-rollback (Serial) and persists signer revocations (Disabled).
type State struct {
	// Serial is the highest manifest serial ever accepted. The updater refuses
	// any manifest whose serial is not strictly greater, which blocks a hostile
	// CDN from replaying an older validly-signed manifest that still lists a
	// key you have since removed.
	Serial uint64 `json:"serial"`

	// Disabled maps signer fingerprints ("SHA256:...") to true. Once a signer
	// is recorded here it is rejected forever on this client, regardless of
	// serial — so a stolen signing key cannot un-revoke itself.
	Disabled map[string]bool `json:"disabled,omitempty"`
}

func statePath(authorizedKeys string) string {
	dir := filepath.Dir(authorizedKeys)
	return filepath.Join(dir, ".ssh-keys-updater.state")
}

func loadState(authorizedKeys string) (*State, error) {
	b, err := os.ReadFile(statePath(authorizedKeys))
	if errors.Is(err, fs.ErrNotExist) {
		return &State{Disabled: map[string]bool{}}, nil
	}
	if err != nil {
		return nil, err
	}
	var s State
	if err := json.Unmarshal(b, &s); err != nil {
		return nil, err
	}
	if s.Disabled == nil {
		s.Disabled = map[string]bool{}
	}
	return &s, nil
}

func saveState(authorizedKeys string, s *State) error {
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	b = append(b, '\n')
	return atomicWrite(statePath(authorizedKeys), b, 0o600)
}
