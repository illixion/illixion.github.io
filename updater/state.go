package main

// State is the anti-rollback + revocation record. It is persisted inside the
// unified sidecar (see sidecar.go); loadState/saveState are thin accessors over
// it so the rest of the code is unaware of the storage layout.
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

func loadState(authorizedKeys string) (*State, error) {
	s, err := loadSidecar(authorizedKeys)
	if err != nil {
		return nil, err
	}
	return s.State, nil
}

func saveState(authorizedKeys string, st *State) error {
	s, err := loadSidecar(authorizedKeys)
	if err != nil {
		return err
	}
	s.State = st
	return saveSidecar(authorizedKeys, s)
}
