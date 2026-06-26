package main

import (
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"time"
)

// Location is the resolved, non-secret "where do I fetch from" config written at
// install time next to authorized_keys. Scheduled (non-interactive) runs read it
// so they never need to prompt. It is convenience/location only — trust lives in
// the compiled-in pinned_signers, never here.
type Location struct {
	DiscoveryURL string `json:"discovery_url,omitempty"` // re-fetched each run to follow relocations
	ManifestURL  string `json:"manifest_url"`            // last good manifest URL (fallback if discovery is down)
	Interval     string `json:"interval,omitempty"`
	Splay        string `json:"splay,omitempty"`
}

func locationPath(authorizedKeys string) string {
	return filepath.Join(filepath.Dir(authorizedKeys), ".ssh-keys-updater.conf")
}

func loadLocation(authorizedKeys string) (*Location, error) {
	b, err := os.ReadFile(locationPath(authorizedKeys))
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil // not configured yet
	}
	if err != nil {
		return nil, err
	}
	var l Location
	if err := json.Unmarshal(b, &l); err != nil {
		return nil, err
	}
	return &l, nil
}

func saveLocation(authorizedKeys string, l *Location) error {
	b, err := json.MarshalIndent(l, "", "  ")
	if err != nil {
		return err
	}
	return atomicWrite(locationPath(authorizedKeys), append(b, '\n'), 0o600)
}

func (l *Location) interval() time.Duration {
	if d, err := time.ParseDuration(l.Interval); err == nil && d > 0 {
		return clampInterval(d)
	}
	return 15 * time.Minute
}

func (l *Location) splay() time.Duration {
	if d, err := time.ParseDuration(l.Splay); err == nil && d >= 0 {
		return d
	}
	return l.interval()
}
