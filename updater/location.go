package main

import (
	"time"
)

// Location is the resolved, non-secret "where do I fetch from" config. It is
// persisted inside the unified sidecar (see sidecar.go). Scheduled
// (non-interactive) runs read it so they never need to prompt. It is
// convenience/location only — trust lives in the compiled-in pinned_signers (and
// any OOB-accepted local pins), never here.
type Location struct {
	DiscoveryURL string `json:"discovery_url,omitempty"` // re-fetched each run to follow relocations
	ManifestURL  string `json:"manifest_url"`            // last good manifest URL (fallback if discovery is down)
	Interval     string `json:"interval,omitempty"`
	Splay        string `json:"splay,omitempty"`
}

func loadLocation(authorizedKeys string) (*Location, error) {
	s, err := loadSidecar(authorizedKeys)
	if err != nil {
		return nil, err
	}
	return s.Location, nil // nil if not configured yet
}

func saveLocation(authorizedKeys string, l *Location) error {
	s, err := loadSidecar(authorizedKeys)
	if err != nil {
		return err
	}
	s.Location = l
	return saveSidecar(authorizedKeys, s)
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
