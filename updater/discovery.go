package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// Discovery is the small, PUBLIC descriptor a deployment publishes at
// <base>/discovery.json. It is fetched from the untrusted website, so it carries
// only location/convenience data — never trust material. The signing keys stay
// compiled into the binary (pinned_signers); the worst a forged discovery.json
// can do is point the client at a different manifest URL, which still must carry
// a valid signature from a pinned key (so: no update, never key injection).
type Discovery struct {
	Schema      int    `json:"schema"`
	BaseURL     string `json:"base_url"`
	ManifestURL string `json:"manifest_url"`
	Interval    string `json:"interval,omitempty"` // e.g. "15m" — author's recommended cadence
	Splay       string `json:"splay,omitempty"`
	Title       string `json:"title,omitempty"`  // page identity (humans)
	Handle      string `json:"handle,omitempty"` // page identity (humans)
	RepoURL     string `json:"repo_url,omitempty"`
}

const discoverySchema = 1

// ensureScheme defaults a bare host to https://.
func ensureScheme(s string) string {
	s = strings.TrimSpace(s)
	if s == "" || strings.Contains(s, "://") {
		return s
	}
	return "https://" + s
}

// discoveryURLFor turns a user-supplied domain / base URL / discovery URL into
// the concrete discovery.json URL to fetch.
func discoveryURLFor(arg string) string {
	s := ensureScheme(arg)
	if strings.HasSuffix(s, "/discovery.json") {
		return s
	}
	return strings.TrimRight(s, "/") + "/discovery.json"
}

// fetchDiscovery GETs and validates discovery.json.
func fetchDiscovery(client *http.Client, url string) (*Discovery, []byte, error) {
	body, err := fetch(client, url)
	if err != nil {
		return nil, nil, err
	}
	d, err := parseDiscovery(body)
	if err != nil {
		return nil, nil, err
	}
	return d, body, nil
}

// parseDiscovery validates the fetched bytes.
func parseDiscovery(b []byte) (*Discovery, error) {
	var d Discovery
	if err := json.Unmarshal(b, &d); err != nil {
		return nil, fmt.Errorf("parsing discovery.json: %w", err)
	}
	if d.Schema != discoverySchema {
		return nil, fmt.Errorf("discovery schema %d != supported %d", d.Schema, discoverySchema)
	}
	if strings.TrimSpace(d.ManifestURL) == "" {
		return nil, fmt.Errorf("discovery.json has no manifest_url")
	}
	return &d, nil
}

// clampInterval keeps an author- or attacker-supplied cadence within sane bounds
// (discovery is untrusted): no tighter than 1m, no looser than 24h.
func clampInterval(d time.Duration) time.Duration {
	switch {
	case d < time.Minute:
		return time.Minute
	case d > 24*time.Hour:
		return 24 * time.Hour
	default:
		return d
	}
}
