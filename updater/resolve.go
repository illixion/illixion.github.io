package main

import (
	"fmt"
	"net/http"
	"os"
)

// resolveLocation decides where to fetch the manifest for this invocation.
// Precedence:
//  1. -manifest-url override (advanced/testing) — skip discovery entirely
//  2. a positional domain given now — fetch its discovery.json
//  3. previously persisted location — re-fetch discovery (follow relocations),
//     falling back to the last-known manifest URL if discovery is unreachable
//  4. interactive prompt (only when stdin is a TTY)
//
// interactiveOK gates prompting and the first-use print/confirm, so scheduled
// runs stay silent and never block.
func resolveLocation(cfg Config, domainArg, manifestOverride string, interactiveOK bool) (*Location, error) {
	client := httpClient(cfg)

	if manifestOverride != "" {
		return &Location{ManifestURL: manifestOverride}, nil
	}

	if domainArg != "" {
		return resolveFromDomain(client, cfg, domainArg, interactiveOK)
	}

	loc, err := loadLocation(cfg.AuthorizedKeys)
	if err != nil {
		return nil, err
	}
	if loc != nil {
		if loc.DiscoveryURL != "" {
			if d, _, derr := fetchDiscovery(client, loc.DiscoveryURL); derr == nil {
				fresh := mergeDiscovery(loc.DiscoveryURL, d)
				_ = saveLocation(cfg.AuthorizedKeys, fresh)
				return fresh, nil
			} else {
				logf("discovery refresh failed (%v); using last-known manifest %s", derr, loc.ManifestURL)
			}
		}
		if loc.ManifestURL == "" {
			return nil, fmt.Errorf("stored config has no manifest URL")
		}
		return loc, nil
	}

	// Fall back to the build-time default location, if one was baked in (from
	// config.env's SKU_BASE_URL). Convenience only: a saved config was already
	// checked above and wins, discovery.json is still fetched, and an explicit
	// argument overrides — so this never costs the no-rebuild host-move property.
	if defaultDomain != "" {
		return resolveFromDomain(client, cfg, defaultDomain, interactiveOK)
	}
	if !interactiveOK {
		return nil, fmt.Errorf("no domain given and nothing configured — run `install <domain>` first")
	}
	dom := ask("Discovery domain (e.g. ssh.illixion.com): ")
	if dom == "" {
		return nil, fmt.Errorf("no domain provided")
	}
	return resolveFromDomain(client, cfg, dom, true)
}

func resolveFromDomain(client *http.Client, cfg Config, domainArg string, interactiveOK bool) (*Location, error) {
	durl := discoveryURLFor(domainArg)
	d, raw, err := fetchDiscovery(client, durl)
	if err == nil {
		existing, _ := loadLocation(cfg.AuthorizedKeys)
		if interactiveOK && existing == nil { // first use: show it and confirm
			printDiscovery(durl, raw)
			if !confirm("Use this discovery configuration?") {
				return nil, fmt.Errorf("aborted by user")
			}
		}
		loc := mergeDiscovery(durl, d)
		_ = saveLocation(cfg.AuthorizedKeys, loc)
		return loc, nil
	}

	if !interactiveOK {
		return nil, fmt.Errorf("fetching %s: %w", durl, err)
	}
	fmt.Fprintf(os.Stderr, "Could not fetch %s: %v\n", durl, err)
	m := ask("Enter the manifest URL directly: ")
	if m == "" {
		return nil, fmt.Errorf("no manifest URL provided")
	}
	loc := &Location{ManifestURL: ensureScheme(m)}
	_ = saveLocation(cfg.AuthorizedKeys, loc)
	return loc, nil
}

func mergeDiscovery(discoveryURL string, d *Discovery) *Location {
	return &Location{
		DiscoveryURL: discoveryURL,
		ManifestURL:  d.ManifestURL,
		Interval:     d.Interval,
		Splay:        d.Splay,
	}
}

func printDiscovery(durl string, raw []byte) {
	fmt.Fprintf(os.Stderr, "\n--- discovery.json (%s) ---\n%s\n---------------------------------\n", durl, string(raw))
}
