package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"time"
)

// version is baked at build time (-ldflags "-X main.version=...").
var version = "dev"

// defaultDomain is an optional convenience baked at release time from
// config.env's SKU_BASE_URL (-X main.defaultDomain=...). When set, `install`/`run`
// with no domain argument and nothing configured fall back to it instead of
// prompting. It is NOT trust and NOT a hard location: discovery.json is still
// fetched at runtime, a saved config always takes precedence (so a host move
// needs no rebuild), and an explicit argument overrides it. Empty in a generic
// build — adopters bake their own via config.env. Trust still lives only in
// pinned_signers (+ any locally-accepted pins).
var defaultDomain = ""

func logf(format string, args ...any) { log.Printf(format, args...) }

func main() {
	log.SetFlags(log.LstdFlags | log.LUTC)
	log.SetPrefix("ssh-keys-updater: ")

	defaultAK, defaultLocal := defaultKeyPaths()

	fs := flag.NewFlagSet("ssh-keys-updater", flag.ExitOnError)
	ak := fs.String("authorized-keys", defaultAK, "authorized_keys file to manage")
	local := fs.String("local-file", defaultLocal, "local key file appended verbatim after the managed block")
	insecure := fs.Bool("insecure-tls", false, "skip TLS verification (the SSHSIG signature still gates content)")
	timeout := fs.Duration("timeout", 30*time.Second, "HTTP timeout")
	manifestURL := fs.String("manifest-url", "", "fetch this manifest URL directly, skipping discovery (advanced)")
	interval := fs.Duration("interval", 15*time.Minute, "scheduled check cadence (overrides discovery)")
	splay := fs.Duration("splay", 0, "max random pre-fetch delay (overrides discovery)")
	scheduled := fs.Bool("scheduled", false, "internal: set by the scheduler so the run applies splay and never prompts")
	acceptSigner := fs.String("accept-signer", "", "at install, trust this SHA256:... signer fingerprint (adopter use; verify it out-of-band first)")
	// gen-page flags (author side; no baked defaults):
	baseURL := fs.String("base-url", "", "public base URL of the page/manifest/bin (gen-page)")
	pageTitle := fs.String("title", "", "owner name shown on the page (gen-page)")
	pageHandle := fs.String("handle", "", "handle shown under the name (gen-page)")
	pageRepo := fs.String("repo", "", "source repository URL for page links (gen-page)")
	pageOut := fs.String("out", "", "write generated page here instead of stdout (gen-page)")
	fs.Usage = usage(fs)

	args := os.Args[1:]
	if len(args) == 0 {
		fs.Usage()
		os.Exit(2)
	}
	cmd := args[0]
	// Parse flags and positionals in any order (flag.Parse stops at the first
	// non-flag; loop so `install ssh.illixion.com -interval 30m` works too).
	var positionals []string
	rest := args[1:]
	for {
		_ = fs.Parse(rest)
		if fs.NArg() == 0 {
			break
		}
		positionals = append(positionals, fs.Arg(0))
		rest = fs.Args()[1:]
	}

	intervalSet, splaySet := false, false
	fs.Visit(func(f *flag.Flag) {
		switch f.Name {
		case "interval":
			intervalSet = true
		case "splay":
			splaySet = true
		}
	})

	cfg := Config{
		AuthorizedKeys: *ak,
		LocalFile:      *local,
		InsecureTLS:    *insecure,
		Timeout:        *timeout,
	}
	domainArg := "" // optional "ssh.illixion.com" for run/install
	if len(positionals) > 0 {
		domainArg = positionals[0]
	}
	// Scheduler-invoked runs splay and must never prompt; interactive (terminal)
	// runs may prompt.
	canPrompt := interactive() && !*scheduled

	// applyOverrides folds -interval/-splay flags onto a resolved location.
	applyOverrides := func(loc *Location) {
		if intervalSet {
			loc.Interval = interval.String()
		}
		if splaySet {
			loc.Splay = splay.String()
		}
	}

	switch cmd {
	case "run":
		loc, err := resolveLocation(cfg, domainArg, *manifestURL, canPrompt)
		if err != nil {
			log.Fatalf("%v", err)
		}
		applyOverrides(loc)
		cfg.ManifestURL = loc.ManifestURL
		if *scheduled { // only scheduler-invoked runs jitter; manual runs are immediate
			applySplay(loc.splay())
		}
		if err := runUpdate(cfg); err != nil {
			log.Fatalf("update failed: %v", err)
		}
	case "install":
		loc, err := resolveLocation(cfg, domainArg, *manifestURL, canPrompt)
		if err != nil {
			log.Fatalf("%v", err)
		}
		applyOverrides(loc)
		if err := saveLocation(cfg.AuthorizedKeys, loc); err != nil {
			log.Fatalf("saving config: %v", err)
		}
		cfg.ManifestURL = loc.ManifestURL
		if err := ensureSignerTrusted(cfg, loc.ManifestURL, *acceptSigner, canPrompt); err != nil {
			log.Fatalf("%v", err)
		}
		exe, err := currentExe()
		if err != nil {
			log.Fatalf("locating binary: %v", err)
		}
		if err := installSchedule(cfg, loc.interval(), exe); err != nil {
			log.Fatalf("install failed: %v", err)
		}
		logf("scheduled every %s (splay up to %s); manifest %s — running once now",
			loc.interval(), loc.splay(), loc.ManifestURL)
		if err := runUpdate(cfg); err != nil { // initial run is immediate (no splay)
			log.Fatalf("initial update failed: %v", err)
		}
	case "system-install":
		dest, err := systemBinPath()
		if err != nil {
			log.Fatalf("%v", err)
		}
		if err := selfInstallBinary(dest); err != nil {
			log.Fatalf("%v", err)
		}
		loc, err := resolveLocation(cfg, domainArg, *manifestURL, canPrompt)
		if err != nil {
			log.Fatalf("%v", err)
		}
		applyOverrides(loc)
		if err := saveLocation(cfg.AuthorizedKeys, loc); err != nil {
			log.Fatalf("saving config: %v", err)
		}
		cfg.ManifestURL = loc.ManifestURL
		if err := ensureSignerTrusted(cfg, loc.ManifestURL, *acceptSigner, canPrompt); err != nil {
			log.Fatalf("%v", err)
		}
		// Schedule from the installed path, not the (possibly throwaway) path we
		// were launched from, so a later rm of the download is harmless.
		if err := installSchedule(cfg, loc.interval(), dest); err != nil {
			log.Fatalf("install failed: %v", err)
		}
		logf("scheduled every %s (splay up to %s) via %s; manifest %s — running once now",
			loc.interval(), loc.splay(), dest, loc.ManifestURL)
		if err := runUpdate(cfg); err != nil {
			log.Fatalf("initial update failed: %v", err)
		}
	case "uninstall":
		if err := uninstallSchedule(); err != nil {
			log.Fatalf("uninstall failed: %v", err)
		}
		logf("scheduled run removed (authorized_keys left in place)")
	case "verify":
		if len(positionals) != 2 {
			log.Fatalf("usage: ssh-keys-updater verify <manifest-file> <sig-file>")
		}
		if err := verifyFiles(cfg, positionals[0], positionals[1]); err != nil {
			log.Fatalf("verify failed: %v", err)
		}
	case "gen-page":
		if *baseURL == "" {
			log.Fatalf("gen-page requires -base-url")
		}
		if err := genPageToFile(*baseURL, *pageTitle, *pageHandle, *pageRepo, *pageOut); err != nil {
			log.Fatalf("gen-page failed: %v", err)
		}
	case "print-pins":
		embedded, err := loadPinnedSigners()
		if err != nil {
			log.Fatalf("%v", err)
		}
		local, err := loadLocalPins(cfg.AuthorizedKeys)
		if err != nil {
			log.Fatalf("%v", err)
		}
		for _, k := range embedded {
			fmt.Printf("%s  %s  [embedded]\n", k.Fingerprint, k.Comment)
		}
		for _, k := range local {
			fmt.Printf("%s  %s  [local]\n", k.Fingerprint, k.Comment)
		}
		if len(embedded)+len(local) == 0 {
			fmt.Println("(no trusted signers — neutral build; run `install` to accept one)")
		}
	case "version":
		fmt.Printf("ssh-keys-updater %s (%s)\n", version, manifestSchemaInfo())
	default:
		fs.Usage()
		os.Exit(2)
	}
}

func manifestSchemaInfo() string { return fmt.Sprintf("manifest schema %d", manifestSchema) }

// ensureSignerTrusted makes sure the deployment's manifest signer is in the
// effective trust set before scheduling. For a first-party host (embedded pin),
// this is a silent no-op. For an adopter on a neutral/differently-pinned build,
// it establishes trust ONCE, interactively, with out-of-band fingerprint
// verification (TOFU, like SSH known_hosts), then pins it locally. A non-prompt
// context (scheduled run) never accepts a new signer — it fails closed.
func ensureSignerTrusted(cfg Config, manifestURL, acceptSigner string, canPrompt bool) error {
	trusted, err := effectiveSigners(cfg.AuthorizedKeys)
	if err != nil {
		return err
	}
	client := httpClient(cfg)
	mb, err := fetch(client, manifestURL)
	if err != nil {
		return fmt.Errorf("fetching manifest for trust check: %w", err)
	}
	sb, err := fetch(client, manifestURL+".sig")
	if err != nil {
		return fmt.Errorf("fetching signature for trust check: %w", err)
	}
	// Validate the signature against the key embedded in it — proves the bytes
	// are self-consistently signed — WITHOUT yet trusting that key.
	signer, err := parseAndCheckSSHSIG(mb, sb)
	if err != nil {
		return fmt.Errorf("manifest signature is not valid: %w", err)
	}
	for _, k := range trusted {
		if k.Fingerprint == signer.Fingerprint {
			return nil // already trusted — silent first-party path
		}
	}

	// New signer: requires explicit, out-of-band-verified acceptance.
	if acceptSigner != "" {
		if acceptSigner != signer.Fingerprint {
			return fmt.Errorf("-accept-signer %s does not match the manifest's signer %s; refusing", acceptSigner, signer.Fingerprint)
		}
		if err := appendLocalPin(cfg.AuthorizedKeys, signer); err != nil {
			return err
		}
		logf("accepted signer %s via -accept-signer", signer.Fingerprint)
		return nil
	}
	if !canPrompt {
		return fmt.Errorf("manifest is signed by an untrusted signer %s; re-run `install` interactively, or pass -accept-signer %s after verifying it out-of-band", signer.Fingerprint, signer.Fingerprint)
	}
	fmt.Fprintf(os.Stderr, "\nThis deployment's manifest is signed by a signer this binary does not yet trust:\n    %s\n", signer.Fingerprint)
	fmt.Fprintf(os.Stderr, "Verify this fingerprint out-of-band against the value the deployment publishes\n(README / release notes) — give it the same trust weight as the binary's SHA-256.\n")
	if !confirm("Trust this signer and pin it locally?") {
		return fmt.Errorf("signer not accepted; aborting")
	}
	if err := appendLocalPin(cfg.AuthorizedKeys, signer); err != nil {
		return err
	}
	logf("pinned signer %s to %s", signer.Fingerprint, sidecarPath(cfg.AuthorizedKeys))
	return nil
}

func verifyFiles(cfg Config, manifestPath, sigPath string) error {
	pinned, err := effectiveSigners(cfg.AuthorizedKeys)
	if err != nil {
		return err
	}
	mb, err := os.ReadFile(manifestPath)
	if err != nil {
		return err
	}
	sb, err := os.ReadFile(sigPath)
	if err != nil {
		return err
	}
	state, err := loadState(cfg.AuthorizedKeys)
	if err != nil {
		return err
	}
	signer, err := VerifySSHSIG(mb, sb, pinned, state.Disabled)
	if err != nil {
		return err
	}
	m, err := parseManifest(mb)
	if err != nil {
		return err
	}
	fmt.Printf("OK: signed by %s (%s)\n", signer.Comment, signer.Fingerprint)
	fmt.Printf("serial=%d issued_at=%s keys=%d\n", m.Serial, m.IssuedAt, len(m.Keys))
	if m.DisableSigner != "" {
		fmt.Printf("disable_signer=%s\n", m.DisableSigner)
	}
	return nil
}

func usage(fs *flag.FlagSet) func() {
	return func() {
		fmt.Fprintf(os.Stderr, `ssh-keys-updater — verify-then-install signed SSH authorized_keys

Usage:
  ssh-keys-updater <command> [flags] [domain]

Commands:
  run [domain]      Fetch, verify, and install the manifest once. Resolves the
                    manifest URL from <domain>/discovery.json, a saved config, or
                    an interactive prompt.
  install [domain]  Resolve + save the location, schedule a periodic run
                    (launchd/systemd/cron/schtasks), and run once. Uses the
                    build-time default location if no domain is given; else prompts
                    when stdin is a terminal. On a build whose signer is not
                    embedded, prompts to accept it after OOB verification (or pass
                    -accept-signer SHA256:...).
  system-install    Like install, but first copies the binary to the canonical
                    system path (/usr/local/bin, or Program Files on Windows) and
                    schedules from there — so deleting the download is harmless.
                    Needs root/Administrator.
  uninstall         Remove the scheduled run.
  verify M S        Offline-verify a local manifest+sig pair.
  gen-page          Render the self-contained HTML page (-base-url required).
  print-pins        List trusted signer fingerprints (embedded + locally-accepted).
  version           Print version.

Flags:
`)
		fs.PrintDefaults()
	}
}
