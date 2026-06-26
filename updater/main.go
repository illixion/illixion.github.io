package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"time"
)

// version is the only build-time-baked value (-ldflags "-X main.version=...").
// There is deliberately NO baked URL or identity: the deployment location is
// supplied at runtime (a domain argument + the site's discovery.json), so a
// host move needs no rebuild. Trust still lives at compile time, in
// pinned_signers.
var version = "dev"

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
		if err := installSchedule(cfg, loc.interval()); err != nil {
			log.Fatalf("install failed: %v", err)
		}
		logf("scheduled every %s (splay up to %s); manifest %s — running once now",
			loc.interval(), loc.splay(), loc.ManifestURL)
		cfg.ManifestURL = loc.ManifestURL
		if err := runUpdate(cfg); err != nil { // initial run is immediate (no splay)
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
		pinned, err := loadPinnedSigners()
		if err != nil {
			log.Fatalf("%v", err)
		}
		for _, k := range pinned {
			fmt.Printf("%s  %s\n", k.Fingerprint, k.Comment)
		}
	case "version":
		fmt.Printf("ssh-keys-updater %s (%s)\n", version, manifestSchemaInfo())
	default:
		fs.Usage()
		os.Exit(2)
	}
}

func manifestSchemaInfo() string { return fmt.Sprintf("manifest schema %d", manifestSchema) }

func verifyFiles(cfg Config, manifestPath, sigPath string) error {
	pinned, err := loadPinnedSigners()
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
                    (launchd/systemd/cron/schtasks), and run once. Prompts for the
                    domain if not given and stdin is a terminal.
  uninstall         Remove the scheduled run.
  verify M S        Offline-verify a local manifest+sig pair.
  gen-page          Render the self-contained HTML page (-base-url required).
  print-pins        List the pinned signer fingerprints baked into this binary.
  version           Print version.

Flags:
`)
		fs.PrintDefaults()
	}
}
