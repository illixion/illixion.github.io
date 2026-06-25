package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"time"
)

// These defaults are baked in at build time via -ldflags from updater/config.env
// (see release.sh) — editing that one file is how you point the whole system at
// your own deployment. The literals here are just fallbacks for plain
// `go build` / `go run`.
var (
	version        = "dev"
	defaultBaseURL = "https://illixion.github.io" // where the page, manifest, and bin/ live
	defaultTitle   = "Ixion"
	defaultHandle  = "@illixion"
	defaultRepoURL = "https://github.com/illixion/illixion.github.io" // source/doc links on the page
)

// defaultManifestURL is derived from the base URL at startup (after -ldflags has
// set defaultBaseURL), so there is only one URL to configure.
var defaultManifestURL = defaultBaseURL + "/manifest.json"

func logf(format string, args ...any) { log.Printf(format, args...) }

func main() {
	log.SetFlags(log.LstdFlags | log.LUTC)
	log.SetPrefix("ssh-keys-updater: ")

	defaultAK, defaultLocal := defaultKeyPaths()

	fs := flag.NewFlagSet("ssh-keys-updater", flag.ExitOnError)
	url := fs.String("url", defaultManifestURL, "manifest URL (signature is fetched from <url>.sig)")
	ak := fs.String("authorized-keys", defaultAK, "authorized_keys file to manage")
	local := fs.String("local-file", defaultLocal, "local key file appended verbatim after the managed block")
	insecure := fs.Bool("insecure-tls", false, "skip TLS verification (the SSHSIG signature still gates content)")
	timeout := fs.Duration("timeout", 30*time.Second, "HTTP timeout")
	interval := fs.Duration("interval", 15*time.Minute, "scheduled check cadence (install)")
	splay := fs.Duration("splay", 0, "max random delay before fetching, to desynchronize traffic (install bakes in =interval by default)")
	baseURL := fs.String("base-url", defaultBaseURL, "public base URL of the page/manifest/bin (gen-page)")
	pageTitle := fs.String("title", defaultTitle, "owner name shown on the page (gen-page)")
	pageHandle := fs.String("handle", defaultHandle, "handle shown under the name (gen-page)")
	pageRepo := fs.String("repo", defaultRepoURL, "source repository URL for page links (gen-page)")
	pageOut := fs.String("out", "", "write generated page here instead of stdout (gen-page)")
	fs.Usage = usage(fs)

	args := os.Args[1:]
	if len(args) == 0 {
		fs.Usage()
		os.Exit(2)
	}
	cmd := args[0]
	_ = fs.Parse(args[1:])

	splaySet := false
	fs.Visit(func(f *flag.Flag) {
		if f.Name == "splay" {
			splaySet = true
		}
	})

	cfg := Config{
		ManifestURL:    *url,
		AuthorizedKeys: *ak,
		LocalFile:      *local,
		InsecureTLS:    *insecure,
		Timeout:        *timeout,
		Splay:          *splay,
	}

	switch cmd {
	case "run":
		applySplay(cfg.Splay)
		if err := runUpdate(cfg); err != nil {
			log.Fatalf("update failed: %v", err)
		}
	case "install":
		// Scheduled runs splay by default (=interval) so checks don't all land
		// on :00/:15/:30/:45; the baked-in value travels via runArgs.
		if !splaySet {
			cfg.Splay = *interval
		}
		if err := installSchedule(cfg, *interval); err != nil {
			log.Fatalf("install failed: %v", err)
		}
		logf("scheduled run installed (every %s, splay up to %s); performing initial update now", *interval, cfg.Splay)
		immediate := cfg
		immediate.Splay = 0 // first run is immediate
		if err := runUpdate(immediate); err != nil {
			log.Fatalf("initial update failed: %v", err)
		}
	case "uninstall":
		if err := uninstallSchedule(); err != nil {
			log.Fatalf("uninstall failed: %v", err)
		}
		logf("scheduled run removed (authorized_keys left in place)")
	case "verify":
		// Offline debug helper: verify <manifest-file> <sig-file>.
		rest := fs.Args()
		if len(rest) != 2 {
			log.Fatalf("usage: ssh-keys-updater verify <manifest-file> <sig-file>")
		}
		if err := verifyFiles(cfg, rest[0], rest[1]); err != nil {
			log.Fatalf("verify failed: %v", err)
		}
	case "gen-page":
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
  ssh-keys-updater <command> [flags]

Commands:
  run         Fetch, verify, and install the manifest once.
  install     Install a periodic scheduled run (launchd/systemd/cron/schtasks) and run once.
  uninstall   Remove the scheduled run.
  verify      Offline-verify a local manifest+sig pair: verify <manifest> <sig>.
  gen-page    Render the self-contained HTML page to stdout or -out.
  print-pins  List the pinned signer fingerprints baked into this binary.
  version     Print version.

Flags:
`)
		fs.PrintDefaults()
	}
}
