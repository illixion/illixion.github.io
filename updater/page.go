package main

import (
	_ "embed"
	"encoding/base64"
	"fmt"
	"html"
	"os"
	"strings"
)

// pageTemplate is the self-contained HTML page (inline CSS + JS, no external
// assets), with {{PLACEHOLDERS}} filled by genPage. It's embedded so the binary
// is a complete "generate my SSH key page" tool — an adopter sets their own
// pinned_signers and base URL, runs `gen-page`, and gets a working page with
// their fingerprints baked in. Dynamic data (the live key list and checksums)
// is fetched client-side, so the page never goes stale between regenerations.
//
//go:embed page.tmpl.html
var pageTemplate string

// genPage renders the page for the given public base URL and owner identity,
// using the pinned signers embedded in this binary as the trust anchor.
func genPage(baseURL, title, handle, repoURL string) (string, error) {
	pinned, err := loadPinnedSigners()
	if err != nil {
		return "", err
	}
	base := strings.TrimRight(baseURL, "/")
	repo := strings.TrimRight(repoURL, "/")
	// "owner/name" form for `gh attestation verify --repo`.
	repoSlug := strings.TrimPrefix(strings.TrimPrefix(repo, "https://github.com/"), "http://github.com/")

	// allowed_signers lines for the manual-verification block.
	var allowed strings.Builder
	for _, k := range pinned {
		fmt.Fprintf(&allowed, "%s %s %s\n",
			k.Comment, k.Algo, base64.StdEncoding.EncodeToString(k.Wire))
	}

	// Fingerprint rows for display.
	var fps strings.Builder
	for i, k := range pinned {
		if i > 0 {
			fps.WriteString("<br>\n")
		}
		fmt.Fprintf(&fps, `<code class="inline">%s</code> %s`,
			html.EscapeString(k.Comment), html.EscapeString(k.Fingerprint))
	}

	repl := strings.NewReplacer(
		"{{TITLE}}", html.EscapeString(title),
		"{{HANDLE}}", html.EscapeString(handle),
		"{{BASE_URL}}", html.EscapeString(base),
		"{{REPO_URL}}", html.EscapeString(repo),
		"{{REPO_SLUG}}", html.EscapeString(repoSlug),
		"{{SIGNERS_ALLOWED}}", html.EscapeString(strings.TrimRight(allowed.String(), "\n")),
		"{{SIGNERS_FP}}", fps.String(),
	)
	return repl.Replace(pageTemplate), nil
}

func genPageToFile(baseURL, title, handle, repoURL, out string) error {
	page, err := genPage(baseURL, title, handle, repoURL)
	if err != nil {
		return err
	}
	if out == "" {
		_, err := os.Stdout.WriteString(page)
		return err
	}
	if err := os.WriteFile(out, []byte(page), 0o644); err != nil {
		return err
	}
	logf("wrote %d bytes -> %s", len(page), out)
	return nil
}
