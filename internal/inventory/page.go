package inventory

import (
	_ "embed"
	"encoding/base64"
	"html/template"
	"io"
)

// All assets are embedded so /status needs no public asset route or CDN.
//
//go:embed console.html
var pageHTML string

//go:embed console.css
var pageCSS string

//go:embed console.js
var pageJS string

//go:embed assets/logo-mark.png
var logo []byte

//go:embed assets/logo-mark-dark.png
var logoDark []byte

var pageTmpl = template.Must(template.New("status").Parse(pageHTML))

// WritePage renders one read-only snapshot. html/template JSON-encodes Snapshot
// in the script data context, escaping script terminators and HTML metacharacters.
// Only embedded, developer-controlled assets use the trusted template types.
func WritePage(w io.Writer, snap Snapshot) error {
	accounts := []string{}
	seen := map[string]bool{}
	for _, c := range snap.Certificates {
		if !seen[c.UIN] {
			accounts = append(accounts, c.UIN)
			seen[c.UIN] = true
		}
	}
	return pageTmpl.Execute(w, struct {
		Snapshot Snapshot
		Accounts []string
		CSS      template.CSS
		JS       template.JS
		Logo     template.URL
		LogoDark template.URL
	}{
		Snapshot: snap, Accounts: accounts,
		CSS: template.CSS(pageCSS), JS: template.JS(pageJS),
		Logo:     template.URL("data:image/png;base64," + base64.StdEncoding.EncodeToString(logo)),
		LogoDark: template.URL("data:image/png;base64," + base64.StdEncoding.EncodeToString(logoDark)),
	})
}
