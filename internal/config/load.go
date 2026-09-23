// Package config defines wecert's declarative desired state (the spec).
//
// Design principle: the YAML says only "what I want" and carries no runtime
// state at all. Runtime state (order URL, ARI window, Tencent Cloud CertId and
// so on) always goes into SQLite, because losing it directly causes duplicate
// orders and runs into Let's Encrypt rate limits.
package config

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

// Split out so one concern lives in one file. Same package.

func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}

	cfg := &Config{}
	dec := yaml.NewDecoder(bytes.NewReader(data))
	// Unknown fields are a hard error, so a misspelled config never takes effect
	// silently.
	dec.KnownFields(true)
	if err := dec.Decode(cfg); err != nil {
		return nil, fmt.Errorf("parse config %s: %w", path, err)
	}
	// A second YAML document is a mistake, not a feature: KnownFields catches a misspelled
	// key but says nothing about everything after a stray "---", which a copy-paste or a
	// template edit produces. Silently ignoring half the file is exactly the "why isn't my
	// certificate being issued" failure this loader exists to prevent.
	if err := RejectExtraDocuments(dec, path); err != nil {
		return nil, err
	}

	// Captured before resolveSecretFiles fills the empty fields from files and the
	// environment: the permission warning at the end of Load is about secrets written
	// IN the file, which is only answerable while the inline values are still
	// distinguishable from the resolved ones.
	inlineSecrets := inlineSecretFields(cfg)

	// Resolve file- and environment-backed secrets before validation, so the validation rules see
	// the credential that will actually be used rather than the field the operator left empty.
	secretFileWarns, err := cfg.resolveSecretFiles()
	if err != nil {
		return nil, err
	}

	if err := cfg.normalize(); err != nil {
		return nil, err
	}

	// Warnings, not refusals -- the same call state.open makes. Each of these names a
	// posture the program cannot tell apart from a deliberate choice (a loopback-only
	// deployment cannot know the operator did not mean 0.0.0.0), so they are stated
	// plainly and left to the operator. See the helpers below; they are pure so the
	// wording is testable without capturing stderr.
	var warns []string
	warns = append(warns, secretFileWarns...)
	warns = append(warns, notifyURLWarnings(cfg.Webhook.NotifyURL)...)
	warns = append(warns, listenWarnings("metrics.listen", cfg.Metrics.Listen)...)
	warns = append(warns, listenWarnings("webhook.listen", cfg.Webhook.Listen)...)
	if len(inlineSecrets) > 0 {
		if fi, statErr := os.Stat(path); statErr == nil {
			warns = append(warns, configPermWarnings(path, fi.Mode().Perm(), inlineSecrets)...)
		}
	}
	for _, w := range warns {
		fmt.Fprintf(os.Stderr, "wecert: WARNING: %s\n", w)
	}
	return cfg, nil
}

// RejectExtraDocuments fails when the input holds more than one YAML document.
//
// An **empty** trailing document is not a second document: yaml.v3 decodes "---\n" to a nil
// value with no error, so a file that merely ends with a separator looked like a second
// document here and was refused. Load failing means the daemon does not start at all, so that
// guard was refusing a file whose meaning was never in doubt. Empty documents are skipped and
// only a document with content in it is rejected.
//
// Exported because the desired-state document uses the same rule and used to carry its own
// copy -- which fixed this for config only, and left the document path still refusing a
// trailing "---". One implementation is what keeps them from drifting again.
func RejectExtraDocuments(dec *yaml.Decoder, path string) error {
	for {
		var extra any
		if err := dec.Decode(&extra); err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return fmt.Errorf("parse config %s: %w", path, err)
		}
		if extra == nil {
			// "---" with nothing behind it. Keep reading: the next Decode is what says
			// whether the file really continues.
			continue
		}
		return fmt.Errorf("%s contains more than one YAML document (a stray '---'?); "+
			"everything after the first document would be ignored, so it is rejected instead", path)
	}
}

// ── startup warnings ────────────────────────────────────────────────────────────────
//
// These are warnings, not refusals -- the same call state.open makes for the state
// database. Each names a posture this program cannot tell apart from a deliberate
// choice, so each is stated plainly and left to the operator. The helpers are pure
// (the file's mode arrives as an argument) so the wording and the decision are
// testable without capturing stderr, exactly like state.statePathWarnings.

// inlineSecretFields lists the credential fields written directly into the config
// file. Called before resolveSecretFiles, which would fill the empty fields from
// files and the environment and make the inline ones indistinguishable.
func inlineSecretFields(c *Config) []string {
	var out []string
	if c.DNS.LoginToken != "" {
		out = append(out, "dns.loginToken")
	}
	// The two providers added next to dnspod carry the same kind of long-lived secret, and a
	// credential in a 0644 config is in every backup of it whether or not the warning knows the
	// field's name. dns.route53.sessionToken is deliberately absent: it is temporary, and it is
	// only read together with the static pair that the secretAccessKey entry already covers.
	if c.DNS.Cloudflare.APIToken != "" {
		out = append(out, "dns.cloudflare.apiToken")
	}
	if c.DNS.Route53.SecretAccessKey != "" {
		out = append(out, "dns.route53.secretAccessKey")
	}
	if c.Tencent.SecretID != "" {
		out = append(out, "tencent.secretId")
	}
	if c.Tencent.SecretKey != "" {
		out = append(out, "tencent.secretKey")
	}
	if c.Webhook.Token != "" {
		out = append(out, "webhook.token")
	}
	if c.Webhook.NotifySecret != "" {
		out = append(out, "webhook.notifySecret")
	}
	return out
}

// configPermWarnings warns when a config file that carries inline secrets is readable
// by anyone but its owner. A warning rather than a refusal: 0644 configs are common
// in the wild, and refusing would push operators toward deleting the check rather
// than tightening the mode. The *_file fields and the environment fallbacks exist so
// the secrets need not be in this file at all.
func configPermWarnings(path string, perm os.FileMode, inlineSecrets []string) []string {
	if len(inlineSecrets) == 0 || perm&0o077 == 0 {
		return nil
	}
	return []string{fmt.Sprintf(
		"the config file %s is readable by group or other (%04o) while carrying inline "+
			"credentials (%s). A credential in a 0644 file is in every backup and every "+
			"backup's off-site copy; use the *_file variants or the environment instead, or "+
			"chmod 0600 the file", path, perm, strings.Join(inlineSecrets, ", "))}
}

// notifyURLWarnings warns about a plaintext notification URL to another host.
//
// Chat/CI webhook endpoints (Slack, Feishu, DingTalk) carry their credential in the
// URL path itself, so http to a non-loopback host exposes the credential to anyone on
// the path. Loopback is exempt: nothing leaves the machine.
func notifyURLWarnings(notifyURL string) []string {
	if notifyURL == "" {
		return nil
	}
	u, err := url.Parse(notifyURL)
	if err != nil {
		// normalize already rejected an unparseable or non-http(s) URL; reaching this
		// branch would mean the two drifted apart, and silence is the wrong drift.
		return []string{fmt.Sprintf("webhook.notifyURL %q could not be re-parsed for the plaintext check: %v", notifyURL, err)}
	}
	if u.Scheme == "http" && !isLoopbackHost(u.Hostname()) {
		return []string{fmt.Sprintf(
			"webhook.notifyURL %q uses plaintext http to a non-loopback host. Notification "+
				"endpoints usually carry their credential in the URL path, so anyone on the "+
				"network path can read it; use https", notifyURL)}
	}
	return nil
}

// listenWarnings warns when a server binds beyond this machine.
//
// metrics.listen serves the expiry state of every certificate, and webhook.listen can
// trigger real issuance (it is token-guarded, but a wider bind widens the brute-force
// surface). Both default to loopback; binding further is sometimes exactly what is
// wanted -- Prometheus scraping from another host -- so this is a warning, not a refusal.
func listenWarnings(field, listen string) []string {
	if listen == "" {
		return nil
	}
	host, _, err := net.SplitHostPort(listen)
	if err != nil {
		// normalize already rejected a malformed address; as above, drift must be loud.
		return []string{fmt.Sprintf("%s %q could not be re-parsed for the bind-scope check: %v", field, listen, err)}
	}
	if isLoopbackHost(host) {
		return nil
	}
	// The trigger endpoint carries a bearer token over plaintext HTTP and can spend
	// real ACME quota. The generic "reachable from beyond this machine" warning is
	// the right tone for /metrics; for the hook it understates what a same-segment
	// observer can do with a sniffed token.
	if field == "webhook.listen" {
		return []string{fmt.Sprintf(
			"%s binds %s, which is reachable from beyond this machine (an empty host means "+
				"every interface). The trigger carries a bearer token over plaintext HTTP and "+
				"can spend real ACME rate-limit quota: put a TLS terminator in front of it, or "+
				"bind 127.0.0.1:<port> and reach it through a tunnel", field, listen)}
	}
	return []string{fmt.Sprintf(
		"%s binds %s, which is reachable from beyond this machine (an empty host means every "+
			"interface). If that is deliberate -- a Prometheus scraper on another host -- ignore "+
			"this; otherwise 127.0.0.1:<port> keeps it local", field, listen)}
}

// isLoopbackHost reports whether host names only this machine.
func isLoopbackHost(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// normalize validates and defaults every section of the configuration.
//
// Split by section so each block can be read (and tested) without scrolling past the
// others: root identity, DNS-01, listeners, Tencent Cloud deploy, the already-structured
// subsections, and the certificate list. The order is the dependency order -- DNS
// settings are only meaningful once the provider is chosen, and the certificate checks
// come last because they consult profile defaults filled in above.
