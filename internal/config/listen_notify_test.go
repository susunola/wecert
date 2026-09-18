package config

import (
	"os"
	"strings"
	"testing"
)

// notifyURL is POSTed to by the notifier after every renewal; a URL without a host
// or with another scheme would fail there, one renewal at a time, with the cause far
// from the config line -- so it is validated at load time.
func TestWebhookNotifyURLIsValidated(t *testing.T) {
	for _, u := range []string{
		"ftp://example.com/hook",
		"https://",
		"not a url",
		"example.com/hook",
	} {
		body := minimalPrefix + `
webhook:
  notifyURL: "` + u + `"
certificates:
  - name: t
    domains: ["example.com"]
`
		_, err := Load(writeConfig(t, body))
		if err == nil {
			t.Errorf("notifyURL %q must be rejected", u)
			continue
		}
		if !strings.Contains(err.Error(), "notifyURL") {
			t.Errorf("notifyURL %q: the error must name the field, got %v", u, err)
		}
	}
}

// A malformed listen address used to surface only when the server tried to bind --
// after the ACME account had been touched. Both listen fields are pre-checked with
// net.SplitHostPort at load time.
func TestListenAddressesArePreChecked(t *testing.T) {
	cases := []struct {
		name string
		body string
		want string
	}{
		{"metrics.listen without a port", "metrics:\n  listen: \"9800\"\n", "metrics.listen"},
		{"webhook.listen without a port", "webhook:\n  listen: \"127.0.0.1\"\n  token: \"0123456789abcdef0123456789abcdef\"\n", "webhook.listen"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Load(writeConfig(t, minimalPrefix+tc.body+`certificates:
  - name: t
    domains: ["example.com"]
`))
			if err == nil {
				t.Fatalf("%s must be rejected", tc.body)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("the error must name %q, got %v", tc.want, err)
			}
		})
	}
}

// Cross-AZ handshakes routinely take 3-5 seconds, so a probe timeout far below that
// fails every probe -- and every failed probe raises probe_errors, an alarm firing
// without a single real failure. There is a floor, like dns.pollingInterval's.
func TestProbeTimeoutHasAFloor(t *testing.T) {
	_, err := Load(writeConfig(t, minimalPrefix+oneCert+`
probe:
  timeout: 100ms
`))
	if err == nil {
		t.Fatal("a 100ms probe timeout must be rejected")
	}
	if !strings.Contains(err.Error(), "probe.timeout") {
		t.Errorf("the error must name the field, got %v", err)
	}
}

// Go durations have no day unit, so "30d" is the classic renewBefore typo; the
// error must point at the fix instead of leaving the operator at "unknown unit".
func TestParseDurationPointsOutThatDaysAreNotAUnit(t *testing.T) {
	_, err := Load(writeConfig(t, minimalPrefix+`certificates:
  - name: example-com
    domains: ["example.com"]
    renewBefore: 30d
`))
	if err == nil {
		t.Fatal("a day-unit duration must be rejected")
	}
	if !strings.Contains(err.Error(), "use hours") {
		t.Errorf("the error must suggest hours, got %v", err)
	}
}

// The warning helpers are pure so the decision and the wording are testable without
// capturing stderr from Load -- the same arrangement as state.statePathWarnings.

// A plaintext notification URL to another host exposes its credential: chat/CI
// webhook endpoints carry it in the URL path itself.
func TestNotifyURLWarnings(t *testing.T) {
	if w := notifyURLWarnings("http://hooks.example.com/x"); len(w) != 1 {
		t.Errorf("http to a non-loopback host must warn, got %v", w)
	}
	for _, u := range []string{
		"https://hooks.example.com/x",
		"http://127.0.0.1:9000/x",
		"http://[::1]:9000/x",
		"http://localhost:9000/x",
		"",
	} {
		if w := notifyURLWarnings(u); len(w) != 0 {
			t.Errorf("notifyURL %q must not warn, got %v", u, w)
		}
	}
}

// Binding beyond loopback widens the exposure of /metrics and of the token-guarded
// trigger endpoint. Sometimes that is exactly what is wanted (a Prometheus scraper on
// another host), so it warns rather than refuses.
func TestListenWarnings(t *testing.T) {
	for _, listen := range []string{"0.0.0.0:9800", ":9800", "10.0.0.5:9800"} {
		if w := listenWarnings("metrics.listen", listen); len(w) != 1 {
			t.Errorf("%q must warn, got %v", listen, w)
		}
	}
	for _, listen := range []string{"", "127.0.0.1:9800", "[::1]:9800", "localhost:9800"} {
		if w := listenWarnings("webhook.listen", listen); len(w) != 0 {
			t.Errorf("%q must not warn, got %v", listen, w)
		}
	}
}

// A config that inlines credentials must not be readable by group or other; the
// *_file variants and the environment exist so the secrets need not be in the file.
// It is a warning, not a refusal: 0644 configs are common in the wild.
func TestConfigPermWarnings(t *testing.T) {
	if w := configPermWarnings("/etc/wecert/config.yaml", 0o644, []string{"dns.loginToken"}); len(w) != 1 {
		t.Fatalf("a 0644 config carrying an inline secret must warn, got %v", w)
	}
	if w := configPermWarnings("/etc/wecert/config.yaml", 0o600, []string{"dns.loginToken"}); len(w) != 0 {
		t.Errorf("a 0600 config must not warn, got %v", w)
	}
	if w := configPermWarnings("/etc/wecert/config.yaml", 0o644, nil); len(w) != 0 {
		t.Errorf("a 0644 config without inline secrets must not warn, got %v", w)
	}
}

// A 0644 config with inline credentials warns but still loads: refusing would push
// operators toward deleting the check rather than tightening the mode.
func TestLoadWarnsButAcceptsALooseConfigWithInlineSecrets(t *testing.T) {
	path := writeConfig(t, minimalPrefix+`certificates:
  - name: example-com
    domains: ["example.com"]
`)
	// writeConfig creates 0600; loosen it to exercise the warning path.
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err != nil {
		t.Fatalf("a 0644 config with inline secrets must load (with a warning), got %v", err)
	}

	// The field list the warning is built from.
	fields := inlineSecretFields(&Config{
		DNS:     DNS{LoginToken: "t"},
		Tencent: Tencent{SecretID: "i", SecretKey: "k"},
		Webhook: Webhook{Token: "w", NotifySecret: "n"},
	})
	if got := strings.Join(fields, ","); got != "dns.loginToken,tencent.secretId,tencent.secretKey,webhook.token,webhook.notifySecret" {
		t.Errorf("inlineSecretFields = %q", got)
	}
}
