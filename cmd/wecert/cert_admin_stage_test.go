package main

import (
	"gopkg.in/yaml.v3"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The new entry has to land INSIDE the certificates list. Appending it to the end
// of the document puts it after tencent:/webhook: and the YAML no longer parses.
func TestInsertCertificateBlockKeepsTheEntryInsideTheList(t *testing.T) {
	config := `statePath: /tmp/wecert-test.db
acme:
  directory: https://acme-staging-v02.api.letsencrypt.org/directory
  email: ops@atomwangnus.com
dns:
  provider: dnspod
  loginToken: token
tencent:
  credentialMode: static
  secretId: id
  secretKey: key
  regions: [ap-guangzhou]
certificates:
  - name: demo
    domains: [demo.example.com]
    profile: classic
    keyType: ecdsa-p256
    deploy:
      enabled: false
`
	// trailing tencent block AFTER the list — this is what used to corrupt
	config += `# nothing follows the list in this fixture\n`
	// simulate the real shape: tencent after certificates
	config = `statePath: /tmp/wecert-test.db
acme:
  directory: https://acme-staging-v02.api.letsencrypt.org/directory
  email: ops@atomwangnus.com
dns:
  provider: dnspod
  loginToken: token
certificates:
  - name: demo
    domains: [demo.example.com]
    profile: classic
    keyType: ecdsa-p256
    deploy:
      enabled: false
tencent:
  credentialMode: static
  secretId: id
  secretKey: key
  regions: [ap-guangzhou]
webhook:
  listen: 127.0.0.1:9801
  token: tok
`
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte(config), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := stageCertificateInConfig(path, "fresh", []string{"fresh.example.com"},
		"classic", "ecdsa-p256", "1000", "720h", "clb"); err != nil {
		t.Fatalf("stageCertificateInConfig: %v", err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	text := string(got)
	// the entry must appear before the tencent block
	idxNew := strings.Index(text, "- name: fresh")
	idxTencent := strings.Index(text, "tencent:")
	if idxNew < 0 {
		t.Fatal("new certificate was not written")
	}
	if idxTencent >= 0 && idxNew > idxTencent {
		t.Fatalf("new certificate landed after tencent: — YAML would not parse:\n%s", text)
	}
	// A column-0 "- name:" is not a list item under certificates:, it is a
	// second top-level fragment. The document must still parse as one.
	var doc map[string]any
	if err := yaml.Unmarshal(got, &doc); err != nil {
		t.Fatalf("config no longer parses after create: %v\n%s", err, text)
	}
	if certs, ok := doc["certificates"].([]any); !ok || len(certs) != 2 {
		t.Fatalf("want 2 certificates in the list, got %#v", doc["certificates"])
	}
	if !strings.Contains(text, "renewBefore: 720h") {
		t.Error("renewBefore missing")
	}
	if !strings.Contains(text, "enabled: true") {
		t.Error("deploy.enabled should be true for deploy=clb")
	}
}

func TestStageCertificateIntoEmptyList(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	config := "certificates: []\ntencent:\n  secretId: id\n"
	if err := os.WriteFile(path, []byte(config), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := stageCertificateInConfig(path, "only", []string{"only.example.com"},
		"classic", "ecdsa-p256", "", "", "none"); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	text := string(got)
	if strings.Contains(text, "certificates: []") {
		t.Errorf("empty list placeholder should be replaced, got:\n%s", text)
	}
	if strings.Index(text, "- name: only") > strings.Index(text, "tencent:") {
		t.Errorf("entry landed after tencent:\n%s", text)
	}
	var doc map[string]any
	if err := yaml.Unmarshal(got, &doc); err != nil {
		t.Fatalf("config no longer parses: %v\n%s", err, text)
	}
}

// A freshly installed or hand-written config declares "no certificates yet"
// with a bare "certificates:" key, which parses as null rather than as an empty
// list. Refusing it would leave the console's create form permanently broken on
// a daemon that is otherwise running fine.
func TestStageCertificateIntoANullList(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	config := "certificates:\ntencent:\n  secretId: id\n"
	if err := os.WriteFile(path, []byte(config), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := stageCertificateInConfig(path, "first", []string{"first.example.com"},
		"classic", "ecdsa-p256", "", "", "clb"); err != nil {
		t.Fatalf("a null certificates list must be usable, got: %v", err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := yaml.Unmarshal(got, &doc); err != nil {
		t.Fatalf("config no longer parses: %v\n%s", err, got)
	}
	certs, ok := doc["certificates"].([]any)
	if !ok || len(certs) != 1 {
		t.Fatalf("want one certificate in the list, got %#v", doc["certificates"])
	}
}

// A certificate that exists only in the console registry must still be
// removable: failing on the config here leaves a row the operator can see in the
// inventory and cannot delete.
func TestRemoveCertificateFromAnEmptyOrMissingListIsANoOp(t *testing.T) {
	dir := t.TempDir()
	for name, config := range map[string]string{
		"null":    "certificates:\ntencent:\n  secretId: id\n",
		"missing": "tencent:\n  secretId: id\n",
		"empty":   "certificates: []\ntencent:\n  secretId: id\n",
	} {
		path := filepath.Join(dir, name+".yaml")
		if err := os.WriteFile(path, []byte(config), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := removeCertificateFromConfig(path, "ghost"); err != nil {
			t.Errorf("%s list: removing a certificate that is not there must be a no-op, got %v", name, err)
		}
	}
}

func TestStageCertificateIntoInlineList(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	config := "certificates: [{name: a, domains: [a.example.com]}]\ntencent:\n  secretId: id\n"
	if err := os.WriteFile(path, []byte(config), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := stageCertificateInConfig(path, "fresh", []string{"fresh.example.com"},
		"classic", "ecdsa-p256", "", "", "none"); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := yaml.Unmarshal(got, &doc); err != nil {
		t.Fatalf("inline certificates list must stay parseable after append: %v\n%s", err, got)
	}
	if certs, ok := doc["certificates"].([]any); !ok || len(certs) != 2 {
		t.Fatalf("want 2 certificates, got %#v", doc["certificates"])
	}
}

func TestStageCertificateDeduplicatesByParsedName(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	config := "certificates:\n  - name: \"fresh\"\n    domains: [fresh.example.com]\n"
	if err := os.WriteFile(path, []byte(config), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := stageCertificateInConfig(path, "fresh", []string{"fresh.example.com"},
		"classic", "ecdsa-p256", "", "", "none")
	if err != nil {
		t.Fatal(err)
	}
	if got != "already-present" {
		t.Fatalf("a quoted name: \"fresh\" must dedupe against the bare name, got %q", got)
	}
}

// wireDNSCredentials must edit the YAML tree, so an inline dns block, a quoted
// value, or a missing dns block is handled correctly rather than missed by a
// line-prefix match.
func TestWireDNSCredentialsEditsTheTree(t *testing.T) {
	cases := []struct {
		name     string
		config   string
		provider string
		token    string
		wantKey  string
	}{
		{"block", "dns:\n  provider: dnspod\n  loginTokenFile: old\n", "dnspod", "/new/token", "loginTokenFile"},
		{"inline", "dns: {provider: dnspod, loginTokenFile: old}\n", "dnspod", "/new/token", "loginTokenFile"},
		{"missing", "tencent:\n  secretId: id\n", "cloudflare", "/cf/token", "apiTokenFile"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "config.yaml")
			if err := os.WriteFile(path, []byte(tc.config), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := wireDNSCredentials(path, tc.provider, tc.token); err != nil {
				t.Fatal(err)
			}
			got, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			var doc map[string]any
			if err := yaml.Unmarshal(got, &doc); err != nil {
				t.Fatalf("config no longer parses: %v\n%s", err, got)
			}
			dns, ok := doc["dns"].(map[string]any)
			if !ok {
				t.Fatalf("dns must be a mapping, got %#v", doc["dns"])
			}
			if dns[tc.wantKey] != tc.token {
				t.Errorf("%s = %v, want %q", tc.wantKey, dns[tc.wantKey], tc.token)
			}
			if dns["provider"] != tc.provider {
				t.Errorf("provider = %v, want %q", dns["provider"], tc.provider)
			}
		})
	}
}
