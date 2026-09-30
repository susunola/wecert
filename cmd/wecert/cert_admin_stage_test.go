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

func TestInsertCertificateBlockIntoEmptyList(t *testing.T) {
	config := "certificates: []\ntencent:\n  secretId: id\n"
	got, err := insertCertificateBlock(config, "\n  - name: only\n")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(got, "certificates: []") {
		t.Errorf("empty list placeholder should be replaced, got:\n%s", got)
	}
	if strings.Index(got, "- name: only") > strings.Index(got, "tencent:") {
		t.Errorf("entry landed after tencent:\n%s", got)
	}
}
