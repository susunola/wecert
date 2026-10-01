package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/susunola/wecert/internal/config"
	"github.com/susunola/wecert/internal/webhook"
	"gopkg.in/yaml.v3"
)

// A name containing a newline must not be able to inject new config keys.
func TestCertificateNodeRejectsYAMLInjection(t *testing.T) {
	evil := "evil\n  attackerKey: pwned\n  keep: x"
	if _, err := certificateNode(evil, []string{"a.example.com"},
		"classic", "ecdsa-p256", "720h", "1000", "clb"); err == nil {
		t.Fatal("a name with a newline must be rejected, not rendered")
	}
	// A quoted-safe name still renders.
	node, err := certificateNode("ok-cert", []string{"a.example.com"},
		"classic", "ecdsa-p256", "720h", "1000", "clb")
	if err != nil {
		t.Fatal(err)
	}
	if node.Kind != yaml.MappingNode {
		t.Fatalf("certificate node must be a mapping, got %d", node.Kind)
	}
	if got := yamlFind(node, "name"); got == nil || got.Value != "ok-cert" {
		t.Errorf("entry missing name: %+v", node)
	}
	out, err := yaml.Marshal(node)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(out), "attackerKey") {
		t.Errorf("unexpected injected key:\n%s", out)
	}
}

// name is joined into a credential path; separators or ".." must be refused.
func TestAccountKeyPathRefusesTraversal(t *testing.T) {
	state := "/var/lib/wecert/state.db"
	root := "/var/lib/wecert/accounts"
	for _, bad := range []string{"../../etc/cron.d/x", "a/b", "..", ".", "x\x00y", "x\ny"} {
		if _, err := accountKeyPath(state, bad, ""); err == nil {
			t.Errorf("name %q must be rejected", bad)
		}
	}
	// A request that tries to escape the accounts dir is refused.
	if _, err := accountKeyPath(state, "good", "/etc/passwd"); err == nil {
		t.Error("keyPath outside the accounts dir must be rejected")
	}
	if _, err := accountKeyPath(state, "good", "/var/lib/wecert/accounts/../accounts/other.key"); err == nil {
		// cleaned path stays inside; allowed only if it resolves under the root
		// (this one cleans to accounts/other.key which is inside) — accept either
		// but never /etc/passwd.
	}
	got, err := accountKeyPath(state, "good", "")
	if err != nil {
		t.Fatal(err)
	}
	if got != filepath.Join(root, "good.key") {
		t.Errorf("derived keyPath = %q", got)
	}
	absInside, err := accountKeyPath(state, "good", filepath.Join(root, "good.key"))
	if err != nil {
		t.Errorf("an in-root keyPath must be allowed: %v", err)
	}
	_ = absInside
}

// A symlinked directory under accounts/ passes the lexical prefix check but
// redirects the AK/SK write outside the root; the resolved path must be refused.
func TestAccountKeyPathRefusesSymlinkedParent(t *testing.T) {
	dir := t.TempDir()
	state := filepath.Join(dir, "state.db")
	root := filepath.Join(dir, "accounts")
	outside := filepath.Join(dir, "outside")
	if err := os.MkdirAll(root, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(outside, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "escape")
	if err := os.Symlink(outside, link); err != nil {
		t.Fatal(err)
	}
	if _, err := accountKeyPath(state, "good", filepath.Join(link, "stolen.key")); err == nil {
		t.Fatal("keyPath through a symlinked directory under accounts/ must be rejected")
	}
	if _, err := accountKeyPath(state, "good", filepath.Join(root, "good.key")); err != nil {
		t.Errorf("an in-root keyPath must still be allowed: %v", err)
	}
}

// --- coverage for the create / account / bind paths (were 0%) ---

func TestCreateCertificateAdminWritesInsideTheListAndValidatesName(t *testing.T) {
	dir := t.TempDir()
	cfg := &config.Config{StatePath: filepath.Join(dir, "state.db")}
	cfgPath := filepath.Join(dir, "config.yaml")
	base := "certificates:\n  - name: demo\n    domains: [d.example.com]\n    profile: classic\n    keyType: ecdsa-p256\n    deploy:\n      enabled: false\ntencent:\n  secretId: id\nwebhook:\n  token: t\n"
	if err := os.WriteFile(cfgPath, []byte(base), 0o600); err != nil {
		t.Fatal(err)
	}
	old := configPathForAdmin
	configPathForAdmin = cfgPath
	defer func() { configPathForAdmin = old }()

	log, _ := quietLog()
	// the real signalSelf SIGHUPs this process; stub it for the test.
	oldSig := signalSelf
	signalSelf = func(os.Signal) error { return nil }
	defer func() { signalSelf = oldSig }()
	// injection must be refused before anything is written
	if _, err := createCertificateAdmin(cfg, webhook.CreateCertificateRequest{
		Name: "x\n evil: 1", Domains: []string{"a.example.com"},
	}, log); err == nil {
		t.Fatal("a name with a newline must be rejected")
	}
	if _, err := createCertificateAdmin(cfg, webhook.CreateCertificateRequest{
		Name: "fresh", Domains: []string{"f.example.com"},
		Profile: "classic", KeyType: "ecdsa-p256", RenewBefore: "30d",
		Deploy: "clb", UIN: "1000",
		DNS: &webhook.DNSCredential{Provider: "dnspod", Cred: "reused"},
	}, log); err != nil {
		t.Fatalf("create: %v", err)
	}
	got, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	text := string(got)
	idxNew := strings.Index(text, "name: fresh")
	idxTencent := strings.Index(text, "tencent:")
	if idxNew < 0 {
		t.Fatal("certificate not written")
	}
	if idxTencent >= 0 && idxNew > idxTencent {
		t.Fatalf("certificate landed after tencent: — YAML would not parse:\n%s", text)
	}
	if strings.Contains(text, "evil") {
		t.Fatalf("injection reached the file:\n%s", text)
	}
	// 30d must be converted to hours before it reaches the parser
	if !strings.Contains(text, "renewBefore: 720h") {
		t.Errorf("renewBefore not converted to Go duration:\n%s", text)
	}
}

// The console's CLB/Nginx filter reads the deploy target back out of the
// inventory, and a certificate created from the console only ever exists in the
// registry sidecar until someone edits the config. If the create path dropped the
// operator's choice there, the row would report the default backend instead of
// the one that was asked for -- and the filter could never show "Nginx".
func TestCreateCertificateAdminRecordsTheDeployChoiceInTheRegistry(t *testing.T) {
	dir := t.TempDir()
	cfg := &config.Config{StatePath: filepath.Join(dir, "state.db")}
	cfgPath := filepath.Join(dir, "config.yaml")
	base := "certificates:\n  - name: demo\n    domains: [d.example.com]\ntencent:\n  secretId: id\nwebhook:\n  token: t\n"
	if err := os.WriteFile(cfgPath, []byte(base), 0o600); err != nil {
		t.Fatal(err)
	}
	old := configPathForAdmin
	configPathForAdmin = cfgPath
	defer func() { configPathForAdmin = old }()
	log, _ := quietLog()
	oldSig := signalSelf
	signalSelf = func(os.Signal) error { return nil }
	defer func() { signalSelf = oldSig }()

	if _, err := createCertificateAdmin(cfg, webhook.CreateCertificateRequest{
		Name: "nginx-row", Domains: []string{"a.example.com"}, Profile: "classic",
		KeyType: "ecdsa-p256", Deploy: "nginx",
		DNS: &webhook.DNSCredential{Provider: "dnspod", Cred: "reused"},
	}, log); err != nil {
		t.Fatalf("create: %v", err)
	}
	list, err := webhook.ReadConsoleCertificates(cfg.StatePath)
	if err != nil {
		t.Fatal(err)
	}
	var found string
	for _, rec := range list {
		if rec.Name == "nginx-row" {
			found = rec.Deploy
		}
	}
	if found == "" {
		t.Fatalf("registry row for nginx-row missing its deploy choice: %+v", list)
	}
	if found != "nginx" {
		t.Errorf("registry deploy = %q, want the operator's nginx choice so the inventory can report it", found)
	}
}

func TestAccountAddRemoveRoundTripAndCorruptRefusal(t *testing.T) {
	dir := t.TempDir()
	cfg := &config.Config{StatePath: filepath.Join(dir, "state.db")}
	log, _ := quietLog()

	if _, err := addCloudAccount(cfg, webhook.AddAccountRequest{
		Name: "Prod", UIN: "111", Cred: "static", SecretID: "a", SecretKey: "b",
	}, log); err != nil {
		t.Fatal(err)
	}
	if _, err := addCloudAccount(cfg, webhook.AddAccountRequest{
		Name: "Stage", UIN: "222", Cred: "static", SecretID: "c", SecretKey: "d",
	}, log); err != nil {
		t.Fatal(err)
	}
	list, err := webhook.ReadCloudAccounts(cfg.StatePath)
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 2 {
		t.Fatalf("want 2 accounts, got %d", len(list))
	}
	// key files are derived under the accounts dir
	if _, err := os.Stat(filepath.Join(dir, "accounts", "Prod.key")); err != nil {
		t.Errorf("account key file missing: %v", err)
	}

	if _, err := removeCloudAccount(cfg, "111", log); err != nil {
		t.Fatal(err)
	}
	list, err = webhook.ReadCloudAccounts(cfg.StatePath)
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 1 || list[0].UIN != "222" {
		t.Fatalf("want only 222 left, got %+v", list)
	}

	// a corrupt registry must refuse the next add instead of wiping it
	reg := filepath.Join(dir, "cloud-accounts.json")
	if err := os.WriteFile(reg, []byte("{broken"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := addCloudAccount(cfg, webhook.AddAccountRequest{
		Name: "X", UIN: "333", Cred: "static", SecretID: "e", SecretKey: "f",
	}, log); err == nil {
		t.Fatal("addCloudAccount must fail on a corrupt registry")
	}
	data, _ := os.ReadFile(reg)
	if string(data) != "{broken" {
		t.Fatalf("corrupt registry was rewritten: %q", data)
	}
}

func TestBindCertificateRejectsMissingListener(t *testing.T) {
	dir := t.TempDir()
	cfg := &config.Config{StatePath: filepath.Join(dir, "state.db")}
	log, _ := quietLog()
	if _, err := bindCertificateAdmin(cfg, "nope", webhook.BindCertificateRequest{
		LoadBalancerID: "lb-1",
	}, log); err == nil {
		t.Fatal("bind without listenerId or createListener must be rejected")
	}
	if _, err := bindCertificateAdmin(cfg, "nope", webhook.BindCertificateRequest{
		LoadBalancerID: "lb-1",
		CreateListener: &webhook.CreateListenerRequest{Port: 99999},
	}, log); err == nil {
		t.Fatal("out-of-range listener port must be rejected")
	}
}

// Deleting the last certificate used to write the emptied config.yaml first and
// let the reload admission gate reject it afterwards: the console was told "ok",
// the file and the running state diverged, and the daemon could not start again
// ("at least one certificate is required" fires at startup too, not only at
// reload). The refusal must happen before the write, with the reason in the
// error the modal shows.
// Deleting the last certificate used to write the emptied config.yaml first and
// let the reload admission gate reject it afterwards: the console was told "ok",
// the file and the running state diverged, and the daemon could not start again.
// Static now legitimately ends empty (console-first cold start), so deleting the
// last one must go through; observe still diffs against the list, so there the
// refusal must happen before the write.
func TestDeleteCertificateAdminLastCertificate(t *testing.T) {
	dir := t.TempDir()
	cfg := &config.Config{StatePath: filepath.Join(dir, "state.db")}
	cfgPath := filepath.Join(dir, "config.yaml")
	state := filepath.Join(dir, "state.db")
	// The guard re-reads the config with config.Load, so the fixtures have to
	// be loadable in full -- the same minimal shape the process-level tests use.
	two := fmt.Sprintf(`statePath: %s
acme:
  directory: https://acme.invalid/directory
  email: ops@atomwangnus.com
dns:
  provider: dnspod
  loginToken: "12345,abcdef"
desiredState:
  mode: static
certificates:
  - name: demo
    domains: [d.example.com]
  - name: other
    domains: [o.example.com]
probe:
  enabled: false
tencent:
  credentialMode: static
  uin: "100012345678"
  regions: [ap-guangzhou]
`, state)
	one := strings.Replace(two,
		"  - name: demo\n    domains: [d.example.com]\n  - name: other\n    domains: [o.example.com]\n",
		"  - name: demo\n    domains: [d.example.com]\n", 1)
	observe := strings.Replace(strings.Replace(one,
		"mode: static", "mode: observe\n  path: "+state+".desired.yaml", 1),
		"", "", 1)

	oldPath := configPathForAdmin
	oldSig := signalSelf
	signalSelf = func(os.Signal) error { return nil }
	defer func() { configPathForAdmin = oldPath; signalSelf = oldSig }()
	log, _ := quietLog()

	// Static, one certificate: the delete goes through and the file ends empty.
	if err := os.WriteFile(cfgPath, []byte(one), 0o600); err != nil {
		t.Fatal(err)
	}
	configPathForAdmin = cfgPath
	if _, err := deleteCertificateAdmin(cfg, "demo", log); err != nil {
		t.Fatalf("static mode must allow emptying the list: %v", err)
	}
	got, _ := os.ReadFile(cfgPath)
	if strings.Contains(string(got), "name: demo") {
		t.Fatalf("static delete-last still wrote the entry:\n%s", got)
	}
	if !strings.Contains(string(got), "certificates: []") {
		t.Fatalf("expected an explicit empty list, got:\n%s", got)
	}

	// Two certificates: same, nothing special.
	if err := os.WriteFile(cfgPath, []byte(two), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := deleteCertificateAdmin(cfg, "demo", log); err != nil {
		t.Fatalf("deleting one of two must succeed: %v", err)
	}
	got, _ = os.ReadFile(cfgPath)
	if strings.Contains(string(got), "name: demo") || !strings.Contains(string(got), "name: other") {
		t.Fatalf("two-cert delete wrote the wrong file:\n%s", got)
	}

	// Observe, one certificate: refused before the write, file keeps the entry.
	if err := os.WriteFile(cfgPath, []byte(observe), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := deleteCertificateAdmin(cfg, "demo", log); err == nil {
		t.Fatal("observe mode must refuse to empty the list")
	}
	got, _ = os.ReadFile(cfgPath)
	if !strings.Contains(string(got), "name: demo") {
		t.Fatalf("refused observe delete must not touch the config:\n%s", got)
	}
}
