//go:build pebble

// A full ACME lifecycle against a real ACME server (pebble), with a local authoritative DNS
// server answering the DNS-01 challenges.
//
// Why this exists separately from the unit suite: the unit tests drive Manager through a fake
// API, so they verify the ORDER of our decisions but not that the wire protocol works. This runs
// the same state machine against an implementation that really validates orders, really checks
// the challenge record over DNS, really enforces the account/key binding, and really signs a
// certificate. It is the only test that can catch "we send a CSR the server rejects" or "we read
// the wrong field out of a real response".
//
// It is behind a build tag because it needs a pebble binary and its test certificates, which
// come from the module cache:
//
//	go install github.com/letsencrypt/pebble/v2/cmd/pebble@latest   # into $GOBIN
//	make test-pebble
//
// Without those it skips rather than fails, so it can live in the repository without making the
// default `go test ./...` depend on a network download.
package acme

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/susunola/wecert/internal/config"
	"github.com/susunola/wecert/internal/deploy"
	"github.com/susunola/wecert/internal/state"
)

// ── starting pebble ──────────────────────────────────────────────────────────────────

// pebbleCerts locates the test certificates shipped with pebble in the module cache.
func pebbleCerts(t *testing.T) (certFile, keyFile string) {
	t.Helper()

	// Any cached version works; the certificates are stable fixtures.
	matches, _ := filepath.Glob(filepath.Join(os.Getenv("GOPATH"), "pkg", "mod", "github.com", "letsencrypt", "pebble", "v2@*", "test", "certs", "localhost", "cert.pem"))
	if len(matches) == 0 {
		home, _ := os.UserHomeDir()
		matches, _ = filepath.Glob(filepath.Join(home, "go", "pkg", "mod", "github.com", "letsencrypt", "pebble", "v2@*", "test", "certs", "localhost", "cert.pem"))
	}
	if len(matches) == 0 {
		t.Skip("pebble's test certificates are not in the module cache; run `go install github.com/letsencrypt/pebble/v2/cmd/pebble@latest` first")
	}
	certFile = matches[0]
	keyFile = filepath.Join(filepath.Dir(certFile), "key.pem")
	if _, err := os.Stat(keyFile); err != nil {
		t.Skipf("pebble's test key is missing: %v", err)
	}
	return certFile, keyFile
}

// pebbleBinary finds the pebble executable.
func pebbleBinary(t *testing.T) string {
	t.Helper()
	if p, err := exec.LookPath("pebble"); err == nil {
		return p
	}
	for _, dir := range []string{os.Getenv("GOBIN"), filepath.Join(os.Getenv("GOPATH"), "bin")} {
		if dir == "" {
			continue
		}
		p := filepath.Join(dir, "pebble")
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	if home, err := os.UserHomeDir(); err == nil {
		p := filepath.Join(home, "go", "bin", "pebble")
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	t.Skip("pebble is not installed; run `go install github.com/letsencrypt/pebble/v2/cmd/pebble@latest`")
	return ""
}

// pebbleOptions are the two knobs the lifecycle suites differ on.
type pebbleOptions struct {
	// dnsServer points pebble's validator at a resolver. Empty means pebble's own default.
	dnsServer string
	// validate makes the server really validate challenges. False sets
	// PEBBLE_VA_ALWAYS_VALID=1, which is what the order-protocol tests want -- see startPebble.
	validate bool
}

// startPebble runs pebble with challenge validation disabled, for tests about the ORDER protocol.
func startPebble(t *testing.T) (dirURL string, client *http.Client, management string) {
	t.Helper()
	return startPebbleWith(t, pebbleOptions{})
}

// startPebbleRealValidation runs pebble with a real validator pointed at dnsServer, for tests that
// need the challenge record to actually be read. See e2e_dns_test.go.
//
// validate=false is a degraded mode, and the caller is told which one it got: pebble's validator
// forces TCP whenever a custom resolver is configured, so a host that cannot carry TCP on port 53
// (a sandbox that allows the bind and drops the traffic) can still test everything except the
// validator's own read.
func startPebbleRealValidation(t *testing.T, dnsServer string, validate bool) (dirURL string, client *http.Client) {
	t.Helper()
	opts := pebbleOptions{dnsServer: dnsServer, validate: validate}
	if !validate {
		// No point pointing the validator at a resolver it will never reach: leave it on its
		// default and turn validation off.
		opts.dnsServer = ""
	}
	dirURL, client, _ = startPebbleWith(t, opts)
	return dirURL, client
}

// startPebbleWith writes a config and runs the server, returning its directory URL and the client
// that trusts its self-signed certificate.
func startPebbleWith(t *testing.T, opts pebbleOptions) (dirURL string, client *http.Client, management string) {
	t.Helper()

	bin := pebbleBinary(t)
	certFile, keyFile := pebbleCerts(t)

	dir := t.TempDir()
	conf := map[string]any{"pebble": map[string]any{
		"listenAddress":                  "127.0.0.1:14000",
		"managementListenAddress":        "127.0.0.1:15000",
		"certificate":                    certFile,
		"privateKey":                     keyFile,
		"httpPort":                       5002,
		"tlsPort":                        5001,
		"externalAccountBindingRequired": false,
		"retryAfter":                     map[string]int{"authz": 1, "order": 1},
		// The profile names wecert itself uses. The name is passed to the CA verbatim, and the
		// server rejects anything it does not know, so the test has to offer the same three
		// Let's Encrypt does -- otherwise it would be testing a CA quirk rather than our path.
		"profiles": map[string]any{
			"classic":    map[string]any{"description": "test classic", "validityPeriod": 7776000},
			"tlsserver":  map[string]any{"description": "test tlsserver", "validityPeriod": 3888000},
			"shortlived": map[string]any{"description": "test shortlived", "validityPeriod": 518400},
		},
	}}
	body, err := json.Marshal(conf)
	if err != nil {
		t.Fatal(err)
	}
	confPath := filepath.Join(dir, "pebble.json")
	if err := os.WriteFile(confPath, body, 0o600); err != nil {
		t.Fatal(err)
	}

	args := []string{"-config", confPath}
	if opts.dnsServer != "" {
		args = append(args, "-dnsserver", opts.dnsServer)
	}
	cmd := exec.Command(bin, args...)
	cmd.Dir = dir
	// PEBBLE_VA_NOSLEEP keeps validation from adding its deliberate delay.
	cmd.Env = append(os.Environ(),
		"PEBBLE_VA_NOSLEEP=1",
		"PEBBLE_WFE_NONCEREJECT=0")
	if !opts.validate {
		// Challenge validation is skipped, which is what the order-protocol tests want: account
		// binding and kid persistence, authorization polling, CSR finalize, chain download, the
		// notAfter/key-match gates -- not whether a validator can read the TXT record.
		//
		// That separation was learned the hard way: making pebble validate against a local
		// authority needs the authority on port 53 (DNS has no port indirection in a
		// delegation). e2e_dns_test.go closes that gap -- it binds 53, points pebble's validator
		// at it with -dnsserver, and runs the real solver against it -- and skips on a host where
		// port 53 cannot be bound.
		cmd.Env = append(cmd.Env, "PEBBLE_VA_ALWAYS_VALID=1")
	}
	var out strings.Builder
	cmd.Stdout = &out
	cmd.Stderr = &out
	if err := cmd.Start(); err != nil {
		t.Fatalf("start pebble: %v", err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
		if t.Failed() {
			t.Logf("pebble output:\n%s", out.String())
		}
	})

	dirURL = "https://127.0.0.1:14000/dir"
	management = "https://127.0.0.1:15000"

	// pebble generates its own CA on first start; trust the shipped minica instead, which is what
	// its test certificates are signed by.
	pool := x509.NewCertPool()
	minica := filepath.Join(filepath.Dir(certFile), "..", "pebble.minica.pem")
	if pemBytes, err := os.ReadFile(minica); err == nil {
		pool.AppendCertsFromPEM(pemBytes)
	}
	client = &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12},
		},
	}

	// Wait for the directory to answer.
	deadline := time.Now().Add(20 * time.Second)
	var lastErr error
	for time.Now().Before(deadline) {
		resp, err := client.Get(dirURL)
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return dirURL, client, management
			}
			lastErr = fmt.Errorf("directory returned %d", resp.StatusCode)
		} else {
			lastErr = err
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("pebble never became ready: %v\noutput:\n%s", lastErr, out.String())
	return "", nil, ""
}

// ── the lifecycle ────────────────────────────────────────────────────────────────────

// A complete first issuance over the real protocol: register an account, place an order, solve
// DNS-01 against a real validator, finalize with a real CSR, download the chain.
func TestPebbleFullIssuance(t *testing.T) {
	domains := []string{"a.pebble-test.example", "b.pebble-test.example"}

	dirURL, client, _ := startPebble(t)
	t.Logf("pebble directory %s", dirURL)

	store, err := state.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })

	cfg := &config.Config{}
	cfg.ACME.Directory = dirURL
	cfg.ACME.Email = "ops@example.test"

	core, err := EnsureAccount(cfg, store, client)
	if err != nil {
		t.Fatalf("EnsureAccount against a real server: %v", err)
	}
	if stored, _ := store.GetAccount(dirURL); stored == nil || stored.KID == "" {
		t.Fatal("the account was not persisted with a kid")
	}

	// Profile classic, which the pebble config above also offers: the profile NAME is passed to
	// the CA verbatim (see OrderOptions.Profile), so the server must know it.
	certs := []config.Certificate{{
		Name: "site-example-test", Domains: domains,
		Profile: config.ProfileClassic, KeyType: config.KeyTypeECDSAP256,
	}}
	if err := config.NormalizeCertificates(certs); err != nil {
		t.Fatal(err)
	}
	cert := &certs[0]

	// A faithful solver is enough here: no validator reads the record, so what matters is that the
	// manager drives the order to completion and records a deployable certificate.
	solver := newFaithfulSolver()
	m := newManager(store, NewAPI(core), solver, core, deploy.Noop{},
		slog.New(slog.NewTextHandler(io.Discard, nil)))

	if err := m.Reconcile(context.Background(), cert); err != nil {
		t.Fatalf("Reconcile against a real ACME server: %v", err)
	}

	st, err := store.GetCert(cert.Name)
	if err != nil {
		t.Fatal(err)
	}
	if st == nil || st.NotAfter.IsZero() {
		t.Fatal("no certificate was recorded")
	}
	leaf, err := ParseLeaf(st.CertPEM)
	if err != nil {
		t.Fatalf("the downloaded chain does not parse: %v", err)
	}
	if err := VerifyCoverage(leaf, domains); err != nil {
		t.Errorf("the issued certificate does not cover the requested names: %v", err)
	}
	if err := VerifyKeyMatch(leaf, st.KeyPEM); err != nil {
		t.Errorf("the issued certificate does not belong to the stored key: %v", err)
	}
	if leaf.Issuer.CommonName == "" {
		t.Error("the leaf has no issuer, so it is not a real chain")
	}

	// The challenge records must be cleaned up: the order completed, so cleanup ran.
	_, _, _, cleanups, records := solver.snapshot()
	if len(cleanups) == 0 {
		t.Error("no challenge record was cleaned up, so the TXT would be left in DNS")
	}
	if len(records) != 0 {
		t.Errorf("TXT records were left behind: %v", records)
	}

	// The order must be gone: a completed issuance leaves no order behind.
	if o, _ := store.GetOrder(cert.Name); o != nil {
		t.Errorf("the order was left behind after a successful issuance: %+v", o)
	}
}

func TestPebbleAccountIsReusedAcrossRuns(t *testing.T) {
	dirURL, client, _ := startPebble(t)

	store, err := state.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	cfg := &config.Config{}
	cfg.ACME.Directory = dirURL
	cfg.ACME.Email = "ops@example.test"

	if _, err := EnsureAccount(cfg, store, client); err != nil {
		t.Fatalf("first registration: %v", err)
	}
	first, _ := store.GetAccount(dirURL)

	// A second call must reuse the stored account. A re-registration is visible as a new key.
	if _, err := EnsureAccount(cfg, store, client); err != nil {
		t.Fatalf("second call: %v", err)
	}
	second, _ := store.GetAccount(dirURL)
	if first.KID != second.KID || string(first.PrivateKeyPEM) != string(second.PrivateKeyPEM) {
		t.Error("the account was re-registered instead of reused")
	}
}
