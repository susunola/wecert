package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/susunola/wecert/internal/state"
)

// selfSignedPEM builds the smallest certificate the revocation path will accept.
func selfSignedPEM(t *testing.T, notAfter time.Time) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(4242),
		Subject:      pkix.Name{CommonName: "example.com"},
		DNSNames:     []string{"example.com"},
		NotBefore:    notAfter.Add(-24 * time.Hour),
		NotAfter:     notAfter,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

// A revocation must be recorded even when the CA cannot be reached at all.
//
// runRevoke used to prepare the ACME account -- the step that reads the CA directory -- BEFORE the
// request was written, so with an unreachable CA the command failed with nothing recorded: no retry,
// no wecert_revocation_pending, and docs/recovery.md's promise ("written to the state store FIRST, so
// a transient CA failure leaves a durable record") quietly false. This drives the whole command
// against a directory that cannot resolve, which is the shape of the outage.
func TestRevokeRecordsTheRequestBeforeItNeedsTheCA(t *testing.T) {
	dir := t.TempDir()
	statePath := filepath.Join(dir, "state.db")
	configPath := filepath.Join(dir, "config.yaml")

	store, err := state.Open(statePath)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if err := store.PutCert(&state.CertState{
		Name:     "example-com",
		NotAfter: time.Now().Add(30 * 24 * time.Hour),
		CertPEM:  selfSignedPEM(t, time.Now().Add(30*24*time.Hour)),
	}); err != nil {
		t.Fatalf("PutCert: %v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	// A directory that cannot be reached: .invalid is reserved and never resolves (RFC 2606).
	cfg := "statePath: " + statePath + "\n" +
		"acme:\n  directory: https://acme.invalid/directory\n  email: ops@atomwangnus.com\n" +
		"dns:\n  provider: dnspod\n  loginToken: \"12345,abcdef\"\n" +
		"tencent:\n  credentialMode: static\n  secretId: id\n  secretKey: key\n" +
		"  regions: [ap-guangzhou]\n" +
		"certificates:\n  - name: example-com\n    domains: [example.com]\n"
	if err := os.WriteFile(configPath, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}

	err = runRevoke(context.Background(), configPath, "", "example-com", "keyCompromise", true)
	if err == nil {
		t.Fatal("an unreachable CA must be reported")
	}
	if !strings.Contains(err.Error(), "prepare the ACME account") {
		t.Errorf("the failure should name the step that failed, got: %v", err)
	}

	store, err = state.Open(statePath)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer store.Close()
	req, err := store.GetRevokeRequest("example-com")
	if err != nil {
		t.Fatalf("GetRevokeRequest: %v", err)
	}
	if req == nil {
		t.Fatal("the operator's decision was not recorded, so nothing will retry it when the CA returns")
	}
	if req.Reason != 1 {
		t.Errorf("reason = %d, want 1 (keyCompromise)", req.Reason)
	}
}

// The signal context now reaches runRevoke, but it must never be consulted BEFORE the
// operator's decision is durable: a SIGTERM landing between the command line and the store
// write would otherwise leave a compromised key unrecorded, with nothing to retry. The CA
// attempt itself is intentionally context-free (see internal/acme's processRevocation), so a
// cancelled ctx changes only the plumbing here -- the recording order is the contract this
// pins.
func TestRevokeWithACancelledSignalContextStillRecordsFirst(t *testing.T) {
	dir := t.TempDir()
	statePath := filepath.Join(dir, "state.db")
	configPath := filepath.Join(dir, "config.yaml")

	store, err := state.Open(statePath)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if err := store.PutCert(&state.CertState{
		Name:     "example-com",
		NotAfter: time.Now().Add(30 * 24 * time.Hour),
		CertPEM:  selfSignedPEM(t, time.Now().Add(30*24*time.Hour)),
	}); err != nil {
		t.Fatalf("PutCert: %v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	// The same unreachable directory as above: the CA attempt must fail, the record must not.
	cfg := "statePath: " + statePath + "\n" +
		"acme:\n  directory: https://acme.invalid/directory\n  email: ops@atomwangnus.com\n" +
		"dns:\n  provider: dnspod\n  loginToken: \"12345,abcdef\"\n" +
		"tencent:\n  credentialMode: static\n  secretId: id\n  secretKey: key\n" +
		"  regions: [ap-guangzhou]\n" +
		"certificates:\n  - name: example-com\n    domains: [example.com]\n"
	if err := os.WriteFile(configPath, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // the signal arrived before the command even started
	err = runRevoke(ctx, configPath, "", "example-com", "keyCompromise", true)
	if err == nil {
		t.Fatal("an unreachable CA must be reported even when the signal context is already cancelled")
	}

	store, err = state.Open(statePath)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer store.Close()
	req, err := store.GetRevokeRequest("example-com")
	if err != nil {
		t.Fatalf("GetRevokeRequest: %v", err)
	}
	if req == nil {
		t.Fatal("a cancelled signal context must not prevent the revocation request from being " +
			"recorded: without the record nothing retries when the CA returns")
	}
}

// A sealed deployment can still record a revocation.
//
// revoke.go opened the state store with the tool path, which installs no sealer: on a deployment
// that had configured stateEncryption, every sealed blob reached the caller as ciphertext, and the
// command failed while reading the certificate it was asked to revoke. That is the worst possible
// place for this failure -- -revoke is the command an operator runs when a key has leaked, and the
// deployments most likely to run it are the ones that sealed the database. The store is opened the
// way the daemon opens it now.
func TestRevokeRecordIsWrittenOnASealedStore(t *testing.T) {
	dir := t.TempDir()
	statePath := filepath.Join(dir, "state.db")
	configPath := filepath.Join(dir, "config.yaml")
	keyPath := filepath.Join(dir, "state.key")
	master := "a-long-random-master-key-for-the-test"
	if err := os.WriteFile(keyPath, []byte(master+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	store, err := state.OpenSealed(statePath, []byte(master))
	if err != nil {
		t.Fatalf("OpenSealed: %v", err)
	}
	if err := store.PutCert(&state.CertState{
		Name:     "example-com",
		NotAfter: time.Now().Add(30 * 24 * time.Hour),
		CertPEM:  selfSignedPEM(t, time.Now().Add(30*24*time.Hour)),
	}); err != nil {
		t.Fatalf("PutCert: %v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	cfg := "statePath: " + statePath + "\n" +
		"stateEncryption:\n  keyFile: " + keyPath + "\n" +
		"acme:\n  directory: https://acme.invalid/directory\n  email: ops@atomwangnus.com\n" +
		"dns:\n  provider: dnspod\n  loginToken: \"12345,abcdef\"\n" +
		"tencent:\n  credentialMode: static\n  secretId: id\n  secretKey: key\n" +
		"  regions: [ap-guangzhou]\n" +
		"certificates:\n  - name: example-com\n    domains: [example.com]\n"
	if err := os.WriteFile(configPath, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}

	err = runRevoke(context.Background(), configPath, "", "example-com", "keyCompromise", true)
	if err == nil {
		t.Fatal("an unreachable CA must still be reported")
	}
	if strings.Contains(err.Error(), "not encrypted with this format") ||
		strings.Contains(err.Error(), "private key") {
		t.Fatalf("the sealed store was opened without its sealer: %v", err)
	}

	// The record is what the next daemon pass retries, so it is the thing that must be durable --
	// and reading it back through a sealed open proves the whole path stayed sealed.
	sealed, err := state.OpenSealed(statePath, []byte(master))
	if err != nil {
		t.Fatalf("reopen sealed: %v", err)
	}
	defer sealed.Close()
	req, err := sealed.GetRevokeRequest("example-com")
	if err != nil {
		t.Fatalf("GetRevokeRequest: %v", err)
	}
	if req == nil || req.Reason != 1 {
		t.Fatalf("sealed revocation request = %+v, want reason 1 (keyCompromise) recorded", req)
	}
}
