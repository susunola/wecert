package main

// Flow-level tests for main.go: the process's outer shell.
//
// main.go is where a wrong answer is expensive in a way the individual steps cannot show on
// their own -- an exit code that reports success for a fleet that went unmanaged, a mode flag
// silently outranked by another, a startup that returns after failing to take the state lock or
// bind a port the operator believes is serving. The tests here drive run()/main() themselves
// (in a child process, because os.Exit cannot be observed from inside the process that calls
// it) plus the small helpers whose entire contract is a decision: which backup plan applies,
// which desired-state source is built, which deployer is chosen, how far jitter may move the
// interval, whether the startup banner tells the truth about the fleet size.
//
// Everything here is local by construction. The ACME account row is written into the state
// store before any run, so EnsureAccount loads it instead of registering one, and the single
// endpoint a run still resolves -- the ACME directory itself -- is a loopback TLS fixture
// (see fakeACMEDirectory). Nothing in this file may reach the network, and a test that did
// would be a bug in the test: it would depend on outbound DNS and turn a machine without it
// into a slow timeout instead of a clear failure.

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/susunola/wecert/internal/config"
	"github.com/susunola/wecert/internal/deploy"
	"github.com/susunola/wecert/internal/group"
	"github.com/susunola/wecert/internal/metrics"
	"github.com/susunola/wecert/internal/reconcile"
	"github.com/susunola/wecert/internal/spec"
	"github.com/susunola/wecert/internal/state"
)

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

// seedAccount makes the state store hold a complete ACME account row -- key and kid.
//
// A row with a kid is what makes EnsureAccount a pure database read (see internal/acme's
// client.go): without it the call registers with the CA, and this package's tests must run
// with no network at all. The key is a real P-256 key because ParsePrivateKeyPEM rejects
// placeholder bytes, and the kid is a real-looking account URL because lego parses it.
func seedAccount(t *testing.T, statePath, directory string) {
	t.Helper()
	store, err := state.Open(statePath)
	if err != nil {
		t.Fatalf("open the state store to seed the account: %v", err)
	}
	defer func() { _ = store.Close() }()
	putAccount(t, store, directory)
}

// putAccount writes the account row into an already-open store, for the tests that hold one.
func putAccount(t *testing.T, store *state.Store, directory string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate the account key: %v", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("marshal the account key: %v", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})

	if err := store.PutAccount(&state.Account{
		Directory:     directory,
		KID:           "https://acme-staging-v02.api.letsencrypt.org/acme/acct/123456",
		PrivateKeyPEM: keyPEM,
	}); err != nil {
		t.Fatalf("PutAccount: %v", err)
	}
}

// fakeACMEDirectory serves the one document a run against a complete account still fetches:
// the ACME directory. It returns the directory URL and the path of a PEM file holding the
// server's certificate, for the child process (see mainHelperEnv).
//
// EnsureAccount loads the stored key and kid from the database, but lego's api.New resolves the
// directory URL before it returns, so even a pure database load needs an answer there -- and
// lego refuses anything that is not https (RFC 8555 requires it, and the wrapper is
// unconditional), so the fixture is a TLS server whose certificate has to be trusted by a
// client this package does not control.
//
// Two trusts, because there are two processes involved:
//
//   - In this process, acme.NewHTTPClient leaves Transport nil, so the request goes through
//     http.DefaultTransport. The test certificate is installed there once (see
//     trustLoopbackTLS). It only *adds* a root for the loopback fixture, so no other test can
//     start failing because of it.
//   - A child test process builds its own transport from the system pool, which is why the
//     certificate is also written out for SSL_CERT_FILE.
//
// Without this the process-level tests would point acme.directory at Let's Encrypt: they would
// depend on outbound DNS, and a machine without it would see them hang for the HTTP timeout
// instead of failing on what they actually test.
func fakeACMEDirectory(t *testing.T) (directory, caFile string) {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/directory", func(w http.ResponseWriter, r *http.Request) {
		base := "https://" + r.Host
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"newNonce":%q,"newAccount":%q,"newOrder":%q,"revokeCert":%q}`,
			base+"/new-nonce", base+"/new-account", base+"/new-order", base+"/revoke-cert")
	})
	srv := httptest.NewTLSServer(mux)
	t.Cleanup(srv.Close)
	trustLoopbackTLS(srv)

	caFile = filepath.Join(t.TempDir(), "acme-test-ca.pem")
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})
	if err := os.WriteFile(caFile, certPEM, 0o600); err != nil {
		t.Fatalf("write the test CA: %v", err)
	}
	return srv.URL + "/directory", caFile
}

// trustLoopbackTLS installs the fixture's certificate as a root on the process's default HTTP
// transport, once.
//
// A sync.Once rather than a per-test assignment: every httptest TLS server in a process shares
// the same self-signed certificate, so one root covers all of them, and replacing the global
// transport repeatedly while background goroutines from earlier tests may still be reading it
// would be a data race under -race.
var trustLoopbackTLSOnce sync.Once

func trustLoopbackTLS(srv *httptest.Server) {
	trustLoopbackTLSOnce.Do(func() {
		base, ok := http.DefaultTransport.(*http.Transport)
		if !ok {
			return
		}
		tr := base.Clone()
		if tr.TLSClientConfig == nil {
			tr.TLSClientConfig = &tls.Config{}
		} else {
			tr.TLSClientConfig = tr.TLSClientConfig.Clone()
		}
		pool := x509.NewCertPool()
		pool.AddCert(srv.Certificate())
		tr.TLSClientConfig.RootCAs = pool
		http.DefaultTransport = tr
	})
}

// cliConfigYAML is the configuration the process-level tests run against: one static
// certificate whose deploy is disabled, DNSPod as the DNS provider, probing off and the Tencent
// deploy target never built. Every step of the startup sequence is therefore local, which is
// what lets run() be driven end to end without a network.
//
// webhookListen carries a token when it is set: config.normalize refuses a listen address with
// no token, deliberately -- that endpoint triggers real issuance.
func cliConfigYAML(directory, statePath, metricsListen, webhookListen string) string {
	webhook := ""
	if webhookListen != "" {
		webhook = fmt.Sprintf("webhook:\n  listen: %s\n  token: \"0123456789abcdef0123456789abcdef\"\n", webhookListen)
	}
	return fmt.Sprintf(`statePath: %s
acme:
  directory: %s
  email: ops@atomwangnus.com
dns:
  provider: dnspod
  loginToken: "12345,abcdef"
desiredState:
  mode: static
certificates:
  - name: example-com
    domains: ["example.com"]
probe:
  enabled: false
metrics:
  listen: %s
%stencent:
  credentialMode: static
  uin: "100012345678"
  regions: [ap-guangzhou]
`, statePath, directory, metricsListen, webhook)
}

// writeFile is os.WriteFile with the failure handled, which is the only reason it exists.
func writeFile(t *testing.T, path, body string) string {
	t.Helper()
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
	return path
}

// freeAddress reserves and immediately releases a loopback port, so a server started on it can
// bind. The alternative -- a hard-coded port -- collides with whatever else the machine runs.
func freeAddress(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve a port: %v", err)
	}
	addr := ln.Addr().String()
	if err := ln.Close(); err != nil {
		t.Fatalf("release the reserved port: %v", err)
	}
	return addr
}

// occupiedAddress reserves a loopback port and keeps it bound, which is what "another wecert
// instance is already running" looks like to net.Listen.
func occupiedAddress(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve a port: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	return ln.Addr().String()
}

// captureStdout runs fn with the process's stdout redirected into a temp file and returns what
// was written. A file rather than a pipe: the startup banner and the reconcile summary are
// written by a logger this function does not control the volume of, and a full pipe buffer
// would deadlock the test rather than fail it.
func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), "stdout-*")
	if err != nil {
		t.Fatalf("create the capture file: %v", err)
	}
	old := os.Stdout
	os.Stdout = f
	defer func() { os.Stdout = old }()

	fn()

	os.Stdout = old
	if _, err := f.Seek(0, 0); err != nil {
		t.Fatalf("rewind the capture file: %v", err)
	}
	out, err := io.ReadAll(f)
	if err != nil {
		t.Fatalf("read the capture file: %v", err)
	}
	_ = f.Close()
	return string(out)
}

// ---------------------------------------------------------------------------
// main(): the exit codes
// ---------------------------------------------------------------------------

// mainArgSep separates the arguments handed to the helper child. Unit Separator cannot appear
// in a flag value an operator would type, so splitting on it cannot misread a path.
const mainArgSep = "\x1f"

// mainHelperEnv marks the child run of TestMainClassifiesExitCodesEndToEnd.
const mainHelperEnv = "WECERT_TEST_MAIN_ARGS"

// main must classify its two failure exits the repository's own way: 64 for "the command line
// itself is wrong", 1 for "the program ran and failed".
//
// main.go documents why the distinction is load-bearing -- wecert-once.service's ExecStart typo
// must not read as the frozen code a monitoring rule keys on -- and the message for a wrapped
// errUsage used to be discarded entirely, so a contradictory command line exited 64 in silence.
// Neither os.Exit nor the exit status can be observed from inside the process that calls it, so
// this re-runs the test binary as a child whose only job is to call main() with the arguments
// the parent chose; the parent then checks the child's real status and streams. The helper
// branch also gives main() the coverage it has never had: the classification below lives in
// main, not in run, and nothing else can reach it.
func TestMainClassifiesExitCodesEndToEnd(t *testing.T) {
	if args, ok := os.LookupEnv(mainHelperEnv); ok {
		os.Args = []string{"wecert"}
		if args != "" {
			os.Args = append(os.Args, strings.Split(args, mainArgSep)...)
		}
		// main returns only on the success paths; the child must not fall back into the test
		// framework's own output afterwards.
		main()
		os.Exit(0)
	}

	dir := t.TempDir()
	statePath := filepath.Join(dir, "state.db")
	directory, caFile := fakeACMEDirectory(t)
	seedAccount(t, statePath, directory)
	goodConfig := writeFile(t, filepath.Join(dir, "config.yaml"),
		cliConfigYAML(directory, statePath, "127.0.0.1:0", ""))

	runChild := func(t *testing.T, args ...string) (code int, stdout, stderr string) {
		t.Helper()
		self, err := os.Executable()
		if err != nil {
			t.Fatalf("locate the test binary: %v", err)
		}
		cmd := exec.Command(self, "-test.run", "^TestMainClassifiesExitCodesEndToEnd$")
		// SSL_CERT_FILE, because the child is a separate process: it builds its own transport
		// from the system pool, so the loopback ACME directory's certificate has to reach it
		// through the environment rather than through this process's http.DefaultTransport.
		cmd.Env = append(os.Environ(),
			mainHelperEnv+"="+strings.Join(args, mainArgSep),
			"SSL_CERT_FILE="+caFile)
		var out, errBuf strings.Builder
		cmd.Stdout = &out
		cmd.Stderr = &errBuf
		err = cmd.Run()
		code = 0
		if err != nil {
			var exitErr *exec.ExitError
			if !errors.As(err, &exitErr) {
				t.Fatalf("run the helper child: %v", err)
			}
			code = exitErr.ExitCode()
		}
		return code, out.String(), errBuf.String()
	}

	t.Run("a successful dry run exits 0", func(t *testing.T) {
		// The documented pre-install check, all the way through main: this is the invocation
		// install.sh runs, and it is the only case here whose exit status must be a clean 0.
		code, stdout, stderr := runChild(t, "-config", goodConfig, "-dry-run")
		if code != 0 {
			t.Fatalf("a dry run against a complete config must exit 0, got %d (stderr: %s)", code, stderr)
		}
		if !strings.Contains(stdout, "dry run finished") {
			t.Errorf("the dry run must say what it checked, stdout:\n%s", stdout)
		}
	})

	t.Run("-version exits 0 without reading the config", func(t *testing.T) {
		code, stdout, _ := runChild(t, "-version")
		if code != 0 {
			t.Fatalf("-version must exit 0, got %d", code)
		}
		if want := "wecert " + version; !strings.Contains(stdout, want) {
			t.Errorf("stdout must carry %q, got:\n%s", want, stdout)
		}
	})

	t.Run("-h exits 0", func(t *testing.T) {
		code, _, stderr := runChild(t, "-h")
		if code != 0 {
			t.Fatalf("asking for help is not a failure, got exit %d (stderr: %s)", code, stderr)
		}
		if !strings.Contains(stderr, "Usage") && !strings.Contains(stderr, "-config") {
			t.Errorf("the flag package's usage must have been printed, stderr:\n%s", stderr)
		}
	})

	t.Run("a contradictory command line exits 64 with its message", func(t *testing.T) {
		code, _, stderr := runChild(t, "-once", "-dry-run")
		if code != exitUsage {
			t.Fatalf("a contradictory command line must exit %d, not %d", exitUsage, code)
		}
		for _, want := range []string{"wecert:", "-once and -dry-run"} {
			if !strings.Contains(stderr, want) {
				t.Errorf("the message must carry %q: a bare sentinel exits %d silently, stderr:\n%s",
					want, exitUsage, stderr)
			}
		}
	})

	t.Run("an unknown flag exits 64 through the flag package", func(t *testing.T) {
		code, _, stderr := runChild(t, "-reovke", "example-com")
		if code != exitUsage {
			t.Fatalf("a typo must exit %d, not 1: a monitoring rule keyed on %d must not read a typo "+
				"as a frozen unit", exitUsage, code)
		}
		if !strings.Contains(stderr, "reovke") {
			t.Errorf("the flag package must have named the offending flag, stderr:\n%s", stderr)
		}
	})

	t.Run("a failing run exits 1", func(t *testing.T) {
		// A config that cannot be read is a run failure, not a command-line one: the operator
		// typed a valid flag pointing at a file that is not there.
		code, _, stderr := runChild(t, "-config", filepath.Join(dir, "absent.yaml"), "-dry-run")
		if code != 1 {
			t.Fatalf("a run failure must exit 1, not %d", code)
		}
		// stderr, not stdout: a failure this early happens before run() installs its own
		// handler, so the line comes from the default logger.
		if !strings.Contains(stderr, "wecert exited with an error") {
			t.Errorf("the failure must be reported, stderr:\n%s", stderr)
		}
	})
}

// ---------------------------------------------------------------------------
// run(): the startup sequence
// ---------------------------------------------------------------------------

// A dry run must walk the whole startup sequence and leave the state database exactly as it
// found it.
//
// This is the documented pre-install step and the one install.sh verifies with, so what it
// owes the operator is a truthful "this config starts": the same config load, the same state
// open, the same desired-state source, the same account load and the same credential-bearing
// components as a real start, minus issuance and deployment. The test pins both halves --
// run() returns nil and says so, and nothing was written: no certificate row, no replaced
// account. A dry run that silently issued or re-registered would be the expensive failure
// (accounts are limited per IP), so the account's kid is compared byte for byte.
func TestTheDryRunWalkstheStartupSequenceAndChangesNothing(t *testing.T) {
	dir := t.TempDir()
	statePath := filepath.Join(dir, "state.db")
	directory, _ := fakeACMEDirectory(t)
	seedAccount(t, statePath, directory)
	configPath := writeFile(t, filepath.Join(dir, "config.yaml"),
		cliConfigYAML(directory, statePath, "127.0.0.1:0", ""))

	before := readAccount(t, statePath, directory)

	withArgs(t, "-config", configPath, "-dry-run")
	stdout := captureStdout(t, func() {
		if err := run(); err != nil {
			t.Fatalf("a complete config must pass the dry run: %v", err)
		}
	})
	if !strings.Contains(stdout, "dry run finished") {
		t.Errorf("the dry run must report what it checked, stdout:\n%s", stdout)
	}
	// "nothing was issued or deployed" is the claim the line makes; the counts prove it did
	// read the config rather than skip the work.
	for _, want := range []string{"certificates=1", "nothing was issued or deployed"} {
		if !strings.Contains(stdout, want) {
			t.Errorf("the dry-run summary must carry %q, stdout:\n%s", want, stdout)
		}
	}

	after := readAccount(t, statePath, directory)
	if before == nil || after == nil {
		t.Fatalf("the seeded account must survive a dry run: before=%v after=%v", before, after)
	}
	if before.KID != after.KID {
		t.Errorf("the account kid changed (%q -> %q): a dry run must not re-register the account, "+
			"which burns the per-IP account quota", before.KID, after.KID)
	}
	store, err := state.Open(statePath)
	if err != nil {
		t.Fatalf("the state lock must be free after the dry run: %v", err)
	}
	defer func() { _ = store.Close() }()
	names, err := store.ListCertNames()
	if err != nil {
		t.Fatalf("ListCertNames: %v", err)
	}
	if len(names) != 0 {
		t.Errorf("a dry run issued something: %v", names)
	}
}

// readAccount returns the account row for the given directory, or nil.
func readAccount(t *testing.T, statePath, directory string) *state.Account {
	t.Helper()
	store, err := state.Open(statePath)
	if err != nil {
		t.Fatalf("open the state store: %v", err)
	}
	defer func() { _ = store.Close() }()
	acc, err := store.GetAccount(directory)
	if err != nil {
		t.Fatalf("GetAccount: %v", err)
	}
	return acc
}

// A port that cannot be bound must abort the run, and must release the state lock on the way
// out.
//
// main.go argues this at length for both servers: /metrics is the only expiry alerting channel
// and the webhook is the only entrance to the event-driven path, so a process that logs a line
// and carries on looks healthy while monitoring hears nothing. What the argument does not say,
// and what this pins, is the other half of failing early: the state lock was already taken in
// openRuntime, so an early return has to give it back -- otherwise the operator's fix-and-retry
// meets "another wecert process has it open" and chases a phantom instance, exactly the
// confusion the webhook's own port-release branch exists to avoid.
func TestRunRefusesToStartWhenAPortIsAlreadyTaken(t *testing.T) {
	cases := []struct {
		name  string
		arg   string
		build func(t *testing.T, dir, statePath, directory string) string
		want  string
	}{
		{
			name: "the metrics port",
			arg:  "-once",
			build: func(t *testing.T, dir, statePath, directory string) string {
				taken := occupiedAddress(t)
				return writeFile(t, filepath.Join(dir, "metrics-taken.yaml"),
					cliConfigYAML(directory, statePath, taken, ""))
			},
			want: "failed to listen on the metrics port",
		},
		{
			name: "the webhook port",
			arg:  "-once",
			build: func(t *testing.T, dir, statePath, directory string) string {
				taken := occupiedAddress(t)
				return writeFile(t, filepath.Join(dir, "webhook-taken.yaml"),
					cliConfigYAML(directory, statePath, "127.0.0.1:0", taken))
			},
			want: "failed to listen on the webhook port",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			statePath := filepath.Join(dir, "state.db")
			directory, _ := fakeACMEDirectory(t)
			seedAccount(t, statePath, directory)
			configPath := tc.build(t, dir, statePath, directory)

			withArgs(t, "-config", configPath, tc.arg)
			var err error
			_ = captureStdout(t, func() { err = run() })
			if err == nil {
				t.Fatal("a port that cannot be bound must fail the run: the operator would otherwise " +
					"believe the endpoint is serving while every event is lost")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("the error must name the endpoint that could not bind (%q), got: %v", tc.want, err)
			}
			// The lock is the part with no other symptom: a leaked one turns the next start into
			// "another wecert process has it open", pointing at an instance that exited.
			assertLockReleased(t, statePath)
		})
	}
}

// Mode flags that contradict each other must be refused, not resolved by branch order.
//
// Each of these used to reach a real action with the other flag never mentioned: -revoke exits
// before the interval floor is read, and a drill next to -once would have been ignored. They
// all have to come back as command-line errors (exit 64), because the operator's next move
// differs: fix the command line rather than the deployment.
func TestRunRefusesContradictoryOneShotModes(t *testing.T) {
	cases := []struct {
		name string
		args []string
		want string
	}{
		{"a drill next to -once", []string{"-backup-drill", "latest", "-once"}, "-backup-drill"},
		{"a drill next to -dry-run", []string{"-backup-drill", "latest", "-dry-run"}, "-backup-drill"},
		{"a drill next to -revoke", []string{"-backup-drill", "latest", "-revoke", "x"}, "-backup-drill"},
		{"a restore next to -revoke", []string{"-restore", "latest", "-revoke", "x"}, "-restore"},
		{"a restore next to -dry-run", []string{"-restore", "latest", "-dry-run"}, "-restore"},
		{"a restore next to -once", []string{"-restore", "latest", "-once"}, "-restore"},
		{"a revocation with a dead interval", []string{"-revoke", "x", "-interval", "1h"}, "-interval"},
		// The read-only state command next to the destructive one. The -restore branch returns
		// before the drill branch is reached, so this pairing used to perform the restore and
		// never mention the drill.
		{"a drill next to -restore", []string{"-restore", "latest", "-backup-drill", "latest"}, "-restore and -backup-drill"},
		{"a restore next to -backup-drill", []string{"-backup-drill", "latest", "-restore", "latest"}, "-restore and -backup-drill"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			withArgs(t, tc.args...)
			err := run()
			if err == nil {
				t.Fatal("this combination must be refused: one flag would silently win and the " +
					"operator would never be told which")
			}
			if !errors.Is(err, errUsage) {
				t.Fatalf("err = %v, want errUsage so main exits %d rather than 1", err, exitUsage)
			}
			if msg := usageExitMessage(err); !strings.Contains(msg, tc.want) {
				t.Errorf("the message must explain what to drop (%q), got %q", tc.want, msg)
			}
		})
	}
}

// oneShotConfigYAML is a loadable config pointing at an existing state database and snapshot
// directory. The one-shot modes never build the DNS solver or the deployer, so only the paths
// and the ACME block have to be valid.
func oneShotConfigYAML(statePath, snapshotDir string) string {
	return fmt.Sprintf(`statePath: %s
stateBackup:
  dir: %s
acme:
  directory: %s
  email: ops@atomwangnus.com
dns:
  provider: dnspod
  loginToken: "12345,abcdef"
desiredState:
  mode: static
certificates:
  - name: example-com
    domains: ["example.com"]
probe:
  enabled: false
metrics:
  listen: 127.0.0.1:0
tencent:
  credentialMode: static
  uin: "100012345678"
  regions: [ap-guangzhou]
`, statePath, snapshotDir, config.DirectoryStaging)
}

// `-restore latest -yes` is the disaster-recovery command, and it must work as one invocation.
//
// The interesting part is what the operator is told: the snapshot's age, how much of the
// rate-limit ledger it is missing, and where the database it replaced was kept. A restore that
// silently swapped the file would leave the next CA refusal ("why is my renewal failing")
// unattributable, which is the failure docs/recovery.md exists to prevent -- so the test checks
// the installed data AND the sentences, not just the exit code.
func TestRunRestoresASnapshotAndSaysWhatItCost(t *testing.T) {
	cfg, snapshotDir := seedRestorableState(t)
	configPath := writeFile(t, filepath.Join(filepath.Dir(cfg.StatePath), "config.yaml"),
		oneShotConfigYAML(cfg.StatePath, snapshotDir))

	withArgs(t, "-config", configPath, "-restore", "latest", "-yes")
	stdout := captureStdout(t, func() {
		if err := run(); err != nil {
			t.Fatalf("-restore latest -yes must restore the newest snapshot: %v", err)
		}
	})
	for _, want := range []string{"Restored", "rate-limit ledger", "Start wecert again"} {
		if !strings.Contains(stdout, want) {
			t.Errorf("the restore must report %q, stdout:\n%s", want, stdout)
		}
	}
	if got := certNames(t, cfg.StatePath); len(got) != 1 || got[0] != "old-cert" {
		t.Errorf("the database must hold the snapshot's contents, got %v", got)
	}
	notice, err := state.LoadRestoreNotice(cfg.StatePath)
	if err != nil || notice == nil {
		t.Fatalf("a restore must leave the record the next start warns from: notice=%v err=%v", notice, err)
	}
}

// `-backup-drill` is the scheduled recovery evidence, and its whole value is that it changes
// nothing: an operator runs it against production snapshots on a timer, so a drill that
// restored "just to check" would be a disaster in its own right.
func TestRunBackupDrillChecksASnapshotWithoutChangingAnything(t *testing.T) {
	cfg, snapshotDir := seedRestorableState(t)
	configPath := writeFile(t, filepath.Join(filepath.Dir(cfg.StatePath), "config.yaml"),
		oneShotConfigYAML(cfg.StatePath, snapshotDir))

	before, err := os.ReadFile(cfg.StatePath)
	if err != nil {
		t.Fatal(err)
	}

	withArgs(t, "-config", configPath, "-backup-drill", "latest")
	stdout := captureStdout(t, func() {
		if err := run(); err != nil {
			t.Fatalf("-backup-drill latest must check the newest snapshot: %v", err)
		}
	})
	if !strings.Contains(stdout, "Backup drill passed") || !strings.Contains(stdout, "No live state was changed") {
		t.Errorf("the drill must report its verdict and that it was read-only, stdout:\n%s", stdout)
	}

	after, err := os.ReadFile(cfg.StatePath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Error("the drill modified the live database: it is documented as safe for a timer")
	}
	if got := certNames(t, cfg.StatePath); len(got) != 2 {
		t.Errorf("the drill must leave both certificates in place, got %v", got)
	}
	if _, err := os.Stat(cfg.StatePath + ".restore-pending"); err == nil {
		t.Error("a drill must not stage a restore")
	}
}

// -h must not be an error: the flag package has already printed the usage, and asking for help
// is not a mistake to classify.
func TestParseArgsTreatsHelpAsItsOwnOutcome(t *testing.T) {
	// The flag package writes the usage to stderr, which would bury a real failure in this
	// package's output; the printing itself is checked by the child-process case above.
	devNull, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = devNull.Close() }()
	oldStderr := os.Stderr
	os.Stderr = devNull
	defer func() { os.Stderr = oldStderr }()

	for _, arg := range []string{"-h", "-help", "--help"} {
		_, _, err := parseArgs([]string{arg})
		if !errors.Is(err, errHelp) {
			t.Errorf("parseArgs(%q) = %v, want errHelp so run() returns nil and main exits 0", arg, err)
		}
	}
}

// ---------------------------------------------------------------------------
// Small decisions
// ---------------------------------------------------------------------------

// jitter must stay inside +/-10% and must actually vary.
//
// Two contracts in one: the bound is what keeps a "one hour" interval from quietly becoming
// two, and the variation is the entire reason the function exists -- a fixed interval keeps
// every instance phase-locked and synchronises their DNS and CA traffic. The non-positive case
// has its own meaning: -interval 0 never reaches the loop (validateFlags rejects it), but
// jitter is also called with the one-second startup delay, and returning 0 there would spin.
func TestJitterStaysInsideTenPercentAndVaries(t *testing.T) {
	for _, d := range []time.Duration{time.Hour, 10 * time.Minute, 90 * time.Second} {
		lo := d - time.Duration(float64(d)*0.1)
		hi := d + time.Duration(float64(d)*0.1)
		for i := 0; i < 500; i++ {
			got := jitter(d)
			if got < lo || got > hi {
				t.Fatalf("jitter(%s) = %s, outside [%s, %s]", d, got, lo, hi)
			}
		}
	}

	seen := map[time.Duration]bool{}
	for i := 0; i < 200; i++ {
		seen[jitter(time.Hour)] = true
	}
	if len(seen) < 2 {
		t.Error("jitter returned the same value every time: a fixed interval phase-locks every " +
			"instance onto the same second")
	}

	for _, d := range []time.Duration{0, -time.Minute} {
		if got := jitter(d); got != time.Second {
			t.Errorf("jitter(%s) = %s, want one second: a zero ticker would panic and a zero delay "+
				"would spin", d, got)
		}
	}
}

// dirIsWritable has to answer about the directory that will actually be written, not about a
// permission bit: ownership, ACLs, a read-only mount and a full disk all decide it, and the
// only honest way to find out is to try. It also creates the directory, because Snapshot does.
func TestDirIsWritableProbesByWritingAndCleansUp(t *testing.T) {
	dir := t.TempDir()
	if !dirIsWritable(dir) {
		t.Error("an ordinary writable directory must report writable")
	}

	nested := filepath.Join(dir, "does", "not", "exist", "yet")
	if !dirIsWritable(nested) {
		t.Error("creating the directory is part of the probe: the snapshot directory often does not exist yet")
	}
	if fi, err := os.Stat(nested); err != nil || !fi.IsDir() {
		t.Errorf("the probe must leave the directory it created in place, err=%v", err)
	}

	// A path whose parent is a regular file cannot be created: the cheapest stand-in for a
	// read-only mount or a full disk that works whatever the test runs as.
	blocker := writeFile(t, filepath.Join(dir, "not-a-directory"), "x")
	if dirIsWritable(filepath.Join(blocker, "snapshots")) {
		t.Error("a directory that cannot be created must report unwritable, or the snapshot loop " +
			"starts and fails every interval")
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".wecert-write-probe-") {
			t.Errorf("the probe file %s was left behind: a writability check must not litter the "+
				"directory it is judging", e.Name())
		}
	}
}

// newProvider decides who has the final say over the desired state, and the three modes differ
// in exactly one way that matters: what happens when the document cannot be read.
//
// static ignores it; observe warns and converges on the config as before (wecert must not stop
// renewing because a shadow source is missing); enforce refuses to start, because "starts up
// with no desired state" means quietly renewing nothing until every certificate expires.
func TestNewProviderDrawsTheLineBetweenObserveAndEnforce(t *testing.T) {
	log, buf := quietLog()
	document := writeDesiredStateDocument(t, filepath.Join(t.TempDir(), "desired.yaml"))

	staticCfg := &config.Config{
		DesiredState: config.DesiredState{Mode: config.ModeStatic},
		Certificates: []config.Certificate{{Name: "example-com", Domains: []string{"example.com"}}},
	}
	provider, err := newProvider(staticCfg, log)
	if err != nil {
		t.Fatalf("static mode must build: %v", err)
	}
	if kind := spec.KindOf(provider); kind != config.ModeStatic {
		t.Errorf("static mode built a %q source, want the config's own list", kind)
	}

	// observe, document absent: a warning, and the config still decides.
	observe := *staticCfg
	observe.DesiredState = config.DesiredState{Mode: config.ModeObserve, Path: filepath.Join(t.TempDir(), "missing.yaml")}
	buf.Reset()
	provider, err = newProvider(&observe, log)
	if err != nil {
		t.Fatalf("observe mode must never stop the process over an unreadable document: %v", err)
	}
	if kind := spec.KindOf(provider); kind != config.ModeStatic {
		t.Errorf("observe mode with no document must converge on the config, built %q", kind)
	}
	if !strings.Contains(buf.String(), "not readable yet") {
		t.Errorf("the fallback has to be visible, or the operator cannot tell whether the diff is "+
			"being reported, got:\n%s", buf.String())
	}

	// observe, document present: the shadow source is attached and reports the diff.
	observe.DesiredState.Path = document
	buf.Reset()
	provider, err = newProvider(&observe, log)
	if err != nil {
		t.Fatalf("observe mode with a readable document must build: %v", err)
	}
	if kind := spec.KindOf(provider); kind == config.ModeStatic {
		t.Errorf("observe mode with a readable document must attach the shadow source, built %q", kind)
	}

	// enforce, document absent: hard failure, with the mode named so the fix is obvious.
	enforce := *staticCfg
	enforce.Certificates = nil
	enforce.DesiredState = config.DesiredState{Mode: config.ModeEnforce, Path: filepath.Join(t.TempDir(), "missing.yaml")}
	if _, err := newProvider(&enforce, log); err == nil {
		t.Error("enforce mode must refuse to start without a readable document: renewing nothing " +
			"silently is the failure mode being prevented")
	} else if !strings.Contains(err.Error(), config.ModeEnforce) {
		t.Errorf("the error must name the mode that requires the document, got: %v", err)
	}

	// enforce, document present: the document is the source.
	enforce.DesiredState.Path = document
	provider, err = newProvider(&enforce, log)
	if err != nil {
		t.Fatalf("enforce mode with a readable document must build: %v", err)
	}
	if _, ok := provider.(*spec.File); !ok {
		t.Errorf("enforce mode must return the document source, got %T", provider)
	}

	// An unknown mode is a configuration error, never a silent default.
	unknown := *staticCfg
	unknown.DesiredState = config.DesiredState{Mode: "suggest"}
	if _, err := newProvider(&unknown, log); err == nil {
		t.Error("an unknown desiredState.mode must be an error")
	}
}

// writeDesiredStateDocument writes the smallest document spec.LoadDocument accepts, which is
// the fixture the enforce/observe tests need: an empty document is rejected on purpose, and the
// certificate name must be the stable one for its registered domain.
func writeDesiredStateDocument(t *testing.T, path string) string {
	t.Helper()
	body := fmt.Sprintf(`apiVersion: wecert/v1
kind: DesiredState
generatedAt: %s
certificates:
  - name: %s
    domains: ["example.com"]
`, time.Now().UTC().Format(time.RFC3339), group.CertName("example.com"))
	return writeFile(t, path, body)
}

// The startup banner is the first thing an operator reads and the only place two warnings
// appear: "this is the production directory and there is no account yet" (accounts are a finite
// resource) and the one-label wildcard note.
func TestLogStartupSaysWhatTheFirstRunCosts(t *testing.T) {
	dir := t.TempDir()
	statePath := filepath.Join(dir, "state.db")
	store, err := state.Open(statePath)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer func() { _ = store.Close() }()

	cfg := &config.Config{
		StatePath: statePath,
		ACME:      config.ACME{Directory: config.DirectoryProduction},
		Certificates: []config.Certificate{{
			// One wildcard and one ordinary host: the note belongs to the wildcard alone, and
			// firing it for a plain name would make the line noise an operator learns to skip.
			Name:    "wild-example-com",
			Domains: []string{"*.a.example.com", "www.example.com"},
		}},
	}

	firstRun, err := isFirstRun(store, cfg)
	if err != nil {
		t.Fatalf("isFirstRun: %v", err)
	}
	if !firstRun {
		t.Fatal("an empty state store means first run")
	}

	log, buf := quietLog()
	logStartup(log, cfg, firstRun)
	out := buf.String()
	for _, want := range []string{
		"no account in the state store",
		"Let's Encrypt production environment",
		"wildcard covers only one label",
		"*.a.example.com",
		"loaded certificate",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("the startup banner must carry %q, got:\n%s", want, out)
		}
	}
	// The note is about the wildcard's coverage, not about wildcards being present: exactly one
	// entry earns it here.
	if n := strings.Count(out, "wildcard covers only one label"); n != 1 {
		t.Errorf("the one-label note must fire once, for the wildcard only, got %d occurrence(s) in:\n%s", n, out)
	}

	// With an account present the warnings are gone: they exist for the first run only.
	putAccount(t, store, config.DirectoryProduction)
	firstRun, err = isFirstRun(store, cfg)
	if err != nil {
		t.Fatalf("isFirstRun after seeding: %v", err)
	}
	if firstRun {
		t.Error("a store holding an account for this directory is not a first run")
	}
	log, buf = quietLog()
	logStartup(log, cfg, firstRun)
	if strings.Contains(buf.String(), "no account in the state store") {
		t.Errorf("a restart must not warn about registering a new account, got:\n%s", buf.String())
	}
}

// Startup must fail on the three steps that come before anything is issued, and each failure
// has to name the step it came from.
//
// The shared property is what makes these worth pinning together: run() installs signal
// handling and opens the state store first, so every one of these paths has to return through
// the deferred store.Close(), and an error that says only "invalid configuration" leaves the
// operator guessing which of the six startup steps rejected it. Two of the three are the
// documented "fail at startup, not at the first reconcile" rules -- an enforce-mode document is
// the whole desired state, and an ACME account key that cannot be parsed is not something a
// later pass can recover from.
func TestStartupFailuresNameTheStepThatFailed(t *testing.T) {
	t.Run("an unreadable enforce-mode document", func(t *testing.T) {
		// No fake ACME directory is needed: this must fail before the account is even loaded,
		// which is exactly the point of building the desired-state source this early.
		dir := t.TempDir()
		statePath := filepath.Join(dir, "state.db")
		seedAccount(t, statePath, config.DirectoryStaging)
		configPath := writeFile(t, filepath.Join(dir, "config.yaml"), fmt.Sprintf(`statePath: %s
acme:
  directory: %s
  email: ops@atomwangnus.com
dns:
  provider: dnspod
  loginToken: "12345,abcdef"
desiredState:
  mode: enforce
  path: %s
probe:
  enabled: false
metrics:
  listen: 127.0.0.1:0
tencent:
  credentialMode: static
  uin: "100012345678"
  regions: [ap-guangzhou]
`, statePath, config.DirectoryStaging, filepath.Join(dir, "absent.yaml")))

		withArgs(t, "-config", configPath, "-dry-run")
		var err error
		_ = captureStdout(t, func() { err = run() })
		if err == nil {
			t.Fatal("enforce mode without a readable document must refuse to start: renewing " +
				"nothing silently is the failure being prevented")
		}
		if !strings.Contains(err.Error(), config.ModeEnforce) {
			t.Errorf("the error must name the mode that requires the document, got: %v", err)
		}
		assertLockReleased(t, statePath)
	})

	t.Run("an unparseable stored account key", func(t *testing.T) {
		dir := t.TempDir()
		statePath := filepath.Join(dir, "state.db")
		store, err := state.Open(statePath)
		if err != nil {
			t.Fatal(err)
		}
		if err := store.PutAccount(&state.Account{
			Directory:     config.DirectoryStaging,
			KID:           "https://acme-staging-v02.api.letsencrypt.org/acme/acct/1",
			PrivateKeyPEM: []byte("-----BEGIN PRIVATE KEY-----\nnot base64\n-----END PRIVATE KEY-----\n"),
		}); err != nil {
			t.Fatal(err)
		}
		_ = store.Close()

		configPath := writeFile(t, filepath.Join(dir, "config.yaml"),
			cliConfigYAML(config.DirectoryStaging, statePath, "127.0.0.1:0", ""))
		withArgs(t, "-config", configPath, "-dry-run")
		var runErr error
		_ = captureStdout(t, func() { runErr = run() })
		if runErr == nil {
			t.Fatal("a state database whose account key cannot be parsed must fail the run")
		}
		if !strings.Contains(runErr.Error(), "account key") {
			t.Errorf("the error must name the account key so the operator knows which file to "+
				"restore, got: %v", runErr)
		}
		assertLockReleased(t, statePath)
	})

	t.Run("a revocation whose config cannot be read", func(t *testing.T) {
		dir := t.TempDir()
		withArgs(t, "-config", filepath.Join(dir, "absent.yaml"), "-revoke", "example-com", "-yes")
		err := run()
		if err == nil {
			t.Fatal("-revoke against a missing config must fail rather than report success")
		}
		if !strings.Contains(err.Error(), "load config") {
			t.Errorf("the error must name the step that failed, got: %v", err)
		}
	})
}

// assertLockReleased proves the state store is not still held after a failed startup: a leaked
// lock turns the operator's fix-and-retry into "another wecert process has it open", pointing
// at an instance that already exited.
func assertLockReleased(t *testing.T, statePath string) {
	t.Helper()
	store, err := state.Open(statePath)
	if err != nil {
		t.Fatalf("the state lock was not released by the failed startup: %v", err)
	}
	_ = store.Close()
}

// certificateCountField is the first number an operator reads, and in enforce mode
// len(cfg.Certificates) is 0 by construction -- printing it says "nothing is managed" about a
// document that may list ten certificates.
func TestCertificateCountFieldDefersToTheDocumentInEnforceMode(t *testing.T) {
	static := &config.Config{Certificates: []config.Certificate{{Name: "a"}, {Name: "b"}}}
	if got := certificateCountField(static); got != 2 {
		t.Errorf("static mode reports the config's list, got %v", got)
	}
	enforce := &config.Config{DesiredState: config.DesiredState{Mode: config.ModeEnforce}}
	got, ok := certificateCountField(enforce).(string)
	if !ok || !strings.Contains(got, "document") {
		t.Errorf("enforce mode must say the count comes from the document, got %v", certificateCountField(enforce))
	}
}

// needsTencentCredentials decides whether a missing CAM credential is a startup failure, and
// each shape below has a different right answer: nginx is entirely local (its certificates must
// not become dependent on Tencent Cloud credentials), enforce mode may deploy anything the
// document declares, and a tencentcloud DNS solver needs CAM regardless of deployment.
func TestNeedsTencentCredentialsFollowsTheDeployShape(t *testing.T) {
	cases := []struct {
		name string
		cfg  *config.Config
		want bool
	}{
		{"tencentcloud DNS needs CAM even with no deployment", &config.Config{DNS: config.DNS{Provider: config.DNSProviderTencentCloud}}, true},
		{"nginx is local even with deploy enabled", &config.Config{
			Deploy:       config.DeploySettings{Target: config.DeployTargetNginx},
			Certificates: []config.Certificate{{Deploy: config.Deploy{Enabled: true}}},
		}, false},
		{"enforce mode may deploy what the document declares", &config.Config{
			DesiredState: config.DesiredState{Mode: config.ModeEnforce},
		}, true},
		{"a certificate with deploy enabled needs CAM", &config.Config{
			Certificates: []config.Certificate{{Deploy: config.Deploy{Enabled: true}}},
		}, true},
		{"local state only needs none", &config.Config{
			Certificates: []config.Certificate{{Name: "a"}},
		}, false},
	}
	for _, tc := range cases {
		if got := needsTencentCredentials(tc.cfg); got != tc.want {
			t.Errorf("%s: needsTencentCredentials = %t, want %t", tc.name, got, tc.want)
		}
	}
}

// newDeployer picks the backend every certificate shares, and the two branches that are not
// "push to CLB" are the ones that decide whether a config fails to start: nginx is a local
// directory, and a config where nothing has deploy enabled must not require cloud credentials
// at all.
func TestNewDeployerSelectsTheConfiguredBackend(t *testing.T) {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))

	off := &config.Config{Certificates: []config.Certificate{{Name: "a"}}}
	d, err := newDeployer(off, log)
	if err != nil {
		t.Fatalf("a purely local configuration must build: %v", err)
	}
	if _, ok := d.(deploy.Noop); !ok {
		t.Errorf("nothing has deploy enabled, so the deployer must be a no-op, got %T", d)
	}

	nginx := &config.Config{
		Deploy: config.DeploySettings{Target: config.DeployTargetNginx},
		// The config layer fills these defaults; this test hands newDeployer a struct directly,
		// so the one field the constructor requires to be a template is set here.
		Nginx: config.NginxTarget{
			DirTemplate: "/etc/nginx/ssl/%s",
			CertFile:    "fullchain.pem",
			KeyFile:     "privkey.pem",
		},
		Certificates: []config.Certificate{{Name: "a", Deploy: config.Deploy{Enabled: true}}},
	}
	d, err = newDeployer(nginx, log)
	if err != nil {
		t.Fatalf("the nginx deployer must build from config alone: %v", err)
	}
	if _, ok := d.(*deploy.Nginx); !ok {
		t.Errorf("deploy.target=nginx must select the nginx deployer, got %T", d)
	}

	clb := &config.Config{
		Certificates: []config.Certificate{{Name: "a", Deploy: config.Deploy{Enabled: true}}},
	}
	clb.Tencent.CredentialMode = config.CredentialStatic
	clb.Tencent.SecretID = "id"
	clb.Tencent.SecretKey = "key"
	clb.Tencent.Regions = []string{"ap-guangzhou"}
	d, err = newDeployer(clb, log)
	if err != nil {
		t.Fatalf("a complete static credential set must build the CLB deployer: %v", err)
	}
	if _, ok := d.(*deploy.TencentCLB); !ok {
		t.Errorf("deploy enabled outside enforce mode must select the CLB deployer, got %T", d)
	}

	// The two ways the selection itself can fail. Both are startup failures rather than
	// surprises on the first pass: a template with no %s would write every certificate's key
	// into one directory, and a CLB deployer with no credentials cannot be built later either.
	badTemplate := &config.Config{
		Deploy: config.DeploySettings{Target: config.DeployTargetNginx},
		Nginx: config.NginxTarget{
			// "%s" is the certificate name; without it every certificate lands in one directory.
			DirTemplate: "/etc/nginx/ssl",
			CertFile:    "fullchain.pem",
			KeyFile:     "privkey.pem",
		},
		Certificates: []config.Certificate{{Name: "a", Deploy: config.Deploy{Enabled: true}}},
	}
	if _, err := newDeployer(badTemplate, log); err == nil {
		t.Error("an nginx directory template with no substitution point must be refused at startup")
	}

	t.Setenv("TENCENTCLOUD_SECRET_ID", "")
	t.Setenv("TENCENTCLOUD_SECRET_KEY", "")
	noCreds := &config.Config{
		Certificates: []config.Certificate{{Name: "a", Deploy: config.Deploy{Enabled: true}}},
	}
	noCreds.Tencent.CredentialMode = config.CredentialStatic
	noCreds.Tencent.Regions = []string{"ap-guangzhou"}
	if _, err := newDeployer(noCreds, log); err == nil {
		t.Error("deploy enabled with credentialMode=static and no credentials must fail at startup, " +
			"not on the first renewal")
	}
}

// finishDryRun is the pre-install check, so a deployer it cannot build must fail the dry run --
// otherwise the "all fine" line is a claim about a configuration that would not start.
func TestFinishDryRunReportsADeployerItCannotBuild(t *testing.T) {
	log, _ := quietLog()
	cfg := &config.Config{
		Deploy: config.DeploySettings{Target: config.DeployTargetNginx},
		Nginx: config.NginxTarget{
			DirTemplate: "/etc/nginx/ssl", // no %s: see above
			CertFile:    "fullchain.pem",
			KeyFile:     "privkey.pem",
		},
		DesiredState: config.DesiredState{Mode: config.ModeStatic},
		Certificates: []config.Certificate{{Name: "a", Domains: []string{"example.com"}}},
	}
	cfg.DNS.Provider = config.DNSProviderDNSPod
	cfg.DNS.LoginToken = "12345,abcdef"

	provider, _, err := buildDesiredAndProber(cfg, log)
	if err != nil {
		t.Fatalf("buildDesiredAndProber: %v", err)
	}
	err = finishDryRun(cfg, provider, nil, log)
	if err == nil {
		t.Fatal("a dry run must not report success for a deployer that cannot be built")
	}
	if !strings.Contains(err.Error(), "deployer") {
		t.Errorf("the error must name the component that failed to build, got: %v", err)
	}
}

// runDaemonWithReload must handle a SIGHUP between passes without losing the loop.
//
// The reload is deliberately narrow -- a rejected configuration logs and the daemon keeps the
// previous runtime -- and what matters to this test is the shape: the hook runs, the passes
// continue afterwards, and the daemon still exits on its context rather than on the reload.
// The channel is driven directly instead of signalling the test process.
func TestRunDaemonWithReloadReloadsBetweenPassesAndKeepsGoing(t *testing.T) {
	log, buf := quietLog()
	reload := make(chan os.Signal, 1)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var passes atomic.Int32
	var reloads atomic.Int32
	done := make(chan struct{})
	go func() {
		defer close(done)
		runDaemonWithReload(ctx, time.Millisecond, log,
			func(context.Context) reconcile.RunReport {
				if n := passes.Add(1); n == 1 {
					reload <- syscall.SIGHUP
				}
				if passes.Load() >= 3 {
					cancel()
				}
				return reconcile.RunReport{Attempted: 1, Succeeded: 1}
			},
			reload,
			func() {
				reloads.Add(1)
				// Whatever a reload does, it must not abort the pass loop: the daemon's contract
				// is "a bad pass is logged and retried on the interval".
				log.Info("reload hook ran")
			})
	}()

	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("the daemon did not exit after its context was cancelled")
	}
	if got := reloads.Load(); got != 1 {
		t.Errorf("the reload hook ran %d time(s), want 1", got)
	}
	if got := passes.Load(); got < 3 {
		t.Errorf("only %d pass(es) ran: a reload must be handled between passes, not replace the loop", got)
	}
	if !strings.Contains(buf.String(), "reload hook ran") {
		t.Error("the reload must be observable in the log")
	}
}

// drainNotifier waits only for a notifier that can wait.
//
// The type assertion is the whole function: a notifier with no drain capability is not an
// error, but it also must not produce the "waited for in-flight notifications" line -- that
// sentence is the shutdown's evidence that nothing was dropped, and printing it for a notifier
// that cannot wait would be a false claim at the moment it matters.
func TestDrainNotifierWaitsOnlyForDrainers(t *testing.T) {
	log, buf := quietLog()

	drainNotifier(plainNotifier{}, log)
	if buf.Len() != 0 {
		t.Errorf("a notifier that cannot drain must not be reported as drained, got:\n%s", buf.String())
	}

	d := &drainingNotifier{}
	drainNotifier(d, log)
	if got := d.drains.Load(); got != 1 {
		t.Errorf("a Drainer must be drained exactly once, got %d", got)
	}
	if !strings.Contains(buf.String(), "waited for in-flight notifications") {
		t.Errorf("the evidence that accepted notifications were flushed must be logged, got:\n%s", buf.String())
	}
}

type plainNotifier struct{}

func (plainNotifier) Renewal(context.Context, string, error) {}

type drainingNotifier struct{ drains atomic.Int32 }

func (d *drainingNotifier) Renewal(context.Context, string, error) {}

func (d *drainingNotifier) Drain(context.Context) { d.drains.Add(1) }

// drainRuntimeBackground must return quietly when nothing is in flight.
//
// The warning it can print says the state store is about to be closed under a pass that is
// still writing, so it must be reserved for that case: an idle shutdown that logged it would
// send an operator looking for a lost write that never happened.
func TestDrainRuntimeBackgroundIsQuietWhenNothingIsInFlight(t *testing.T) {
	dir := t.TempDir()
	store, err := state.Open(filepath.Join(dir, "state.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer func() { _ = store.Close() }()

	log, _ := quietLog()
	cfg := &config.Config{
		StatePath:    filepath.Join(dir, "state.db"),
		DesiredState: config.DesiredState{Mode: config.ModeStatic},
	}
	cfg.DNS.Provider = config.DNSProviderDNSPod
	cfg.DNS.LoginToken = "12345,abcdef"

	provider, prober, err := buildDesiredAndProber(cfg, log)
	if err != nil {
		t.Fatalf("buildDesiredAndProber: %v", err)
	}
	reconciler, notifier, err := buildManager(cfg, store, nil, provider, prober, log)
	if err != nil {
		t.Fatalf("buildManager: %v", err)
	}
	controller := newRuntimeController(cfg, reconciler, notifier, store)

	log, buf := quietLog()
	drainRuntimeBackground(controller, log)
	if buf.Len() != 0 {
		t.Errorf("draining an idle runtime must be silent, got:\n%s", buf.String())
	}
}

// takeSnapshots must fail closed on a remote target it cannot sign for, and must report an
// upload failure to its caller rather than only to the log.
//
// The signing half is a documented invariant: a configured hmacKeyFile that cannot be read must
// not fall back to an unsigned upload, because an operator who configured signing and got a
// silent skip believes the bucket is signed. The other half is why the return value matters at
// all: the one-shot exit code is built from it, and a remote copy that was never written is
// exactly the recovery gap the timer has to report.
func TestTakeSnapshotsFailsClosedOnRemoteTargets(t *testing.T) {
	dir := t.TempDir()
	store, err := state.Open(filepath.Join(dir, "state.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer func() { _ = store.Close() }()
	if err := store.PutCert(&state.CertState{Name: "example-com", KeyPEM: []byte("PRIVATE KEY")}); err != nil {
		t.Fatalf("PutCert: %v", err)
	}

	log, buf := quietLog()

	// A signing key that cannot be loaded: no upload may be attempted at all.
	signed := config.BackupTarget{
		Name: "signed", Type: "s3", Bucket: "b",
		HMACKeyFile: filepath.Join(dir, "missing.key"),
	}
	err = takeSnapshots(context.Background(), store, []string{filepath.Join(dir, "snaps")},
		[]config.BackupTarget{signed}, 3, time.Hour, log)
	if err == nil {
		t.Fatal("a configured signing key that cannot be read must fail the snapshot, not fall " +
			"back to an unsigned upload")
	}
	if !strings.Contains(err.Error(), "hmac") {
		t.Errorf("the error must name the target and the cause, got: %v", err)
	}
	if !strings.Contains(buf.String(), "HMAC key file is not usable") {
		t.Errorf("the operator has to be told signing was refused, got:\n%s", buf.String())
	}

	// An upload that fails must reach the caller and the metric, and it must not be confused
	// with the "prune failed after a successful upload" case.
	before := testutil.ToFloat64(metrics.BackupRemoteErrors.WithLabelValues("bogus", "bogus-type"))
	err = takeSnapshots(context.Background(), store, []string{filepath.Join(dir, "snaps2")},
		[]config.BackupTarget{{Name: "bogus", Type: "bogus-type", Bucket: "b"}}, 3, time.Hour, log)
	if err == nil {
		t.Fatal("a remote target whose upload failed must be reported: the recovery copy does not exist")
	}
	if !strings.Contains(err.Error(), "bogus") {
		t.Errorf("the error must name the target that failed, got: %v", err)
	}
	if !strings.Contains(buf.String(), "remote state snapshot upload failed") {
		t.Errorf("the failure must be logged where the other operational problems are, got:\n%s", buf.String())
	}
	after := testutil.ToFloat64(metrics.BackupRemoteErrors.WithLabelValues("bogus", "bogus-type"))
	if after != before+1 {
		t.Errorf("a failed remote upload must increment wecert_backup_remote_errors (%.0f -> %.0f)", before, after)
	}

	// The local snapshot is written first and stays written: one bad remote target must not
	// cost the local recovery point.
	snaps, err := store.Snapshots(filepath.Join(dir, "snaps2"))
	if err != nil {
		t.Fatalf("Snapshots: %v", err)
	}
	if len(snaps) != 1 {
		t.Errorf("the local snapshot must survive a failed remote upload, got %v", snaps)
	}
}

// The snapshot loop takes one snapshot immediately and then one per interval.
//
// The immediate one is why a fresh deployment has a recovery point at all (orders are in flight
// during the first hours); the periodic one is the whole reason the loop exists. The existing
// shutdown test only ever sees the first, so the ticker branch is pinned here: a loop that took
// its immediate snapshot and then never ticked would look identical from the outside.
func TestSnapshotLoopKeepsTakingSnapshotsOnTheInterval(t *testing.T) {
	var count atomic.Int32
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan struct{})
	go snapshotLoop(ctx, time.Millisecond, func() { count.Add(1) }, done)

	deadline := time.Now().Add(2 * time.Second)
	for count.Load() < 3 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("the loop did not stop after its context was cancelled")
	}
	if got := count.Load(); got < 3 {
		t.Errorf("the loop took %d snapshot(s): the periodic half never ran", got)
	}
}
