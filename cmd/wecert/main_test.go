package main

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/susunola/wecert/internal/config"
	"github.com/susunola/wecert/internal/deploy"
	"github.com/susunola/wecert/internal/reconcile"
	"github.com/susunola/wecert/internal/state"
	"sync/atomic"
	"time"
)

// Enforce forbids certificates in the config, and its document can enable
// deployment after startup. It must therefore retain a deferred cloud deployer
// rather than silently selecting Noop from the empty config list.
func TestEnforceUsesLazyTencentDeployer(t *testing.T) {
	cfg := &config.Config{
		DesiredState: config.DesiredState{Mode: config.ModeEnforce},
		Tencent: config.Tencent{
			CredentialMode: config.CredentialStatic,
			SecretID:       "id",
			SecretKey:      "key",
		},
	}

	d, err := newDeployer(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatalf("construct deployer: %v", err)
	}
	if _, ok := d.(*deploy.LazyTencentCLB); !ok {
		t.Fatalf("enforce mode must retain a lazy Tencent deployer, got %T", d)
	}
}

func TestEnforceDefersUnusedStaticCredentials(t *testing.T) {
	cfg := &config.Config{DesiredState: config.DesiredState{Mode: config.ModeEnforce}}
	cfg.Tencent.CredentialMode = config.CredentialStatic
	d, err := newDeployer(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatalf("purely local enforce mode must not validate unused credentials: %v", err)
	}
	if _, ok := d.(*deploy.LazyTencentCLB); !ok {
		t.Fatalf("enforce mode must retain a lazy deployer, got %T", d)
	}
}

// A one-shot run that did not converge must fail.
//
// wecert-once.service runs this with -once, and "exited 0 with every certificate failing" is the
// failure this report exists to prevent: the timer reports success while the fleet goes unmanaged.
func TestOnceExitFailsWhenThePassDidNotConverge(t *testing.T) {
	trouble := []struct {
		name string
		rep  reconcile.RunReport
	}{
		{"a certificate failed", reconcile.RunReport{Attempted: 3, Succeeded: 2, Failed: 1}},
		{"the desired state was unreadable", reconcile.RunReport{DesiredStateUnreadable: true}},
		// Attempted nothing and skipped everything is not "nothing to do": it is the state a
		// certificate stuck in a long backoff sits in, which is exactly what a one-shot run has to
		// report.
		{"nothing was attempted and everything was skipped", reconcile.RunReport{Skipped: []string{"a", "b"}}},
	}
	for _, tc := range trouble {
		if err := onceExit(tc.rep); err == nil {
			t.Errorf("%s: a one-shot run must exit non-zero so the timer reports the failure", tc.name)
		}
	}

	healthy := []struct {
		name string
		rep  reconcile.RunReport
	}{
		{"everything succeeded", reconcile.RunReport{Attempted: 2, Succeeded: 2}},
		{"a certificate is inside its retry window", reconcile.RunReport{Attempted: 0, Backoff: 1}},
	}
	for _, tc := range healthy {
		if err := onceExit(tc.rep); err != nil {
			t.Errorf("%s: this is a healthy pass, got %v", tc.name, err)
		}
	}
}

// "Enabled but the directory is not writable" must be its own outcome, not the running one.
//
// EnabledOr() returns the explicit setting whenever it is set, so treating it as sufficient sent
// this case into the branch that starts the loop: it then took a snapshot every interval, failed,
// and logged an ERROR each time -- the noise the diagnostic branch exists to replace, and it was
// unreachable because its guard was the condition the first branch had already consumed.
func TestPlanStateBackupsDistinguishesEnabledFromWritable(t *testing.T) {
	yes, no := true, false
	cases := []struct {
		name     string
		enabled  *bool
		writable bool
		want     backupPlan
	}{
		{"explicitly enabled, writable", &yes, true, backupsRun},
		{"explicitly enabled, unwritable", &yes, false, backupsEnabledButUnwritable},
		{"explicitly disabled, writable", &no, true, backupsDisabled},
		{"unset (the default) follows the directory", nil, true, backupsRun},
		{"unset with an unwritable directory", nil, false, backupsDisabled},
	}
	for _, tc := range cases {
		if got := planStateBackups(tc.enabled, tc.writable); got != tc.want {
			t.Errorf("%s: planStateBackups = %v, want %v", tc.name, got, tc.want)
		}
	}
}

// A pass that did not converge must not stop the daemon, and the pass summary must say what it did.
//
// This is the difference between the two run modes: the timer unit fails loudly on a bad pass, the
// daemon logs it and comes back on the next interval -- a daemon that exits on the first unreachable
// DNS server is worse than one that retries. The loop used to reach for a wrapper that discarded
// the report, so "a pass ran and converged nothing" and "a pass converged everything" left the same
// trace.
func TestTheDaemonKeepsRunningAfterAPassThatDidNotConverge(t *testing.T) {
	var logs bytes.Buffer
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var passes atomic.Int64
	release := make(chan struct{})
	pass := func(context.Context) reconcile.RunReport {
		n := passes.Add(1)
		if n >= 3 {
			// Enough evidence: the loop came back after two troubled passes.
			cancel()
		}
		if n == 1 {
			close(release)
		}
		return reconcile.RunReport{Attempted: 2, Succeeded: 1, Failed: 1}
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		runDaemon(ctx, time.Millisecond, slog.New(slog.NewTextHandler(&logs, nil)), pass)
	}()
	<-release
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("the daemon did not exit after its context was cancelled")
	}

	if got := passes.Load(); got < 3 {
		t.Errorf("the daemon ran %d pass(es): a failed pass must not end the loop", got)
	}
	out := logs.String()
	for _, want := range []string{"reconcile pass finished", "failed=1", "trouble=true"} {
		if !strings.Contains(out, want) {
			t.Errorf("the per-pass summary must carry %q so a pass that converged nothing is visible, got:\n%s",
				want, out)
		}
	}
}

// A restart on an empty database must not evict the snapshots that still hold the real state.
//
// This is the shape of the documented disaster: state.db is lost, the daemon starts with a fresh
// one, and the periodic snapshot runs immediately (by design -- waiting a whole interval would
// leave a fresh deployment with no recoverable state). Retention counted that empty copy as a peer,
// so three restarts with keep=3 removed all three genuine snapshots, and the operator's last good
// copy was gone before anyone noticed the loss.
func TestAnEmptyDatabaseIsNotSnapshotted(t *testing.T) {
	dir := t.TempDir()
	store, err := state.Open(filepath.Join(dir, "state.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })

	backups := filepath.Join(dir, "backups")
	var logs bytes.Buffer
	log := slog.New(slog.NewTextHandler(&logs, nil))

	takeSnapshot(store, backups, 3, time.Hour, log)

	if _, err := os.Stat(backups); !os.IsNotExist(err) {
		t.Errorf("no snapshot may be written for a database with nothing to recover, backup dir stat err %v", err)
	}
	if !strings.Contains(logs.String(), "skipping this snapshot") {
		t.Errorf("the skip has to be visible, got:\n%s", logs.String())
	}

	// With one certificate the same call must write, so the guard is about content, not about
	// disabling snapshots.
	if err := store.PutCert(&state.CertState{Name: "example-com", KeyPEM: []byte("PRIVATE KEY")}); err != nil {
		t.Fatalf("PutCert: %v", err)
	}
	logs.Reset()
	takeSnapshot(store, backups, 3, time.Hour, log)

	snaps, err := store.Snapshots(backups)
	if err != nil {
		t.Fatalf("Snapshots: %v", err)
	}
	if len(snaps) != 1 {
		t.Errorf("a database with a certificate in it must be snapshotted, got %d: %v (%s)",
			len(snaps), snaps, logs.String())
	}
}
