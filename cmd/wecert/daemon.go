package main

import (
	"context"
	"fmt"
	"log/slog"
	"math/rand"
	"os"
	"os/signal"
	"time"

	"github.com/susunola/wecert/internal/config"
	"github.com/susunola/wecert/internal/reconcile"
	"github.com/susunola/wecert/internal/spec"
)

func notifyContext(parent context.Context, signals ...os.Signal) (context.Context, context.CancelFunc) {
	ctx, stop := signal.NotifyContext(parent, signals...)
	go func() {
		<-ctx.Done()
		stop()
	}()
	return ctx, stop
}

// backgroundDrainTimeout bounds how long a shutdown waits for webhook-triggered passes.
//
// A pass can be inside a CA call that lego's context-free API cannot interrupt, and a stop signal
// must not hang forever; the timeout is generous enough for the state writes that matter, and the
// warning says plainly what a timeout means.
const backgroundDrainTimeout = 30 * time.Second

func drainBackground(reconciler *reconcile.Reconciler, log *slog.Logger) {
	ctx, cancel := context.WithTimeout(context.Background(), backgroundDrainTimeout)
	defer cancel()
	if err := reconciler.Drain(ctx); err != nil {
		log.Warn("a background pass did not finish before shutdown; the state store is about to be "+
			"closed under it, so its last write may be lost (the next pass resumes from the order URL "+
			"that is already on disk)",
			"waited", backgroundDrainTimeout, "err", err)
	}
}

func drainRuntimeBackground(runtime *runtimeController, log *slog.Logger) {
	ctx, cancel := context.WithTimeout(context.Background(), backgroundDrainTimeout)
	defer cancel()
	if err := runtime.Drain(ctx); err != nil {
		log.Warn("a background pass did not finish before shutdown; the state store is about to be closed under it, so its last write may be lost (the next pass resumes from the order URL that is already on disk)",
			"waited", backgroundDrainTimeout, "err", err)
	}
}

// dirIsWritable reports whether a directory can be written to, creating it first if it does not
// exist (Snapshot does the same, and the answer has to describe what will actually happen).
//
// A probe rather than a permission bit: ownership, ACLs, a read-only mount and a full disk all
// decide this, and the only honest way to find out is to try.
func dirIsWritable(dir string) bool {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return false
	}
	f, err := os.CreateTemp(dir, ".wecert-write-probe-*")
	if err != nil {
		return false
	}
	name := f.Name()
	_ = f.Close()
	_ = os.Remove(name)
	return true
}

// backupPlan is what the state-backup switch and the directory's writability together imply.
type backupPlan int

const (
	backupsDisabled backupPlan = iota
	backupsEnabledButUnwritable
	backupsRun
)

// planStateBackups decides between running, refusing loudly, and warning.
//
// The two inputs are independent and that is the whole point: "enabled" says what the operator
// asked for, "writable" says whether it can happen. Collapsing them (treating an explicit true as
// sufficient) started the loop against an unwritable directory, where it failed and logged an
// ERROR every interval -- noise that trains the reader to ignore the one line that means the
// recovery posture is gone -- while the branch written to report exactly that was unreachable.
func planStateBackups(enabled *bool, writable bool) backupPlan {
	switch {
	case enabled != nil && *enabled:
		if writable {
			return backupsRun
		}
		return backupsEnabledButUnwritable
	case enabled != nil && !*enabled:
		return backupsDisabled
	case writable:
		// Unset means "take them when the directory allows it", the documented default.
		return backupsRun
	default:
		return backupsDisabled
	}
}

// onceExit turns a one-shot pass's report into the process outcome.
//
// A systemd timer runs this with -once, so exiting 0 while every certificate failed reports
// success for a fleet that went unmanaged. A pass that attempted nothing and skipped everything
// counts as trouble too: it means the desired state resolved to nothing to do.
func onceExit(rep reconcile.RunReport) error {
	if !rep.Trouble() {
		return nil
	}
	// backoff is in the message because it is the reason a pass can attempt nothing without skipping
	// anything: "attempted=0 ... skipped=0" used to be the whole explanation for a run that exited
	// non-zero because every certificate was parked in its retry window.
	return fmt.Errorf("the pass did not converge: attempted=%d succeeded=%d failed=%d skipped=%d "+
		"backoff=%d desiredStateUnreadable=%t", rep.Attempted, rep.Succeeded, rep.Failed,
		len(rep.Skipped), rep.Backoff, rep.DesiredStateUnreadable)
}

// drainNotifier waits briefly for accepted notifications to be delivered.
//
// The wait is bounded so a receiver that never answers cannot hold shutdown open; each
// individual send is already bounded by its own 10s timeout, so in practice this returns as
// soon as the last one finishes.
func drainNotifier(n reconcile.Notifier, log *slog.Logger) {
	d, ok := n.(reconcile.Drainer)
	if !ok {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	d.Drain(ctx)
	log.Info("waited for in-flight notifications before exiting")
}

// newProvider assembles the desired-state source according to desiredState.mode.
//
// What separates the three modes is **who has the final say**, not "how many files are
// read":
//
//	static   the config's certificates decide. Historic behaviour, zero risk.
//	observe  still converges on certificates, but also reads the document and reports the diff.
//	enforce  the document decides; certificates must be empty.
//
// Inference is kept outside wecert because every known pitfall in this system lives in
// the "judging", and judging logic will keep changing while the certificate lifecycle
// must stay stable.
func newProvider(cfg *config.Config, log *slog.Logger) (spec.Provider, error) {
	static := spec.NewStatic(cfg.Certificates)

	switch cfg.DesiredState.Mode {
	case config.ModeStatic:
		log.Info("desired state comes from the configuration file",
			"mode", config.ModeStatic, "certificates", len(cfg.Certificates))
		return static, nil

	case config.ModeObserve:
		// A shadow source that fails to build must **not** stop the process: before the
		// document exists, converge on the config exactly as before, just with no diff.
		shadow, err := spec.NewFile(cfg.DesiredState.Path, log)
		if err != nil {
			log.Warn("observe mode: the desired-state document is not readable yet; "+
				"convergence will run on the configuration file exactly as before",
				"path", cfg.DesiredState.Path, "err", err)
			return static, nil
		}
		log.Info("observe mode: converging on the configuration file while reporting the diff against the document",
			"path", cfg.DesiredState.Path)
		return spec.NewObserver(static, shadow, log), nil

	case config.ModeEnforce:
		// In enforce mode an unreadable document must **hard fail**.
		//
		// Allowing "starts up with no desired state" means wecert quietly renews nothing
		// until the certificates expire -- the worst kind of failure: silent, with all of
		// the consequences landing in production. Failing to start is at least loud;
		// systemd restarts it, and a human notices.
		f, err := spec.NewFile(cfg.DesiredState.Path, log)
		if err != nil {
			return nil, fmt.Errorf("desiredState.mode=%q requires a readable document: %w",
				config.ModeEnforce, err)
		}
		log.Info("enforce mode: the desired-state document is the single source of truth",
			"path", cfg.DesiredState.Path)
		return f, nil
	}

	return nil, fmt.Errorf("unknown desiredState.mode %q", cfg.DesiredState.Mode)
}

// runDaemon runs one pass after startup and then one per (jittered) interval.
//
// The pass is injected rather than reached through the Reconciler so the loop's own contract can
// be tested: a pass that did not converge must NOT stop the daemon. That is the whole difference
// between the daemon and the one-shot unit, and it is the kind of behaviour that is easy to lose
// when the two paths are edited separately.
func runDaemon(ctx context.Context, interval time.Duration, log *slog.Logger, pass func(context.Context) reconcile.RunReport) {
	runDaemonWithReload(ctx, interval, log, pass, nil, nil)
}

// runDaemonWithReload is runDaemon plus a deliberately narrow SIGHUP hook.  A
// reload is handled between timer passes; the runtime controller itself also
// rejects it while a webhook-started pass is in flight.
func runDaemonWithReload(ctx context.Context, interval time.Duration, log *slog.Logger, pass func(context.Context) reconcile.RunReport, reload <-chan os.Signal, onReload func()) {
	// Run one pass after startup, then loop on the interval; jitter avoids simultaneous knocking.
	next := time.After(jitter(time.Second))
	for {
		select {
		case <-ctx.Done():
			log.Info("stop signal received; exiting")
			return
		case <-reload:
			if onReload != nil {
				onReload()
			}
			continue
		case <-next:
		}

		start := time.Now()
		// The daemon does not fail on a bad pass -- it keeps running and retries on the interval,
		// which is the point of the daemon -- but it does say what the pass did. Without this the
		// only signal was one line per failing certificate, and "a pass ran and converged nothing"
		// looked the same as "a pass converged everything".
		rep := pass(ctx)
		log.Info("reconcile pass finished",
			"duration", time.Since(start).Round(time.Millisecond),
			"attempted", rep.Attempted, "succeeded", rep.Succeeded, "failed", rep.Failed,
			"backoff", rep.Backoff, "skipped", len(rep.Skipped),
			"trouble", rep.Trouble())

		// Re-jitter every round: a fixed interval keeps all instances phase-locked.
		next = time.After(jitter(interval))
	}
}

// jitter returns a random value in [d*0.9, d*1.1).
func jitter(d time.Duration) time.Duration {
	if d <= 0 {
		return time.Second
	}
	delta := float64(d) * 0.1
	return d - time.Duration(delta) + time.Duration(rand.Float64()*2*delta)
}

// startMetricsServer starts the metrics server.
//
// It calls net.Listen synchronously and returns an error on failure, rather than
// dropping ListenAndServe into a goroutine and merely logging a line if it breaks.
//
// Why: /metrics is this system's **only** expiry alerting channel -- the README insists
// that "expiry alerting is driven by not_after, not by whether the renewal job reported
// an error". If the port is taken and we quietly log one error, the program looks
// perfectly healthy while monitoring never hears another signal, and certificates slide
// silently into expiry. That is precisely the failure this project exists to prevent,
// and it should not manufacture one itself.
//
// The doc comment above belongs to startMetricsServer; the one below to startStateBackups. They
// had run together when the pair was split out of run(), which left startStateBackups documented
// by both and startMetricsServer by neither.
//
// startStateBackups snapshots the state database on an interval, in the background.
//
// It never fails the process: a snapshot that cannot be written is a degraded recovery
// posture, not a reason to stop renewing certificates. It is logged at ERROR so it shows
// up in the same place every other operational problem does, and it is reported through
// the same metric channel as everything else.
//
// It returns the immediate snapshot's health -- which the one-shot run reads to decide its exit
// code -- and a stop function, which the caller MUST call before the state store is closed.
// The snapshot goroutine is the one background worker in this process that writes to SQLite
// on its own schedule, and nothing waited for it: a pass that returned at the moment the
// ticker fired raced the deferred store.Close() against store.Snapshot's VACUUM INTO, so
