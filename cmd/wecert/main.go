// Command wecert is a cert-manager-style ACME certificate renewal daemon, built for
// deployments where TLS terminates at a Tencent Cloud CLB and the CVM fleet only runs
// the business workload.
//
// Because decryption happens at the CLB, the system needs no node agent and no
// certificate files have to be distributed: one machine, one binary, one SQLite file.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"math/rand"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/susunola/wecert/internal/acme"
	"github.com/susunola/wecert/internal/backup"
	"github.com/susunola/wecert/internal/config"
	"github.com/susunola/wecert/internal/deploy"
	"github.com/susunola/wecert/internal/reconcile"
	"github.com/susunola/wecert/internal/spec"
	"github.com/susunola/wecert/internal/state"
	"github.com/susunola/wecert/internal/webhook"
)

// version can be injected through -ldflags "-X main.version=...".
var version = "dev"

func main() {
	// The ACME User-Agent names the running build, so a CA-side log lines up with the binary that
	// sent the request. It is set here, at process start, rather than inside run(): run() returns
	// from the -revoke branch early, and having the call after that branch meant every revocation
	// -- the request an operator makes about a compromised key -- identified itself as "wecert/dev".
	// A global with no dependencies belongs at the top, where no branch can skip it.
	acme.SetUserAgentVersion(version)

	if err := run(); err != nil {
		// exitUsage is the conventional "the command line itself is wrong" code, the same one
		// wecert-onboard and wecert-probe use -- and it matters here because the alternative was
		// flag.ExitOnError's 2, which this repository documents as wecert-onboard's "deliberately
		// frozen, a human should look" code. A typo in wecert-once.service's ExecStart is not a
		// freeze, and a monitoring rule keyed on 2 must not read it as one. The flag package has
		// already printed the offending flag and the usage to stderr.
		if errors.Is(err, errUsage) {
			os.Exit(exitUsage)
		}
		slog.Error("wecert exited with an error", "err", err)
		os.Exit(1)
	}
}

const (
	// exitUsage: the command line itself is wrong (see main).
	exitUsage = 64

	// snapshotWait bounds how long a one-shot run waits for the immediate snapshot before judging it
	// (see snapshotHealth.wait).
	snapshotWait = 60 * time.Second
)

// errUsage marks a command-line error, so main can pick the exit code without re-printing what the
// flag package already printed.
var errUsage = errors.New("invalid command line")

// flags holds every flag this command takes.
//
// It left run's locals so that parsing has a test: the "explicitly set" map used to be built
// with flag.Visit -- the package-level FlagSet, which nothing in this program ever parses --
// so it was always empty and every contradiction validateFlags exists to catch was accepted.
// See parseArgs.
type flags struct {
	configPath  string
	statePath   string
	once        bool
	interval    time.Duration
	logLevel    string
	dryRun      bool
	showVer     bool
	revokeCert  string
	restoreFrom string
	revokeWhy   string
	yesFlag     bool
}

// newFlagSet registers every flag on fs -- never on the package-level flag.CommandLine, which
// fs.Parse cannot see.
func newFlagSet(f *flags) *flag.FlagSet {
	fs := flag.NewFlagSet("wecert", flag.ContinueOnError)
	fs.StringVar(&f.configPath, "config", "config.yaml", "path to the configuration file")
	fs.StringVar(&f.statePath, "state", "", "override statePath from the config (handy for tests or running multiple instances)")
	fs.BoolVar(&f.once, "once", false, "run one pass and exit (for a systemd timer / cron)")
	fs.DurationVar(&f.interval, "interval", time.Hour, "reconcile interval in daemon mode")
	fs.StringVar(&f.logLevel, "log-level", "info", "log level: debug|info|warn|error")
	fs.BoolVar(&f.dryRun, "dry-run", false, "validate the config, initialise the account and build the DNS provider and deployer; issue and deploy nothing")
	fs.BoolVar(&f.showVer, "version", false, "print the version and exit")
	fs.StringVar(&f.revokeCert, "revoke", "", "ask the CA to revoke this certificate and exit (see also -yes)")
	fs.StringVar(&f.restoreFrom, "restore", "",
		"restore a state snapshot and exit: a snapshot file, a directory of snapshots, or \"latest\"")
	fs.StringVar(&f.revokeWhy, "revoke-reason", "unspecified",
		"revocation reason: unspecified|keyCompromise|affiliationChanged|superseded|cessationOfOperation")
	fs.BoolVar(&f.yesFlag, "yes", false, "with -revoke: skip the interactive confirmation")
	return fs
}

// errHelp is parseArgs' answer to -h: the flag package has already printed the usage, and
// asking for help is not an error.
var errHelp = errors.New("help requested")

// parseArgs parses args and reports which flags were set explicitly.
func parseArgs(args []string) (*flags, map[string]bool, error) {
	var f flags
	fs := newFlagSet(&f)
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil, nil, errHelp
		}
		return nil, nil, errUsage
	}

	// Only an explicitly set flag can contradict another one: -log-level and -interval have
	// defaults, so "-revoke x -log-level info" sets nothing the operator asked for.
	//
	// fs.Visit, not flag.Visit: the latter walks the package-level CommandLine, which this
	// program never parses, so it reported nothing as explicitly set.
	explicit := map[string]bool{}
	fs.Visit(func(fl *flag.Flag) { explicit[fl.Name] = true })
	return &f, explicit, nil
}

func run() error {
	// A ContinueOnError FlagSet rather than the package-level one, because that one exits 2 on a
	// typo (see main).
	f, explicit, err := parseArgs(os.Args[1:])
	if err != nil {
		if errors.Is(err, errHelp) {
			return nil
		}
		return err
	}

	if f.showVer {
		fmt.Println("wecert", version)
		return nil
	}

	if err := validateFlags(explicit, f.once, f.dryRun, f.interval); err != nil {
		return err
	}

	if f.restoreFrom != "" {
		// A mode flag next to -restore is a mistake worth refusing rather than ordering: every one of
		// the others does something to a state database, and "restore, and then also reconcile once"
		// is not a thing an operator can have meant.
		if f.once || f.dryRun || f.revokeCert != "" {
			return errRestoreConflict
		}
		return runRestore(f.configPath, f.statePath, f.restoreFrom)
	}

	// Install signal handling before anything touches the network (config load, EnsureAccount,
	// the revocation path). This used to be registered just before the daemon loop, so a SIGTERM
	// during the first account setup -- a network call that can hang for a while -- got the
	// default kill instead of a graceful shutdown.
	//
	// The context is process-level on purpose: a webhook-triggered reconcile runs in the
	// background for minutes, so it must hang off the process context, not a request's.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if f.revokeCert != "" {
		return runRevoke(f.configPath, f.statePath, f.revokeCert, f.revokeWhy, f.yesFlag)
	}

	level, err := parseLogLevel(f.logLevel)
	if err != nil {
		return err
	}
	log := newLogger(level)

	cfg, store, err := openRuntime(f, log)
	if err != nil {
		return err
	}
	defer store.Close()

	provider, prober, err := buildDesiredAndProber(cfg, log)
	if err != nil {
		return err
	}

	httpClient := acme.NewHTTPClient(60 * time.Second)
	core, err := acme.EnsureAccount(cfg, store, httpClient)
	if err != nil {
		return err
	}

	if f.dryRun {
		return finishDryRun(cfg, provider, prober, log)
	}

	reconciler, notifier, err := buildManager(cfg, store, core, provider, prober, log)
	if err != nil {
		return err
	}

	// Evaluate once up front and cache it, so the read-only endpoints (webhook name
	// resolution, diagnostics) answer correctly before the first reconcile finishes
	// rather than returning an empty list -- which reads as "the desired state is empty".
	reconciler.Prime(ctx)
	logEnforceFleet(cfg, reconciler, provider, log)

	// Periodic consistent snapshots of state.db. Started here so a snapshot exists before
	// the first renewal window can lose an order: the file holds the ACME account key and
	// every in-flight order URL, and losing an order URL means re-placing it into the
	// exact-set rate limit.
	var snapshots *snapshotHealth
	var stopBackups func()
	// Registered after `defer store.Close()` above, so it runs BEFORE it: defers are LIFO,
	// and the snapshot goroutine writes to SQLite on its own schedule.
	defer func() {
		if stopBackups != nil {
			stopBackups()
		}
	}()
	snapshots, stopBackups = startBackupsIfNeeded(ctx, store, cfg, log)

	// Metrics server. Bind the port synchronously first and exit on failure -- see below.
	if err := startMetricsServer(ctx, cfg.Metrics.Listen, log); err != nil {
		return err
	}

	// Event-trigger endpoint. Same rule: a failed port bind must be a hard failure.
	if err := startWebhookServer(ctx, cfg, reconciler, store, log); err != nil {
		return err
	}

	if f.once {
		return runOncePass(ctx, reconciler, notifier, snapshots, log)
	}

	log.Info("entering daemon mode", "interval", f.interval)
	runDaemon(ctx, f.interval, log, reconciler.RunDetailed)
	// Wait for background passes and notifications before returning: the deferred store.Close()
	// would otherwise close SQLite under a pass that is mid-renewal, losing the promotion or the
	// resume anchor it was writing. See Reconciler.Drain.
	drainBackground(reconciler, log)
	drainNotifier(notifier, log)
	return nil
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
	// Run one pass after startup, then loop on the interval; jitter avoids simultaneous knocking.
	next := time.After(jitter(time.Second))
	for {
		select {
		case <-ctx.Done():
			log.Info("stop signal received; exiting")
			return
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
// the process could exit holding the lock out from under a half-written snapshot file.
func startStateBackups(ctx context.Context, store *state.Store, cfg *config.Config, log *slog.Logger) (*snapshotHealth, func()) {
	dirs := stateBackupDirs(cfg)

	snapshot := func() error {
		return takeSnapshots(ctx, store, dirs, cfg.StateBackup.RemoteTargets, cfg.StateBackup.Keep, cfg.StateBackup.IntervalDur, log)
	}

	// first records the outcome of the immediate snapshot: the one-shot run reads it to decide
	// its exit code (see snapshotHealth).
	first := make(chan error, 1)
	health := &snapshotHealth{first: first}

	// Its own context, so shutdown does not depend on the process context having been
	// cancelled: run() returns normally from -once and from a daemon stop, and
	// signal.NotifyContext's stop() does not cancel. Waiting on ctx.Done() there would
	// have hung forever.
	snapCtx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})

	// Only the immediate snapshot's outcome is reported: first is buffered by exactly one, so
	// sending every interval's result would block this goroutine forever once nobody reads it
	// -- and a blocked snapshot goroutine is also a stop function that never returns.
	var reported bool
	go snapshotLoop(snapCtx, cfg.StateBackup.IntervalDur, func() {
		err := snapshot()
		if !reported {
			reported = true
			first <- err
		}
	}, done)

	log.Info("periodic state database snapshots are on",
		"dirs", dirs, "interval", cfg.StateBackup.IntervalDur, "keep", cfg.StateBackup.Keep)

	return health, func() { stopSnapshotLoop(cancel, done, log) }
}

// snapshotHealth carries the immediate snapshot's outcome to the one-shot exit code.
//
// Why the exit code has to know: `wecert-once.timer` runs `-once` hourly, and its unit status is the
// ONLY channel a timer-mode deployment has (round 9: /metrics does not live long enough for any rule
// with a `for:`). A snapshot that cannot be written leaves the recovery posture broken -- no
// recoverable copy of the account key or of any in-flight order URL -- and that used to be an ERROR
// line inside a background goroutine, so a pass that converged still exited 0 and the unit stayed
// green. The round-11 Linux verification reproduced it with an injected fsync EIO: "state database
// snapshot failed", exit 0.
//
// It lives in this file rather than in internal/state because the decision is the CLI's: the daemon
// must NOT exit over a failed snapshot (it retries on the next interval and says so in the journal),
// while a one-shot run that leaves no backup behind is a failure the timer should report.
type snapshotHealth struct {
	first chan error
}

// wait returns the immediate snapshot's error, or nil when it succeeded, was skipped because the
// database holds nothing to recover, or has not reported yet within the grace period.
func (h *snapshotHealth) wait(timeout time.Duration) error {
	if h == nil {
		return nil
	}
	select {
	case err := <-h.first:
		return err
	case <-time.After(timeout):
		// Still writing: a snapshot of a large database takes seconds, and the pass it overlapped has
		// already finished. Reporting a timeout as a snapshot failure would be a false alarm on a
		// slow disk, so the run stays green and the daemon logs the real outcome.
		return nil
	}
}

// snapshotLoop takes one snapshot immediately and then one per interval until ctx is done,
// closing done as it returns.
//
// Split out of startStateBackups so the shutdown wait has a test: what it has to guarantee is
// that stopSnapshotLoop does not return while a snapshot is still running, and that is only
// observable with a snapshot function the test controls.
func snapshotLoop(ctx context.Context, interval time.Duration, snapshot func(), done chan<- struct{}) {
	defer close(done)
	// One immediately: waiting a whole interval means a fresh deployment has no
	// recoverable state for its first day, which is exactly when orders are in flight.
	snapshot()

	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			snapshot()
		}
	}
}

// stopSnapshotLoop cancels the loop and waits for it to finish.
//
// The wait is bounded on purpose: a snapshot is a VACUUM INTO of a database that is a few
// hundred kilobytes, so 15s is generous -- and a stop signal must never hang on it. The wait
// is best-effort, the same way drainBackground's is.
func stopSnapshotLoop(cancel context.CancelFunc, done <-chan struct{}, log *slog.Logger) {
	cancel()
	select {
	case <-done:
	case <-time.After(snapshotDrainTimeout):
		log.Warn("a state snapshot was still running at shutdown; the state store is about to "+
			"be closed under it, so that snapshot may be truncated",
			"waited", snapshotDrainTimeout)
	}
}

// snapshotDrainTimeout bounds how long shutdown waits for an in-flight state snapshot.
const snapshotDrainTimeout = 15 * time.Second

// takeSnapshot writes one snapshot, unless the database holds nothing a snapshot could recover.
//
// The second half is the point. A copy of a freshly created database is not a recovery point, but
// retention counts it as one -- and the case snapshots exist for is exactly the case that produces
// an empty database: after state.db is lost, every restart wrote a snapshot of the empty
// replacement and evicted a genuine backup, so three restarts with keep=3 destroyed all three real
// snapshots before anyone looked at the directory. Rate buckets and failure counters do not count
// as recoverable state: losing them costs rate-limit knowledge, not a certificate.
func takeSnapshot(store *state.Store, dir string, keep int, interval time.Duration, log *slog.Logger) error {
	return takeSnapshots(context.Background(), store, []string{dir}, nil, keep, interval, log)
}

// takeSnapshots writes a fully consistent SQLite snapshot to every configured
// local destination. Each call to Store.Snapshot uses VACUUM INTO; copying
// state.db (especially while WAL is enabled) is never used as a shortcut.
func takeSnapshots(ctx context.Context, store *state.Store, dirs []string, remote []config.BackupTarget, keep int, interval time.Duration, log *slog.Logger) error {
	has, err := store.HasRecoverableState()
	if err != nil {
		log.Error("cannot tell whether the state database holds anything worth snapshotting", "err", err)
		return err
	}
	if !has {
		// Not a failure: a copy of a database with nothing to recover is not a recovery point.
		log.Warn("skipping this snapshot: the state database holds no account, certificate, order "+
			"or revocation request yet, so a copy of it is not a recovery point -- and retention "+
			"would count it as one and evict a snapshot that is",
			"dirs", dirs, "keep", keep)
		return nil
	}

	var errs []error
	var uploaded string
	for _, dir := range dirs {
		path, err := store.Snapshot(dir, keep)
		if err != nil {
			// A partial failure still writes the file; say which, so a successful snapshot with a
			// failed prune is not read as "no backup exists".
			log.Error("state database snapshot failed", "dir", dir, "err", err)
			if path != "" {
				log.Info("a snapshot was written despite the error", "path", path)
			}
			errs = append(errs, fmt.Errorf("%s: %w", dir, err))
			continue
		}
		log.Info("state database snapshotted", "path", path, "interval", interval, "keep", keep)
		if uploaded == "" {
			uploaded = path
		}
	}
	if uploaded != "" {
		for _, target := range remote {
			err := backup.Upload(ctx, backup.Target{Type: target.Type, Name: target.Name, Bucket: target.Bucket, Prefix: target.Prefix, Endpoint: target.Endpoint, Region: target.Region, Host: target.Host, Username: target.Username, RemoteDir: target.RemoteDir, PasswordEnv: target.PasswordEnv, PrivateKeyFile: target.PrivateKeyFile, PrivateKeyPassphraseEnv: target.PrivateKeyPassphraseEnv, KnownHostsFile: target.KnownHostsFile, Keep: target.Keep, Timeout: target.TimeoutDur}, uploaded)
			if err != nil {
				log.Error("remote state snapshot upload failed", "target", target.Name, "type", target.Type, "err", err)
				errs = append(errs, fmt.Errorf("remote target %s: %w", target.Name, err))
			} else {
				log.Info("state snapshot uploaded", "target", target.Name, "type", target.Type, "path", uploaded)
			}
		}
	}
	return errors.Join(errs...)
}

func startMetricsServer(ctx context.Context, addr string, log *slog.Logger) error {
	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.Handler())
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf(
			"failed to listen on the metrics port %s: %w (already in use? only one wecert instance should run per machine; "+
				"do not enable both the daemon and the timer)", addr, err)
	}

	srv := &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		// The webhook server below sets all three; this one used to set only the header
		// timeout. ReadTimeout=0 means a client that announces a body and then dribbles it
		// (net/http drains up to 256KB in finishRequest) pins a connection and its file
		// descriptor with no upper bound, and IdleTimeout=0 falls back to ReadTimeout=0, so
		// keep-alive connections never expire either. The default bind is loopback, which
		// limits the exposure -- but binding metrics to a VPC address so Prometheus can
		// scrape it is a documented setup, and that is where this matters.
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
	}()

	go func() {
		// The only error that can reach here is ErrServerClosed from Shutdown.
		if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Error("the metrics server exited unexpectedly", "err", err)
		}
	}()

	log.Info("metrics server started", "addr", ln.Addr().String(), "metrics", "/metrics")
	return nil
}

// startWebhookServer starts the event-trigger endpoint.
//
// Like the metrics server it binds the port **synchronously** and exits on failure, for
// the same reason: this is the only entrance to the event-driven path, and occupying the
// port while merely logging a line makes people believe it is configured when in fact
// every event is lost -- and certificates march on toward expiry regardless.
func startWebhookServer(
	ctx context.Context, cfg *config.Config,
	rec *reconcile.Reconciler, store *state.Store, log *slog.Logger,
) error {
	if cfg.Webhook.Listen == "" {
		log.Info("webhook disabled (webhook.listen is empty); converging on the timer only")
		return nil
	}

	ln, err := net.Listen("tcp", cfg.Webhook.Listen)
	if err != nil {
		return fmt.Errorf(
			"failed to listen on the webhook port %s: %w (already in use?)", cfg.Webhook.Listen, err)
	}

	api, err := webhook.New(rec, store, cfg.Webhook.Token, ctx, log)
	if err != nil {
		// The port is already bound above, and returning here used to leak it: this process
		// exits because of the error, so a restart is fine, but the exit path taken when
		// webhook.New rejects the config is exactly the one an operator fixes by editing
		// webhook.token and rerunning -- and the rerun then fails with "address already in
		// use", pointing at a phantom instance instead of at the setting they just changed.
		_ = ln.Close()
		return fmt.Errorf("failed to initialise the webhook server (the port %s has been released): %w",
			cfg.Webhook.Listen, err)
	}
	api.SetAccountUIN(cfg.Tencent.UIN)

	srv := &http.Server{
		Handler:           api.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      15 * time.Second,
		// Explicit, matching startMetricsServer: IdleTimeout=0 falls back to
		// ReadTimeout, so keep-alives would silently inherit whatever that is set to
		// later instead of the longer idle window the metrics server documents.
		IdleTimeout: 60 * time.Second,
	}

	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
	}()

	go func() {
		if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Error("the webhook server exited unexpectedly", "err", err)
		}
	}()

	log.Info("webhook server started",
		"addr", ln.Addr().String(),
		"trigger", "POST /hook/reconcile",
		"status", "GET /hook/status")
	return nil
}

func newDeployer(cfg *config.Config, log *slog.Logger) (deploy.Deployer, error) {
	// Enforce is driven by a document that may change while this process is
	// running. Its config-level certificate list is deliberately empty, so
	// scanning it would permanently select Noop even when the document enables
	// deploy. Keep a lazily initialised cloud deployer available instead.
	if cfg.DesiredState.Mode == config.ModeEnforce {
		log.Info("Tencent Cloud deploy is available for enforce-mode desired-state certificates",
			"credentialMode", cfg.Tencent.CredentialMode,
			"resourceTypes", cfg.Tencent.ResourceTypes,
			"regions", cfg.Tencent.Regions)
		return deploy.NewLazyTencentCLB(cfg.Tencent, log), nil
	}

	enabled := false
	for _, c := range cfg.Certificates {
		if c.Deploy.Enabled {
			enabled = true
			break
		}
	}
	if !enabled {
		log.Info("no certificate has deploy enabled; keeping local state only (nothing is pushed to Tencent Cloud)")
		return deploy.Noop{}, nil
	}

	d, err := deploy.NewTencentCLB(cfg.Tencent, log)
	if err != nil {
		return nil, err
	}
	log.Info("Tencent Cloud deploy enabled",
		"credentialMode", cfg.Tencent.CredentialMode,
		"resourceTypes", cfg.Tencent.ResourceTypes,
		"regions", cfg.Tencent.Regions)
	return d, nil
}

func isFirstRun(store *state.Store, cfg *config.Config) (bool, error) {
	acc, err := store.GetAccount(cfg.ACME.Directory)
	if err != nil {
		return false, err
	}
	return acc == nil, nil
}

func logStartup(log *slog.Logger, cfg *config.Config, firstRun bool) {
	production := cfg.ACME.Directory == config.DirectoryProduction

	log.Info("wecert starting",
		"version", version,
		"directory", cfg.ACME.Directory,
		"production", production,
		"statePath", cfg.StatePath,
		"mode", cfg.DesiredState.Mode,
		"certificates", certificateCountField(cfg))

	if firstRun {
		log.Warn("no account in the state store; registering a new ACME account")
		if production {
			log.Warn("WARNING: pointed at the Let's Encrypt production environment. " +
				"Run the whole flow against https://acme-staging-v02.api.letsencrypt.org/directory first, " +
				"otherwise failed retries burn real production quota")
		}
	}

	for _, c := range cfg.Certificates {
		log.Info("loaded certificate",
			"cert", c.Name,
			"profile", c.Profile,
			"domains", len(c.Domains),
			"maxNames", c.MaxNames(),
			"renewBefore", c.RenewBeforeDur,
			"deploy", c.Deploy.Enabled)

		// A wildcard covers one label only; deeper subdomains need their own entry. The classic mistake.
		for _, d := range c.Domains {
			if strings.HasPrefix(d, "*.") && strings.Count(d, ".") > 1 {
				log.Info("note: a wildcard covers only one label",
					"cert", c.Name, "domain", d,
					"hint", "e.g. *.a.example.com does not include b.a.example.com; add *.b.a.example.com or list it explicitly")
			}
		}
	}
}

// buildCredentialBearingComponents constructs the parts of the program that read credentials,
// without issuing or deploying anything.
//
// It exists so -dry-run can make its own summary true: internal/config deliberately leaves the
// validation of static Tencent credentials to deploy.NewCredentialSource, so a config with
// credentialMode=static and no secretId/secretKey passed the documented pre-install check and exited
// 0 with "all fine" -- failing on the first real pass instead, after a production ACME account had
// been registered and an interval had gone by.
//
// Note the middle call: in enforce mode newDeployer returns the LAZY CLB client on purpose (the
// document decides what is deployed), so without asking for the credential source directly, a
// deployment using DNSPod tokens for DNS would still not have its CAM credentials checked here.
func buildCredentialBearingComponents(cfg *config.Config, log *slog.Logger) error {
	if _, err := acme.NewDNSSolver(cfg.DNS, cfg.Tencent, log); err != nil {
		return fmt.Errorf("the DNS provider would not build: %w", err)
	}
	if _, err := deploy.NewCredentialSource(cfg.Tencent); err != nil {
		return fmt.Errorf("the Tencent Cloud credentials would not build: %w", err)
	}
	if _, err := newDeployer(cfg, log); err != nil {
		return fmt.Errorf("the deployer would not build: %w", err)
	}
	return nil
}

// minReconcileInterval is the smallest -interval the daemon accepts.
//
// jitter maps a non-positive interval to one second, and even an explicit few seconds is a full
// reconcile per round -- DNS lookups, cloud API reads, a TLS dial per name. An interval that
// small is a misconfiguration: it hammers the DNS provider and the cloud APIs, so it is rejected
// at startup rather than silently run.
const minReconcileInterval = time.Minute

// validateFlags rejects flag combinations that used to be resolved silently, with one flag
// quietly winning over the other and the operator never told.
//
// -revoke exits before the logger, the dry-run branch and the reconcile loop, so -once,
// -dry-run, -log-level and -interval are dead flags next to it. -once and -dry-run exclude each
// other: the dry run returns before any pass exists for -once to mean. And the reconcile
// interval has a floor (see minReconcileInterval), checked only when the loop will actually run.
func validateFlags(explicit map[string]bool, once, dryRun bool, interval time.Duration) error {
	if explicit["revoke"] {
		for _, dead := range []string{"once", "dry-run", "log-level", "interval"} {
			if explicit[dead] {
				return fmt.Errorf("-%s has no effect with -revoke (revocation exits before that flag "+
					"is read); drop it so the command line says what it does", dead)
			}
		}
		return nil
	}
	if once && dryRun {
		return fmt.Errorf("-once and -dry-run cannot be combined: the dry run validates the config and " +
			"exits before any pass, so there is nothing for -once to run")
	}
	if !once && !dryRun && interval < minReconcileInterval {
		return fmt.Errorf("-interval must be at least %s, got %s: daemon mode runs a full reconcile per "+
			"interval, and a shorter one hammers the DNS provider and the cloud APIs",
			minReconcileInterval, interval)
	}
	return nil
}

// certificateCountField is what the banner and the dry-run summary report as `certificates`.
//
// In enforce mode len(cfg.Certificates) is 0 by construction -- config.normalize refuses a non-empty
// list there, because the document is the single source of truth -- so printing the number said
// "nothing is managed" about a document that may list ten certificates, and it is the first field an
// operator reads. The real count is logged once the document has been resolved (see the Prime call
// in run), which is the only point where it exists.
func certificateCountField(cfg *config.Config) any {
	if cfg.DesiredState.Mode == config.ModeEnforce {
		return "from the desired-state document (counted below)"
	}
	return len(cfg.Certificates)
}

// parseLogLevel turns the -log-level flag into an slog.Level.
//
// An unknown value is an error, not a silent fall back to info: the fall back meant a typo like
// "wran" ran the daemon at a verbosity the operator did not ask for, with no line anywhere
// saying so.
func parseLogLevel(level string) (slog.Level, error) {
	switch strings.ToLower(level) {
	case "debug":
		return slog.LevelDebug, nil
	case "info":
		return slog.LevelInfo, nil
	case "warn":
		return slog.LevelWarn, nil
	case "error":
		return slog.LevelError, nil
	}
	return 0, fmt.Errorf("unknown log level %q (want debug|info|warn|error)", level)
}

func newLogger(level slog.Level) *slog.Logger {
	// Without timestamps it reads better under systemd/journald; in a terminal they help.
	handler := slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: level})
	return slog.New(handler)
}
