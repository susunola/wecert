package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/susunola/wecert/internal/acme"
)

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

	// A contradiction or a bad value here is a command-line error, not a run failure: wrap
	// errUsage so main prints the sentence and exits 64 instead of 1 (the repository's own
	// classification, documented at exitUsage).
	if err := validateFlags(explicit, f.once, f.dryRun, f.interval); err != nil {
		return fmt.Errorf("%w: %v", errUsage, err)
	}

	// -restore and -backup-drill are the two one-shot state commands, and they contradict each
	// other: one replaces the database, the other reads a snapshot without touching it. Checked
	// before either branch runs, because the -restore branch returns first -- so "the read-only
	// mode was asked for next to the destructive one" used to end in a completed restore with the
	// drill silently ignored.
	if f.restoreFrom != "" && f.backupDrill != "" {
		return fmt.Errorf("%w: -restore and -backup-drill are different one-shot state commands and "+
			"cannot be combined", errUsage)
	}
	if f.restoreFrom != "" {
		// A mode flag next to -restore is a mistake worth refusing rather than ordering: every one of
		// the others does something to a state database, and "restore, and then also reconcile once"
		// is not a thing an operator can have meant.
		if f.once || f.dryRun || f.revokeCert != "" {
			return errRestoreConflict
		}
		return runRestore(f.configPath, f.statePath, f.restoreFrom, f.yesFlag)
	}
	if f.backupDrill != "" {
		if f.once || f.dryRun || f.revokeCert != "" {
			return fmt.Errorf("%w: -backup-drill is read-only and cannot be combined with another mode", errUsage)
		}
		return runBackupDrill(f.configPath, f.statePath, f.backupDrill)
	}

	// Install signal handling before anything touches the network (config load, EnsureAccount,
	// the revocation path -- which receives this ctx below). This used to be registered just
	// before the daemon loop, so a SIGTERM during the first account setup -- a network call that
	// can hang for a while -- got the default kill instead of a graceful shutdown.
	//
	// The context is process-level on purpose: a webhook-triggered reconcile runs in the
	// background for minutes, so it must hang off the process context, not a request's.
	//
	// notifyContext, not a bare signal.NotifyContext: NotifyContext keeps diverting signals for
	// the rest of the process's life, so a second SIGTERM during a slow graceful shutdown was
	// swallowed too, leaving no way to force the process down short of SIGKILL. Restoring the
	// default disposition once the graceful path has started is the missing half.
	ctx, stop := notifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if f.revokeCert != "" {
		return runRevoke(ctx, f.configPath, f.statePath, f.revokeCert, f.revokeWhy, f.yesFlag)
	}

	level, err := parseLogLevel(f.logLevel)
	if err != nil {
		// Same classification as validateFlags: an illegal -log-level is a wrong command line.
		return fmt.Errorf("%w: %v", errUsage, err)
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
	core, err := acme.EnsureFailoverAPI(cfg, store, httpClient)
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
	runtime := newRuntimeController(cfg, reconciler, notifier, store)

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

	// The two HTTP listeners get their own context, cancelled before the one-shot path drains.
	//
	// They hang off ctx, and nothing cancels ctx before the process exits on the -once path:
	// `defer stop()` was registered first, so it runs last -- after the drain, after the final
	// snapshot wait and after store.Close(). A trigger accepted in that window starts a pass
	// nothing waits for, on a database that is closing, which is the failure drainBackground
	// exists to prevent. Cancelling this context closes the listeners; the passes already
	// accepted are still drained below.
	serverCtx, stopServers := context.WithCancel(ctx)
	defer stopServers()

	// Metrics server. Bind the port synchronously first and exit on failure -- see below.
	if err := startMetricsServer(serverCtx, cfg.Metrics.Listen, log); err != nil {
		return err
	}

	// Event-trigger endpoint. Same rule: a failed port bind must be a hard failure.
	web, err := startWebhookServer(serverCtx, ctx, cfg, runtime, store, log)
	if err != nil {
		return err
	}

	if f.once {
		return runOncePass(ctx, reconciler, notifier, snapshots, stopServers, log)
	}

	log.Info("entering daemon mode", "interval", f.interval)
	reloadSignals := make(chan os.Signal, 1)
	signal.Notify(reloadSignals, syscall.SIGHUP)
	defer signal.Stop(reloadSignals)
	runDaemonWithReload(ctx, f.interval, log, runtime.RunDetailed, reloadSignals, func() {
		next, err := runtime.reload(ctx, f, log)
		if err != nil {
			log.Error("configuration reload rejected; continuing with the previous runtime", "err", err)
			return
		}
		if web != nil {
			web.SetToken(next.Webhook.Token)
			web.SetAdminToken(next.Webhook.AdminToken)
			web.SetAccountUIN(next.Tencent.UIN)
		}
		log.Info("configuration reloaded", "config", f.configPath, "certificates", certificateCountField(next))
	})
	// Wait for background passes and notifications before returning: the deferred store.Close()
	// would otherwise close SQLite under a pass that is mid-renewal, losing the promotion or the
	// resume anchor it was writing. See Reconciler.Drain.
	drainRuntimeBackground(runtime, log)
	drainNotifier(runtime.Notifier(), log)
	return nil
}

// notifyContext is signal.NotifyContext plus the missing second half of graceful shutdown.
//
// NotifyContext keeps diverting the signals into the (already cancelled) context for the rest
// of the process's life, so a second SIGTERM during a slow graceful shutdown -- waiting on a
// background pass, on the snapshot goroutine, on the network -- was swallowed exactly like the
// first, and the only way out was SIGKILL. Once the first signal has started the graceful path
// the default disposition is restored: a second signal then kills the process immediately.
// The returned stop is the one NotifyContext handed back, so the caller's deferred stop and the
