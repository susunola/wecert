// Runtime assembly for cmd/wecert: the steps run() walks through in order, each
// kept in one place so the boot sequence can be read as a list instead of a
// 340-line function.
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"path/filepath"
	"strings"
	"time"

	"github.com/susunola/wecert/internal/acme"
	"github.com/susunola/wecert/internal/config"
	"github.com/susunola/wecert/internal/probe"
	"github.com/susunola/wecert/internal/reconcile"
	"github.com/susunola/wecert/internal/spec"
	"github.com/susunola/wecert/internal/state"
	"github.com/susunola/wecert/internal/webhook"
	"os"
)

// openRuntime loads the config, opens the state store under the cross-process lock
// and prints the startup banner.
//
// The lock is taken here rather than at first issuance: "at most one in-flight order
// per certificate" used to hold only inside a single process, but running the daemon
// and the timer at once means concurrent orders -- and what you hit is the 7-day,
// unrecoverable exact-set limit.
//
// -dry-run is exempt: it almost always runs while the daemon is already running, and
// "cannot even validate the config because the daemon is up" pushes people into
// blindly editing the config. That path only reads the existing ACME account.
func openRuntime(f *flags, log *slog.Logger) (*config.Config, *state.Store, error) {
	cfg, err := config.Load(f.configPath)
	if err != nil {
		return nil, nil, err
	}
	if f.statePath != "" {
		cfg.StatePath = f.statePath
	}

	openStore := state.Open
	if cfg.StateEncryption.Key != "" {
		openStore = func(path string) (*state.Store, error) {
			return state.OpenSealed(path, []byte(cfg.StateEncryption.Key))
		}
	}
	if f.dryRun {
		// Prefers the lock and falls back when the daemon holds it: see state.OpenForTool. Opening
		// unlocked unconditionally is what made `-dry-run` fail on a fresh installation.
		if cfg.StateEncryption.Key != "" {
			openStore = func(path string) (*state.Store, error) {
				return state.OpenSealedForTool(path, []byte(cfg.StateEncryption.Key))
			}
		} else {
			openStore = state.OpenForTool
		}
	}
	store, err := openStore(cfg.StatePath)
	if err != nil {
		return nil, nil, err
	}

	// The first run creates a new ACME account. If it is also the production directory,
	// say this plainly up front: accounts are a finite resource (at most 10 per IP per
	// 3 hours) and should not be recreated over and over.
	firstRun, err := isFirstRun(store, cfg)
	if err != nil {
		_ = store.Close()
		return nil, nil, err
	}
	logStartup(log, cfg, firstRun)

	// If this database came from a snapshot, say what that costs before the first pass runs: the
	// rate-limit ledger in it stops at the snapshot, and the refusal that follows days later looks
	// like an ordinary quota problem. See logRestoreNotice.
	logRestoreNotice(log, cfg.StatePath, time.Now())
	return cfg, store, nil
}

// buildDesiredAndProber constructs the desired-state source and the network prober,
// both before anything touches the network.
//
// The source is first so an unreadable enforce-mode document blows up at **startup**,
// not at the first reconcile: allowing "starts up with no desired state" means wecert
// quietly renews nothing, and nobody finds out until every certificate has expired.
// Being this early is also what lets -dry-run answer "if I switch to this now, will it
// start?" without first registering an ACME account.
func buildDesiredAndProber(cfg *config.Config, log *slog.Logger) (spec.Provider, *probe.Runner, error) {
	provider, err := newProvider(cfg, log)
	if err != nil {
		return nil, nil, err
	}

	// The prober only reads config and touches no network, and "is probing on at all,
	// and which port does it dial" is one of the first things to confirm when switching
	// configuration. It is the only evidence that does not trust the cloud control
	// plane, so it is on by default -- but it may not fit every deployment: on a box
	// that cannot dial the CLB VIP, probe_errors climbs while probe_match stays flat,
	// so certificates never look broken.
	var prober *probe.Runner
	if cfg.Probe.EnabledOr(true) {
		prober = probe.NewRunner(
			probe.Options{Port: cfg.Probe.Port, Timeout: cfg.Probe.TimeoutDur},
			cfg.Probe.MinValidDur, log)
	}
	return provider, prober, nil
}

// finishDryRun reports the dry-run result after the credential-bearing components
// have been constructed. Nothing is issued or deployed.
func finishDryRun(cfg *config.Config, provider spec.Provider, prober *probe.Runner, log *slog.Logger) error {
	probeState := "off"
	if prober != nil {
		probeState = fmt.Sprintf("on (port %d, timeout %s, max %d hosts/cert)",
			cfg.Probe.Port, cfg.Probe.TimeoutDur,
			cfg.Probe.MaxHostsPerCertOr(config.DefaultMaxHostsPerCert))
	}

	// Build the two components that READ CREDENTIALS even though nothing is issued or deployed.
	//
	// This is what makes the line below true, and it used to be false in the direction that
	// costs the most: internal/config deliberately leaves the validation of static Tencent
	// credentials to deploy.NewCredentialSource, so a config with credentialMode=static and no
	// secretId/secretKey sailed through `-dry-run` with "all fine" and exit 0 -- and then failed
	// on the first real pass, after a production ACME account had been registered and a whole
	// interval had gone by. The dry run documented in README.md is the step an operator runs
	// BEFORE installing the units; "the credentials are usable" is exactly the question it is
	// asked, and install.sh runs it as its verification step.
	//
	// It costs no API call: the DNS provider and the CLB client are constructed, credentials are
	// read and validated from config or environment, and for the CVM instance role the fetch
	// stays deferred to first use.
	if err := buildCredentialBearingComponents(cfg, log); err != nil {
		return fmt.Errorf("dry run: %w", err)
	}

	log.Info("dry run finished: the config, the ACME account, the desired-state source, the DNS "+
		"provider and the deployer are all fine; nothing was issued or deployed",
		"mode", cfg.DesiredState.Mode,
		"provider", spec.KindOf(provider),
		"certificates", certificateCountField(cfg),
		"probing", probeState)
	return nil
}

// buildManager wires the ACME manager and the reconciler, including the optional
// failure fallback and the network prober.
func buildManager(
	cfg *config.Config, store *state.Store, core acme.API,
	provider spec.Provider, prober *probe.Runner, log *slog.Logger,
) (*reconcile.Reconciler, reconcile.Notifier, error) {
	solver, err := acme.NewDNSSolver(cfg.DNS, cfg.Tencent, log)
	if err != nil {
		return nil, nil, err
	}
	log.Info("DNS-01 solver ready", "provider", cfg.DNS.Provider, "ttl", cfg.DNS.TTL)

	deployer, err := newDeployer(cfg, log)
	if err != nil {
		return nil, nil, err
	}

	// Note the shape: a nil interface and an interface holding a nil pointer differ, and
	// stuffing (*webhook.Notifier)(nil) into one defeats the != nil check below.
	var notifier reconcile.Notifier
	if n := webhook.NewNotifier(cfg.Webhook.NotifyURL, cfg.Webhook.NotifySecret, log); n != nil {
		notifier = n
		// The target is logged redacted: a chat/CI notification URL carries its secret in the path
		// (Slack, Feishu, DingTalk) or in the query, and the journal has a wider audience than the
		// daemon's owner. See webhook.RedactNotifyURL.
		log.Info("renewal results will be pushed out", "target", webhook.RedactNotifyURL(cfg.Webhook.NotifyURL),
			"signed", cfg.Webhook.NotifySecret != "")
	}

	manager := acme.NewManager(store, core, solver, deployer, log)

	// Near-expiry degradation: when a few names in a certificate keep failing to issue
	// while it nears expiry, drop them and issue for the rest. Off by default -- it
	// changes what the certificate covers, which is a security call for a human.
	if cfg.Fallback.EnabledOr(false) {
		manager.SetFallbackPolicy(cfg.Fallback)
		log.Warn("the failure fallback is ON: if issuance keeps failing near expiry, wecert will drop " +
			"the names whose authorizations keep failing so the rest stay available; " +
			"the dropped names lose coverage, which is the whole tradeoff, and it is logged at ERROR when it happens")
	}
	reconciler := reconcile.New(cfg, provider, store, manager, notifier, log)

	// Network-side probing: dial a real TLS connection to confirm the served cert is the deployed one.
	reconciler.SetProber(prober)
	logProberConfig(cfg, prober, log)
	return reconciler, notifier, nil
}

func logProberConfig(cfg *config.Config, prober *probe.Runner, log *slog.Logger) {
	if prober == nil {
		log.Warn("network-side certificate probing is off: nothing will verify that the " +
			"certificate the cloud API reports as deployed is the one actually being served")
		return
	}
	cap := cfg.Probe.MaxHostsPerCertOr(config.DefaultMaxHostsPerCert)
	// Reported at startup because it decides what probe_match means: with it on, a listener
	// serving the deployed certificate without its intermediate is a mismatch, which is a
	// change from every earlier version. Someone who turns it off for an internal CA should
	// see that in the log too, next to the rest of the probe configuration.
	requireTrusted := cfg.Probe.RequireTrustedOr(true)
	log.Info("network-side certificate probing is on",
		"port", cfg.Probe.Port, "timeout", cfg.Probe.TimeoutDur,
		"maxHostsPerCert", cap, "requireTrusted", requireTrusted)
	if cap <= 0 {
		// A cap of 0 is "probe nothing", which looks exactly like "probing is on" in every
		// other line this program prints. Say it once at startup, where the config is being
		// reported anyway -- otherwise the silence of the probe series reads as "nothing to
		// report" rather than "nothing was dialled".
		log.Warn("probe.maxHostsPerCert is 0, so nothing will actually be dialled: the probe "+
			"series will report no host at all, and a probe_match alert that compares against "+
			"an absent series stays silent", "maxHostsPerCert", cap)
	}
}

// logEnforceFleet reports the document's certificate count once the reconciler has
// been primed. In enforce mode this is the first point that can state the fleet size.
func logEnforceFleet(cfg *config.Config, reconciler *reconcile.Reconciler, provider spec.Provider, log *slog.Logger) {
	if cfg.DesiredState.Mode != config.ModeEnforce {
		return
	}
	names := reconciler.CertNames()
	log.Info("the desired-state document declares the certificates to manage",
		"certificates", len(names), "path", cfg.DesiredState.Path,
		"provider", spec.KindOf(provider))
	if len(names) == 0 {
		log.Warn("the desired-state document declares no certificates: nothing will be renewed " +
			"while that is true")
	}
}

// startBackupsIfNeeded starts the snapshot loop, or explains why it is not running.
//
// "On by default where it can be useful, off where it cannot" (config.StateBackup) is decided
// here, because this is the first point that knows the directory.
func startBackupsIfNeeded(ctx context.Context, store *state.Store, cfg *config.Config, log *slog.Logger) (
	snapshots *snapshotHealth, stop func(),
) {
	backupDirs := stateBackupDirs(cfg)
	backupDir := backupDirs[0]
	writable := true
	for _, dir := range backupDirs {
		if !dirIsWritable(dir) {
			writable = false
			backupDir = dir
			break
		}
	}
	// The switch and the directory are checked separately. Treating "enabled" as sufficient
	// (EnabledOr returns the explicit setting whenever it is set) made the unwritable case fall
	// into the running branch: the loop started, took a snapshot every interval, failed, and
	// logged an ERROR each time -- while the branch written to say exactly that was unreachable,
	// because its guard was the same condition the first branch had already consumed.
	switch planStateBackups(cfg.StateBackup.Enabled, writable) {
	case backupsRun:
		return startStateBackups(ctx, store, cfg, log)
	case backupsEnabledButUnwritable:
		log.Error("periodic state database snapshots are ENABLED but the directory is not writable, "+
			"so none will be taken", "dir", backupDir)
	default:
		// Two different situations reach this arm, and they have different fixes: the operator wrote
		// stateBackup.enabled: false, or the setting is unset (the documented default) and the
		// directory cannot be written. The message used to assert the first in both cases and carry
		// no attributes at all, so the operator grepped the config for a line that was not there and
		// could not see which directory to fix -- while the sibling arm above prints dir=.
		if cfg.StateBackup.Enabled != nil {
			log.Warn("periodic state database snapshots are DISABLED in the config " +
				"(stateBackup.enabled: false): losing state.db means a new ACME account and re-placed " +
				"orders, and nothing here will be able to restore it")
		} else {
			log.Warn("periodic state database snapshots are OFF because this directory is not "+
				"writable (stateBackup.enabled is unset, and snapshots default to on where they can "+
				"be taken): losing state.db means a new ACME account and re-placed orders, and "+
				"nothing here will be able to restore it",
				"dir", backupDir, "hint", "point stateBackup.dir at a writable path, or make this one writable")
		}
	}
	return nil, nil
}

// stateBackupDirs returns the primary snapshot destination followed by
// independently retained local copies. Future remote backends use this same
// snapshot loop rather than copying the live SQLite file.
func stateBackupDirs(cfg *config.Config) []string {
	primary := cfg.StateBackup.Dir
	if primary == "" {
		primary = filepath.Dir(cfg.StatePath)
	}
	return append([]string{primary}, cfg.StateBackup.LocalDirs...)
}

// runOncePass runs the single convergence pass -once is named for, then drains.
//
// RunDetailed, not a wrapper that drops the report: the one-shot unit is what a systemd
// timer runs, and "exited 0 with every certificate failing" is the failure mode this
// report exists to prevent -- the timer would report success while the fleet went
// unmanaged. A pass that attempted nothing and skipped everything counts as trouble
// too, because that is a desired state that resolved to nothing.
func runOncePass(
	ctx context.Context,
	reconciler *reconcile.Reconciler,
	notifier reconcile.Notifier,
	snapshots *snapshotHealth,
	log *slog.Logger,
) error {
	rep := reconciler.RunDetailed(ctx)
	// That pass has finished, but a webhook-triggered one may be running: the listener is
	// started before this branch, so -once can coexist with an accepted background pass. Both
	// it and the notifications have to be waited for before the deferred store.Close() runs.
	drainBackground(reconciler, log)
	drainNotifier(notifier, log)
	if err := snapshots.wait(snapshotWait); err != nil {
		// The pass's own report comes first when there is one: "it converged but there is no
		// backup" and "it did not converge" are different answers, and onceExit already knows how
		// to word the second.
		if passErr := onceExit(rep); passErr != nil {
			return errors.Join(passErr, fmt.Errorf("and the state snapshot failed: %w", err))
		}
		return fmt.Errorf("the pass converged, but the state database could not be snapshotted, so "+
			"there is no recovery point for it: %w", err)
	}
	return onceExit(rep)
}

// adminAuditPath is the append-only admin audit log beside the state database.
func adminAuditPath(statePath string) string {
	if statePath == "" {
		return ""
	}
	return statePath + ".admin-audit.jsonl"
}

// adminOps wires the guarded /admin surface to the same code paths the CLI uses.
// nil fields simply are not mounted (see webhook.AdminOps).
func adminOps(cfg *config.Config, log *slog.Logger) webhook.AdminOps {
	return webhook.AdminOps{
		BackupHealth: func(ctx context.Context) (any, error) {
			return backupHealth(cfg)
		},
		RecoveryPlan: func(ctx context.Context) (any, error) {
			return recoveryPlan(cfg)
		},
		RecoveryDrill: func(ctx context.Context) (any, error) {
			return recoveryDrill(cfg)
		},
		Restore: func(ctx context.Context, source string) (any, error) {
			return adminRestore(cfg, source, log)
		},
	}
}

// backupHealth is the read-only snapshot posture (local + remote).
func backupHealth(cfg *config.Config) (any, error) {
	out := map[string]any{
		"statePath": cfg.StatePath,
		"enabled":   cfg.StateBackup.Enabled,
		"dir":       cfg.StateBackup.Dir,
	}
	if fi, err := os.Stat(cfg.StatePath); err == nil {
		out["stateAgeSeconds"] = int(time.Since(fi.ModTime()).Seconds())
		out["stateBytes"] = fi.Size()
	}
	notice, err := state.LoadRestoreNotice(cfg.StatePath)
	if err == nil && notice != nil {
		out["lastRestoreAt"] = notice.RestoredAt.UTC().Format(time.RFC3339)
	}
	return out, nil
}

// recoveryPlan is non-destructive: what would `latest` restore.
func recoveryPlan(cfg *config.Config) (any, error) {
	src, cleanup, err := resolveRestoreSnapshot(cfg, "latest")
	if err != nil {
		return nil, err
	}
	defer cleanup()
	info, err := state.InspectSnapshot(src)
	if err != nil {
		return nil, err
	}
	fi, err := os.Stat(src)
	if err != nil {
		return nil, err
	}
	return map[string]any{
		"source":        src,
		"snapshotAge":   time.Since(fi.ModTime()).Round(time.Second).String(),
		"certificates":  info.Certificates,
		"account":       info.Account,
		"liveStatePath": cfg.StatePath,
		"note":          "read-only; POST /admin/recovery-drill to test the snapshot, or /admin/challenge then /admin/restore to apply it (applied on next start if the daemon holds the lock)",
	}, nil
}

// recoveryDrill opens and checks a snapshot without touching live state.
func recoveryDrill(cfg *config.Config) (any, error) {
	src, cleanup, err := resolveRestoreSnapshot(cfg, "latest")
	if err != nil {
		return nil, err
	}
	defer cleanup()
	info, err := state.InspectSnapshot(src)
	if err != nil {
		return nil, err
	}
	fi, err := os.Stat(src)
	if err != nil {
		return nil, err
	}
	return map[string]any{
		"source":       src,
		"snapshotAge":  time.Since(fi.ModTime()).Round(time.Second).String(),
		"certificates": info.Certificates,
		"account":      info.Account,
		"passed":       true,
		"note":         "no live state was changed",
	}, nil
}

// adminRestore applies (or stages) a snapshot. If the daemon holds the state lock --
// which it does -- the snapshot is verified and staged as state.db.restore-pending and
// applied on the next start. That is the only honest response to "restore now" while
// this process has the database open: swapping the file underneath us would leave
// every write going to an unlinked inode.
func adminRestore(cfg *config.Config, source string, log *slog.Logger) (any, error) {
	if err := adminRestoreSourceAllowed(cfg, source); err != nil {
		return nil, err
	}
	src, cleanup, err := resolveRestoreSnapshot(cfg, source)
	if err != nil {
		return nil, err
	}
	defer cleanup()
	pending, err := state.StagePendingRestore(cfg.StatePath, src)
	if err != nil {
		return nil, err
	}
	log.Warn("admin restore staged; it is applied on the next start of wecert",
		"source", src, "pending", pending, "statePath", cfg.StatePath)
	return map[string]any{
		"pending":            true,
		"appliedOnNextStart": true,
		"pendingPath":        pending,
		"source":             src,
		"note":               "the live database is still open in this process; restart wecert to apply. The previous database is kept as state.db.replaced-<stamp> when the pending restore runs.",
	}, nil
}

// adminRestoreSourceAllowed keeps the web restore inside the snapshot directories
// and the configured remote targets. The CLI can restore any path an operator
// types; an HTTP client holding the admin token must not be able to point the
// pending restore at /tmp/evil.db just because the process can read it.
func adminRestoreSourceAllowed(cfg *config.Config, source string) error {
	if source == "latest" {
		return nil
	}
	if strings.HasPrefix(source, "remote:") {
		name := strings.TrimPrefix(source, "remote:")
		for _, t := range cfg.StateBackup.RemoteTargets {
			if t.Name == name {
				return nil
			}
		}
		return fmt.Errorf("remote target %q is not in stateBackup.remoteTargets", name)
	}
	dir := cfg.StateBackup.Dir
	if dir == "" {
		dir = filepath.Dir(cfg.StatePath)
	}
	allowed := map[string]bool{}
	for _, d := range []string{dir, filepath.Dir(cfg.StatePath)} {
		if d == "" {
			continue
		}
		if abs, err := filepath.Abs(d); err == nil {
			allowed[abs] = true
		}
	}
	for _, t := range cfg.StateBackup.LocalDirs {
		if abs, err := filepath.Abs(t); err == nil {
			allowed[abs] = true
		}
	}
	if fi, err := os.Stat(source); err == nil && fi.IsDir() {
		if abs, err := filepath.Abs(source); err == nil && allowed[abs] {
			return nil
		}
	}
	abs, err := filepath.Abs(source)
	if err != nil {
		return err
	}
	parent := filepath.Dir(abs)
	if !allowed[parent] {
		return fmt.Errorf("admin restore source %s is outside the snapshot directories; "+
			"use latest, a file under stateBackup.dir, or remote:<name>", source)
	}
	return nil
}
