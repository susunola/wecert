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
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/susunola/wecert/internal/acme"
	"github.com/susunola/wecert/internal/config"
	"github.com/susunola/wecert/internal/deploy"
	"github.com/susunola/wecert/internal/probe"
	"github.com/susunola/wecert/internal/reconcile"
	"github.com/susunola/wecert/internal/spec"
	"github.com/susunola/wecert/internal/state"
	"github.com/susunola/wecert/internal/webhook"
)

// version can be injected through -ldflags "-X main.version=...".
var version = "dev"

func main() {
	if err := run(); err != nil {
		slog.Error("wecert exited with an error", "err", err)
		os.Exit(1)
	}
}

func run() error {
	var (
		configPath = flag.String("config", "config.yaml", "path to the configuration file")
		statePath  = flag.String("state", "", "override statePath from the config (handy for tests or running multiple instances)")
		once       = flag.Bool("once", false, "run one pass and exit (for a systemd timer / cron)")
		interval   = flag.Duration("interval", time.Hour, "reconcile interval in daemon mode")
		logLevel   = flag.String("log-level", "info", "log level: debug|info|warn|error")
		dryRun     = flag.Bool("dry-run", false, "validate the config and initialise the account only; issue and deploy nothing")
		showVer    = flag.Bool("version", false, "print the version and exit")
		revokeCert = flag.String("revoke", "", "ask the CA to revoke this certificate and exit (see also -yes)")
		revokeWhy  = flag.String("revoke-reason", "unspecified",
			"revocation reason: unspecified|keyCompromise|affiliationChanged|superseded|cessationOfOperation")
		yesFlag = flag.Bool("yes", false, "with -revoke: skip the interactive confirmation")
	)
	flag.Parse()

	if *showVer {
		fmt.Println("wecert", version)
		return nil
	}

	if *revokeCert != "" {
		return runRevoke(*configPath, *statePath, *revokeCert, *revokeWhy, *yesFlag)
	}

	log := newLogger(*logLevel)

	// Let the ACME User-Agent name the running build, so a CA-side log lines up with the
	// binary that sent the request.
	acme.SetUserAgentVersion(version)

	cfg, err := config.Load(*configPath)
	if err != nil {
		return err
	}
	if *statePath != "" {
		cfg.StatePath = *statePath
	}

	// Take the cross-process exclusive lock on the state store. "At most one in-flight
	// order per certificate" used to hold only inside a single process, but running the
	// daemon and the timer at once means concurrent orders -- and what you hit is the
	// 7-day, unrecoverable exact-set limit.
	//
	// -dry-run is exempt: it almost always runs while the daemon is already running, and
	// "cannot even validate the config because the daemon is up" pushes people into
	// blindly editing the config. This path only reads the existing ACME account; no issuance.
	openStore := state.Open
	if *dryRun {
		// Prefers the lock and falls back when the daemon holds it: see state.OpenForTool. Opening
		// unlocked unconditionally is what made `-dry-run` fail on a fresh installation.
		openStore = state.OpenForTool
	}
	store, err := openStore(cfg.StatePath)
	if err != nil {
		return err
	}
	defer store.Close()

	// The first run creates a new ACME account. If it is also the production directory,
	// say this plainly up front: accounts are a finite resource (at most 10 per IP per
	// 3 hours) and should not be recreated over and over.
	firstRun, err := isFirstRun(store, cfg)
	if err != nil {
		return err
	}
	logStartup(log, cfg, firstRun)

	// The desired-state source is constructed before anything touches the network.
	//
	// In enforce mode an unreadable document must blow up at **startup**, not at the
	// first reconcile: allowing "starts up with no desired state" means wecert quietly
	// renews nothing, and nobody finds out until every certificate has expired.
	//
	// Being this early is also what lets -dry-run answer the question that matters: "if I
	// switch to this now, will it start?", without first registering an ACME account.
	provider, err := newProvider(cfg, log)
	if err != nil {
		return err
	}

	// The network-side prober is built here as well: it only reads config and touches no
	// network, and "is probing on at all, and which port does it dial" is one of the first
	// things to confirm when switching configuration.
	//
	// It is the only evidence that does not trust the cloud control plane, so it is on by
	// default -- but it may not fit every deployment: on a box that cannot dial the CLB VIP,
	// probe_errors climbs while probe_match stays flat, so certificates never look broken.
	var prober *probe.Runner
	if cfg.Probe.EnabledOr(true) {
		prober = probe.NewRunner(
			probe.Options{Port: cfg.Probe.Port, Timeout: cfg.Probe.TimeoutDur},
			cfg.Probe.MinValidDur, log)
	}

	httpClient := acme.NewHTTPClient(60 * time.Second)
	core, err := acme.EnsureAccount(cfg, store, httpClient)
	if err != nil {
		return err
	}

	if *dryRun {
		probeState := "off"
		if prober != nil {
			probeState = fmt.Sprintf("on (port %d, timeout %s, max %d hosts/cert)",
				cfg.Probe.Port, cfg.Probe.TimeoutDur, cfg.Probe.MaxHostsPerCert)
		}
		log.Info("dry run finished: the config, the ACME account and the desired-state source are all fine",
			"mode", cfg.DesiredState.Mode,
			"provider", spec.KindOf(provider),
			"certificates", len(cfg.Certificates),
			"probing", probeState)
		return nil
	}

	solver, err := acme.NewDNSSolver(cfg.DNS, cfg.Tencent, log)
	if err != nil {
		return err
	}
	log.Info("DNS-01 solver ready", "provider", cfg.DNS.Provider, "ttl", cfg.DNS.TTL)

	deployer, err := newDeployer(cfg, log)
	if err != nil {
		return err
	}

	// Build the process-level context first: a webhook-triggered reconcile runs in the
	// background for minutes, so it must hang off the process context, not a request's.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// Note the shape: a nil interface and an interface holding a nil pointer differ, and
	// stuffing (*webhook.Notifier)(nil) into one defeats the != nil check below.
	var notifier reconcile.Notifier
	if n := webhook.NewNotifier(cfg.Webhook.NotifyURL, cfg.Webhook.NotifySecret, log); n != nil {
		notifier = n
		log.Info("renewal results will be pushed out", "url", cfg.Webhook.NotifyURL,
			"signed", cfg.Webhook.NotifySecret != "")
	}

	manager := acme.NewManager(store, acme.NewAPI(core), solver, deployer, log)

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
	if prober != nil {
		log.Info("network-side certificate probing is on",
			"port", cfg.Probe.Port, "timeout", cfg.Probe.TimeoutDur,
			"maxHostsPerCert", cfg.Probe.MaxHostsPerCert)
	} else {
		log.Warn("network-side certificate probing is off: nothing will verify that the " +
			"certificate the cloud API reports as deployed is the one actually being served")
	}

	// Evaluate once up front and cache it, so the read-only endpoints (webhook name
	// resolution, diagnostics) answer correctly before the first reconcile finishes
	// rather than returning an empty list -- which reads as "the desired state is empty".
	reconciler.Prime(ctx)

	// Periodic consistent snapshots of state.db. Started here so a snapshot exists before
	// the first renewal window can lose an order: the file holds the ACME account key and
	// every in-flight order URL, and losing an order URL means re-placing it into the
	// exact-set rate limit.
	// "On by default where it can be useful, off where it cannot" (config.StateBackup) is decided
	// here, because this is the first point that knows the directory. EnabledOr's argument used to
	// be a literal true, so a deployment with an unwritable snapshot directory stayed enabled and
	// logged an ERROR every interval forever -- noise that trains the reader to ignore the one line
	// that means the recovery posture is gone.
	backupDir := cfg.StateBackup.Dir
	if backupDir == "" {
		backupDir = filepath.Dir(cfg.StatePath)
	}
	// The switch and the directory are checked separately. Treating "enabled" as sufficient
	// (EnabledOr returns the explicit setting whenever it is set) made the unwritable case fall
	// into the running branch: the loop started, took a snapshot every interval, failed, and
	// logged an ERROR each time -- while the branch written to say exactly that was unreachable,
	// because its guard was the same condition the first branch had already consumed.
	switch planStateBackups(cfg.StateBackup.Enabled, dirIsWritable(backupDir)) {
	case backupsRun:
		startStateBackups(ctx, store, cfg, log)
	case backupsEnabledButUnwritable:
		log.Error("periodic state database snapshots are ENABLED but the directory is not writable, "+
			"so none will be taken", "dir", backupDir)
	default:
		log.Warn("periodic state database snapshots are DISABLED: losing state.db means a new ACME " +
			"account and re-placed orders, and nothing here will be able to restore it")
	}

	// Metrics server. Bind the port synchronously first and exit on failure -- see below.
	if err := startMetricsServer(ctx, cfg.Metrics.Listen, log); err != nil {
		return err
	}

	// Event-trigger endpoint. Same rule: a failed port bind must be a hard failure.
	if err := startWebhookServer(ctx, cfg, reconciler, store, log); err != nil {
		return err
	}

	if *once {
		// RunDetailed, not RunOnce: the one-shot unit is what a systemd timer runs, and
		// "exited 0 with every certificate failing" is the failure mode this report exists to
		// prevent -- the timer would report success while the fleet went unmanaged. A pass that
		// attempted nothing and skipped everything counts as trouble too, because that is a
		// desired state that resolved to nothing.
		rep := reconciler.RunDetailed(ctx)
		// The pass has finished, but the notifications it triggered are delivered on
		// their own goroutines. Returning here would exit with them in flight and lose
		// them -- including the "result":"error" one, which is the notification an
		// operator most needs.
		drainNotifier(notifier, log)
		return onceExit(rep)
	}

	log.Info("entering daemon mode", "interval", *interval)
	runDaemon(ctx, reconciler, *interval, log)
	drainNotifier(notifier, log)
	return nil
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
	return fmt.Errorf("the pass did not converge: attempted=%d succeeded=%d failed=%d skipped=%d "+
		"desiredStateUnreadable=%t", rep.Attempted, rep.Succeeded, rep.Failed, len(rep.Skipped),
		rep.DesiredStateUnreadable)
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

func runDaemon(ctx context.Context, r *reconcile.Reconciler, interval time.Duration, log *slog.Logger) {
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
		r.RunOnce(ctx)
		log.Info("reconcile pass finished", "duration", time.Since(start).Round(time.Millisecond))

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
// startStateBackups snapshots the state database on an interval, in the background.
//
// It never fails the process: a snapshot that cannot be written is a degraded recovery
// posture, not a reason to stop renewing certificates. It is logged at ERROR so it shows
// up in the same place every other operational problem does, and it is reported through
// the same metric channel as everything else.
func startStateBackups(ctx context.Context, store *state.Store, cfg *config.Config, log *slog.Logger) {
	dir := cfg.StateBackup.Dir
	if dir == "" {
		dir = filepath.Dir(cfg.StatePath)
	}

	snapshot := func() {
		path, err := store.Snapshot(dir, cfg.StateBackup.Keep)
		if err != nil {
			// A partial failure still writes the file; say which, so a successful
			// snapshot with a failed prune is not read as "no backup exists".
			log.Error("state database snapshot failed", "dir", dir, "err", err)
			if path != "" {
				log.Info("a snapshot was written despite the error", "path", path)
			}
			return
		}
		log.Info("state database snapshotted", "path", path,
			"interval", cfg.StateBackup.IntervalDur, "keep", cfg.StateBackup.Keep)
	}

	go func() {
		// One immediately: waiting a whole interval means a fresh deployment has no
		// recoverable state for its first day, which is exactly when orders are in flight.
		snapshot()

		ticker := time.NewTicker(cfg.StateBackup.IntervalDur)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				snapshot()
			}
		}
	}()

	log.Info("periodic state database snapshots are on",
		"dir", dir, "interval", cfg.StateBackup.IntervalDur, "keep", cfg.StateBackup.Keep)
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
		return fmt.Errorf("failed to initialise the webhook server: %w", err)
	}

	srv := &http.Server{
		Handler:           api.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      15 * time.Second,
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
		"certificates", len(cfg.Certificates))

	if firstRun {
		log.Warn("no account in the state store; registering a new ACME account")
		if production {
			log.Warn("WARNING: pointed at the Let's Encrypt production environment." +
				"run the whole flow against https://acme-staging-v02.api.letsencrypt.org/directory first," +
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

func newLogger(level string) *slog.Logger {
	var lv slog.Level
	switch strings.ToLower(level) {
	case "debug":
		lv = slog.LevelDebug
	case "warn":
		lv = slog.LevelWarn
	case "error":
		lv = slog.LevelError
	default:
		lv = slog.LevelInfo
	}

	// Without timestamps it reads better under systemd/journald; in a terminal they help.
	handler := slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: lv})
	return slog.New(handler)
}
