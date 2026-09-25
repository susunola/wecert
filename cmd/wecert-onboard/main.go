// Command wecert-onboard turns the _wecert declarations in DNS into a desired-state document.
//
// It is the "infer" half of this system; wecert is the "act" half. They talk only through
// the document, so this half can be rewritten, replaced or thrown away without affecting issuance.
//
// The easiest way to use it:
//
//	wecert-onboard -config /etc/wecert/config.yaml
//
// The first time you wire it in, add -dry-run: it prints what would be added and removed
// under the computed document, writing nothing at all. Look it over before it lands on disk.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/susunola/wecert/internal/atomicfile"
	"github.com/susunola/wecert/internal/config"
	"github.com/susunola/wecert/internal/onboarding"
	"github.com/susunola/wecert/internal/ratelimit"
	"github.com/susunola/wecert/internal/spec"
	"github.com/susunola/wecert/internal/state"
)

// version can be injected through -ldflags "-X main.version=...".
var version = "dev"

func main() {
	code, err := run()
	if err != nil {
		fmt.Fprintf(os.Stderr, "wecert-onboard: %v\n", err)
		if code == 0 {
			code = 1
		}
	}
	os.Exit(code)
}

// Exit codes. The freeze case uses 2 rather than 1 so monitoring can tell "this round
// deliberately froze" (a human should look) from "the program itself crashed" (a bug to fix).
const (
	exitOK = 0
	// exitUsage is the conventional "the command line itself is wrong" code, and it is what
	// wecert-probe and wecert-preflight already use. A missing -config or a bad flag used to exit 1,
	// which every document in this repository defines as "the program ran and failed" -- so a typo
	// in a systemd ExecStart looked exactly like a failed round.
	exitUsage  = 64
	exitError  = 1
	exitFrozen = 2
)

func run() (int, error) {
	fs := flag.NewFlagSet("wecert-onboard", flag.ContinueOnError)
	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), `wecert-onboard %s

Turn the _wecert TXT declarations in DNS into a desired-state document.

Usage:
  wecert-onboard -config /etc/wecert/config.yaml [-dry-run]

The config file is the same one wecert reads; the "onboarding" section holds
the policy (zones, guards, grace period, budget). Every flag below overrides
the corresponding config value.

Flags:
`, version)
		fs.PrintDefaults()
	}

	var (
		configPath = fs.String("config", "", "path to the wecert config file (required)")
		outPath    = fs.String("out", "", "desired-state document path (default: desiredState.path from the config)")
		statePath  = fs.String("state", "", "onboarding state path (default: <out>.state.json)")
		reportPath = fs.String("report", "", "decision report path (default: <out>.report.json)")
		noReport   = fs.Bool("no-report", false, "do not write the decision report")

		zones      = fs.String("zones", "", "comma-separated DNS zones to enumerate (default: every zone the credentials can see)")
		requireCLB = fs.Bool("require-clb", true, "a declaration only counts when a CLB rule serves the name (guard 1)")
		allow      = fs.String("allow", "", "comma-separated registered domains that may be issued for (default: no restriction)")

		maxNames = fs.Int("max-names", 0, "maximum SAN entries per certificate (default 25)")
		profile  = fs.String("profile", "", "default ACME profile")
		keyType  = fs.String("keytype", "", "default key type")
		deploy   = fs.Bool("deploy", true, "default deploy setting for generated certificates")

		grace        = fs.Duration("grace", 0, "how long a name must be confirmed absent before it is removed (default 24h)")
		budget       = fs.Int("budget", 0, "maximum name-set changes per budget window (default 25)")
		budgetWindow = fs.Duration("budget-window", 0, "the budget window (default 168h)")
		drop         = fs.Float64("drop-threshold", 0, "freeze when the declared name set shrinks by more than this fraction (default 0.30)")

		force   = fs.Bool("force", false, "skip the fuse, the budget, the grace period AND the CLB reference check; only for a change you made on purpose")
		dryRun  = fs.Bool("dry-run", false, "compute everything but write nothing")
		asJSON  = fs.Bool("json", false, "print the report as JSON instead of a human summary")
		quiet   = fs.Bool("quiet", false, "only print the final one-line summary")
		showVer = fs.Bool("version", false, "print the version and exit")
	)

	if err := fs.Parse(os.Args[1:]); err != nil {
		// flag.ContinueOnError has already printed the error and the usage to fs.Output();
		// returning the error here would make main print it a second time.
		// -h is not a usage error: the operator asked for help and got it (tatrun agrees).
		if errors.Is(err, flag.ErrHelp) {
			return exitOK, nil
		}
		return exitUsage, nil
	}
	if *showVer {
		fmt.Println("wecert-onboard", version)
		return exitOK, nil
	}
	if *configPath == "" {
		fs.Usage()
		return exitUsage, errors.New("-config is required")
	}

	// Only flags **explicitly given** override the config. Use fs.Visit, not zero-value
	// comparison: the latter cannot tell "-require-clb=false" from "flag not passed".
	explicit := map[string]bool{}
	fs.Visit(func(f *flag.Flag) { explicit[f.Name] = true })

	cfg, err := config.Load(*configPath)
	if err != nil {
		return exitError, err
	}

	out := firstNonEmpty(*outPath, cfg.DesiredState.Path)
	if out == "" {
		return exitError, errors.New("no output path: set -out, or desiredState.path in the config")
	}
	stateFile := firstNonEmpty(*statePath, cfg.Onboarding.StatePath, out+".state.json")
	report := firstNonEmpty(*reportPath, cfg.Onboarding.ReportPath, out+".report.json")
	if *noReport {
		report = ""
	}

	opts := onboarding.Options{
		DocumentPath: out,
		StatePath:    stateFile,
		ReportPath:   report,
		Generator:    "wecert-onboard/" + version,

		Profile: firstNonEmpty(*profile, cfg.Onboarding.Profile, config.ProfileClassic),
		KeyType: firstNonEmpty(*keyType, cfg.Onboarding.KeyType, config.KeyTypeECDSAP256),
		Deploy:  cfg.Onboarding.DeployOr(true),

		MaxNames:    cfg.Onboarding.MaxNames,
		RequireRule: cfg.Onboarding.RequireCLBRuleOr(true),
		Allowlist:   cfg.Onboarding.Allowlist,

		GracePeriod:              cfg.Onboarding.GraceDur,
		BudgetWindow:             cfg.Onboarding.BudgetDur,
		Budget:                   cfg.Onboarding.Budget,
		DropThreshold:            cfg.Onboarding.DropThreshold,
		BlockedRegisteredDomains: blockedRegisteredDomains(cfg.StatePath, time.Now()),

		Force: *force,
	}

	// Config provides the baseline; explicit flags override it.
	zoneList := applyExplicitFlags(explicit, &opts, flagValues{
		zones: *zones, requireCLB: *requireCLB, allow: *allow,
		maxNames: *maxNames, profile: *profile, keyType: *keyType,
		deploy: *deploy, grace: *grace, budget: *budget,
		budgetWindow: *budgetWindow, drop: *drop,
	}, cfg.Onboarding.Zones)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	src, err := onboarding.TencentSources(cfg.Tencent, zoneList, nil)
	if err != nil {
		return exitError, err
	}

	ob, err := onboarding.New(src, opts, nil)
	if err != nil {
		return exitError, err
	}

	// Two overlapping runs (cron fired again while the previous one was still
	// working) would load the same state baseline and then last-writer-wins each
	// other's save: Changes entries are lost (the budget's accounting) and
	// AbsentSince / LastDeclared regress (the deletion grace clock and the fuse's
	// baseline jump backwards). Hold the same cross-process lock the state store
	// uses for the whole load-compute-write cycle, and fail fast when it is taken
	// -- a second run that queued up would apply its stale baseline the moment the
	// first one exits, which is worse than an outright error.
	//
	// -dry-run is exempt: it writes nothing, so it cannot corrupt the state, and it
	// is exactly what a human runs while the scheduled job is also active.
	var lock *state.FileLock
	if !*dryRun {
		if lock, err = state.AcquireFileLock(stateFile + ".lock"); err != nil {
			return exitError, err
		}
		defer func() { _ = lock.Unlock() }()
	}

	rep, err := ob.Run(ctx)
	if err != nil {
		// A round that fails this early (a corrupt state file, an unreadable previous
		// document) never reaches Commit, so without this the report file simply goes
		// stale -- and the report file is what monitoring watches. Publish a minimal
		// frozen report carrying the failure as its reason, best effort: the exit code
		// and stderr carry the error either way.
		//
		// A dry run is exempt: it promises to write nothing at all, and it holds no lock,
		// so a report written here could race the report of a real run happening
		// concurrently. The non-dry-run call is made while holding the state lock, so it
		// cannot race a peer.
		if !*dryRun {
			writeFailureReport(report, err)
		}
		return exitError, err
	}

	if !*dryRun {
		// flock is bound to the inode, not the name: if the lock file was removed
		// mid-run (the classic "clear the stale lock" habit), the next cron run locks a
		// NEW file and both runs last-writer-wins the same state. That cannot be
		// prevented, only noticed -- so notice it before publishing anything.
		if err := lock.VerifyHeld(); err != nil {
			return exitError, err
		}
		if err := ob.Commit(rep); err != nil {
			return exitError, err
		}
	}

	if *asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(rep); err != nil {
			return exitError, err
		}
	} else {
		printSummary(os.Stdout, rep, out, *dryRun, *quiet)
	}

	if rep.Frozen() {
		return exitFrozen, nil
	}
	return exitOK, nil
}

// blockedRegisteredDomains reads only CA-provided retry deadlines from the
// daemon's state. Missing or unavailable state is intentionally non-fatal: the
// normal onboarding budget remains the safe fallback, while a known deadline
// must prevent publishing a change that would immediately be refused.
func blockedRegisteredDomains(statePath string, now time.Time) map[string]time.Time {
	if statePath == "" {
		return nil
	}
	if _, err := os.Stat(statePath); err != nil {
		return nil
	}
	store, err := state.OpenForTool(statePath)
	if err != nil {
		return nil
	}
	defer store.Close()
	scopes, err := store.ListRateBucketScopes(ratelimit.CertsPerRegisteredDomain.Name)
	if err != nil {
		return nil
	}
	blocked := map[string]time.Time{}
	for _, scope := range scopes {
		bucket, err := store.GetRateBucket(ratelimit.CertsPerRegisteredDomain.Name, scope)
		if err == nil && bucket.ResetAt.After(now) {
			blocked[scope] = bucket.ResetAt
		}
	}
	return blocked
}

// flagValues is the raw CLI values applyExplicitFlags consults.
type flagValues struct {
	zones               string
	requireCLB          bool
	allow               string
	maxNames            int
	profile, keyType    string
	deploy              bool
	grace, budgetWindow time.Duration
	budget              int
	drop                float64
}

// applyExplicitFlags overlays only the flags the operator actually set onto opts.
// fs.Visit, not zero-value comparison: that cannot tell "-require-clb=false" from
// "flag not passed".
func applyExplicitFlags(explicit map[string]bool, opts *onboarding.Options, f flagValues, defaultZones []string) []string {
	zoneList := defaultZones
	if explicit["zones"] {
		zoneList = splitList(f.zones)
	}
	if explicit["require-clb"] {
		opts.RequireRule = f.requireCLB
	}
	if explicit["allow"] {
		opts.Allowlist = splitList(f.allow)
	}
	if explicit["max-names"] {
		opts.MaxNames = f.maxNames
	}
	if explicit["profile"] {
		opts.Profile = f.profile
	}
	if explicit["keytype"] {
		opts.KeyType = f.keyType
	}
	if explicit["deploy"] {
		opts.Deploy = f.deploy
	}
	if explicit["grace"] {
		opts.GracePeriod = f.grace
	}
	if explicit["budget"] {
		opts.Budget = f.budget
	}
	if explicit["budget-window"] {
		opts.BudgetWindow = f.budgetWindow
	}
	if explicit["drop-threshold"] {
		opts.DropThreshold = f.drop
	}
	return zoneList
}

func printSummary(w io.Writer, rep *onboarding.Report, out string, dryRun, quiet bool) {
	if !quiet {
		fmt.Fprintf(w, "generator:       %s\n", rep.Generator)
		fmt.Fprintf(w, "mode:            %s\n", rep.Mode)
		if rep.PreviousRevision != "" {
			fmt.Fprintf(w, "revision:        %s -> %s\n", rep.PreviousRevision, rep.Revision)
		} else {
			fmt.Fprintf(w, "revision:        %s\n", rep.Revision)
		}
		fmt.Fprintf(w, "declared names:  %d\n", rep.Declared)
		fmt.Fprintf(w, "included names:  %d\n", rep.Included)
		fmt.Fprintf(w, "  covered by a declared wildcard: %d (these cost no extra issuance)\n", rep.CoveredByWildcard)
		fmt.Fprintf(w, "  carried forward from the previous revision: %d\n", rep.CarriedForward)
		fmt.Fprintf(w, "certificates:    %d\n", rep.Certificates)
		if rep.GuardIncomplete {
			fmt.Fprintf(w, "guard 1 (CLB rules): INCOMPLETE this round (the API reported more objects "+
				"than it returned), so no name was removed\n")
		} else if rep.GuardUnavailable {
			fmt.Fprintf(w, "guard 1 (CLB rules): UNAVAILABLE this round, so no name was removed\n")
		}
		fmt.Fprintln(w)
		printDecisions(w, rep.Decisions)
		fmt.Fprintln(w)
	}

	switch {
	case rep.Frozen():
		fmt.Fprintf(w, "FROZEN: the previous desired state is untouched\n")
		for _, r := range rep.FreezeReasons {
			fmt.Fprintf(w, "  - %s\n", r)
		}
		if dryRun {
			fmt.Fprintf(w, "(dry run: nothing would have been written anyway)\n")
		}
	case dryRun:
		fmt.Fprintf(w, "dry run: %s would have been written (revision %s)\n", out, rep.Revision)
	default:
		fmt.Fprintf(w, "wrote %s (revision %s)\n", out, rep.Revision)
	}
}

// printDecisions puts the exclusions first.
//
// "Why was it not included" is the number one question for a system like this, and
// burying it behind hundreds of success lines is as good as no observability at all.
func printDecisions(w io.Writer, ds []spec.Decision) {
	var excluded, included []spec.Decision
	for _, d := range ds {
		if d.Included {
			included = append(included, d)
		} else {
			excluded = append(excluded, d)
		}
	}

	if len(excluded) > 0 {
		fmt.Fprintf(w, "not included (%d):\n", len(excluded))
		for _, d := range excluded {
			fmt.Fprintf(w, "  %-45s %s\n", d.Hostname, d.Reason)
		}
	}
	if len(included) > 0 {
		fmt.Fprintf(w, "included (%d):\n", len(included))
		for _, d := range included {
			fmt.Fprintf(w, "  %-45s -> %-20s %s\n", d.Hostname, d.Certificate, d.Reason)
		}
	}
}

// writeFailureReport publishes a minimal frozen report for a round that failed before it
// could produce one.
//
// Commit's contract is "the report exists exactly when the round completed", and this does
// not break it: the report here says mode "frozen" with the failure as its reason, which is
// the truth -- nothing moved. What it fixes is the failure's visibility: monitoring watches
// the report file, and a round that dies on a corrupt state file or an unreadable document
// otherwise shows up only as the file going stale.
//
// Best effort on purpose: the exit code and stderr already carry the error, so a report
// that cannot be written (the same broken directory usually holds it) is only warned about.
//
// Callers: only a real (non-dry-run) round, while holding the state lock. A dry run must not
// call this -- it promises to write nothing, and without the lock its write could race a
// concurrent real run's report.
func writeFailureReport(path string, cause error) {
	if path == "" {
		return
	}
	rep := onboarding.Report{
		GeneratedAt:   time.Now(),
		Generator:     "wecert-onboard/" + version,
		Mode:          onboarding.ModeFrozen,
		FreezeReasons: []string{cause.Error()},
	}
	data, err := json.MarshalIndent(rep, "", "  ")
	if err != nil {
		return
	}
	if err := atomicfile.Write(path, append(data, '\n'), 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "wecert-onboard: could not write the failure report %s: %v\n", path, err)
	}
}

func splitList(s string) []string {
	parts := strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == ' ' || r == '\t' })
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	sort.Strings(out)
	return out
}

func firstNonEmpty(vs ...string) string {
	for _, v := range vs {
		if v != "" {
			return v
		}
	}
	return ""
}
