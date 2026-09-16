// Command wecert-onboard 把 DNS 里的 _wecert 声明求值成一份期望状态文档。
//
// 它是这套系统里"推断"的那一半，wecert 是"执行"的那一半。两者只通过
// 文档通信，所以这个组件可以随时重写、替换、甚至整个丢掉，而不影响签发。
//
// 最省事的用法：
//
//	wecert-onboard -config /etc/wecert/config.yaml
//
// 第一次接进去时先加 -dry-run：它会把"如果真的按这份文档来，会加什么、
// 会删什么"打出来，但一个字都不写。看清楚了再让它落盘。
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

	"github.com/susunola/wecert/internal/config"
	"github.com/susunola/wecert/internal/onboarding"
	"github.com/susunola/wecert/internal/spec"
)

// version 可通过 -ldflags "-X main.version=..." 注入。
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

// 退出码。冻结用 2 而不是 1，是为了让监控能区分
// "这一轮有意冻结了"（需要人看一眼）和"程序本身跑挂了"（需要修 bug）。
const (
	exitOK     = 0
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

		force   = fs.Bool("force", false, "skip the fuse, the budget and the grace period; only for a change you made on purpose")
		dryRun  = fs.Bool("dry-run", false, "compute everything but write nothing")
		asJSON  = fs.Bool("json", false, "print the report as JSON instead of a human summary")
		quiet   = fs.Bool("quiet", false, "only print the final one-line summary")
		showVer = fs.Bool("version", false, "print the version and exit")
	)

	if err := fs.Parse(os.Args[1:]); err != nil {
		return exitError, err
	}
	if *showVer {
		fmt.Println("wecert-onboard", version)
		return exitOK, nil
	}
	if *configPath == "" {
		fs.Usage()
		return exitError, errors.New("-config is required")
	}

	// 只有**显式给过**的 flag 才覆盖配置。用 fs.Visit 而不是比较零值：
	// 后者会让 "-require-clb=false" 和"没写这个 flag"变得无法区分。
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
	state := firstNonEmpty(*statePath, cfg.Onboarding.StatePath, out+".state.json")
	report := firstNonEmpty(*reportPath, cfg.Onboarding.ReportPath, out+".report.json")
	if *noReport {
		report = ""
	}

	opts := onboarding.Options{
		DocumentPath: out,
		StatePath:    state,
		ReportPath:   report,
		Generator:    "wecert-onboard/" + version,

		Profile: firstNonEmpty(*profile, cfg.Onboarding.Profile, config.ProfileClassic),
		KeyType: firstNonEmpty(*keyType, cfg.Onboarding.KeyType, config.KeyTypeECDSAP256),
		Deploy:  cfg.Onboarding.DeployOr(true),

		MaxNames:    cfg.Onboarding.MaxNames,
		RequireRule: cfg.Onboarding.RequireCLBRuleOr(true),
		Allowlist:   cfg.Onboarding.Allowlist,

		GracePeriod:   cfg.Onboarding.GraceDur,
		BudgetWindow:  cfg.Onboarding.BudgetDur,
		Budget:        cfg.Onboarding.Budget,
		DropThreshold: cfg.Onboarding.DropThreshold,

		Force: *force,
	}

	// 配置打底，显式 flag 覆盖。
	zoneList := cfg.Onboarding.Zones
	if explicit["zones"] {
		zoneList = splitList(*zones)
	}
	if explicit["require-clb"] {
		opts.RequireRule = *requireCLB
	}
	if explicit["allow"] {
		opts.Allowlist = splitList(*allow)
	}
	if explicit["max-names"] {
		opts.MaxNames = *maxNames
	}
	if explicit["profile"] {
		opts.Profile = *profile
	}
	if explicit["keytype"] {
		opts.KeyType = *keyType
	}
	if explicit["deploy"] {
		opts.Deploy = *deploy
	}
	if explicit["grace"] {
		opts.GracePeriod = *grace
	}
	if explicit["budget"] {
		opts.Budget = *budget
	}
	if explicit["budget-window"] {
		opts.BudgetWindow = *budgetWindow
	}
	if explicit["drop-threshold"] {
		opts.DropThreshold = *drop
	}

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

	rep, err := ob.Run(ctx)
	if err != nil {
		return exitError, err
	}

	if !*dryRun {
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
		if rep.GuardUnavailable {
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

// printDecisions 把排除项排在前面。
//
// "为什么没进去"是这类系统的头号问题，把它埋在几百行成功项后面
// 等于没做可观测性。
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
