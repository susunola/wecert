package main

import (
	"errors"
	"flag"
	"fmt"
	"time"

	"github.com/susunola/wecert/internal/config"
)

const (
	// exitUsage: the command line itself is wrong (see main).
	exitUsage = 64

	// snapshotWait bounds how long a one-shot run waits for the immediate snapshot before judging it
	// (see snapshotHealth.wait).
	snapshotWait = 60 * time.Second
)

// errUsage marks a command-line error, so main can pick the exit code. Returned bare it means
// the flag package already printed the cause; wrapped in another error it only sets the
// classification, and main prints the wrapper's message before exiting.
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
	backupDrill string
	revokeWhy   string
	yesFlag     bool
	// acceptPlaintextBackups is the CLI half of stateBackup.allowUnencryptedRemote.
	acceptPlaintextBackups bool
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
	fs.StringVar(&f.backupDrill, "backup-drill", "", "download/open/check a backup without changing state: latest, a path, or remote:<target>")
	fs.StringVar(&f.revokeWhy, "revoke-reason", "unspecified",
		"revocation reason: unspecified|keyCompromise|affiliationChanged|superseded|cessationOfOperation")
	fs.BoolVar(&f.yesFlag, "yes", false, "with -revoke or -restore: skip the interactive confirmation")
	fs.BoolVar(&f.acceptPlaintextBackups, "accept-plaintext-backups", false,
		"allow stateBackup.remoteTargets while stateEncryption.keyFile is unset (snapshots leave the host with private keys in the clear)")
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
