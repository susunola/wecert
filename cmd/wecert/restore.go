package main

import (
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"github.com/susunola/wecert/internal/config"
	"github.com/susunola/wecert/internal/state"
)

// runRestore implements -restore: put a snapshot back in place, as one command.
//
// Why this is a command rather than a paragraph in docs/recovery.md: the paragraph had five steps
// (stop the daemon, find the newest snapshot, move state.db aside, copy, chown), and the one that
// carries the real risk is not in it at all -- a snapshot's rate-limit ledger stops at the moment it
// was written, so the daemon that starts afterwards believes it has spent nothing since. The next
// order may then be refused by the CA, which is exactly the "why is my renewal failing" question
// nobody can answer from the logs. Restoring through this command leaves a record behind, and the
// next start warns from it (see logRestoreNotice).
func runRestore(configPath, statePathOverride, arg string) error {
	cfg, err := config.Load(configPath)
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}
	if statePathOverride != "" {
		cfg.StatePath = statePathOverride
	}
	return restoreState(cfg, arg)
}

// restoreState is runRestore with the config already in hand, so the whole path -- including which
// snapshot "latest" resolves to and what the operator is told -- is testable without a YAML file.
func restoreState(cfg *config.Config, arg string) error {
	source, err := resolveSnapshot(cfg, arg)
	if err != nil {
		return err
	}

	res, err := state.Restore(cfg.StatePath, source)
	if err != nil {
		return err
	}

	fmt.Printf("Restored %s over %s.\n", res.Source, res.Dest)
	if res.Dest != cfg.StatePath {
		fmt.Printf("  (%s is a symlink; the bytes went to its target, and the link is untouched.)\n",
			cfg.StatePath)
	}
	fmt.Printf("  The snapshot holds %s and %d certificate(s); its data is from %s.\n",
		accountPhrase(res.Account), res.Certificates, res.SourceWrittenAt.Local().Format(time.RFC3339))
	if res.Replaced != "" {
		fmt.Printf("  The database it replaced (written %s) is kept at %s.\n",
			res.ReplacedWrittenAt.Local().Format(time.RFC3339), res.Replaced)
	}
	fmt.Printf("  The rate-limit ledger in the snapshot stops at that date: any order placed after it\n"+
		"  is still counted by the CA but not here. Until %s the CA may refuse an\n"+
		"  order it believes is over quota -- wecert records that refusal and backs off, so the\n"+
		"  certificate is not lost, it is late.\n",
		res.RestoredAt.Add(state.RestoreCaveatWindow).Local().Format(time.RFC3339))
	fmt.Printf("Start wecert again when you are ready.\n")
	return nil
}

func accountPhrase(hasAccount bool) string {
	if hasAccount {
		return "an ACME account"
	}
	return "no ACME account (the next start registers one, and they are limited per IP)"
}

// resolveSnapshot turns the -restore argument into a file.
//
// Three forms, because the operator's situation decides which one they can type: a file (they were
// handed one), a directory (they know where snapshots live but not which is newest), and "latest"
// (they know neither -- the common case during an incident, and the one where reading
// stateBackup.dir out of the config by hand is the last thing anyone wants to do).
func resolveSnapshot(cfg *config.Config, arg string) (string, error) {
	dir := cfg.StateBackup.Dir
	if dir == "" {
		dir = filepath.Dir(cfg.StatePath)
	}

	if arg == "latest" {
		return newestSnapshot(dir, cfg.StatePath)
	}

	fi, err := os.Lstat(arg)
	if err != nil {
		return "", fmt.Errorf("restore: read %s: %w", arg, err)
	}
	if fi.IsDir() {
		return newestSnapshot(arg, cfg.StatePath)
	}
	return arg, nil
}

// newestSnapshot picks the newest snapshot of this state database in dir.
//
// "Newest" is by the timestamp in the NAME, which is the same order retention uses and the same
// caveat applies to it: after a backward clock step a newer file can carry an older name. That is
// why this is not silent about its choice -- the caller prints which snapshot it used and how old
// its data is, and an operator who disagrees can name the file explicitly.
func newestSnapshot(dir, statePath string) (string, error) {
	snaps, err := state.SnapshotsIn(dir, statePath)
	if err != nil {
		// A directory that does not exist is the same answer as one with no snapshots, and the
		// operator needs the sentence below rather than an open(2) error: `-restore latest` on a host
		// where stateBackup never ran is an ordinary situation during a recovery. Verified in the
		// round-11 restore drill, which printed "open /tmp/drill/snapshots: no such file or directory".
		if !os.IsNotExist(err) {
			return "", fmt.Errorf("restore: list the snapshots in %s: %w", dir, err)
		}
	}
	if len(snaps) == 0 {
		return "", fmt.Errorf("restore: there are no snapshots of %s in %s (the directory "+
			"stateBackup.dir points at, or the one holding state.db). Is stateBackup enabled? "+
			"Nothing was changed", filepath.Base(statePath), dir)
	}
	return snaps[len(snaps)-1], nil
}

// logRestoreNotice tells the operator what a previous restore did to the rate-limit accounting.
//
// It is the one consequence of restoring a snapshot that no other signal carries: the CA's counts
// are its own, the local ones are visibly low, and the refusal that follows looks like an ordinary
// quota problem days after the restore that caused it. The warning is time-bounded by the longest
// window we account for (see state.RestoreCaveatWindow), because after that every bucket that could
// have been under-counted has refilled and the ledger is whole again.
func logRestoreNotice(log *slog.Logger, statePath string, now time.Time) {
	notice, err := state.LoadRestoreNotice(statePath)
	if err != nil {
		log.Warn("this state database has a restore record that cannot be read, so whether its "+
			"rate-limit ledger is short cannot be told", "err", err)
		return
	}
	if notice == nil {
		return
	}
	if !notice.CaveatApplies(now) {
		log.Debug("a restore of this state database is now older than longest rate-limit window; "+
			"the ledger is whole again", "restoredAt", notice.RestoredAt)
		return
	}
	log.Warn("this state database was restored from a snapshot, so its rate-limit accounting is "+
		"short by every order placed after the snapshot was written",
		"restoredAt", notice.RestoredAt,
		"source", notice.Source,
		"dataFrom", notice.SourceWrittenAt,
		"caveatUntil", notice.RestoredAt.Add(state.RestoreCaveatWindow),
		"whatToExpect", "the CA may refuse one order it believes is over quota; wecert records the "+
			"refusal and backs off, and wecert_ratelimit_remaining_tokens overstates what is left "+
			"until the window above passes")
}

// errRestoreConflict is what a second mode flag next to -restore produces. It wraps errUsage, so the
// process exits 64 ("the command line is wrong") rather than 1 ("the program ran and failed").
var errRestoreConflict = fmt.Errorf("%w: -restore replaces the state database and then exits, so it "+
	"cannot be combined with -once, -dry-run or -revoke", errUsage)
