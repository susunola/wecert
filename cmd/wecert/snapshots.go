package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/susunola/wecert/internal/backup"
	"github.com/susunola/wecert/internal/config"
	"github.com/susunola/wecert/internal/metrics"
	"github.com/susunola/wecert/internal/state"
)

func startStateBackups(ctx context.Context, store *state.Store, cfg *config.Config, log *slog.Logger) (*snapshotHealth, func()) {
	dirs := stateBackupDirs(cfg)
	configuredAt := float64(time.Now().Unix())
	for _, target := range cfg.StateBackup.RemoteTargets {
		metrics.BackupRemoteLastSuccess.WithLabelValues(target.Name, target.Type).Set(0)
		metrics.BackupRemoteConfiguredAt.WithLabelValues(target.Name, target.Type).Set(configuredAt)
		metrics.BackupRemoteInterval.WithLabelValues(target.Name, target.Type).Set(cfg.StateBackup.IntervalDur.Seconds())
	}

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
			hmacKey, herr := hmacKeyFrom(target.HMACKeyFile)
			if herr != nil {
				// A configured signing key that cannot be loaded must not fall back
				// to an unsigned upload: the operator would believe the bucket is
				// signed while every object in it is not.
				log.Error("remote state snapshot skipped: HMAC key file is not usable",
					"target", target.Name, "err", herr)
				errs = append(errs, fmt.Errorf("remote target %s hmac: %w", target.Name, herr))
				continue
			}
			remoteTarget := backup.Target{HMACKey: hmacKey, Type: target.Type, Name: target.Name, Bucket: target.Bucket, Prefix: target.Prefix, Endpoint: target.Endpoint, Region: target.Region, Host: target.Host, Username: target.Username, RemoteDir: target.RemoteDir, PasswordEnv: target.PasswordEnv, PrivateKeyFile: target.PrivateKeyFile, PrivateKeyPassphraseEnv: target.PrivateKeyPassphraseEnv, KnownHostsFile: target.KnownHostsFile, SecretIDEnv: target.SecretIDEnv, SecretKeyEnv: target.SecretKeyEnv, Keep: target.Keep, Timeout: target.TimeoutDur}
			err := backup.Upload(ctx, remoteTarget, uploaded)
			// A retention prune failure is not an upload failure: the object is on the
			// remote and must still be verified. Reporting a red backup here lied about
			// the recovery posture (see backup.IsUploaded).
			if err != nil && !backup.IsUploaded(err) {
				log.Error("remote state snapshot upload failed", "target", target.Name, "type", target.Type, "err", err)
				metrics.BackupRemoteErrors.WithLabelValues(target.Name, target.Type).Inc()
				errs = append(errs, fmt.Errorf("remote target %s: %w", target.Name, err))
				continue
			}
			if err != nil {
				log.Warn("remote state snapshot uploaded but retention prune failed",
					"target", target.Name, "type", target.Type, "err", err)
				errs = append(errs, fmt.Errorf("remote target %s prune: %w", target.Name, err))
			}
			if err := backup.VerifyUpload(ctx, remoteTarget, uploaded); err != nil {
				log.Error("remote state snapshot verification failed", "target", target.Name, "type", target.Type, "err", err)
				metrics.BackupRemoteErrors.WithLabelValues(target.Name, target.Type).Inc()
				errs = append(errs, fmt.Errorf("remote target %s verification: %w", target.Name, err))
			} else {
				log.Info("state snapshot uploaded and verified", "target", target.Name, "type", target.Type, "path", uploaded)
				metrics.BackupRemoteLastSuccess.WithLabelValues(target.Name, target.Type).Set(float64(time.Now().Unix()))
			}
		}
	}
	return errors.Join(errs...)
}
