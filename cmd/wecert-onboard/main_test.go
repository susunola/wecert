package main

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/susunola/wecert/internal/state"
)

// writeConfig writes the smallest config Load accepts: enforce mode (so no
// certificates block is needed) with dummy static credentials. TencentSources only
// constructs API clients, so with these nothing leaves the process before the lock
// check the tests exercise.
func writeConfig(t *testing.T, dir string) (cfgPath, out string) {
	t.Helper()

	out = filepath.Join(dir, "desired-state.yaml")
	cfgPath = filepath.Join(dir, "config.yaml")
	cfg := `
statePath: ` + filepath.Join(dir, "state.db") + `
acme:
  directory: https://acme-staging-v02.api.letsencrypt.org/directory
  email: ops@example.com
dns:
  provider: tencentcloud
tencent:
  credentialMode: static
  secretId: dummy-id
  secretKey: dummy-key
  regions: [ap-guangzhou]
desiredState:
  mode: enforce
  path: ` + out + `
`
	if err := os.WriteFile(cfgPath, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	return cfgPath, out
}

func withArgs(t *testing.T, args ...string) {
	t.Helper()
	old := os.Args
	os.Args = append([]string{"wecert-onboard"}, args...)
	t.Cleanup(func() { os.Args = old })
}

// Two overlapping cron runs must never load the same baseline and last-writer-wins
// each other's state save (losing Changes entries, regressing AbsentSince). The
// second run has to fail fast on the lock, not queue up behind the first.
func TestRunFailsFastWhenTheStateIsLocked(t *testing.T) {
	cfgPath, out := writeConfig(t, t.TempDir())

	// Simulate the previous run still holding the state file's lock.
	unlock, err := state.LockFile(out + ".state.json.lock")
	if err != nil {
		t.Fatalf("taking the lock failed: %v", err)
	}
	defer func() { _ = unlock() }()

	withArgs(t, "-config", cfgPath)
	code, err := run()
	if !errors.Is(err, state.ErrLocked) {
		t.Fatalf("a held lock must fail the run with ErrLocked, got (%d, %v)", code, err)
	}
	if code != exitError {
		t.Errorf("the exit code must be a plain error, got %d", code)
	}
}

// Once the previous run's lock is gone, the same invocation must get past the lock
// check -- it fails later (the dummy credentials cannot really enumerate DNS), but
// never with ErrLocked.
func TestRunProceedsAfterTheLockIsReleased(t *testing.T) {
	cfgPath, out := writeConfig(t, t.TempDir())

	unlock, err := state.LockFile(out + ".state.json.lock")
	if err != nil {
		t.Fatalf("taking the lock failed: %v", err)
	}
	if err := unlock(); err != nil {
		t.Fatalf("releasing the lock failed: %v", err)
	}

	withArgs(t, "-config", cfgPath)
	_, err = run()
	if errors.Is(err, state.ErrLocked) {
		t.Fatalf("a released lock must not block the run, got %v", err)
	}
}
