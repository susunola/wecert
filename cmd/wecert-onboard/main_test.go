package main

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/susunola/wecert/internal/state"
)

// splitList parses the comma- or space-separated flag values (-zones, -allow). Sorted output is
// deliberate: an unsorted allowlist makes Onboarding's binary search miss entries, which silently
// drops names from certificates.
func TestSplitListParsesSortsAndDropsBlanks(t *testing.T) {
	got := splitList(" b.example.com, a.example.com ,, \t , c.example.com ")
	want := []string{"a.example.com", "b.example.com", "c.example.com"}
	if len(got) != len(want) {
		t.Fatalf("splitList = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("splitList = %v, want %v (sorted)", got, want)
		}
	}
	// Whitespace alone separates too, since both are documented as accepted.
	if got := splitList("x.example.com y.example.com"); len(got) != 2 {
		t.Errorf("space-separated values must parse, got %v", got)
	}
	if got := splitList(""); len(got) != 0 {
		t.Errorf("splitList(\"\") = %v, want empty", got)
	}
}

// firstNonEmpty is what makes "flag beats config beats default" work for the enum options.
func TestFirstNonEmptyPrefersTheFirstSetValue(t *testing.T) {
	if got := firstNonEmpty("", "config", "default"); got != "config" {
		t.Errorf("got %q, want config", got)
	}
	if got := firstNonEmpty("flag", "config", "default"); got != "flag" {
		t.Errorf("got %q, want the flag to win", got)
	}
	if got := firstNonEmpty("", "", "default"); got != "default" {
		t.Errorf("got %q, want the default", got)
	}
	if got := firstNonEmpty("", ""); got != "" {
		t.Errorf("got %q, want empty", got)
	}
}

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
  email: ops@atomwangnus.com
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
