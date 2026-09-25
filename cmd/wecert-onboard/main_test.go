package main

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/susunola/wecert/internal/onboarding"
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
	lock, err := state.AcquireFileLock(out + ".state.json.lock")
	if err != nil {
		t.Fatalf("taking the lock failed: %v", err)
	}
	defer func() { _ = lock.Unlock() }()

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

	lock, err := state.AcquireFileLock(out + ".state.json.lock")
	if err != nil {
		t.Fatalf("taking the lock failed: %v", err)
	}
	if err := lock.Unlock(); err != nil {
		t.Fatalf("releasing the lock failed: %v", err)
	}

	withArgs(t, "-config", cfgPath)
	_, err = run()
	if errors.Is(err, state.ErrLocked) {
		t.Fatalf("a released lock must not block the run, got %v", err)
	}
}

// A bad flag is already reported by the flag package itself (ContinueOnError prints the
// error and the usage); run must not hand the same error back to main for a second print.
func TestFlagErrorIsReportedOnce(t *testing.T) {
	withArgs(t, "-no-such-flag")
	code, err := run()
	if err != nil {
		t.Errorf("the flag package already printed the error; run must not return it again, got %v", err)
	}
	if code != exitUsage {
		t.Errorf("a command-line mistake is a usage error, got exit code %d", code)
	}
}

// A negative policy value passed explicitly is a typo, not "unset": the config layer rejects
// the same values, and silently substituting the default would leave the operator believing
// the guard was tuned when it was not. New is the chokepoint that sees both paths.
func TestExplicitNegativePolicyFlagIsRejected(t *testing.T) {
	cfgPath, _ := writeConfig(t, t.TempDir())

	withArgs(t, "-config", cfgPath, "-budget=-1")
	code, err := run()
	if err == nil {
		t.Fatal("an explicitly negative budget must fail, not fall back to the default")
	}
	if !strings.Contains(err.Error(), "Budget") {
		t.Errorf("the error must name the knob, got %v", err)
	}
	if code != exitError {
		t.Errorf("a rejected policy value is a plain error, got exit code %d", code)
	}
}

// A round that fails before producing a report (here: a corrupt state file) must still
// publish one: monitoring watches the report file, and "no new report" only ever shows up
// as staleness. The report says frozen and carries the failure as its reason.
func TestRunFailureStillWritesAReport(t *testing.T) {
	cfgPath, out := writeConfig(t, t.TempDir())

	// A state file that cannot be parsed must fail the round outright -- LoadState refuses
	// to read it as empty state.
	if err := os.WriteFile(out+".state.json", []byte(`{"absentSince": {`), 0o600); err != nil {
		t.Fatal(err)
	}

	withArgs(t, "-config", cfgPath)
	code, err := run()
	if err == nil {
		t.Fatal("a corrupt state file must fail the run")
	}
	if code != exitError {
		t.Errorf("a failed round is a plain error, got exit code %d", code)
	}

	data, err := os.ReadFile(out + ".report.json")
	if err != nil {
		t.Fatalf("a failed round must still leave a report for monitoring: %v", err)
	}
	var rep onboarding.Report
	if err := json.Unmarshal(data, &rep); err != nil {
		t.Fatalf("the failure report must parse: %v", err)
	}
	if rep.Mode != onboarding.ModeFrozen {
		t.Errorf("the failure report must say frozen (nothing moved), got mode %q", rep.Mode)
	}
	if len(rep.FreezeReasons) == 0 {
		t.Error("the failure report must carry the cause as its freeze reason")
	}
}

// Asking for help is not a wrong command line: -h must exit 0, not 64. The flag package has
// already printed the usage; classifying it as a usage error made `wecert-onboard -h` look like
// a typo to anything watching the exit code (tatrun already treats it as success).
func TestHelpIsNotAnError(t *testing.T) {
	withArgs(t, "-h")
	code, err := run()
	if err != nil {
		t.Errorf("-h must not produce an error, got %v", err)
	}
	if code != exitOK {
		t.Errorf("-h must exit %d, got %d", exitOK, code)
	}
}

// A failing DRY run must not write the report: -dry-run promises to write nothing at all, and
// it holds no lock, so a report written here could race the report of a real run happening
// concurrently -- each overwriting the file the other just published.
func TestDryRunFailureWritesNoReport(t *testing.T) {
	cfgPath, out := writeConfig(t, t.TempDir())

	// Same failure shape as the real-run case above: a state file that cannot be parsed.
	if err := os.WriteFile(out+".state.json", []byte(`{"absentSince": {`), 0o600); err != nil {
		t.Fatal(err)
	}

	withArgs(t, "-config", cfgPath, "-dry-run")
	code, err := run()
	if err == nil {
		t.Fatal("a corrupt state file must fail the dry run")
	}
	if code != exitError {
		t.Errorf("a failed round is a plain error, got exit code %d", code)
	}
	if _, statErr := os.Stat(out + ".report.json"); !os.IsNotExist(statErr) {
		t.Errorf("a dry run must not write the report file (stat err %v)", statErr)
	}
}
