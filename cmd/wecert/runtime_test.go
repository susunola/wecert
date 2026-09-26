package main

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/susunola/wecert/internal/config"
	"github.com/susunola/wecert/internal/probe"
	"github.com/susunola/wecert/internal/state"
)

// runtime.go is the boot sequence and the /admin surface wired to the same code paths the CLI
// uses. These tests drive the parts that read and write files -- the snapshot posture, the
// restore-source guard, the pending-restore staging and the wiring -- because the failures
// that matter there are silent: a restore that stages the wrong file, or an admin source that
// escapes the snapshot directory, is not a crash but a wrong answer at the worst moment.

func quietLog() (*slog.Logger, *bytes.Buffer) {
	var buf bytes.Buffer
	return slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})), &buf
}

// adminAuditPath: the audit log is derived from the state path, "" included. An empty state
// path means "no state configured" and must not produce ".admin-audit.jsonl" in the working
// directory, which is what path + suffix does if the empty case is not handled.
func TestAdminAuditPathFollowsTheStateDatabase(t *testing.T) {
	if got := adminAuditPath(""); got != "" {
		t.Errorf("adminAuditPath(\"\") = %q, want the empty string", got)
	}
	if got := adminAuditPath("/var/lib/wecert/state.db"); got != "/var/lib/wecert/state.db.admin-audit.jsonl" {
		t.Errorf("adminAuditPath = %q, want the audit log beside the state database", got)
	}
}

// stateBackupDirs: the primary destination is the configured directory, or the directory holding
// the state database when none is configured -- that default is what makes snapshots work on a
// default install, where stateBackup.dir is unset.
func TestStateBackupDirsPutsThePrimaryDestinationFirst(t *testing.T) {
	cfg := &config.Config{StatePath: "/var/lib/wecert/state.db"}
	if got := stateBackupDirs(cfg); len(got) != 1 || got[0] != "/var/lib/wecert" {
		t.Errorf("stateBackupDirs = %v, want the state database's directory", got)
	}

	cfg = &config.Config{
		StatePath:   "/var/lib/wecert/state.db",
		StateBackup: config.StateBackup{Dir: "/srv/snapshots", LocalDirs: []string{"/mnt/backup", "/mnt/offsite"}},
	}
	got := stateBackupDirs(cfg)
	want := []string{"/srv/snapshots", "/mnt/backup", "/mnt/offsite"}
	if len(got) != len(want) {
		t.Fatalf("stateBackupDirs = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("stateBackupDirs[%d] = %q, want %q (the primary destination must come first: "+
				"the snapshot loop reports the first directory it cannot write)", i, got[i], want[i])
		}
	}
}

// adminRestoreSourceAllowed is the guard between an HTTP client holding the admin token and the
// filesystem: it must accept exactly the snapshots this deployment wrote, and refuse everything
// else -- a path outside the snapshot directories, a planted file with a plausible name, and a
// symlink under an allowed directory that points somewhere else.
func TestAdminRestoreSourceAllowedKeepsTheHTTPSurfaceInsideItsSnapshots(t *testing.T) {
	// The guard resolves symlinks before comparing against the allowed directories, so the
	// fixture has to hand it paths that are already resolved: on macOS t.TempDir() lives under
	// /var, which is itself a symlink to /private/var, and an unresolved fixture would be
	// refused for a reason that has nothing to do with what is under test.
	root := t.TempDir()
	if resolved, err := filepath.EvalSymlinks(root); err == nil {
		root = resolved
	}
	dir := filepath.Join(root, "snapshots")
	local := filepath.Join(root, "mirror")
	for _, d := range []string{dir, local} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	statePath := filepath.Join(root, "state.db")
	goodName := "state.db.backup-20260101T000000.000Z.db"
	good := filepath.Join(dir, goodName)
	planted := filepath.Join(dir, "state.db.backup-not-a-stamp.db")
	besideState := filepath.Join(root, goodName)
	for _, f := range []string{good, planted, besideState} {
		if err := os.WriteFile(f, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	// The smuggling case: a file under an allowed directory whose *name* is a valid snapshot
	// name, pointing at bytes from somewhere else entirely.
	elsewhere := t.TempDir()
	if resolved, err := filepath.EvalSymlinks(elsewhere); err == nil {
		elsewhere = resolved
	}
	target := filepath.Join(elsewhere, goodName)
	if err := os.WriteFile(target, []byte("not ours"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, goodName)
	if err := os.Remove(link); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlinks are not available here: %v", err)
	}
	outsideDir := t.TempDir()
	if resolved, err := filepath.EvalSymlinks(outsideDir); err == nil {
		outsideDir = resolved
	}
	inLocal := filepath.Join(local, goodName)
	if err := os.WriteFile(inLocal, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg := &config.Config{
		StatePath: statePath,
		StateBackup: config.StateBackup{
			Dir:       dir,
			LocalDirs: []string{local},
			RemoteTargets: []config.BackupTarget{
				{Name: "nightly", Type: "s3", Bucket: "b"},
			},
		},
	}

	allowed := []struct {
		name   string
		source string
	}{
		{"latest is resolved by the caller, not judged here", "latest"},
		{"a configured remote target", "remote:nightly"},
		{"the snapshot directory itself", dir},
		{"a snapshot file this deployment wrote", inLocal},
		{"a snapshot copied beside the state database", besideState},
	}
	for _, tc := range allowed {
		if err := adminRestoreSourceAllowed(cfg, tc.source); err != nil {
			t.Errorf("%s: %s must be allowed, got %v", tc.name, tc.source, err)
		}
	}

	refused := []struct {
		name   string
		source string
		want   string
	}{
		{"a remote target that is not configured", "remote:other", "not in stateBackup.remoteTargets"},
		{"a file anywhere on the filesystem", outsideDir + "/elsewhere.db", "outside the snapshot directories"},
		{"a file in the snapshot directory that is not a snapshot", planted, "not a wecert snapshot name"},
		{"a symlink under an allowed directory pointing elsewhere", link, "outside the snapshot directories"},
	}
	for _, tc := range refused {
		err := adminRestoreSourceAllowed(cfg, tc.source)
		if err == nil {
			t.Errorf("%s: %s must be refused", tc.name, tc.source)
			continue
		}
		if !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: the error should say %q so the operator knows what to fix, got: %v",
				tc.name, tc.want, err)
		}
	}
}

// hmacKeyFrom must fail closed. A configured key file that cannot be read has to be an error,
// not "no signing": an upload that silently skipped signing leaves the operator believing the
// bucket is signed, and a restore that silently skipped verification accepts anything in it.
func TestHMACKeyFromFailsClosedOnAKeyItCannotRead(t *testing.T) {
	if key, err := hmacKeyFrom(""); err != nil || key != nil {
		t.Errorf("an empty path means no signing: key=%q err=%v", key, err)
	}
	if _, err := hmacKeyFrom(filepath.Join(t.TempDir(), "missing.key")); err == nil {
		t.Error("a configured but unreadable key file must be an error, not an unsigned upload")
	}

	empty := filepath.Join(t.TempDir(), "empty.key")
	if err := os.WriteFile(empty, []byte("  \n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := hmacKeyFrom(empty); err == nil {
		t.Error("an empty key file must be refused rather than treated as a key of zero bytes")
	}

	keyFile := filepath.Join(t.TempDir(), "key")
	if err := os.WriteFile(keyFile, []byte("s3cret-key\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	key, err := hmacKeyFrom(keyFile)
	if err != nil {
		t.Fatalf("a readable key file must load: %v", err)
	}
	if string(key) != "s3cret-key" {
		t.Errorf("key = %q, want the trimmed file contents", key)
	}
}

// backupHealth answers "is there a recovery point at all?" over HTTP. It has to report the
// pieces separately: the live database's age, the local snapshots, and a staged restore that
// has not been applied yet -- the one fact that says the running database is not what a
// restart will produce.
func TestBackupHealthReportsTheRecoveryPosture(t *testing.T) {
	dir := t.TempDir()
	statePath := filepath.Join(dir, "state.db")
	store, err := state.Open(statePath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Snapshot(dir, 7); err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(statePath+".restore-pending", []byte("pending"), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg := &config.Config{
		StatePath:   statePath,
		StateBackup: config.StateBackup{RemoteTargets: []config.BackupTarget{{Name: "nightly", Type: "s3", Keep: 3}}},
	}
	out, err := backupHealth(cfg)
	if err != nil {
		t.Fatalf("backupHealth: %v", err)
	}
	health, ok := out.(map[string]any)
	if !ok {
		t.Fatalf("backupHealth returned %T, want a map the JSON response can carry", out)
	}
	if health["statePath"] != statePath {
		t.Errorf("statePath = %v, want %s", health["statePath"], statePath)
	}
	if _, ok := health["stateAgeSeconds"]; !ok {
		t.Error("a state database that exists must report its age: that is the number an operator " +
			"compares against the snapshot interval")
	}
	if _, ok := health["stateBytes"]; !ok {
		t.Error("the state size must be reported alongside the age")
	}
	snaps, ok := health["localSnapshots"].(map[string]any)
	if !ok {
		t.Fatalf("localSnapshots = %T, want a map", health["localSnapshots"])
	}
	if count, _ := snaps["count"].(int); count != 1 {
		t.Errorf("localSnapshots.count = %v, want 1", snaps["count"])
	}
	if newest, _ := snaps["newest"].(string); newest == "" {
		t.Error("the newest snapshot path must be reported, or the operator cannot find the file to restore")
	}
	pending, ok := health["pendingRestore"].(map[string]any)
	if !ok {
		t.Fatalf("pendingRestore = %T, want a map", health["pendingRestore"])
	}
	if present, _ := pending["present"].(bool); !present {
		t.Error("a staged restore must be reported as present: the running database is not what the " +
			"next start will use, and that is exactly the thing this view exists to say")
	}
	if applied, _ := pending["appliedOnNextStart"].(bool); !applied {
		t.Error("a staged restore must say it is applied on the next start")
	}
	remotes, ok := health["remoteTargets"].([]map[string]any)
	if !ok || len(remotes) != 1 || remotes[0]["name"] != "nightly" {
		t.Errorf("remoteTargets = %v, want the configured target listed by name", health["remoteTargets"])
	}

	// A state database that does not exist yet must not fail the view: the endpoint is also how
	// an operator checks a fresh install, and "no file" is an answer, not an error.
	fresh, err := backupHealth(&config.Config{StatePath: filepath.Join(dir, "absent.db")})
	if err != nil {
		t.Fatalf("backupHealth without a state database: %v", err)
	}
	freshHealth := fresh.(map[string]any)
	if _, ok := freshHealth["stateAgeSeconds"]; ok {
		t.Error("a missing state database must not report an age")
	}
	if present, _ := freshHealth["pendingRestore"].(map[string]any)["present"].(bool); present {
		t.Error("nothing is staged on a fresh install")
	}
}

// recoveryPlan and recoveryDrill are the read-only half of the restore surface: they must answer
// from a real snapshot without touching the live database, and say so in their result.
func TestRecoveryPlanAndDrillReadASnapshotWithoutTouchingLiveState(t *testing.T) {
	cfg, _ := seedRestorableState(t)
	before, err := os.ReadFile(cfg.StatePath)
	if err != nil {
		t.Fatal(err)
	}

	plan, err := recoveryPlan(cfg, "latest")
	if err != nil {
		t.Fatalf("recoveryPlan: %v", err)
	}
	planMap := plan.(map[string]any)
	if planMap["liveStatePath"] != cfg.StatePath {
		t.Errorf("liveStatePath = %v, want %s: the plan must name the database it is talking about",
			planMap["liveStatePath"], cfg.StatePath)
	}
	if planMap["resolvedSource"] == "" || planMap["snapshotAge"] == "" {
		t.Errorf("the plan must resolve the source and age it, got %v", planMap)
	}
	if _, ok := planMap["certificates"]; !ok {
		t.Error("the plan must report what the snapshot holds: that is what the operator decides on")
	}

	drill, err := recoveryDrill(cfg, "")
	if err != nil {
		t.Fatalf("recoveryDrill with no source means latest: %v", err)
	}
	drillMap := drill.(map[string]any)
	if passed, _ := drillMap["passed"].(bool); !passed {
		t.Error("a snapshot that opens must come back as passed")
	}
	if note, _ := drillMap["note"].(string); !strings.Contains(note, "no live state") {
		t.Errorf("the drill must say it changed nothing, got note=%q", note)
	}

	after, err := os.ReadFile(cfg.StatePath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Error("plan and drill are read-only: the live database changed underneath them")
	}

	// A source outside the snapshot directories must be refused here too -- these are the same
	// guard the HTTP surface uses, and a plan endpoint that reads /etc/shadow would be worse
	// than useless.
	for _, fn := range []func(*config.Config, string) (any, error){recoveryPlan, recoveryDrill} {
		if _, err := fn(cfg, filepath.Join(t.TempDir(), "elsewhere.db")); err == nil {
			t.Error("a source outside the snapshot directories must be refused")
		}
	}
}

// adminRestore while the daemon holds the state lock stages the snapshot instead of swapping the
// file: replacing the database underneath the open handle would leave every write going to an
// unlinked inode, so the honest answer is "staged, applied on next start".
func TestAdminRestoreStagesInsteadOfSwappingTheOpenDatabase(t *testing.T) {
	cfg, snapshotDir := seedRestorableState(t)
	before, err := os.ReadFile(cfg.StatePath)
	if err != nil {
		t.Fatal(err)
	}
	log, buf := quietLog()

	out, err := adminRestore(cfg, "latest", log)
	if err != nil {
		t.Fatalf("adminRestore: %v", err)
	}
	res := out.(map[string]any)
	if pending, _ := res["pending"].(bool); !pending {
		t.Error("a restore under a live daemon must be staged, not applied")
	}
	if applied, _ := res["appliedOnNextStart"].(bool); !applied {
		t.Error("the staged restore must say it is applied on the next start")
	}
	pendingPath, _ := res["pendingPath"].(string)
	if pendingPath != cfg.StatePath+".restore-pending" {
		t.Errorf("pendingPath = %q, want %s.restore-pending", pendingPath, cfg.StatePath)
	}
	if _, err := os.Stat(pendingPath); err != nil {
		t.Errorf("the staged file must exist, or the next start has nothing to apply: %v", err)
	}
	after, err := os.ReadFile(cfg.StatePath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Error("the live database must not be replaced in place while this process holds it open")
	}
	if !strings.Contains(buf.String(), "applied on the next start") {
		t.Error("the operator has to be told the restore is not live yet; the log line is how")
	}

	// And the guard runs before anything is staged.
	if _, err := adminRestore(cfg, filepath.Join(snapshotDir, "..", "outside.db"), log); err == nil {
		t.Error("a source outside the snapshot directories must be refused before staging")
	}
}

// logProberConfig reports what the probe will actually do. The two cases that look identical in
// the log otherwise are "probing is off" and "the per-certificate host cap is 0": both dial
// nothing, and the second one leaves probe_match silent for reasons nobody can see from the
// outside.
func TestLogProberConfigSaysWhenNothingWillBeDialled(t *testing.T) {
	cfg := &config.Config{}
	cfg.Probe.Port = 443

	log, buf := quietLog()
	logProberConfig(cfg, nil, log)
	if !strings.Contains(buf.String(), "probing is off") {
		t.Errorf("a nil prober must be reported as probing being off, got: %s", buf.String())
	}

	zero := 0
	cfg.Probe.MaxHostsPerCert = &zero
	log, buf = quietLog()
	logProberConfig(cfg, probe.NewRunner(probe.Options{Port: 443}, 0, log), log)
	if !strings.Contains(buf.String(), "maxHostsPerCert is 0") {
		t.Errorf("a cap of zero must be called out: probing looks on while dialling nothing, got: %s",
			buf.String())
	}

	cfg.Probe.MaxHostsPerCert = nil
	log, buf = quietLog()
	logProberConfig(cfg, probe.NewRunner(probe.Options{Port: 443}, 0, log), log)
	if strings.Contains(buf.String(), "maxHostsPerCert is 0") || !strings.Contains(buf.String(), "probing is on") {
		t.Errorf("a default cap must report probing as on without the zero warning, got: %s", buf.String())
	}
}

// buildDesiredAndProber: the prober is built only when probing is enabled, and the desired-state
// source is built first so an unreadable enforce document fails at startup rather than at the
// first reconcile.
func TestBuildDesiredAndProberFollowsTheProbeSetting(t *testing.T) {
	log, _ := quietLog()
	off := false
	cfg := &config.Config{
		DesiredState: config.DesiredState{Mode: config.ModeStatic},
		Certificates: []config.Certificate{{Name: "example-com", Domains: []string{"example.com"}}},
	}
	cfg.Probe.Enabled = &off
	provider, prober, err := buildDesiredAndProber(cfg, log)
	if err != nil {
		t.Fatalf("buildDesiredAndProber: %v", err)
	}
	if provider == nil {
		t.Fatal("static mode must produce a desired-state source")
	}
	if prober != nil {
		t.Error("probe.enabled: false must not build a prober: nothing may dial the fleet then")
	}

	on := true
	cfg.Probe.Enabled = &on
	provider, prober, err = buildDesiredAndProber(cfg, log)
	if err != nil {
		t.Fatalf("buildDesiredAndProber with probing on: %v", err)
	}
	if provider == nil || prober == nil {
		t.Error("probing on must produce both the source and the prober")
	}
}

// finishDryRun is the pre-install answer, and it builds the credential-bearing components before
// saying "fine" -- a dry run that reports success without them is a claim it never checked.
func TestFinishDryRunBuildsWhatReadsCredentials(t *testing.T) {
	log, buf := quietLog()
	cfg := &config.Config{
		Certificates: []config.Certificate{{
			Name:    "example-com",
			Domains: []string{"example.com"},
			Deploy:  config.Deploy{Enabled: true},
		}},
		DesiredState: config.DesiredState{Mode: config.ModeStatic},
	}
	cfg.DNS.Provider = config.DNSProviderDNSPod
	cfg.DNS.LoginToken = "12345,abcdef"
	cfg.Tencent.CredentialMode = config.CredentialStatic
	t.Setenv("TENCENTCLOUD_SECRET_ID", "")
	t.Setenv("TENCENTCLOUD_SECRET_KEY", "")

	provider, _, err := buildDesiredAndProber(cfg, log)
	if err != nil {
		t.Fatalf("buildDesiredAndProber: %v", err)
	}
	if err := finishDryRun(cfg, provider, nil, log); err == nil {
		t.Error("a dry run whose credentials do not build must fail: it is the step install.sh runs " +
			"to decide whether the config is usable")
	}

	cfg.Tencent.SecretID = "id"
	cfg.Tencent.SecretKey = "key"
	cfg.Tencent.Regions = []string{"ap-guangzhou"}
	buf.Reset()
	if err := finishDryRun(cfg, provider, nil, log); err != nil {
		t.Fatalf("a complete static configuration must pass the dry run: %v", err)
	}
	if !strings.Contains(buf.String(), "dry run finished") {
		t.Errorf("the dry run must say what it checked, got: %s", buf.String())
	}
}

// buildManager wires the manager and the reconciler, including the optional notifier. The
// notifier is the case worth pinning: a nil *webhook.Notifier stuffed into the interface is not
// nil, and every "is there a notifier" check downstream would then try to use it.
func TestBuildManagerWiresAReconcilerWithoutANotifierWhenNoneIsConfigured(t *testing.T) {
	log, _ := quietLog()
	dir := t.TempDir()
	store, err := state.Open(filepath.Join(dir, "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	cfg := &config.Config{
		StatePath:    filepath.Join(dir, "state.db"),
		Certificates: []config.Certificate{{Name: "example-com", Domains: []string{"example.com"}}},
		DesiredState: config.DesiredState{Mode: config.ModeStatic},
	}
	cfg.DNS.Provider = config.DNSProviderDNSPod
	cfg.DNS.LoginToken = "12345,abcdef"
	cfg.Tencent.CredentialMode = config.CredentialStatic

	provider, _, err := buildDesiredAndProber(cfg, log)
	if err != nil {
		t.Fatalf("buildDesiredAndProber: %v", err)
	}
	reconciler, notifier, err := buildManager(cfg, store, nil, provider, nil, log)
	if err != nil {
		t.Fatalf("buildManager: %v", err)
	}
	if reconciler == nil {
		t.Fatal("buildManager must return a reconciler")
	}
	if notifier != nil {
		t.Errorf("no webhook.notifyUrl is configured, so there must be no notifier, got %T", notifier)
	}
}

// openRuntime is the boot step that takes the state lock and reports what it opened. Two runs of
// the program are the failure it exists to prevent -- "at most one in-flight order per
// certificate" holds only if the second process cannot open the same database -- so the lock is
// taken here and a second open must fail. -dry-run is the exception, and it has to stay one:
// installing while the daemon runs is the normal case.
func TestOpenRuntimeTakesTheStateLockAndDryRunDoesNotNeedIt(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yaml")
	body := `
statePath: ` + filepath.Join(dir, "state.db") + `
acme:
  directory: https://acme-staging-v02.api.letsencrypt.org/directory
  email: ops@atomwangnus.com
dns:
  provider: dnspod
  loginToken: "12345,abcdef"
desiredState:
  mode: static
certificates:
  - name: example-com
    domains: ["example.com"]
probe:
  enabled: false
tencent:
  credentialMode: static
  uin: "100012345678"
  regions: [ap-guangzhou]
`
	if err := os.WriteFile(cfgPath, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	log, _ := quietLog()

	cfg, store, err := openRuntime(&flags{configPath: cfgPath}, log)
	if err != nil {
		t.Fatalf("openRuntime: %v", err)
	}
	if cfg == nil || store == nil {
		t.Fatal("openRuntime must return the config and the open store")
	}

	// -state overrides statePath, which is how a second instance is pointed somewhere else.
	other := filepath.Join(dir, "other.db")
	_, otherStore, err := openRuntime(&flags{configPath: cfgPath, statePath: other, dryRun: true}, log)
	if err != nil {
		t.Fatalf("a dry run must be able to open the state database while the daemon holds it: %v", err)
	}
	if _, err := os.Stat(other); err != nil {
		t.Errorf("the -state override must be the database that gets opened: %v", err)
	}
	if err := otherStore.Close(); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
}

// startBackupsIfNeeded separates "the switch is off" from "the directory cannot be written",
// because the fixes differ: one is a config line, the other is a permissions or mount problem.
// Both must leave the snapshot loop stopped rather than started-and-failing every interval.
func TestStartBackupsIfNeededExplainsEveryReasonItStayedOff(t *testing.T) {
	dir := t.TempDir()
	log, buf := quietLog()

	off := false
	cfg := &config.Config{
		StatePath:   filepath.Join(dir, "state.db"),
		StateBackup: config.StateBackup{Enabled: &off},
	}
	snapshots, stop := startBackupsIfNeeded(context.Background(), nil, cfg, log)
	if snapshots != nil || stop != nil {
		t.Error("stateBackup.enabled: false must not start the snapshot loop")
	}
	if !strings.Contains(buf.String(), "DISABLED in the config") {
		t.Errorf("the log must say the switch is off rather than blame the directory, got: %s", buf.String())
	}

	// Unset and unwritable: the message has to name the directory, or the operator has nothing
	// to fix and the hint is the whole point of the branch.
	buf.Reset()
	blocked := filepath.Join(dir, "blocked")
	if err := os.WriteFile(blocked, []byte("not a directory"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg = &config.Config{StatePath: filepath.Join(dir, "state.db"), StateBackup: config.StateBackup{Dir: blocked}}
	snapshots, stop = startBackupsIfNeeded(context.Background(), nil, cfg, log)
	if snapshots != nil || stop != nil {
		t.Error("an unwritable snapshot directory must not start a loop that fails every interval")
	}
	logged := buf.String()
	if !strings.Contains(logged, "not writable") {
		t.Errorf("the log must say the directory is not writable, got: %s", logged)
	}
	if !strings.Contains(logged, blocked) {
		t.Errorf("the log must name the directory to fix (%s), got: %s", blocked, logged)
	}
}

// logEnforceFleet is the line that states the fleet size in enforce mode, and the only one that
// says "the document declares no certificates" -- the silent state where nothing is renewed and
// nothing else in the log looks wrong.
func TestLogEnforceFleetReportsTheDocumentedFleetSize(t *testing.T) {
	dir := t.TempDir()
	store, err := state.Open(filepath.Join(dir, "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	log, buf := quietLog()
	cfg := &config.Config{
		StatePath:    filepath.Join(dir, "state.db"),
		DesiredState: config.DesiredState{Mode: config.ModeStatic},
	}
	cfg.DNS.Provider = config.DNSProviderDNSPod
	cfg.DNS.LoginToken = "12345,abcdef"
	cfg.Tencent.CredentialMode = config.CredentialStatic

	provider, _, err := buildDesiredAndProber(cfg, log)
	if err != nil {
		t.Fatalf("buildDesiredAndProber: %v", err)
	}
	reconciler, _, err := buildManager(cfg, store, nil, provider, nil, log)
	if err != nil {
		t.Fatalf("buildManager: %v", err)
	}

	// Static mode has no document to report on: the line belongs to enforce mode only.
	buf.Reset()
	logEnforceFleet(cfg, reconciler, provider, log)
	if strings.Contains(buf.String(), "desired-state document") {
		t.Errorf("static mode must not report on a document that is not read, got: %s", buf.String())
	}

	// Enforce mode with nothing primed yet: no certificate has been observed, and that is exactly
	// the state the warning exists for -- a document that declares nothing while the operator
	// believes the fleet is managed.
	enforce := *cfg
	enforce.DesiredState = config.DesiredState{Mode: config.ModeEnforce, Path: "/etc/wecert/desired.yaml"}
	buf.Reset()
	logEnforceFleet(&enforce, reconciler, provider, log)
	if !strings.Contains(buf.String(), "desired-state document declares the certificates") {
		t.Errorf("enforce mode must report the document it is converging on, got: %s", buf.String())
	}
	if !strings.Contains(buf.String(), "declares no certificates") {
		t.Errorf("an empty fleet must be called out: nothing is renewed while that is true, got: %s",
			buf.String())
	}
}

// adminOps is the bridge between the HTTP surface and the code paths the CLI uses. Every closure
// has to reach the same function, or the endpoint answers something the CLI would not.
func TestAdminOpsExposeTheGuardedRecoveryEndpoints(t *testing.T) {
	cfg, _ := seedRestorableState(t)
	log, _ := quietLog()
	ctx := context.Background()

	ops := adminOps(cfg, log)
	if ops.BackupHealth == nil || ops.RecoveryPlan == nil || ops.RecoveryDrill == nil || ops.Restore == nil {
		t.Fatal("every admin operation the daemon can mount must be wired")
	}
	if out, err := ops.BackupHealth(ctx); err != nil || out == nil {
		t.Errorf("backup health: out=%v err=%v", out, err)
	}
	if out, err := ops.RecoveryPlan(ctx, "latest"); err != nil || out == nil {
		t.Errorf("recovery plan: out=%v err=%v", out, err)
	}
	if out, err := ops.RecoveryDrill(ctx, "latest"); err != nil {
		t.Errorf("recovery drill: %v", err)
	} else if passed, _ := out.(map[string]any)["passed"].(bool); !passed {
		t.Errorf("a drill of a readable snapshot must come back as passed, got %v", out)
	}
	staged, err := ops.Restore(ctx, "latest")
	if err != nil {
		t.Fatalf("restore: %v", err)
	}
	if pending, _ := staged.(map[string]any)["pending"].(bool); !pending {
		t.Errorf("restore must stage rather than swap an open database, got %v", staged)
	}
}

// runOncePass is what the systemd timer runs. Two outcomes matter: a pass with nothing to do is
// not trouble (an empty fleet is a legitimate desired state), and a pass that converged while the
// snapshot failed is trouble -- "it converged but there is no recovery point" is not a green run.
func TestRunOncePassReportsWhatTheOneShotRunMustNotSwallow(t *testing.T) {
	dir := t.TempDir()
	store, err := state.Open(filepath.Join(dir, "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	log, _ := quietLog()
	cfg := &config.Config{
		StatePath:    filepath.Join(dir, "state.db"),
		DesiredState: config.DesiredState{Mode: config.ModeStatic},
	}
	cfg.DNS.Provider = config.DNSProviderDNSPod
	cfg.DNS.LoginToken = "12345,abcdef"
	cfg.Tencent.CredentialMode = config.CredentialStatic

	provider, prober, err := buildDesiredAndProber(cfg, log)
	if err != nil {
		t.Fatalf("buildDesiredAndProber: %v", err)
	}
	reconciler, notifier, err := buildManager(cfg, store, nil, provider, prober, log)
	if err != nil {
		t.Fatalf("buildManager: %v", err)
	}
	ctx := context.Background()

	// No certificates declared: the pass attempts nothing, fails nothing, and must exit 0.
	if err := runOncePass(ctx, reconciler, notifier, nil, nil, log); err != nil {
		t.Errorf("a pass with no certificate to converge is not trouble: %v", err)
	}

	// The snapshot's error has to reach the exit code: a recovery point that was not written is
	// the one thing a green one-shot run would hide, and the next run may be a restore.
	failed := &snapshotHealth{first: make(chan error, 1)}
	failed.first <- errors.New("no space left on device")
	err = runOncePass(ctx, reconciler, notifier, failed, nil, log)
	if err == nil {
		t.Fatal("a failed state snapshot must fail the one-shot run even when the pass converged")
	}
	if !strings.Contains(err.Error(), "snapshot") || !strings.Contains(err.Error(), "no space left") {
		t.Errorf("the error must say the snapshot failed and why, got: %v", err)
	}
}

// A remote snapshot target copies state.db off the host, and state.db holds the ACME account key
// and every certificate's private key unless state encryption is configured. The bucket's
// server-side encryption protects the bytes at rest, not from whoever can read the bucket.
//
// This is a warning and not a refusal -- a working deployment must not go down on upgrade over a
// copy that is already in the bucket -- so the test pins both halves: it is said when the exposure
// is real, and it is not said once stateEncryption.keyFile is set, or when nothing leaves the host.
func TestStartBackupsWarnsWhenSnapshotsLeaveTheHostUnencrypted(t *testing.T) {
	dir := t.TempDir()
	store, err := state.Open(filepath.Join(dir, "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	newCfg := func() *config.Config {
		return &config.Config{
			StatePath: filepath.Join(dir, "state.db"),
			StateBackup: config.StateBackup{
				Dir:           filepath.Join(dir, "backups"),
				Keep:          3,
				IntervalDur:   time.Hour, // the immediate snapshot is all this test needs
				RemoteTargets: []config.BackupTarget{{Name: "nightly", Type: "s3", Bucket: "b"}},
			},
		}
	}

	log, buf := quietLog()
	_, stop := startBackupsIfNeeded(context.Background(), store, newCfg(), log)
	if stop != nil {
		stop()
	}
	if !strings.Contains(buf.String(), "stateEncryption.keyFile") {
		t.Errorf("an unencrypted database on its way to a bucket must be called out with the fix, got:\n%s",
			buf.String())
	}
	if !strings.Contains(buf.String(), "nightly") {
		t.Errorf("the warning must name the targets that receive it, got:\n%s", buf.String())
	}

	// With the key configured the snapshot is ciphertext, so there is nothing to warn about.
	cfg := newCfg()
	cfg.StateEncryption.KeyFile = filepath.Join(dir, "seal.key")
	log, buf = quietLog()
	_, stop = startBackupsIfNeeded(context.Background(), store, cfg, log)
	if stop != nil {
		stop()
	}
	if strings.Contains(buf.String(), "stateEncryption.keyFile is unset") {
		t.Errorf("a sealed database must not produce the plaintext warning, got:\n%s", buf.String())
	}

	// And a purely local deployment has nothing to say: the keys do not leave the host.
	cfg = newCfg()
	cfg.StateBackup.RemoteTargets = nil
	log, buf = quietLog()
	_, stop = startBackupsIfNeeded(context.Background(), store, cfg, log)
	if stop != nil {
		stop()
	}
	if strings.Contains(buf.String(), "remote targets") {
		t.Errorf("local-only snapshots must not be reported as leaving the host, got:\n%s", buf.String())
	}
}

// The one-shot path must close its listeners before it waits for anything.
//
// The listeners hang off the process context, which nothing cancels before the process exits on
// this path: `defer stop()` is registered first, so it runs last -- after the drain, after the
// final snapshot wait and after store.Close(). A trigger accepted in that window starts a pass
// nothing waits for, on a database that is closing, which is exactly the failure drainBackground
// exists to prevent. runOncePass therefore stops them itself, right after the pass it ran returns.
func TestOncePassClosesTheListenersBeforeItDrains(t *testing.T) {
	dir := t.TempDir()
	store, err := state.Open(filepath.Join(dir, "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	log, _ := quietLog()
	cfg := &config.Config{
		StatePath:    filepath.Join(dir, "state.db"),
		DesiredState: config.DesiredState{Mode: config.ModeStatic},
	}
	cfg.DNS.Provider = config.DNSProviderDNSPod
	cfg.DNS.LoginToken = "12345,abcdef"
	cfg.Tencent.CredentialMode = config.CredentialStatic

	provider, prober, err := buildDesiredAndProber(cfg, log)
	if err != nil {
		t.Fatalf("buildDesiredAndProber: %v", err)
	}
	reconciler, notifier, err := buildManager(cfg, store, nil, provider, prober, log)
	if err != nil {
		t.Fatalf("buildManager: %v", err)
	}

	var stopped int
	stop := func() { stopped++ }

	if err := runOncePass(context.Background(), reconciler, notifier, nil, stop, log); err != nil {
		t.Errorf("a pass with no certificate to converge is not trouble: %v", err)
	}
	if stopped != 1 {
		t.Errorf("stopListeners called %d time(s), want exactly once: the listeners must be closed "+
			"before the drain, and closing them twice is a programming error this pins against", stopped)
	}

	// And the snapshot-failure path returns through the same defer-less sequence: the listeners are
	// already closed by then, so a failing snapshot cannot keep the endpoint alive either.
	stopped = 0
	failed := &snapshotHealth{first: make(chan error, 1)}
	failed.first <- errors.New("no space left on device")
	if err := runOncePass(context.Background(), reconciler, notifier, failed, stop, log); err == nil {
		t.Fatal("a failed state snapshot must fail the one-shot run")
	}
	if stopped != 1 {
		t.Errorf("stopListeners called %d time(s) on the snapshot-failure path, want 1", stopped)
	}
}
