package main

import (
	"io"
	"log/slog"
	"testing"

	"github.com/susunola/wecert/internal/config"
	"github.com/susunola/wecert/internal/deploy"
	"github.com/susunola/wecert/internal/reconcile"
)

// Enforce forbids certificates in the config, and its document can enable
// deployment after startup. It must therefore retain a deferred cloud deployer
// rather than silently selecting Noop from the empty config list.
func TestEnforceUsesLazyTencentDeployer(t *testing.T) {
	cfg := &config.Config{
		DesiredState: config.DesiredState{Mode: config.ModeEnforce},
		Tencent: config.Tencent{
			CredentialMode: config.CredentialStatic,
			SecretID:       "id",
			SecretKey:      "key",
		},
	}

	d, err := newDeployer(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatalf("construct deployer: %v", err)
	}
	if _, ok := d.(*deploy.LazyTencentCLB); !ok {
		t.Fatalf("enforce mode must retain a lazy Tencent deployer, got %T", d)
	}
}

func TestEnforceDefersUnusedStaticCredentials(t *testing.T) {
	cfg := &config.Config{DesiredState: config.DesiredState{Mode: config.ModeEnforce}}
	cfg.Tencent.CredentialMode = config.CredentialStatic
	d, err := newDeployer(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatalf("purely local enforce mode must not validate unused credentials: %v", err)
	}
	if _, ok := d.(*deploy.LazyTencentCLB); !ok {
		t.Fatalf("enforce mode must retain a lazy deployer, got %T", d)
	}
}

// A one-shot run that did not converge must fail.
//
// wecert-once.service runs this with -once, and "exited 0 with every certificate failing" is the
// failure this report exists to prevent: the timer reports success while the fleet goes unmanaged.
func TestOnceExitFailsWhenThePassDidNotConverge(t *testing.T) {
	trouble := []struct {
		name string
		rep  reconcile.RunReport
	}{
		{"a certificate failed", reconcile.RunReport{Attempted: 3, Succeeded: 2, Failed: 1}},
		{"the desired state was unreadable", reconcile.RunReport{DesiredStateUnreadable: true}},
		// Attempted nothing and skipped everything is not "nothing to do": it is the state a
		// certificate stuck in a long backoff sits in, which is exactly what a one-shot run has to
		// report.
		{"nothing was attempted and everything was skipped", reconcile.RunReport{Skipped: []string{"a", "b"}}},
	}
	for _, tc := range trouble {
		if err := onceExit(tc.rep); err == nil {
			t.Errorf("%s: a one-shot run must exit non-zero so the timer reports the failure", tc.name)
		}
	}

	healthy := []struct {
		name string
		rep  reconcile.RunReport
	}{
		{"everything succeeded", reconcile.RunReport{Attempted: 2, Succeeded: 2}},
		{"a certificate is inside its retry window", reconcile.RunReport{Attempted: 0, Backoff: 1}},
	}
	for _, tc := range healthy {
		if err := onceExit(tc.rep); err != nil {
			t.Errorf("%s: this is a healthy pass, got %v", tc.name, err)
		}
	}
}

// "Enabled but the directory is not writable" must be its own outcome, not the running one.
//
// EnabledOr() returns the explicit setting whenever it is set, so treating it as sufficient sent
// this case into the branch that starts the loop: it then took a snapshot every interval, failed,
// and logged an ERROR each time -- the noise the diagnostic branch exists to replace, and it was
// unreachable because its guard was the condition the first branch had already consumed.
func TestPlanStateBackupsDistinguishesEnabledFromWritable(t *testing.T) {
	yes, no := true, false
	cases := []struct {
		name     string
		enabled  *bool
		writable bool
		want     backupPlan
	}{
		{"explicitly enabled, writable", &yes, true, backupsRun},
		{"explicitly enabled, unwritable", &yes, false, backupsEnabledButUnwritable},
		{"explicitly disabled, writable", &no, true, backupsDisabled},
		{"unset (the default) follows the directory", nil, true, backupsRun},
		{"unset with an unwritable directory", nil, false, backupsDisabled},
	}
	for _, tc := range cases {
		if got := planStateBackups(tc.enabled, tc.writable); got != tc.want {
			t.Errorf("%s: planStateBackups = %v, want %v", tc.name, got, tc.want)
		}
	}
}
