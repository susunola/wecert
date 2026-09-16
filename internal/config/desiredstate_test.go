package config

import (
	"strings"
	"testing"
	"time"
)

const oneCert = `
certificates:
  - name: example-com
    domains: [example.com]
`

func TestDesiredStateDefaultsToStatic(t *testing.T) {
	cfg, err := Load(writeConfig(t, minimalPrefix+oneCert))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.DesiredState.Mode != ModeStatic {
		t.Errorf("default should be %q, got %q", ModeStatic, cfg.DesiredState.Mode)
	}
	if cfg.DesiredState.MaxStalenessDur != 48*time.Hour {
		t.Errorf("maxStaleness default should be 48h, got %v", cfg.DesiredState.MaxStalenessDur)
	}
}

// An unused path left in static mode is almost certainly a half-finished switch
// to observe/enforce. Silently ignoring it makes people think the document is
// already in effect.
func TestStaticModeRejectsAnUnusedPath(t *testing.T) {
	_, err := Load(writeConfig(t, minimalPrefix+oneCert+`
desiredState:
  path: /tmp/desired-state.yaml
`))
	if err == nil || !strings.Contains(err.Error(), "desiredState.path") {
		t.Fatalf("setting path in static mode should error, got %v", err)
	}
}

func TestObserveAndEnforceRequireAPath(t *testing.T) {
	for _, mode := range []string{ModeObserve, ModeEnforce} {
		_, err := Load(writeConfig(t, minimalPrefix+oneCert+`
desiredState:
  mode: `+mode+`
`))
		if err == nil || !strings.Contains(err.Error(), "requires desiredState.path") {
			t.Errorf("mode=%s without path should error, got %v", mode, err)
		}
	}
}

// observe still converges on certificates, so the list is still required. It is
// not a "does nothing" mode: it only reports an extra diff.
func TestObserveStillRequiresCertificates(t *testing.T) {
	_, err := Load(writeConfig(t, minimalPrefix+`
desiredState:
  mode: observe
  path: /tmp/desired-state.yaml
`))
	if err == nil || !strings.Contains(err.Error(), "at least one certificate") {
		t.Fatalf("observe mode without certificates should error, got %v", err)
	}

	if _, err := Load(writeConfig(t, minimalPrefix+oneCert+`
desiredState:
  mode: observe
  path: /tmp/desired-state.yaml
`)); err != nil {
		t.Fatalf("observe mode with certificates should pass, got %v", err)
	}
}

// In enforce mode the document is the only source; leaving a certificates block
// behind only creates the hardest-to-debug confusion: "I changed the config and
// nothing happened".
func TestEnforceModeRejectsCertificatesInTheConfig(t *testing.T) {
	_, err := Load(writeConfig(t, minimalPrefix+oneCert+`
desiredState:
  mode: enforce
  path: /tmp/desired-state.yaml
`))
	if err == nil || !strings.Contains(err.Error(), "certificates is not empty") {
		t.Fatalf("enforce mode with certificates should error, got %v", err)
	}

	cfg, err := Load(writeConfig(t, minimalPrefix+`
desiredState:
  mode: enforce
  path: /tmp/desired-state.yaml
`))
	if err != nil {
		t.Fatalf("enforce mode without certificates should pass, got %v", err)
	}
	if cfg.DesiredState.Mode != ModeEnforce {
		t.Errorf("mode = %q", cfg.DesiredState.Mode)
	}
}

func TestUnknownDesiredStateModeIsRejected(t *testing.T) {
	_, err := Load(writeConfig(t, minimalPrefix+oneCert+`
desiredState:
  mode: auto
  path: /tmp/desired-state.yaml
`))
	if err == nil || !strings.Contains(err.Error(), "desiredState.mode must be") {
		t.Fatalf("an unknown mode should error, got %v", err)
	}
}

func TestOnboardingDefaults(t *testing.T) {
	cfg, err := Load(writeConfig(t, minimalPrefix+oneCert))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Onboarding.GraceDur != 24*time.Hour {
		t.Errorf("gracePeriod default should be 24h, got %v", cfg.Onboarding.GraceDur)
	}
	if cfg.Onboarding.BudgetDur != 7*24*time.Hour {
		t.Errorf("budgetWindow default should be 168h, got %v", cfg.Onboarding.BudgetDur)
	}
	// Unset means the pointer is nil and the caller supplies the default: the CLI
	// passes true (guard 1 is on by default), which blocks cases like "declared but
	// the rule is not configured yet" that cause useless issuance.
	if cfg.Onboarding.RequireCLBRule != nil {
		t.Error("an omitted requireCLBRule should stay unset, not be filled with some value")
	}
	if !cfg.Onboarding.RequireCLBRuleOr(true) {
		t.Error("when unset it should take the caller-supplied default")
	}
	if !cfg.Onboarding.DeployOr(true) {
		t.Error("an unset deploy should follow the caller-supplied default")
	}
}

// Why the pointer fields exist: false is meaningful, and the zero value cannot
// distinguish "not written" from "written false".
func TestOnboardingPointerFieldsCanBeSetToFalse(t *testing.T) {
	cfg, err := Load(writeConfig(t, minimalPrefix+oneCert+`
onboarding:
  requireCLBRule: false
  deploy: false
  gracePeriod: 72h
  budget: 5
`))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Onboarding.RequireCLBRuleOr(true) {
		t.Error("an explicit false must not be overridden by the default")
	}
	if cfg.Onboarding.DeployOr(true) {
		t.Error("an explicit false must not be overridden by the default")
	}
	if cfg.Onboarding.GraceDur != 72*time.Hour {
		t.Errorf("gracePeriod = %v", cfg.Onboarding.GraceDur)
	}
	if cfg.Onboarding.Budget != 5 {
		t.Errorf("budget = %d", cfg.Onboarding.Budget)
	}
}

func TestOnboardingRejectsABadDuration(t *testing.T) {
	_, err := Load(writeConfig(t, minimalPrefix+oneCert+`
onboarding:
  gracePeriod: someday
`))
	if err == nil || !strings.Contains(err.Error(), "onboarding.gracePeriod") {
		t.Fatalf("an invalid duration should error, got %v", err)
	}
}
