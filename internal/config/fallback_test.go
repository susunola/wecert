package config

import (
	"strings"
	"testing"
	"time"
)

func TestFailureFallbackDefaults(t *testing.T) {
	cfg, err := Load(writeConfig(t, minimalPrefix+oneCert))
	if err != nil {
		t.Fatal(err)
	}

	// Off by default: it changes what a certificate covers, a security decision.
	if cfg.Fallback.Enabled != nil {
		t.Error("an omitted failureFallback.enabled should stay unset")
	}
	if cfg.Fallback.EnabledOr(false) {
		t.Error("the default must be off")
	}
	if cfg.Fallback.BeforeExpiryDur != 7*24*time.Hour {
		t.Errorf("beforeExpiry default should be 168h, got %v", cfg.Fallback.BeforeExpiryDur)
	}
	if cfg.Fallback.FailureWindowDur != 24*time.Hour {
		t.Errorf("failureWindow default should be 24h, got %v", cfg.Fallback.FailureWindowDur)
	}
}

func TestFailureFallbackOverrides(t *testing.T) {
	cfg, err := Load(writeConfig(t, minimalPrefix+oneCert+`
failureFallback:
  enabled: true
  afterFailures: 8
  beforeExpiry: 72h
  minIdentifierFailures: 5
  failureWindow: 48h
  minNames: 3
`))
	if err != nil {
		t.Fatal(err)
	}

	if !cfg.Fallback.EnabledOr(false) {
		t.Error("an explicit enable should be true")
	}
	if cfg.Fallback.AfterFailuresOr(5) != 8 {
		t.Errorf("afterFailures = %d", cfg.Fallback.AfterFailuresOr(5))
	}
	if cfg.Fallback.BeforeExpiryDur != 72*time.Hour {
		t.Errorf("beforeExpiry = %v", cfg.Fallback.BeforeExpiryDur)
	}
	if cfg.Fallback.MinIdentifierFailuresOr(3) != 5 {
		t.Errorf("minIdentifierFailures = %d", cfg.Fallback.MinIdentifierFailuresOr(3))
	}
	if cfg.Fallback.FailureWindowDur != 48*time.Hour {
		t.Errorf("failureWindow = %v", cfg.Fallback.FailureWindowDur)
	}
	if cfg.Fallback.MinNamesOr(1) != 3 {
		t.Errorf("minNames = %d", cfg.Fallback.MinNamesOr(1))
	}
}

func TestFailureFallbackRejectsABadDuration(t *testing.T) {
	_, err := Load(writeConfig(t, minimalPrefix+oneCert+`
failureFallback:
  beforeExpiry: eventually
`))
	if err == nil || !strings.Contains(err.Error(), "failureFallback.beforeExpiry") {
		t.Fatalf("an invalid duration should error, got %v", err)
	}
}
