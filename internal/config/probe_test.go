package config

import (
	"strings"
	"testing"
	"time"
)

func TestProbeDefaults(t *testing.T) {
	cfg, err := Load(writeConfig(t, minimalPrefix+oneCert))
	if err != nil {
		t.Fatal(err)
	}

	if cfg.Probe.Port != 443 {
		t.Errorf("port default should be 443, got %d", cfg.Probe.Port)
	}
	if cfg.Probe.TimeoutDur != 10*time.Second {
		t.Errorf("timeout default should be 10s, got %v", cfg.Probe.TimeoutDur)
	}
	if cfg.Probe.MaxHostsPerCert != nil {
		t.Errorf("an omitted maxHostsPerCert must stay unset, got %v", *cfg.Probe.MaxHostsPerCert)
	}
	if cfg.Probe.MaxHostsPerCertOr(DefaultMaxHostsPerCert) != 3 {
		t.Errorf("maxHostsPerCert default should be 3, got %d", cfg.Probe.MaxHostsPerCertOr(DefaultMaxHostsPerCert))
	}
	if cfg.Probe.MinValidDur != 0 {
		t.Errorf("minValidFor default should be no check, got %v", cfg.Probe.MinValidDur)
	}
	// Unset means nil and the caller supplies the default — main passes true.
	if cfg.Probe.Enabled != nil {
		t.Error("an omitted probe.enabled should stay unset")
	}
	if !cfg.Probe.EnabledOr(true) {
		t.Error("when unset it should take the caller-supplied default")
	}
}

// An explicit off switch is necessary: not every deployment can dial this VIP
// from the machine running wecert.
func TestProbeCanBeTurnedOff(t *testing.T) {
	cfg, err := Load(writeConfig(t, minimalPrefix+oneCert+`
probe:
  enabled: false
`))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Probe.EnabledOr(true) {
		t.Error("an explicit false must not be overridden by the default")
	}
}

func TestProbeOverrides(t *testing.T) {
	cfg, err := Load(writeConfig(t, minimalPrefix+oneCert+`
probe:
  port: 8443
  timeout: 3s
  maxHostsPerCert: 1
  minValidFor: 168h
`))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Probe.Port != 8443 {
		t.Errorf("port = %d", cfg.Probe.Port)
	}
	if cfg.Probe.TimeoutDur != 3*time.Second {
		t.Errorf("timeout = %v", cfg.Probe.TimeoutDur)
	}
	if cfg.Probe.MaxHostsPerCertOr(DefaultMaxHostsPerCert) != 1 {
		t.Errorf("maxHostsPerCert = %d", cfg.Probe.MaxHostsPerCertOr(DefaultMaxHostsPerCert))
	}
	if cfg.Probe.MinValidDur != 168*time.Hour {
		t.Errorf("minValidFor = %v", cfg.Probe.MinValidDur)
	}
}

func TestProbeRejectsAnOutOfRangePort(t *testing.T) {
	for _, port := range []string{"-1", "70000"} {
		_, err := Load(writeConfig(t, minimalPrefix+oneCert+`
probe:
  port: `+port+`
`))
		if err == nil || !strings.Contains(err.Error(), "probe.port") {
			t.Errorf("port=%s should error, got %v", port, err)
		}
	}
}

func TestProbeRejectsABadDuration(t *testing.T) {
	_, err := Load(writeConfig(t, minimalPrefix+oneCert+`
probe:
  timeout: soon
`))
	if err == nil || !strings.Contains(err.Error(), "probe.timeout") {
		t.Fatalf("an invalid duration should error, got %v", err)
	}
}

func TestProbeRejectsANegativeCap(t *testing.T) {
	_, err := Load(writeConfig(t, minimalPrefix+oneCert+`
probe:
  maxHostsPerCert: -1
`))
	if err == nil || !strings.Contains(err.Error(), "maxHostsPerCert") {
		t.Fatalf("a negative cap should error, got %v", err)
	}
}

// An explicit 0 must survive loading.
//
// It used to be rewritten to the default by normalize, because the field was a plain int and
// 0 was indistinguishable from unset. That made the branch in reconcile which documents "the
// per-certificate host cap is 0, so probing is off" dead code in production: writing
// maxHostsPerCert: 0 to pause probing during an investigation silently kept probing three
// hosts per certificate. This is not the same as enabled: false -- that removes the prober
// entirely, while 0 keeps it and pauses the dialling.
func TestProbeHonoursAnExplicitZeroCap(t *testing.T) {
	cfg, err := Load(writeConfig(t, minimalPrefix+oneCert+`
probe:
  maxHostsPerCert: 0
`))
	if err != nil {
		t.Fatalf("maxHostsPerCert: 0 must be accepted, got %v", err)
	}
	if cfg.Probe.MaxHostsPerCert == nil {
		t.Fatal("an explicit 0 must be stored, not read as unset")
	}
	if got := cfg.Probe.MaxHostsPerCertOr(DefaultMaxHostsPerCert); got != 0 {
		t.Errorf("MaxHostsPerCertOr = %d, want 0: an explicit cap of 0 means probe nothing", got)
	}
	if cfg.Probe.EnabledOr(true) != true {
		t.Error("a zero host cap must not read as the probe being disabled outright")
	}
}
