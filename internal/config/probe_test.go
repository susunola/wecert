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
	if cfg.Probe.MaxHostsPerCert != 3 {
		t.Errorf("maxHostsPerCert default should be 3, got %d", cfg.Probe.MaxHostsPerCert)
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
	if cfg.Probe.MaxHostsPerCert != 1 {
		t.Errorf("maxHostsPerCert = %d", cfg.Probe.MaxHostsPerCert)
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

// A cap of 0 is filled in by normalize as the default; only a negative is an
// error — that usually means someone wrote 0 to say "off", but off is spelled
// enabled: false.
func TestProbeRejectsANegativeCap(t *testing.T) {
	_, err := Load(writeConfig(t, minimalPrefix+oneCert+`
probe:
  maxHostsPerCert: -1
`))
	if err == nil || !strings.Contains(err.Error(), "maxHostsPerCert") {
		t.Fatalf("a negative cap should error, got %v", err)
	}
}
