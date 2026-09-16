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
		t.Errorf("port 默认应当是 443，实际 %d", cfg.Probe.Port)
	}
	if cfg.Probe.TimeoutDur != 10*time.Second {
		t.Errorf("timeout 默认应当是 10s，实际 %v", cfg.Probe.TimeoutDur)
	}
	if cfg.Probe.MaxHostsPerCert != 3 {
		t.Errorf("maxHostsPerCert 默认应当是 3，实际 %d", cfg.Probe.MaxHostsPerCert)
	}
	if cfg.Probe.MinValidDur != 0 {
		t.Errorf("minValidFor 默认应当是不检查，实际 %v", cfg.Probe.MinValidDur)
	}
	// 未设置时是 nil，默认值由调用方给 —— main 传的是 true。
	if cfg.Probe.Enabled != nil {
		t.Error("没写 probe.enabled 时应当是未设置状态")
	}
	if !cfg.Probe.EnabledOr(true) {
		t.Error("未设置时应当采用调用方给的默认值")
	}
}

// 显式关掉是必要的：不是每个部署都能从运行 wecert 的机器拨到这个 VIP。
func TestProbeCanBeTurnedOff(t *testing.T) {
	cfg, err := Load(writeConfig(t, minimalPrefix+oneCert+`
probe:
  enabled: false
`))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Probe.EnabledOr(true) {
		t.Error("显式写成 false 时不该被默认值盖掉")
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
			t.Errorf("port=%s 应当报错，实际 %v", port, err)
		}
	}
}

func TestProbeRejectsABadDuration(t *testing.T) {
	_, err := Load(writeConfig(t, minimalPrefix+oneCert+`
probe:
  timeout: soon
`))
	if err == nil || !strings.Contains(err.Error(), "probe.timeout") {
		t.Fatalf("非法时长应当报错，实际 %v", err)
	}
}

// 上限为 0 会被 normalize 补成默认值，负数才是错误 ——
// 那多半是想写 0 表达"关掉"，而关掉应该用 enabled: false。
func TestProbeRejectsANegativeCap(t *testing.T) {
	_, err := Load(writeConfig(t, minimalPrefix+oneCert+`
probe:
  maxHostsPerCert: -1
`))
	if err == nil || !strings.Contains(err.Error(), "maxHostsPerCert") {
		t.Fatalf("负数上限应当报错，实际 %v", err)
	}
}
