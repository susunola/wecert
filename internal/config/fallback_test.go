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

	// 默认关闭：它会改变证书覆盖什么，那是安全决策。
	if cfg.Fallback.Enabled != nil {
		t.Error("没写 failureFallback.enabled 时应当是未设置状态")
	}
	if cfg.Fallback.EnabledOr(false) {
		t.Error("默认必须是关闭")
	}
	if cfg.Fallback.BeforeExpiryDur != 7*24*time.Hour {
		t.Errorf("beforeExpiry 默认应当是 168h，实际 %v", cfg.Fallback.BeforeExpiryDur)
	}
	if cfg.Fallback.FailureWindowDur != 24*time.Hour {
		t.Errorf("failureWindow 默认应当是 24h，实际 %v", cfg.Fallback.FailureWindowDur)
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
		t.Error("显式开启时应当为真")
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
		t.Fatalf("非法时长应当报错，实际 %v", err)
	}
}
