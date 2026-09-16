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
		t.Errorf("默认应当是 %q，实际 %q", ModeStatic, cfg.DesiredState.Mode)
	}
	if cfg.DesiredState.MaxStalenessDur != 48*time.Hour {
		t.Errorf("maxStaleness 默认应当是 48h，实际 %v", cfg.DesiredState.MaxStalenessDur)
	}
}

// static 模式下留着一个用不上的 path，几乎一定是"切到 observe/enforce 切了一半"。
// 静默忽略它，会让人以为文档已经在生效了。
func TestStaticModeRejectsAnUnusedPath(t *testing.T) {
	_, err := Load(writeConfig(t, minimalPrefix+oneCert+`
desiredState:
  path: /tmp/desired-state.yaml
`))
	if err == nil || !strings.Contains(err.Error(), "desiredState.path") {
		t.Fatalf("static 模式下设置 path 应当报错，实际 %v", err)
	}
}

func TestObserveAndEnforceRequireAPath(t *testing.T) {
	for _, mode := range []string{ModeObserve, ModeEnforce} {
		_, err := Load(writeConfig(t, minimalPrefix+oneCert+`
desiredState:
  mode: `+mode+`
`))
		if err == nil || !strings.Contains(err.Error(), "requires desiredState.path") {
			t.Errorf("mode=%s 缺少 path 应当报错，实际 %v", mode, err)
		}
	}
}

// observe 仍然按 certificates 收敛，所以证书列表还是必需的。
// 它不是一个"什么都不做"的模式：它只是额外报告一份差异。
func TestObserveStillRequiresCertificates(t *testing.T) {
	_, err := Load(writeConfig(t, minimalPrefix+`
desiredState:
  mode: observe
  path: /tmp/desired-state.yaml
`))
	if err == nil || !strings.Contains(err.Error(), "at least one certificate") {
		t.Fatalf("observe 模式缺少 certificates 应当报错，实际 %v", err)
	}

	if _, err := Load(writeConfig(t, minimalPrefix+oneCert+`
desiredState:
  mode: observe
  path: /tmp/desired-state.yaml
`)); err != nil {
		t.Fatalf("observe 模式带 certificates 应当通过，实际 %v", err)
	}
}

// enforce 模式下文档是唯一来源，配置里再留一份 certificates 只会造成
// "我改了配置却没生效"这种最难查的困惑。
func TestEnforceModeRejectsCertificatesInTheConfig(t *testing.T) {
	_, err := Load(writeConfig(t, minimalPrefix+oneCert+`
desiredState:
  mode: enforce
  path: /tmp/desired-state.yaml
`))
	if err == nil || !strings.Contains(err.Error(), "certificates is not empty") {
		t.Fatalf("enforce 模式带 certificates 应当报错，实际 %v", err)
	}

	cfg, err := Load(writeConfig(t, minimalPrefix+`
desiredState:
  mode: enforce
  path: /tmp/desired-state.yaml
`))
	if err != nil {
		t.Fatalf("enforce 模式不带 certificates 应当通过，实际 %v", err)
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
		t.Fatalf("未知模式应当报错，实际 %v", err)
	}
}

func TestOnboardingDefaults(t *testing.T) {
	cfg, err := Load(writeConfig(t, minimalPrefix+oneCert))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Onboarding.GraceDur != 24*time.Hour {
		t.Errorf("gracePeriod 默认应当是 24h，实际 %v", cfg.Onboarding.GraceDur)
	}
	if cfg.Onboarding.BudgetDur != 7*24*time.Hour {
		t.Errorf("budgetWindow 默认应当是 168h，实际 %v", cfg.Onboarding.BudgetDur)
	}
	// 未设置时指针应当是 nil，默认值由调用方给：
	// CLI 传的默认值是 true（守卫 1 默认开启），
	// 它挡住"声明写了但规则还没配"这类会造成无用签发的情况。
	if cfg.Onboarding.RequireCLBRule != nil {
		t.Error("没写 requireCLBRule 时应当是未设置状态，而不是被填成某个值")
	}
	if !cfg.Onboarding.RequireCLBRuleOr(true) {
		t.Error("未设置时应当采用调用方给的默认值")
	}
	if !cfg.Onboarding.DeployOr(true) {
		t.Error("deploy 未设置时应当沿调用方给的默认值")
	}
}

// 指针字段存在的理由：false 是有意义的值，而零值分不出"没写"和"写了 false"。
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
		t.Error("显式写成 false 时不该被默认值盖掉")
	}
	if cfg.Onboarding.DeployOr(true) {
		t.Error("显式写成 false 时不该被默认值盖掉")
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
		t.Fatalf("非法时长应当报错，实际 %v", err)
	}
}
