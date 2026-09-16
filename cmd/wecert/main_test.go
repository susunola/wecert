package main

import (
	"io"
	"log/slog"
	"testing"

	"github.com/susunola/wecert/internal/config"
	"github.com/susunola/wecert/internal/deploy"
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
