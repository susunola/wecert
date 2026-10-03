package main

import (
	"context"
	"github.com/susunola/wecert/internal/config"
	"github.com/susunola/wecert/internal/webhook"
	"log/slog"
)

// Follow the running configuration after reload, without exposing Nginx writes.
func wireDeploymentOps(ops *webhook.AdminOps, runtime *runtimeController, log *slog.Logger) {
	ops.DeploymentSettings = func(context.Context) (any, error) {
		cfg := runtime.Config()
		target := cfg.Deploy.Target
		if target == "" {
			target = config.DeployTargetTencent
		}
		return map[string]any{"target": target, "editable": cfg.DesiredState.Mode != config.ModeEnforce}, nil
	}
	ops.CreateCertificate = func(ctx context.Context, body webhook.CreateCertificateRequest) (any, error) {
		return createCertificateAdmin(runtime.Config(), body, log)
	}
	ops.ListBindings = func(context.Context) (any, error) { return listCloudBindings(runtime.Config()) }
	ops.BindCertificate = func(ctx context.Context, name string, body webhook.BindCertificateRequest) (any, error) {
		cfg := runtime.Config()
		if cfg.Deploy.Target == config.DeployTargetNginx {
			return nil, webhook.InvalidRequestf("CLB binding is unavailable for this daemon's nginx backend")
		}
		return bindCertificateAdmin(cfg, name, body, log)
	}
	ops.UnbindCertificate = func(ctx context.Context, name string) (any, error) {
		cfg := runtime.Config()
		if cfg.Deploy.Target == config.DeployTargetNginx {
			return nil, webhook.InvalidRequestf("nginx deployment is managed through the daemon configuration")
		}
		return unbindCertificateAdmin(cfg, name, log)
	}
}
