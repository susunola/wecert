package main

import (
	"fmt"
	"log/slog"
	"strings"

	"github.com/susunola/wecert/internal/acme"
	"github.com/susunola/wecert/internal/config"
	"github.com/susunola/wecert/internal/deploy"
	"github.com/susunola/wecert/internal/state"
)

func newDeployer(cfg *config.Config, log *slog.Logger) (deploy.Deployer, error) {
	// nginx is a local directory + reload: no cloud credentials, no regions.
	// Selected before the enforce/static split because the desired-state document
	// still names certificates the same way -- the backend is process-wide
	// (config.Deploy.Target), and enforce mode only changes *where the list comes
	// from*, not where the files land.
	if cfg.Deploy.Target == config.DeployTargetNginx {
		d, err := deploy.NewNginxFromConfig(*cfg, log)
		if err != nil {
			return nil, err
		}
		opts := d.Options()
		log.Info("nginx deploy enabled",
			"dirTemplate", opts.DirTemplate,
			"certFile", opts.CertFile,
			"keyFile", opts.KeyFile,
			"reload", opts.Reload,
			"overrides", len(opts.Overrides))
		return d, nil
	}

	// Enforce is driven by a document that may change while this process is
	// running. Its config-level certificate list is deliberately empty, so
	// scanning it would permanently select Noop even when the document enables
	// deploy. Keep a lazily initialised cloud deployer available instead.
	if cfg.DesiredState.Mode == config.ModeEnforce {
		log.Info("Tencent Cloud deploy is available for enforce-mode desired-state certificates",
			"credentialMode", cfg.Tencent.CredentialMode,
			"resourceTypes", cfg.Tencent.ResourceTypes,
			"regions", cfg.Tencent.Regions)
		return deploy.NewLazyTencentCLB(cfg.Tencent, log), nil
	}

	enabled := false
	for _, c := range cfg.Certificates {
		if c.Deploy.Enabled {
			enabled = true
			break
		}
	}
	if !enabled {
		log.Info("no certificate has deploy enabled; keeping local state only (nothing is pushed to Tencent Cloud)")
		return deploy.Noop{}, nil
	}

	d, err := deploy.NewTencentCLB(cfg.Tencent, log)
	if err != nil {
		return nil, err
	}
	log.Info("Tencent Cloud deploy enabled",
		"credentialMode", cfg.Tencent.CredentialMode,
		"resourceTypes", cfg.Tencent.ResourceTypes,
		"regions", cfg.Tencent.Regions)
	return d, nil
}

func isFirstRun(store *state.Store, cfg *config.Config) (bool, error) {
	acc, err := store.GetAccount(cfg.ACME.Directory)
	if err != nil {
		return false, err
	}
	return acc == nil, nil
}

func logStartup(log *slog.Logger, cfg *config.Config, firstRun bool) {
	production := cfg.ACME.Directory == config.DirectoryProduction

	log.Info("wecert starting",
		"version", version,
		"directory", cfg.ACME.Directory,
		"production", production,
		"statePath", cfg.StatePath,
		"mode", cfg.DesiredState.Mode,
		"certificates", certificateCountField(cfg))

	if firstRun {
		log.Warn("no account in the state store; registering a new ACME account")
		if production {
			log.Warn("WARNING: pointed at the Let's Encrypt production environment. " +
				"Run the whole flow against https://acme-staging-v02.api.letsencrypt.org/directory first, " +
				"otherwise failed retries burn real production quota")
		}
	}

	for _, c := range cfg.Certificates {
		log.Info("loaded certificate",
			"cert", c.Name,
			"profile", c.Profile,
			"domains", len(c.Domains),
			"maxNames", c.MaxNames(),
			"renewBefore", c.RenewBeforeDur,
			"deploy", c.Deploy.Enabled)

		// A wildcard covers one label only; deeper subdomains need their own entry. The classic mistake.
		for _, d := range c.Domains {
			if strings.HasPrefix(d, "*.") && strings.Count(d, ".") > 1 {
				log.Info("note: a wildcard covers only one label",
					"cert", c.Name, "domain", d,
					"hint", "e.g. *.a.example.com does not include b.a.example.com; add *.b.a.example.com or list it explicitly")
			}
		}
	}
}

// buildCredentialBearingComponents constructs the parts of the program that read credentials,
// without issuing or deploying anything.
//
// It exists so -dry-run can make its own summary true: internal/config deliberately leaves the
// validation of static Tencent credentials to deploy.NewCredentialSource, so a config with
// credentialMode=static and no secretId/secretKey passed the documented pre-install check and exited
// 0 with "all fine" -- failing on the first real pass instead, after a production ACME account had
// been registered and an interval had gone by.
//
// Note the middle call: in enforce mode newDeployer returns the LAZY CLB client on purpose (the
// document decides what is deployed), so without asking for the credential source directly, a
// deployment using DNSPod tokens for DNS would still not have its CAM credentials checked here.
func buildCredentialBearingComponents(cfg *config.Config, log *slog.Logger) error {
	if _, err := acme.NewDNSSolver(cfg.DNS, cfg.Tencent, log); err != nil {
		return fmt.Errorf("the DNS provider would not build: %w", err)
	}
	if needsTencentCredentials(cfg) {
		if _, err := deploy.NewCredentialSource(cfg.Tencent); err != nil {
			return fmt.Errorf("the Tencent Cloud credentials would not build: %w", err)
		}
	}
	if _, err := newDeployer(cfg, log); err != nil {
		return fmt.Errorf("the deployer would not build: %w", err)
	}
	return nil
}

func needsTencentCredentials(cfg *config.Config) bool {
	if cfg.DNS.Provider == config.DNSProviderTencentCloud {
		return true
	}
	// nginx deployment is entirely local. Do not make an otherwise valid
	// nginx-only configuration depend on Tencent Cloud credentials merely
	// because the certificate has deployment enabled.
	if cfg.Deploy.Target == config.DeployTargetNginx {
		return false
	}
	if cfg.DesiredState.Mode == config.ModeEnforce {
		return true
	}
	for _, cert := range cfg.Certificates {
		if cert.Deploy.Enabled {
			return true
		}
	}
	return false
}
