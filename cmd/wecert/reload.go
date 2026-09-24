package main

// Runtime hot reload support.  A reload is deliberately an admission-controlled
// replacement, not mutation of a live manager: DNS solvers, cloud credentials and
// ACME cores all hold configuration internally.  Replacing the complete bundle
// avoids a half-old / half-new credential set.

import (
	"context"
	"fmt"
	"log/slog"
	"reflect"
	"sync"
	"time"

	"github.com/susunola/wecert/internal/acme"
	"github.com/susunola/wecert/internal/config"
	"github.com/susunola/wecert/internal/probe"
	"github.com/susunola/wecert/internal/ratelimit"
	"github.com/susunola/wecert/internal/reconcile"
	"github.com/susunola/wecert/internal/spec"
	"github.com/susunola/wecert/internal/state"
)

// runtimeController is the stable object handed to the daemon and HTTP server.
// Its read lock is also the admission gate: a reload holds the write lock while
// checking Idle, so no timer or webhook pass can slip between the check and swap.
type runtimeController struct {
	mu       sync.RWMutex
	cfg      *config.Config
	rec      *reconcile.Reconciler
	notifier reconcile.Notifier
	store    *state.Store
}

func newRuntimeController(cfg *config.Config, rec *reconcile.Reconciler, notifier reconcile.Notifier, store *state.Store) *runtimeController {
	return &runtimeController{cfg: cfg, rec: rec, notifier: notifier, store: store}
}

func (c *runtimeController) RunDetailed(ctx context.Context) reconcile.RunReport {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.rec.RunDetailed(ctx)
}

func (c *runtimeController) CertNames() []string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.rec.CertNames()
}
func (c *runtimeController) StartCert(ctx context.Context, name string) error {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.rec.StartCert(ctx, name)
}
func (c *runtimeController) StartNamed(ctx context.Context, names []string) ([]string, []string, []string, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.rec.StartNamed(ctx, names)
}
func (c *runtimeController) StartAll(ctx context.Context) ([]string, []string, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.rec.StartAll(ctx)
}
func (c *runtimeController) LastResult() *spec.Result {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.rec.LastResult()
}
func (c *runtimeController) ProbeEnabled() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.rec.ProbeEnabled()
}
func (c *runtimeController) ProbeAnswers(name string) []probe.Answer {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.rec.ProbeAnswers(name)
}
func (c *runtimeController) ResourceTypes() []string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.rec.ResourceTypes()
}

// QuotaStatus is intentionally forwarded so the read-only inventory remains a
// truthful view after a reload.  The concrete result type keeps it compatible
// with webhook.QuotaReader without coupling that package back into main.
func (c *runtimeController) QuotaStatus() []ratelimit.QuotaReport {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.rec.QuotaStatus()
}

func (c *runtimeController) Config() *config.Config { c.mu.RLock(); defer c.mu.RUnlock(); return c.cfg }
func (c *runtimeController) Notifier() reconcile.Notifier {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.notifier
}

func (c *runtimeController) Drain(ctx context.Context) error {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.rec.Drain(ctx)
}

// reload exchanges only settings whose live resources can be retained.  Listener
// addresses, the state database and ACME directory identify long-lived resources;
// changing any of those requires a deliberate service restart rather than an
// apparently-successful reload that leaves the old socket or account in place.
func (c *runtimeController) reload(ctx context.Context, f *flags, log *slog.Logger) (*config.Config, error) {
	candidate, err := config.Load(f.configPath)
	if err != nil {
		return nil, err
	}
	if f.statePath != "" {
		candidate.StatePath = f.statePath
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	old := c.cfg
	if err := reloadImmutable(old, candidate); err != nil {
		return nil, err
	}
	if !c.rec.Idle() {
		return nil, fmt.Errorf("a certificate reconciliation is in flight; reload was not applied (send SIGHUP again after it finishes)")
	}

	provider, prober, err := buildDesiredAndProber(candidate, log)
	if err != nil {
		return nil, err
	}
	core, err := acme.EnsureAccount(candidate, c.store, acme.NewHTTPClient(60*time.Second))
	if err != nil {
		return nil, err
	}
	rec, notifier, err := buildManager(candidate, c.store, core, provider, prober, log)
	if err != nil {
		return nil, err
	}
	rec.Prime(ctx)
	c.cfg, c.rec, c.notifier = candidate, rec, notifier
	return candidate, nil
}

func reloadImmutable(old, next *config.Config) error {
	if old.StatePath != next.StatePath {
		return fmt.Errorf("statePath changed; restart is required")
	}
	if old.ACME.Directory != next.ACME.Directory {
		return fmt.Errorf("acme.directory changed; restart is required")
	}
	if old.Metrics.Listen != next.Metrics.Listen {
		return fmt.Errorf("metrics.listen changed; restart is required")
	}
	if old.Webhook.Listen != next.Webhook.Listen {
		return fmt.Errorf("webhook.listen changed; restart is required")
	}
	if !reflect.DeepEqual(old.StateBackup, next.StateBackup) {
		return fmt.Errorf("stateBackup changed; restart is required")
	}
	return nil
}
