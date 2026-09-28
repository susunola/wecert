package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/susunola/wecert/internal/config"
	"github.com/susunola/wecert/internal/state"
	"github.com/susunola/wecert/internal/webhook"
)

func startMetricsServer(ctx context.Context, addr string, log *slog.Logger) error {
	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.Handler())
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf(
			"failed to listen on the metrics port %s: %w (already in use? only one wecert instance should run per machine; "+
				"do not enable both the daemon and the timer)", addr, err)
	}

	srv := &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		// The webhook server below sets all three; this one used to set only the header
		// timeout. ReadTimeout=0 means a client that announces a body and then dribbles it
		// (net/http drains up to 256KB in finishRequest) pins a connection and its file
		// descriptor with no upper bound, and IdleTimeout=0 falls back to ReadTimeout=0, so
		// keep-alive connections never expire either. The default bind is loopback, which
		// limits the exposure -- but binding metrics to a VPC address so Prometheus can
		// scrape it is a documented setup, and that is where this matters.
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
	}()

	go func() {
		// The only error that can reach here is ErrServerClosed from Shutdown.
		if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Error("the metrics server exited unexpectedly", "err", err)
		}
	}()

	log.Info("metrics server started", "addr", ln.Addr().String(), "metrics", "/metrics")
	return nil
}

// startWebhookServer starts the event-trigger endpoint.
//
// Like the metrics server it binds the port **synchronously** and exits on failure, for
// the same reason: this is the only entrance to the event-driven path, and occupying the
// port while merely logging a line makes people believe it is configured when in fact
// every event is lost -- and certificates march on toward expiry regardless.
func startWebhookServer(
	listenerCtx, processCtx context.Context, cfg *config.Config,
	rec webhook.Reconciler, store *state.Store, log *slog.Logger,
) (*webhook.Server, error) {
	if cfg.Webhook.Listen == "" {
		log.Info("webhook disabled (webhook.listen is empty); converging on the timer only")
		return nil, nil
	}

	ln, err := net.Listen("tcp", cfg.Webhook.Listen)
	if err != nil {
		return nil, fmt.Errorf(
			"failed to listen on the webhook port %s: %w (already in use?)", cfg.Webhook.Listen, err)
	}

	admin := webhook.AdminOptions{
		Token:     cfg.Webhook.AdminToken,
		AuditPath: adminAuditPath(cfg.StatePath),
		Ops:       adminOps(cfg, log),
	}
	api, err := webhook.NewWithAdmin(rec, store, cfg.Webhook.Token, admin, processCtx, log)
	if err != nil {
		// The port is already bound above, and returning here used to leak it: this process
		// exits because of the error, so a restart is fine, but the exit path taken when
		// webhook.New rejects the config is exactly the one an operator fixes by editing
		// webhook.token and rerunning -- and the rerun then fails with "address already in
		// use", pointing at a phantom instance instead of at the setting they just changed.
		_ = ln.Close()
		return nil, fmt.Errorf("failed to initialise the webhook server (the port %s has been released): %w",
			cfg.Webhook.Listen, err)
	}
	api.SetAccountUIN(cfg.Tencent.UIN)

	srv := &http.Server{
		Handler:           api.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      15 * time.Second,
		// Explicit, matching startMetricsServer: IdleTimeout=0 falls back to
		// ReadTimeout, so keep-alives would silently inherit whatever that is set to
		// later instead of the longer idle window the metrics server documents.
		IdleTimeout: 60 * time.Second,
	}

	go func() {
		<-listenerCtx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
	}()

	go func() {
		if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Error("the webhook server exited unexpectedly", "err", err)
		}
	}()

	log.Info("webhook server started",
		"addr", ln.Addr().String(),
		"trigger", "POST /hook/reconcile",
		"status", "GET /hook/status")
	return api, nil
}
