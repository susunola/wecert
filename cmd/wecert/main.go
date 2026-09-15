// Command wecert 是一个 cert-manager 风格的 ACME 证书自动续期器，
// 面向"TLS 在腾讯云 CLB 终结、多台 CVM 只跑业务"的部署形态。
//
// 因为解密发生在 CLB，整个系统不需要节点 agent，也不需要分发证书文件：
// 一台机器、一个二进制、一个 SQLite 文件就够了。
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"math/rand"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/susunola/wecert/internal/acme"
	"github.com/susunola/wecert/internal/config"
	"github.com/susunola/wecert/internal/deploy"
	"github.com/susunola/wecert/internal/reconcile"
	"github.com/susunola/wecert/internal/state"
	"github.com/susunola/wecert/internal/webhook"
)

// version 可通过 -ldflags "-X main.version=..." 注入。
var version = "dev"

func main() {
	if err := run(); err != nil {
		slog.Error("wecert 异常退出", "err", err)
		os.Exit(1)
	}
}

func run() error {
	var (
		configPath = flag.String("config", "config.yaml", "配置文件路径")
		statePath  = flag.String("state", "", "覆盖配置里的 statePath（便于测试或跑多实例）")
		once       = flag.Bool("once", false, "只跑一轮就退出（配合 systemd timer / cron）")
		interval   = flag.Duration("interval", time.Hour, "守护模式下的收敛间隔")
		logLevel   = flag.String("log-level", "info", "日志级别: debug|info|warn|error")
		dryRun     = flag.Bool("dry-run", false, "只校验配置并初始化账号，不签发也不部署")
		showVer    = flag.Bool("version", false, "打印版本后退出")
	)
	flag.Parse()

	if *showVer {
		fmt.Println("wecert", version)
		return nil
	}

	log := newLogger(*logLevel)

	cfg, err := config.Load(*configPath)
	if err != nil {
		return err
	}
	if *statePath != "" {
		cfg.StatePath = *statePath
	}

	store, err := state.Open(cfg.StatePath)
	if err != nil {
		return err
	}
	defer store.Close()

	// 首次运行会新建 ACME 账号。如果同时还是生产目录，值得先把话说清楚：
	// 账号是有限资源（每 IP 每 3 小时最多 10 个），不该反复重建。
	firstRun, err := isFirstRun(store, cfg)
	if err != nil {
		return err
	}
	logStartup(log, cfg, firstRun)

	httpClient := acme.NewHTTPClient(60 * time.Second)
	core, err := acme.EnsureAccount(cfg, store, httpClient)
	if err != nil {
		return err
	}

	if *dryRun {
		log.Info("dry-run 完成：配置与 ACME 账号均正常", "certificates", len(cfg.Certificates))
		return nil
	}

	solver, err := acme.NewDNSSolver(cfg.DNS, cfg.Tencent, log)
	if err != nil {
		return err
	}
	log.Info("DNS-01 solver 已就绪", "provider", cfg.DNS.Provider, "ttl", cfg.DNS.TTL)

	deployer, err := newDeployer(cfg, log)
	if err != nil {
		return err
	}

	// 先建进程级上下文：webhook 触发的收敛要在后台跑几分钟，
	// 必须挂在进程上下文上，而不是某个请求的 context 上。
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// 注意这里的写法：接口值为 nil 和"持有一个 nil 指针的接口"是两回事，
	// 直接把 (*webhook.Notifier)(nil) 塞进接口会让下面的 != nil 判断失效。
	var notifier reconcile.Notifier
	if n := webhook.NewNotifier(cfg.Webhook.NotifyURL, log); n != nil {
		notifier = n
		log.Info("续期结果会推送出去", "url", cfg.Webhook.NotifyURL)
	}

	manager := acme.NewManager(store, core, solver, deployer, log)
	reconciler := reconcile.New(cfg, store, manager, notifier, log)

	// 指标服务。先同步绑定端口，失败就直接退出 —— 见下面的注释。
	if err := startMetricsServer(ctx, cfg.Metrics.Listen, log); err != nil {
		return err
	}

	// 事件触发端点。同理：端口绑定失败必须硬失败。
	if err := startWebhookServer(ctx, cfg, reconciler, store, log); err != nil {
		return err
	}

	if *once {
		reconciler.RunOnce(ctx)
		return nil
	}

	log.Info("进入守护模式", "interval", *interval)
	runDaemon(ctx, reconciler, *interval, log)
	return nil
}

func runDaemon(ctx context.Context, r *reconcile.Reconciler, interval time.Duration, log *slog.Logger) {
	// 启动后先跑一轮，再按间隔循环。加抖动避免多实例同时敲门。
	next := time.After(jitter(time.Second))
	for {
		select {
		case <-ctx.Done():
			log.Info("收到停止信号，退出")
			return
		case <-next:
		}

		start := time.Now()
		r.RunOnce(ctx)
		log.Info("收敛轮次结束", "duration", time.Since(start).Round(time.Millisecond))

		// 每轮都重新抖动：固定间隔会让所有实例长期保持同相位。
		next = time.After(jitter(interval))
	}
}

// jitter 在 [d*0.9, d*1.1) 内取一个随机值。
func jitter(d time.Duration) time.Duration {
	if d <= 0 {
		return time.Second
	}
	delta := float64(d) * 0.1
	return d - time.Duration(delta) + time.Duration(rand.Float64()*2*delta)
}

// startMetricsServer 启动指标服务。
//
// 这里先同步 net.Listen、失败就返回错误，而不是把 ListenAndServe 丢进
// goroutine、出错只打一行日志了事。
//
// 原因：/metrics 是这个系统**唯一**的到期告警通道 —— README 明确要求
// "到期告警基于 not_after 做，而不要基于续期任务有没有报错"。
// 端口被占用时如果只是安静地打一条错误，程序看上去一切正常，
// 但监控侧从此再也收不到任何信号，证书会一路静默过期。
// 这正是本项目最想避免的那种失效，不该由自己制造一个。
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
			"监听指标端口 %s 失败: %w（端口被占用？同一台机器上只应跑一个 wecert 实例，"+
				"daemon 与 timer 两种模式不要同时启用）", addr, err)
	}

	srv := &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}

	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
	}()

	go func() {
		// 走到这里的错误只能是 Shutdown 触发的 ErrServerClosed。
		if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Error("指标服务异常退出", "err", err)
		}
	}()

	log.Info("指标服务已启动", "addr", ln.Addr().String(), "metrics", "/metrics")
	return nil
}

// startWebhookServer 启动事件触发端点。
//
// 和指标服务一样**同步**绑定端口，失败就退出。理由也一样：
// 这是"事件驱动"这条路径的唯一入口，端口被占却只打一行日志，
// 会让人以为配好了、实际所有事件都丢了 —— 而证书会照常走向过期。
func startWebhookServer(
	ctx context.Context, cfg *config.Config,
	rec *reconcile.Reconciler, store *state.Store, log *slog.Logger,
) error {
	if cfg.Webhook.Listen == "" {
		log.Info("webhook 未启用（webhook.listen 为空），只按定时器收敛")
		return nil
	}

	ln, err := net.Listen("tcp", cfg.Webhook.Listen)
	if err != nil {
		return fmt.Errorf(
			"监听 webhook 端口 %s 失败: %w（端口被占用？）", cfg.Webhook.Listen, err)
	}

	api := webhook.New(rec, store, cfg.Webhook.Token, ctx, log)

	srv := &http.Server{
		Handler:           api.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      15 * time.Second,
	}

	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
	}()

	go func() {
		if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Error("webhook 服务异常退出", "err", err)
		}
	}()

	log.Info("webhook 已启动",
		"addr", ln.Addr().String(),
		"trigger", "POST /hook/reconcile",
		"status", "GET /hook/status")
	return nil
}

func newDeployer(cfg *config.Config, log *slog.Logger) (deploy.Deployer, error) {
	enabled := false
	for _, c := range cfg.Certificates {
		if c.Deploy.Enabled {
			enabled = true
			break
		}
	}
	if !enabled {
		log.Info("所有证书都未开启 deploy，仅维护本地状态（证书不会推送到腾讯云）")
		return deploy.Noop{}, nil
	}

	d, err := deploy.NewTencentCLB(cfg.Tencent, log)
	if err != nil {
		return nil, err
	}
	log.Info("已启用腾讯云部署",
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

	log.Info("wecert 启动",
		"version", version,
		"directory", cfg.ACME.Directory,
		"production", production,
		"statePath", cfg.StatePath,
		"certificates", len(cfg.Certificates))

	if firstRun {
		log.Warn("状态库中没有账号，将注册一个新的 ACME 账号")
		if production {
			log.Warn("⚠️  当前指向 Let's Encrypt 生产环境。" +
				"建议先用 https://acme-staging-v02.api.letsencrypt.org/directory 跑通全流程，" +
				"否则失败重试会消耗真实的生产配额")
		}
	}

	for _, c := range cfg.Certificates {
		log.Info("已加载证书",
			"cert", c.Name,
			"profile", c.Profile,
			"domains", len(c.Domains),
			"maxNames", c.MaxNames(),
			"renewBefore", c.RenewBeforeDur,
			"deploy", c.Deploy.Enabled)

		// 通配符只覆盖一层，二层子域需要单独申请。这是最常见的一个误解。
		for _, d := range c.Domains {
			if strings.HasPrefix(d, "*.") && strings.Count(d, ".") > 1 {
				log.Info("注意：通配符只覆盖一层标签",
					"cert", c.Name, "domain", d,
					"hint", "例如 *.a.example.com 不包含 b.a.example.com，需要另加 *.b.a.example.com 或显式列出")
			}
		}
	}
}

func newLogger(level string) *slog.Logger {
	var lv slog.Level
	switch strings.ToLower(level) {
	case "debug":
		lv = slog.LevelDebug
	case "warn":
		lv = slog.LevelWarn
	case "error":
		lv = slog.LevelError
	default:
		lv = slog.LevelInfo
	}

	// systemd/journald 下不带时间戳更好读；直接跑在终端时时间戳有用。
	handler := slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: lv})
	return slog.New(handler)
}
