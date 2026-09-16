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
	"github.com/susunola/wecert/internal/probe"
	"github.com/susunola/wecert/internal/reconcile"
	"github.com/susunola/wecert/internal/spec"
	"github.com/susunola/wecert/internal/state"
	"github.com/susunola/wecert/internal/webhook"
)

// version 可通过 -ldflags "-X main.version=..." 注入。
var version = "dev"

func main() {
	if err := run(); err != nil {
		slog.Error("wecert exited with an error", "err", err)
		os.Exit(1)
	}
}

func run() error {
	var (
		configPath = flag.String("config", "config.yaml", "path to the configuration file")
		statePath  = flag.String("state", "", "override statePath from the config (handy for tests or running multiple instances)")
		once       = flag.Bool("once", false, "run one pass and exit (for a systemd timer / cron)")
		interval   = flag.Duration("interval", time.Hour, "reconcile interval in daemon mode")
		logLevel   = flag.String("log-level", "info", "log level: debug|info|warn|error")
		dryRun     = flag.Bool("dry-run", false, "validate the config and initialise the account only; issue and deploy nothing")
		showVer    = flag.Bool("version", false, "print the version and exit")
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

	// 取状态库的跨进程排他锁。"每张证书最多一个在飞订单"原本只在一个
	// 进程内成立，而 daemon 与 timer 两种模式同时启用就会并发下单 ——
	// 撞上的是 7 天不可恢复的 exact-set 限额。
	//
	// -dry-run 例外：它几乎总是在 daemon 正在跑的时候被执行，
	// 而"因为 daemon 在跑所以连配置都校验不了"会把人逼去瞎改配置。
	// 这条路径只读已有的 ACME 账号、不发起签发。
	openStore := state.Open
	if *dryRun {
		openStore = state.OpenUnlocked
	}
	store, err := openStore(cfg.StatePath)
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

	// 期望状态来源在碰网络之前就构造好。
	//
	// enforce 模式下文档读不到必须在**启动时**就炸，而不是等到第一次收敛 ——
	// 允许"起得来但没有期望状态"意味着 wecert 会安静地什么都不续期，
	// 直到所有证书过期才被发现。
	//
	// 放在这里而不是更后面，还让 -dry-run 能真正回答那个最关键的问题：
	// "现在切过去，它起得来吗？" —— 而且不必先成功注册一次 ACME 账号。
	provider, err := newProvider(cfg, log)
	if err != nil {
		return err
	}

	// 网络侧探测器也在这里就构造好：它只读配置、不碰网络，
	// 而"探测到底开着没有、拨哪个端口"是切换配置时最该确认的事情之一。
	//
	// 它是唯一不信任云控制面的证据，所以默认开着。但它可能不适用 ——
	// 比如 wecert 跑在一台拨不到 CLB VIP 的机器上。那种情况下的表现是
	// probe_errors 涨，而 probe_match 不动，不会让证书看起来是坏的。
	var prober *probe.Runner
	if cfg.Probe.EnabledOr(true) {
		prober = probe.NewRunner(
			probe.Options{Port: cfg.Probe.Port, Timeout: cfg.Probe.TimeoutDur},
			cfg.Probe.MinValidDur, log)
	}

	httpClient := acme.NewHTTPClient(60 * time.Second)
	core, err := acme.EnsureAccount(cfg, store, httpClient)
	if err != nil {
		return err
	}

	if *dryRun {
		probeState := "off"
		if prober != nil {
			probeState = fmt.Sprintf("on (port %d, timeout %s, max %d hosts/cert)",
				cfg.Probe.Port, cfg.Probe.TimeoutDur, cfg.Probe.MaxHostsPerCert)
		}
		log.Info("dry run finished: the config, the ACME account and the desired-state source are all fine",
			"mode", cfg.DesiredState.Mode,
			"provider", spec.KindOf(provider),
			"certificates", len(cfg.Certificates),
			"probing", probeState)
		return nil
	}

	solver, err := acme.NewDNSSolver(cfg.DNS, cfg.Tencent, log)
	if err != nil {
		return err
	}
	log.Info("DNS-01 solver ready", "provider", cfg.DNS.Provider, "ttl", cfg.DNS.TTL)

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
		log.Info("renewal results will be pushed out", "url", cfg.Webhook.NotifyURL)
	}

	manager := acme.NewManager(store, acme.NewAPI(core), solver, deployer, log)
	reconciler := reconcile.New(cfg, provider, store, manager, notifier, log)

	// 网络侧探测：拨一个真实的 TLS 连接，确认线上服务的确实是部署的那张证书。
	reconciler.SetProber(prober)
	if prober != nil {
		log.Info("network-side certificate probing is on",
			"port", cfg.Probe.Port, "timeout", cfg.Probe.TimeoutDur,
			"maxHostsPerCert", cfg.Probe.MaxHostsPerCert)
	} else {
		log.Warn("network-side certificate probing is off: nothing will verify that the " +
			"certificate the cloud API reports as deployed is the one actually being served")
	}

	// 先求值一次并缓存。这样只读端点（webhook 的名字解析、诊断端点）
	// 在第一次收敛跑完之前就能给出正确答案，而不是先返回一个空列表 ——
	// 空列表会被读成"期望为空"。
	reconciler.Prime(ctx)

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

	log.Info("entering daemon mode", "interval", *interval)
	runDaemon(ctx, reconciler, *interval, log)
	return nil
}

// newProvider 按 desiredState.mode 装配期望状态来源。
//
// 三种模式的差别是**谁有最终解释权**，而不是"读几个文件"：
//
//	static   配置里的 certificates 说了算。历史行为，零风险。
//	observe  仍然按 certificates 收敛，但同时读文档并报告差异。
//	enforce  文档说了算，certificates 必须为空。
//
// 之所以把推断挡在 wecert 之外：这个系统所有已知的坑都在"判断"上，
// 而判断逻辑必然会反复改，证书生命周期必须稳。
func newProvider(cfg *config.Config, log *slog.Logger) (spec.Provider, error) {
	static := spec.NewStatic(cfg.Certificates)

	switch cfg.DesiredState.Mode {
	case config.ModeStatic:
		log.Info("desired state comes from the configuration file",
			"mode", config.ModeStatic, "certificates", len(cfg.Certificates))
		return static, nil

	case config.ModeObserve:
		// 影子来源构造失败**不**让进程起不来：观察阶段文档还没生成是很正常的事，
		// 此时应当照旧按配置收敛，只是没有对比结果。
		shadow, err := spec.NewFile(cfg.DesiredState.Path, log)
		if err != nil {
			log.Warn("observe mode: the desired-state document is not readable yet; "+
				"convergence will run on the configuration file exactly as before",
				"path", cfg.DesiredState.Path, "err", err)
			return static, nil
		}
		log.Info("observe mode: converging on the configuration file while reporting the diff against the document",
			"path", cfg.DesiredState.Path)
		return spec.NewObserver(static, shadow, log), nil

	case config.ModeEnforce:
		// enforce 模式下文档读不到必须**硬失败**。
		//
		// 允许"起得来但没有期望状态"意味着 wecert 会安静地什么都不续期，
		// 直到所有证书过期才被发现 —— 那是最糟的一种失败：无声，且后果全在线上。
		// 起不来至少是吵闹的，systemd 会重启它，人也会注意到。
		f, err := spec.NewFile(cfg.DesiredState.Path, log)
		if err != nil {
			return nil, fmt.Errorf("desiredState.mode=%q requires a readable document: %w",
				config.ModeEnforce, err)
		}
		log.Info("enforce mode: the desired-state document is the single source of truth",
			"path", cfg.DesiredState.Path)
		return f, nil
	}

	return nil, fmt.Errorf("unknown desiredState.mode %q", cfg.DesiredState.Mode)
}

func runDaemon(ctx context.Context, r *reconcile.Reconciler, interval time.Duration, log *slog.Logger) {
	// 启动后先跑一轮，再按间隔循环。加抖动避免多实例同时敲门。
	next := time.After(jitter(time.Second))
	for {
		select {
		case <-ctx.Done():
			log.Info("stop signal received; exiting")
			return
		case <-next:
		}

		start := time.Now()
		r.RunOnce(ctx)
		log.Info("reconcile pass finished", "duration", time.Since(start).Round(time.Millisecond))

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
			"failed to listen on the metrics port %s: %w (already in use? only one wecert instance should run per machine; "+
				"do not enable both the daemon and the timer)", addr, err)
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
			log.Error("the metrics server exited unexpectedly", "err", err)
		}
	}()

	log.Info("metrics server started", "addr", ln.Addr().String(), "metrics", "/metrics")
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
		log.Info("webhook disabled (webhook.listen is empty); converging on the timer only")
		return nil
	}

	ln, err := net.Listen("tcp", cfg.Webhook.Listen)
	if err != nil {
		return fmt.Errorf(
			"failed to listen on the webhook port %s: %w (already in use?)", cfg.Webhook.Listen, err)
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
			log.Error("the webhook server exited unexpectedly", "err", err)
		}
	}()

	log.Info("webhook server started",
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
		"certificates", len(cfg.Certificates))

	if firstRun {
		log.Warn("no account in the state store; registering a new ACME account")
		if production {
			log.Warn("WARNING: pointed at the Let's Encrypt production environment." +
				"run the whole flow against https://acme-staging-v02.api.letsencrypt.org/directory first," +
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

		// 通配符只覆盖一层，二层子域需要单独申请。这是最常见的一个误解。
		for _, d := range c.Domains {
			if strings.HasPrefix(d, "*.") && strings.Count(d, ".") > 1 {
				log.Info("note: a wildcard covers only one label",
					"cert", c.Name, "domain", d,
					"hint", "e.g. *.a.example.com does not include b.a.example.com; add *.b.a.example.com or list it explicitly")
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
