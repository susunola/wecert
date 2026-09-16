// Package webhook 让 wecert 可以被外部事件触发，而不是只能等定时器。
//
// 典型用法：域名新增后由 CI 或事件总线调一次，不必等到下一个整点。
//
// 这个端点会触发**真实签发**并消耗 Let's Encrypt 的速率限制配额，
// 所以鉴权不是可选项 —— 见 config.Webhook 的 token 校验。
package webhook

import (
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/susunola/wecert/internal/reconcile"
	"github.com/susunola/wecert/internal/spec"
	"github.com/susunola/wecert/internal/state"
)

// errBothForms 拦截同时给了 cert 和 certs 的请求 —— 语义有歧义，不如直接拒绝。
var errBothForms = errors.New("cert and certs are mutually exclusive")

// Reconciler 是 webhook 需要的收敛能力。定义在使用方，便于测试替换。
type Reconciler interface {
	CertNames() []string
	StartCert(ctx context.Context, name string) error
	StartAll(ctx context.Context) []string
}

// DesiredReader 是只读诊断端点需要的能力。
//
// 单独定义而不是塞进 Reconciler，是为了让这个端点保持
// "可有可无的只读附加物"的定位：不实现它就只是不挂载，
// 不影响触发路径，也不需要每个测试替身都去实现它。
type DesiredReader interface {
	LastResult() *spec.Result
}

// Server 提供触发端点与状态端点。
//
// baseCtx 是**进程级**上下文，不是某个请求的。后台那轮收敛可能跑几分钟，
// 用请求的 context 会在响应返回时被立刻取消 —— 那样触发等于没触发。
type Server struct {
	rec     Reconciler
	store   *state.Store
	token   string
	baseCtx context.Context
	log     *slog.Logger
	now     func() time.Time
}

// New 构造 webhook 服务。
func New(rec Reconciler, store *state.Store, token string, baseCtx context.Context, log *slog.Logger) *Server {
	return &Server{
		rec:     rec,
		store:   store,
		token:   token,
		baseCtx: baseCtx,
		log:     log,
		now:     time.Now,
	}
}

// Handler 返回路由。
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()

	// 健康检查不需要鉴权：它不泄漏任何信息，且探活要能拿到。
	mux.HandleFunc("/healthz", s.handleHealth)

	mux.HandleFunc("/hook/reconcile", s.auth(s.handleReconcile))
	mux.HandleFunc("/hook/status", s.auth(s.handleStatus))

	if dr, ok := s.rec.(DesiredReader); ok {
		mux.HandleFunc("/hook/desired", s.auth(s.handleDesired(dr)))
	}

	return mux
}

// ── 鉴权 ────────────────────────────────────────────────────────────────────

func (s *Server) auth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !s.tokenMatches(r) {
			s.log.Warn("webhook authentication failed",
				"remote", r.RemoteAddr, "path", r.URL.Path, "method", r.Method)
			writeJSON(w, http.StatusUnauthorized,
				map[string]string{"error": "missing or invalid token"})
			return
		}
		next(w, r)
	}
}

// tokenMatches 支持两种带法，并用常量时间比较。
func (s *Server) tokenMatches(r *http.Request) bool {
	presented := ""
	if h := r.Header.Get("Authorization"); strings.HasPrefix(h, "Bearer ") {
		presented = strings.TrimPrefix(h, "Bearer ")
	} else if h := r.Header.Get("X-Wecert-Token"); h != "" {
		presented = h
	}

	// 常量时间比较：逐字符比较会在第一个不同的字符处返回，
	// 从而泄漏 token 前缀。这个端点的价值足以让人逐位试探。
	return subtle.ConstantTimeCompare([]byte(presented), []byte(s.token)) == 1
}

// ── 端点 ────────────────────────────────────────────────────────────────────

func (s *Server) handleHealth(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok\n"))
}

// reconcileRequest 是触发请求体。整体可以省略 —— 不带 body 就是"全部处理"。
type reconcileRequest struct {
	Cert  string   `json:"cert"`
	Certs []string `json:"certs"`
}

type reconcileResponse struct {
	Accepted []string `json:"accepted"`
	Skipped  []string `json:"skipped,omitempty"`
	Unknown  []string `json:"unknown,omitempty"`
}

func (s *Server) handleReconcile(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		writeJSON(w, http.StatusMethodNotAllowed,
			map[string]string{"error": "use POST"})
		return
	}

	req, err := parseTrigger(r)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}

	targets, unknown := s.resolveTargets(req)

	resp := reconcileResponse{Unknown: unknown}

	// 不带 cert/certs 就是全量触发。
	if len(targets) == 0 && len(unknown) == 0 {
		resp.Skipped = s.rec.StartAll(s.baseCtx)
		resp.Accepted = s.rec.CertNames()
		resp.Accepted = subtract(resp.Accepted, resp.Skipped)
		s.log.Info("webhook triggered a full convergence",
			"accepted", len(resp.Accepted), "skipped", len(resp.Skipped), "remote", r.RemoteAddr)
	} else {
		for _, name := range targets {
			switch err := s.rec.StartCert(s.baseCtx, name); {
			case err == nil:
				resp.Accepted = append(resp.Accepted, name)
			case errors.Is(err, reconcile.ErrAlreadyRunning):
				resp.Skipped = append(resp.Skipped, name)
			default:
				resp.Unknown = append(resp.Unknown, name)
			}
		}
		s.log.Info("webhook triggered convergence",
			"accepted", resp.Accepted, "skipped", resp.Skipped, "unknown", resp.Unknown,
			"remote", r.RemoteAddr)
	}

	// 202 而不是 200：收敛已经受理，但还没跑完。
	// 一轮可能要几分钟（DNS 传播），让调用方等着只会把它的超时拖爆。
	// 想知道结果就轮询 /hook/status。
	writeJSON(w, http.StatusAccepted, resp)
}

// parseTrigger 读取请求体。空 body 合法，表示全量触发。
func parseTrigger(r *http.Request) (reconcileRequest, error) {
	var req reconcileRequest
	if r.Body == nil {
		return req, nil
	}

	// 限制体积：这是个触发端点，没有理由接受大 body。
	body, err := io.ReadAll(io.LimitReader(r.Body, 64<<10))
	if err != nil {
		return req, err
	}
	if len(bytes.TrimSpace(body)) == 0 {
		return req, nil
	}
	if err := json.Unmarshal(body, &req); err != nil {
		return req, err
	}
	if req.Cert != "" && len(req.Certs) > 0 {
		return req, errBothForms
	}
	return req, nil
}

// resolveTargets 把请求里的名字映射到配置中真实存在的证书。
func (s *Server) resolveTargets(req reconcileRequest) (targets, unknown []string) {
	known := make(map[string]struct{})
	for _, n := range s.rec.CertNames() {
		known[n] = struct{}{}
	}

	wanted := req.Certs
	if req.Cert != "" {
		wanted = []string{req.Cert}
	}

	for _, n := range wanted {
		if _, ok := known[n]; ok {
			targets = append(targets, n)
		} else {
			unknown = append(unknown, n)
		}
	}
	return targets, unknown
}

// ── 状态端点 ────────────────────────────────────────────────────────────────

type certStatus struct {
	Name                string `json:"name"`
	NotAfter            string `json:"notAfter,omitempty"`
	DaysLeft            *int   `json:"daysLeft,omitempty"`
	Deployed            bool   `json:"deployed"`
	DeployConfirmed     bool   `json:"deployConfirmed"`
	ConsecutiveFailures int    `json:"consecutiveFailures"`
	NextAttemptAt       string `json:"nextAttemptAt,omitempty"`
	LastError           string `json:"lastError,omitempty"`
}

// handleStatus 让调用方在触发之后能查结果。
//
// 触发是异步的（202），所以需要一个地方回答"到底成了没有" ——
// 否则调用方只能去翻日志。
func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		writeJSON(w, http.StatusMethodNotAllowed,
			map[string]string{"error": "use GET"})
		return
	}

	now := s.now()
	out := struct {
		Time         string       `json:"time"`
		Certificates []certStatus `json:"certificates"`
	}{Time: now.UTC().Format(time.RFC3339)}

	for _, name := range s.rec.CertNames() {
		st := certStatus{Name: name}

		rec, err := s.store.GetCert(name)
		if err != nil {
			s.log.Warn("failed to read the certificate state", "cert", name, "err", err)
			out.Certificates = append(out.Certificates, st)
			continue
		}
		if rec != nil {
			if !rec.NotAfter.IsZero() {
				st.NotAfter = rec.NotAfter.UTC().Format(time.RFC3339)
				days := int(rec.NotAfter.Sub(now).Hours() / 24)
				st.DaysLeft = &days
			}
			st.Deployed = rec.DeployedCertID != ""
			st.DeployConfirmed = rec.DeployConfirmed
			st.ConsecutiveFailures = rec.ConsecutiveFailures
			st.LastError = rec.LastError
			if !rec.NextAttemptAt.IsZero() {
				st.NextAttemptAt = rec.NextAttemptAt.UTC().Format(time.RFC3339)
			}
		}
		out.Certificates = append(out.Certificates, st)
	}

	writeJSON(w, http.StatusOK, out)
}

// ── 诊断端点 ────────────────────────────────────────────────────────────────

// desiredCert 把"期望什么"和"实际上有没有"并排放在一起。
type desiredCert struct {
	Name     string   `json:"name"`
	Domains  []string `json:"domains"`
	Profile  string   `json:"profile"`
	KeyType  string   `json:"keyType"`
	Deploy   bool     `json:"deploy"`
	Issued   bool     `json:"issued"`
	NotAfter string   `json:"notAfter,omitempty"`
	DaysLeft *int     `json:"daysLeft,omitempty"`
}

type desiredView struct {
	Revision string `json:"revision,omitempty"`
	Frozen   bool   `json:"frozen"`

	// FreezeReason 非空说明这一轮来源读不到，收敛在上一版可用状态上。
	FreezeReason string `json:"freezeReason,omitempty"`

	GeneratedAt string             `json:"generatedAt,omitempty"`
	Shadow      *spec.ShadowReport `json:"shadow,omitempty"`

	Certificates []desiredCert   `json:"certificates"`
	Decisions    []spec.Decision `json:"decisions"`
}

// handleDesired 回答这套系统上线后最常被问的那几个问题：
//
//	期望状态是什么？        certificates
//	某个域名为什么没进去？   decisions[].reason
//	和另一份来源差在哪？     shadow（observe 模式下）
//	期望了但实际有没有？     certificates[].issued
//
// 没有它，这几个问题都只能靠翻日志，而日志会被轮转掉。
func (s *Server) handleDesired(dr DesiredReader) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.Header().Set("Allow", "GET")
			writeJSON(w, http.StatusMethodNotAllowed,
				map[string]string{"error": "use GET"})
			return
		}

		res := dr.LastResult()
		if res == nil {
			// 还没成功读过一次期望状态。这不是"期望为空"，
			// 所以绝不能返回一份空的证书列表 —— 那会被读成"什么都没有"。
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{
				"error": "no desired state has been read yet; this is not the same as an empty desired state",
			})
			return
		}

		now := s.now()
		out := desiredView{
			Revision:     res.Revision,
			Frozen:       res.Frozen,
			FreezeReason: res.FreezeReason,
			Shadow:       res.Shadow,
			Decisions:    res.Decisions,
			Certificates: make([]desiredCert, 0, len(res.Certificates)),
		}
		if !res.GeneratedAt.IsZero() {
			out.GeneratedAt = res.GeneratedAt.UTC().Format(time.RFC3339)
		}

		for i := range res.Certificates {
			c := &res.Certificates[i]
			dc := desiredCert{
				Name:    c.Name,
				Domains: c.Domains,
				Profile: c.Profile,
				KeyType: c.KeyType,
				Deploy:  c.Deploy.Enabled,
			}
			if st, err := s.store.GetCert(c.Name); err == nil && st != nil && !st.NotAfter.IsZero() {
				dc.Issued = true
				dc.NotAfter = st.NotAfter.UTC().Format(time.RFC3339)
				days := int(st.NotAfter.Sub(now).Hours() / 24)
				dc.DaysLeft = &days
			}
			out.Certificates = append(out.Certificates, dc)
		}

		writeJSON(w, http.StatusOK, out)
	}
}

// ── 小工具 ──────────────────────────────────────────────────────────────────

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(v)
}

func subtract(all, remove []string) []string {
	if len(remove) == 0 {
		return all
	}
	drop := make(map[string]struct{}, len(remove))
	for _, n := range remove {
		drop[n] = struct{}{}
	}
	out := make([]string, 0, len(all))
	for _, n := range all {
		if _, ok := drop[n]; !ok {
			out = append(out, n)
		}
	}
	return out
}
