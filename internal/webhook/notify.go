package webhook

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"time"
)

// Notifier 把续期结果推到外部 URL。
//
// 它实现的是 reconcile.Notifier。放在这里而不是 reconcile 里，
// 是因为"通过 HTTP 通知"只是一种实现 —— 收敛层只该知道
// "有人想知道结果"，不该知道是怎么通知的。
type Notifier struct {
	url    string
	client *http.Client
	log    *slog.Logger
}

// RenewalEvent 是推给外部的事件体。
type RenewalEvent struct {
	Event     string `json:"event"`
	Cert      string `json:"cert"`
	Result    string `json:"result"` // ok | error
	Error     string `json:"error,omitempty"`
	Timestamp string `json:"timestamp"`
}

// NewNotifier 构造通知器。url 为空时返回 nil，调用方按 nil 处理即可。
func NewNotifier(url string, log *slog.Logger) *Notifier {
	if url == "" {
		return nil
	}
	return &Notifier{
		url: url,
		// 通知是尽力而为的，超时给短一点。
		client: &http.Client{Timeout: 10 * time.Second},
		log:    log,
	}
}

// Renewal 在每次续期尝试结束后推送一条事件。
//
// 刻意是**异步**的：通知目标慢或挂掉，绝不能拖住收敛循环 ——
// 那和"一张证书失败拖住其它证书"是同一类耦合错误。
func (n *Notifier) Renewal(ctx context.Context, certName string, reconcileErr error) {
	if n == nil {
		return
	}

	ev := RenewalEvent{
		Event:     "renewal",
		Cert:      certName,
		Result:    "ok",
		Timestamp: time.Now().UTC().Format(time.RFC3339),
	}
	if reconcileErr != nil {
		ev.Result = "error"
		ev.Error = reconcileErr.Error()
	}

	// 脱离调用方的 ctx：收敛的 ctx 这时候可能已经到期或被取消，
	// 但"续期成功了"这件事仍然值得发出去。
	ctx = context.WithoutCancel(ctx)

	go n.send(ctx, ev)
}

func (n *Notifier) send(ctx context.Context, ev RenewalEvent) {
	body, err := json.Marshal(ev)
	if err != nil {
		n.log.Warn("failed to serialise the notification event", "cert", ev.Cert, "err", err)
		return
	}

	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, n.url, bytes.NewReader(body))
	if err != nil {
		n.log.Warn("failed to build the notification request", "cert", ev.Cert, "err", err)
		return
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := n.client.Do(req)
	if err != nil {
		n.log.Warn("failed to deliver the renewal notification", "cert", ev.Cert, "result", ev.Result, "err", err)
		return
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))

	if resp.StatusCode >= 300 {
		n.log.Warn("the renewal notification was rejected",
			"cert", ev.Cert, "status", resp.StatusCode)
		return
	}
	n.log.Debug("renewal notification delivered", "cert", ev.Cert, "result", ev.Result)
}
