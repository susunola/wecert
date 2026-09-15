package acme

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	legoacme "github.com/go-acme/lego/v4/acme"
	"github.com/go-acme/lego/v4/acme/api"

	"github.com/atom/wecert/internal/config"
	"github.com/atom/wecert/internal/deploy"
	"github.com/atom/wecert/internal/state"
)

// 授权轮询与订单等待的上限。超过就退避，下一轮接着推进同一个订单 ——
// 因为订单已经落盘，"下一轮"是廉价的，重新下单才是昂贵的。
const (
	authzWaitTimeout = 3 * time.Minute
	orderWaitTimeout = 2 * time.Minute
	pollInterval     = 3 * time.Second
	// ACME 的 expires 是可选字段。解析失败或未返回时用这个保守上限，
	// 绝不能落成零值 —— 零值会被当成"已经过期"而丢掉未完成的订单。
	defaultOrderTTL = 7 * 24 * time.Hour
)

// Manager 把期望状态（config.Certificate）收敛到实际状态（state.CertState）。
//
// 整个系统的正确性依赖三条不变量，都体现在下面的代码里：
//
//  1. 任何时刻每张证书最多一个进行中的订单，且 order URL 必须落盘。
//     reconcile 进来先看有没有未过期的 pending order，有就推进它，绝不新建。
//  2. ARI 优先，且下单时必须带 replaces —— 不带就拿不到"豁免全部速率限制"的待遇。
//  3. wildcard 与 apex 会写到同一个 _acme-challenge 名字上，
//     必须"全部写入 → 全部验证 → 才统一清理"。
type Manager struct {
	store    *state.Store
	core     *api.Core
	dns      *DNSSolver
	deployer deploy.Deployer
	log      *slog.Logger

	ariInterval time.Duration
	retention   time.Duration
	now         func() time.Time
}

// NewManager 构造收敛器。
func NewManager(
	store *state.Store,
	core *api.Core,
	dns *DNSSolver,
	deployer deploy.Deployer,
	log *slog.Logger,
) *Manager {
	return &Manager{
		store:       store,
		core:        core,
		dns:         dns,
		deployer:    deployer,
		log:         log,
		ariInterval: 6 * time.Hour,
		retention:   7 * 24 * time.Hour,
		now:         time.Now,
	}
}
