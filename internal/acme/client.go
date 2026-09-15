package acme

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"net/http"
	"time"

	legoacme "github.com/go-acme/lego/v4/acme"
	"github.com/go-acme/lego/v4/acme/api"

	"github.com/atom/wecert/internal/config"
	"github.com/atom/wecert/internal/state"
)

// userAgent 会出现在 ACME 请求里，排障时能对上日志。
const userAgent = "wecert/0.1 (+https://github.com/susunola/wecert)"

// NewHTTPClient 构造 ACME 用的 HTTP 客户端。
func NewHTTPClient(timeout time.Duration) *http.Client {
	return &http.Client{Timeout: timeout}
}

// EnsureAccount 加载或注册 ACME 账号，返回可直接使用的低层 api.Core。
//
// 这里刻意用低层 api.Core，而不是 lego 高层的 certificate.Obtain。
// 原因：高层会在内部自己 newOrder，我们无法把 order URL 持久化并跨重启复用 ——
// 进程一崩溃重启就会重新下单，直接撞上
// "5 certificates per exact set of identifiers / 7 days" 这条限额。
//
// 账号私钥和 kid 都落 SQLite：丢了就等于换了个新账号，
// 白白多消耗一份账号维度的配额。
func EnsureAccount(cfg *config.Config, store *state.Store, httpClient *http.Client) (*api.Core, error) {
	directory := cfg.ACME.Directory

	acc, err := store.GetAccount(directory)
	if err != nil {
		return nil, err
	}

	if acc != nil && len(acc.PrivateKeyPEM) > 0 {
		key, err := ParsePrivateKeyPEM(acc.PrivateKeyPEM)
		if err != nil {
			return nil, fmt.Errorf("解析已存的账号私钥: %w", err)
		}
		core, err := api.New(httpClient, userAgent, directory, acc.KID, key)
		if err != nil {
			return nil, fmt.Errorf("初始化 ACME 客户端: %w", err)
		}
		return core, nil
	}

	// 首次运行：生成账号私钥并注册账号。
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("生成账号私钥: %w", err)
	}

	core, err := api.New(httpClient, userAgent, directory, "", key)
	if err != nil {
		return nil, fmt.Errorf("初始化 ACME 客户端: %w", err)
	}

	reg, err := core.Accounts.New(legoacme.Account{
		Contact:              []string{"mailto:" + cfg.ACME.Email},
		TermsOfServiceAgreed: true,
	})
	if err != nil {
		return nil, fmt.Errorf("注册 ACME 账号: %w", err)
	}
	if reg.Location == "" {
		return nil, fmt.Errorf("注册 ACME 账号: 服务器未返回账号 URL (kid)")
	}

	keyPEM, err := MarshalPrivateKeyPEM(key)
	if err != nil {
		return nil, err
	}
	if err := store.PutAccount(&state.Account{
		Directory:     directory,
		KID:           reg.Location,
		PrivateKeyPEM: keyPEM,
	}); err != nil {
		return nil, err
	}

	return core, nil
}

// 编译期断言：注册账号用的 ECDSA 私钥必须满足 crypto.PrivateKey，
// 否则 api.New 在运行时才会报错。
var _ crypto.PrivateKey = (*ecdsa.PrivateKey)(nil)
