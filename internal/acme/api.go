package acme

import (
	"net/http"

	legoacme "github.com/go-acme/lego/v4/acme"
	"github.com/go-acme/lego/v4/acme/api"
)

// API 是 Manager 需要的**全部** ACME 操作。
//
// 抽出来是为了让完整签发流程能进单测。在此之前只有清理路径有窄接口，
// 于是订单状态机 —— 这套系统里最容易出错、也最贵的一段 —— 只能靠
// 起一个假的 ACME HTTP 服务器来覆盖。那能跑，但没法回答"它到底按什么
// 顺序调了哪些方法"，而顺序恰恰是这里全部的正确性所在：
//
//   - order URL 必须在 newOrder 返回之后**立刻**落盘，在任何别的事情之前
//   - 通配符与顶点必须"全写 → 全验 → 一起清"
//   - CSR 必须提交到 finalize URL，而不是 order URL
//   - 下单必须带 replaces，否则拿不到 ARI 的限速豁免
//
// 这几条任何一条错了，代价都是 7 天不可恢复的 exact-set 限额。
//
// 注意这些方法**不带 context**：lego 的 api.Core 本身不是 context 感知的，
// 它靠 http.Client 的超时。硬加一个 ctx 参数只会造出一个"看起来能取消、
// 实际不会"的假接口 —— 那比没有更危险，因为它会让人以为取消是生效的。
type API interface {
	// NewOrder 新建订单。
	//
	// opts 里的 ReplacesCertID 是 ARI 限速豁免的前提。漏掉它不会报错，
	// 只会让这次签发实打实地消耗配额 —— 这类"不报错的错误"正是
	// 需要一个能断言调用参数的假实现的原因。
	NewOrder(domains []string, opts *api.OrderOptions) (legoacme.ExtendedOrder, error)

	// GetOrder 读订单当前状态。幂等，也是崩溃恢复的入口。
	GetOrder(orderURL string) (legoacme.ExtendedOrder, error)

	// UpdateOrderForCSR 把 CSR 提交到 finalize URL。
	//
	// 参数名是 finalizeURL 而不是 lego 那个误导性的 orderURL：
	// 传了 order URL 会被 LE 当成 POST-as-GET 并报
	// "POST-as-GET requests must have an empty payload"。
	UpdateOrderForCSR(finalizeURL string, csr []byte) (legoacme.ExtendedOrder, error)

	// GetAuthorization 读一条授权的当前状态。
	GetAuthorization(authzURL string) (legoacme.Authorization, error)

	// AcceptChallenge 通知 CA 去验证。
	AcceptChallenge(challengeURL string) error

	// GetCertificate 下载证书。bundle=true 时返回 fullchain（叶子 + 中间），
	// 正是 CLB 需要的格式。
	GetCertificate(certURL string, bundle bool) ([]byte, []byte, error)

	// GetRenewalInfo 读 ARI（RFC 9773）。
	//
	// 返回原始的 *http.Response 而不是解析好的结构，是因为 Retry-After
	// 头本身就是结论的一部分 —— lego 已经帮我们处理了它两种格式
	// （秒数 / HTTP-date），而这个头决定"多久之后再来问"。
	GetRenewalInfo(certID string) (*http.Response, error)

	// GetKeyAuthorization 把 challenge token 换算成 key authorization，
	// 也就是要写进 DNS TXT 的那个值。
	GetKeyAuthorization(token string) (string, error)
}

// NewAPI 把 lego 的 *api.Core 适配成 API。
func NewAPI(core *api.Core) API { return coreAPI{core: core} }

// coreAPI 是 API 在 lego 上的实现。
//
// 刻意只做转发、不做任何判断：判断属于 Manager，而 adapter 里多一行逻辑
// 就多一个只有真跑 ACME 才能覆盖的地方 —— 那正是这次重构要消除的东西。
type coreAPI struct{ core *api.Core }

func (c coreAPI) NewOrder(domains []string, opts *api.OrderOptions) (legoacme.ExtendedOrder, error) {
	return c.core.Orders.NewWithOptions(domains, opts)
}

func (c coreAPI) GetOrder(orderURL string) (legoacme.ExtendedOrder, error) {
	return c.core.Orders.Get(orderURL)
}

func (c coreAPI) UpdateOrderForCSR(finalizeURL string, csr []byte) (legoacme.ExtendedOrder, error) {
	return c.core.Orders.UpdateForCSR(finalizeURL, csr)
}

func (c coreAPI) GetAuthorization(authzURL string) (legoacme.Authorization, error) {
	return c.core.Authorizations.Get(authzURL)
}

// AcceptChallenge 把 lego 返回的 ExtendedChallenge 丢掉。
//
// Manager 只关心"通知发出去了没有"，而逼着假实现去构造一个它根本不看的
// 结构体，只会让测试里多出一堆与断言无关的噪声。
func (c coreAPI) AcceptChallenge(challengeURL string) error {
	_, err := c.core.Challenges.New(challengeURL)
	return err
}

func (c coreAPI) GetCertificate(certURL string, bundle bool) ([]byte, []byte, error) {
	return c.core.Certificates.Get(certURL, bundle)
}

func (c coreAPI) GetRenewalInfo(certID string) (*http.Response, error) {
	return c.core.Certificates.GetRenewalInfo(certID)
}

func (c coreAPI) GetKeyAuthorization(token string) (string, error) {
	return c.core.GetKeyAuthorization(token)
}
