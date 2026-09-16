package spec

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/susunola/wecert/internal/config"
	"github.com/susunola/wecert/internal/group"
)

// 文档信封。这两个字段不是装饰：它们让"拿错文件"变成一条清晰的报错，
// 而不是一份被静默当成期望状态解析的无关 YAML。
const (
	APIVersionV1     = "wecert/v1"
	KindDesiredState = "DesiredState"
)

// DocumentHeader 写在生成的文档最前面。
//
// 文档是**派生产物**：手工改它会在下一次 onboarding 时被覆盖。
// 把这句话放在文件第一行，比写在 README 里有用得多。
const DocumentHeader = `# 本文件由 wecert-onboard 生成，请勿手工编辑。
# 它是一份契约：wecert 只读它，不做任何推断。
# 要改期望状态，请改上游声明（DNS 的 _wecert 记录 / onboarding 配置），
# 然后重跑 wecert-onboard；手工改动会在下一次生成时被覆盖。
`

// Document 是 onboarding 组件与 wecert 之间的契约。
type Document struct {
	APIVersion string `yaml:"apiVersion" json:"apiVersion"`
	Kind       string `yaml:"kind" json:"kind"`

	// GeneratedAt 是写入时刻。wecert 用它判断文档是不是已经太旧
	// （太旧意味着 onboarding 组件挂了，而这本身需要告警）。
	GeneratedAt time.Time `yaml:"generatedAt" json:"generatedAt"`

	// Generator 记下是谁、什么版本写的，便于回溯"上周二为什么多签了一张"。
	Generator string `yaml:"generator" json:"generator"`

	// Revision 是 Certificates 的指纹，与 Result.Revision 同源。
	Revision string `yaml:"revision" json:"revision"`

	Certificates []config.Certificate `yaml:"certificates" json:"certificates"`
}

// Revision 是期望状态内容的指纹。
//
// 只覆盖证书本身，故意**不含** GeneratedAt 和 Revision：否则每跑一次
// onboarding 指纹都会变，"期望状态到底变了没有"这个最基本的问题就答不了。
// 域名先排序，让顺序差异不被误判成变化。
func Revision(certs []config.Certificate) string {
	h := sha256.New()
	for _, c := range certs {
		fmt.Fprintf(h, "name=%s\nprofile=%s\nkeyType=%s\nrenewBefore=%s\ndeploy=%t\n",
			c.Name, c.Profile, c.KeyType, c.RenewBefore, c.Deploy.Enabled)

		domains := append([]string(nil), c.Domains...)
		sort.Strings(domains)
		for _, d := range domains {
			fmt.Fprintf(h, "domain=%s\n", d)
		}
		h.Write([]byte{0})
	}
	return "sha256:" + hex.EncodeToString(h.Sum(nil))[:16]
}

// LoadDocument 读取并校验一份期望状态文档。
//
// 校验比配置文件更严，因为这份文档是机器写的：机器写的文件出了问题，
// 说明上游逻辑有 bug，此时**拒绝**远比"尽力而为"安全。
func LoadDocument(path string) (*Document, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read desired-state document: %w", err)
	}

	doc := &Document{}
	dec := yaml.NewDecoder(bytes.NewReader(data))
	// 未知字段直接报错：文档是契约，字段拼错必须炸，不能被静默忽略 ——
	// 一个被忽略的 deploy 字段会让证书签出来却不部署，而且毫无声响。
	dec.KnownFields(true)
	if err := dec.Decode(doc); err != nil {
		return nil, fmt.Errorf("parse desired-state document %s: %w", path, err)
	}

	if err := doc.Validate(); err != nil {
		return nil, fmt.Errorf("desired-state document %s: %w", path, err)
	}
	return doc, nil
}

// Validate 校验文档的信封、证书列表与 Name 稳定性。
func (d *Document) Validate() error {
	if d.APIVersion != APIVersionV1 {
		return fmt.Errorf("apiVersion must be %q, got %q", APIVersionV1, d.APIVersion)
	}
	if d.Kind != KindDesiredState {
		return fmt.Errorf("kind must be %q, got %q", KindDesiredState, d.Kind)
	}
	if d.GeneratedAt.IsZero() {
		return errors.New("generatedAt is required: without it there is no way to tell a fresh document from one the onboarding component stopped updating weeks ago")
	}

	// 空文档一律拒绝。
	//
	// "合法的空"和"生成失败导致的空"在文件里长得一模一样，而后者一旦被接受，
	// 后果是每张证书的每个域名都被摘掉。这个风险不对称到不值得为了
	// "支持真的想清空"而留口子 —— 那件事应该由人显式地、吵闹地去做。
	if len(d.Certificates) == 0 {
		return errors.New("certificates is empty: an empty desired state is indistinguishable from a failed generation, and acting on it would strip every name from every certificate")
	}

	// 与静态配置走同一个入口，避免两条路径的宽松程度不一致。
	if err := config.NormalizeCertificates(d.Certificates); err != nil {
		return err
	}

	for i := range d.Certificates {
		if err := checkNameStability(&d.Certificates[i]); err != nil {
			return err
		}
	}

	want := Revision(d.Certificates)
	if d.Revision == "" {
		d.Revision = want
	} else if d.Revision != want {
		return fmt.Errorf("revision %q does not match the certificates it describes (computed %q); "+
			"the file was most likely edited by hand or written by a different generator", d.Revision, want)
	}
	return nil
}

// checkNameStability 钉住 Name 稳定性。
//
// 证书名必须由分组键派生，而不是由域名集合派生。这条一旦破掉，
// 加一个域名就会在状态库里凭空多出一条新记录，旧那条的 order URL、
// ARI certID、deployed CertID 全部成为孤儿 ——
// "每张证书最多一个进行中的订单"随之失效，两边的订单会同时飞，
// 直接撞上 exact-set 限速（5 / 7 天，没有 override）。
//
// 这个检查放在契约边界上，因为这里是唯一能拦住它的地方：
// 等到 wecert 读进来的时候，孤儿状态已经产生了。
func checkNameStability(c *config.Certificate) error {
	regs := make(map[string]bool, 1)
	for _, d := range c.Domains {
		if reg := group.RegisteredDomain(d); reg != "" {
			regs[reg] = true
		}
	}
	if len(regs) == 0 {
		return fmt.Errorf("certificate %q: no domain has a registered domain", c.Name)
	}
	if len(regs) > 1 {
		// 跨注册域 = 爆炸半径失控，而且 LE 的配额本来就是按注册域算的，
		// 把它们塞进一张证书只会让"谁拖死了谁"变得无法解释。
		names := make([]string, 0, len(regs))
		for r := range regs {
			names = append(names, r)
		}
		sort.Strings(names)
		return fmt.Errorf("certificate %q spans %d registered domains (%s): "+
			"every name in one certificate lives and dies together, and Let's Encrypt counts quota per registered domain, "+
			"so one certificate must stay inside one registered domain",
			c.Name, len(regs), strings.Join(names, ", "))
	}

	var reg string
	for r := range regs {
		reg = r
	}
	if want := group.CertName(reg); c.Name != want {
		return fmt.Errorf("certificate name %q is not stable for its domains: they all belong to %q, "+
			"so the name must be %q; a name that follows the domain set orphans the order URL, "+
			"ARI certID and deployed CertID every time a domain is added or removed",
			c.Name, reg, want)
	}
	return nil
}

// WriteDocument 原子地写下文档。
//
// 必须先写同目录临时文件再 rename：wecert 可能正好在读到一半的时刻，
// 而一份被截断的文档看起来就像"域名少了一半" —— 那正是最危险的输入。
// rename 在同一个文件系统内是原子的，读者要么看到旧版，要么看到新版。
func WriteDocument(path string, doc *Document) error {
	if err := doc.Validate(); err != nil {
		return err
	}
	return WriteDocumentUnchecked(path, doc)
}

// WriteDocumentUnchecked 与 WriteDocument 相同，但不做校验。
//
// 仅给 onboarding 组件在校验会失败、又必须留下证据的场景使用
// （比如把一份"本该生成但没有"的状态写进报告），不要用它绕开校验。
func WriteDocumentUnchecked(path string, doc *Document) error {
	body, err := yaml.Marshal(doc)
	if err != nil {
		return fmt.Errorf("encode desired-state document: %w", err)
	}

	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".desired-state-*.tmp")
	if err != nil {
		return fmt.Errorf("create temp file in %s: %w", dir, err)
	}
	tmpName := tmp.Name()
	// 任何一条失败路径都要把临时文件清掉，否则目录里会慢慢积起垃圾。
	defer func() {
		if tmpName != "" {
			_ = os.Remove(tmpName)
		}
	}()

	if _, err := tmp.WriteString(DocumentHeader); err != nil {
		tmp.Close()
		return fmt.Errorf("write document header: %w", err)
	}
	if _, err := tmp.Write(body); err != nil {
		tmp.Close()
		return fmt.Errorf("write document body: %w", err)
	}
	// 先 fsync 再 rename：否则机器掉电后可能留下一个 rename 过、
	// 内容却还没落盘的 0 字节文档。
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return fmt.Errorf("sync document: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close document: %w", err)
	}
	if err := os.Chmod(tmpName, 0o644); err != nil {
		return fmt.Errorf("chmod document: %w", err)
	}

	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("replace %s: %w", path, err)
	}
	tmpName = "" // 已经 rename 走了，不要删。
	return nil
}
