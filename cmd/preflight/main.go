// Command preflight 在动任何云资源之前验证凭证与前置条件。
//
// 检查三件事（全部只读，不会创建或修改任何东西）：
//  1. 凭证能用（SSL 证书服务能列出来）
//  2. 有 DNSPod 读权限，且目标域名确实在这个账号下
//  3. 目标域名的 NS 确实指向 DNSPod —— 否则写了 TXT 也不会生效，
//     白白消耗一次授权失败配额
//  4. 是否已存在 _acme-challenge 记录（残留会让验证出现难以解释的结果）
//
// 第 3 项是排障价值最高的一条，也是"写了 TXT 但 CA 就是验不过"
// 最常见的根因：域名托管在别处，或者 NS 还没切换完。
package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common"
	tcerrors "github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common/errors"
	"github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common/profile"
	dnspod "github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/dnspod/v20210323"
	ssl "github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/ssl/v20191205"
)

func main() {
	domain := flag.String("domain", "", "domain to verify, e.g. atomwangnus.com")
	listCerts := flag.Bool("list-certs", false, "list SSL certificates in the account (ID / alias / domain / status)")
	pruneCerts := flag.Bool("prune-certs", false, "delete the certificates wecert uploaded (alias starting with wecert/)")
	yes := flag.Bool("yes", false, "use with -prune-certs to skip the interactive confirmation")
	flag.Parse()

	switch {
	case *pruneCerts:
		if err := pruneCertificates(*yes); err != nil {
			fmt.Fprintf(os.Stderr, "\n❌ %v\n", err)
			os.Exit(1)
		}
		return
	case *listCerts:
		if err := listCertificates(); err != nil {
			fmt.Fprintf(os.Stderr, "\n❌ %v\n", err)
			os.Exit(1)
		}
		return
	case *domain == "":
		fmt.Fprintln(os.Stderr, "usage: preflight -domain <domain>")
		fmt.Fprintln(os.Stderr, "      preflight -list-certs")
		fmt.Fprintln(os.Stderr, "      preflight -prune-certs [-yes]")
		os.Exit(1)
	}

	if err := run(*domain); err != nil {
		fmt.Fprintf(os.Stderr, "\nFAILED: preflight error: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("\nOK: all preflight checks passed")
}

// creds 读取并校验腾讯云凭证。
//
// 不回显 SecretId 前缀：旧的实现直接写 id[:8]，环境变量被截断或写错时
// 会 panic，而且把一个秘密的前缀写进终端历史也没什么好处 ——
// 知道"已加载"就够了。
func creds() (common.CredentialIface, error) {
	id := os.Getenv("TENCENTCLOUD_SECRET_ID")
	key := os.Getenv("TENCENTCLOUD_SECRET_KEY")
	if id == "" || key == "" {
		return nil, fmt.Errorf("missing credentials: set TENCENTCLOUD_SECRET_ID / TENCENTCLOUD_SECRET_KEY")
	}
	return common.NewCredential(id, key), nil
}

func run(domain string) error {
	cred, err := creds()
	if err != nil {
		return err
	}
	fmt.Println("credentials: loaded")
	fmt.Println()

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	if err := checkSSL(ctx, cred); err != nil {
		return err
	}
	if err := checkDNSPod(ctx, cred, domain); err != nil {
		return err
	}
	return checkDelegation(ctx, domain)
}

// checkDelegation 确认域名的权威 NS 确实是 DNSPod 的。
//
// 这一条值得单独查：域名写进 DNSPod 了、但 NS 还指着别处托管商，
// 是"TXT 写成功、CA 却验证失败"最典型的成因。此时 wecert 每次尝试
// 都要赔上一次 authorization failure 配额（5 次/小时），
// 而错误信息只会说"验证失败"，看不出根因。
func checkDelegation(ctx context.Context, domain string) error {
	fmt.Println()
	fmt.Println("[4/4] authoritative nameserver delegation check")

	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	names, err := net.DefaultResolver.LookupNS(ctx, domain)
	if err != nil {
		return fmt.Errorf("lookup NS for %s failed: %w", domain, err)
	}
	if len(names) == 0 {
		return fmt.Errorf("%s has no NS records", domain)
	}

	var hosts []string
	onDNSPod := false
	for _, ns := range names {
		host := strings.TrimSuffix(ns.Host, ".")
		hosts = append(hosts, host)
		// DNSPod 的权威 NS 域名形如 xxx.dnspod.net / xxx.dnsv1.com 等。
		if strings.Contains(host, "dnspod") || strings.Contains(host, "dnsv") {
			onDNSPod = true
		}
	}

	if !onDNSPod {
		return fmt.Errorf(
			"%s's nameservers are not DNSPod: %s\n"+
				"     TXT records written at DNSPod will never be resolved, so CA validation is guaranteed to fail.\n"+
				"     point the domain's NS at DNSPod first, or switch to the dns.provider for that host\n",
			domain, strings.Join(hosts, ", "))
	}

	fmt.Printf("      OK - %d nameservers, all pointing at DNSPod (%s)\n", len(hosts), hosts[0])
	return nil
}

// checkSSL 验证 SSL 证书服务的读权限。
func checkSSL(ctx context.Context, cred common.CredentialIface) error {
	fmt.Println("[1/4] SSL certificate service read access")
	cpf := profile.NewClientProfile()
	cpf.HttpProfile.Endpoint = "ssl.tencentcloudapi.com"

	client, err := ssl.NewClient(cred, "", cpf)
	if err != nil {
		return fmt.Errorf("build SSL client: %w", err)
	}

	req := ssl.NewDescribeCertificatesRequest()
	req.Limit = common.Uint64Ptr(1)

	resp, err := client.DescribeCertificatesWithContext(ctx, req)
	if err != nil {
		return fmt.Errorf("DescribeCertificates failed (check the ssl:DescribeCertificates permission): %w", err)
	}

	var total uint64
	if resp.Response != nil && resp.Response.TotalCount != nil {
		total = *resp.Response.TotalCount
	}
	fmt.Printf("      OK - the account already holds %d certificates\n", total)
	return nil
}

// checkDNSPod 验证 DNSPod 读权限，并确认域名在这个账号下。
func checkDNSPod(ctx context.Context, cred common.CredentialIface, domain string) error {
	fmt.Println("[2/4] DNSPod domain ownership")

	cpf := profile.NewClientProfile()
	cpf.HttpProfile.Endpoint = "dnspod.tencentcloudapi.com"

	client, err := dnspod.NewClient(cred, "", cpf)
	if err != nil {
		return fmt.Errorf("build DNSPod client: %w", err)
	}

	// 先用接口直接查目标域名，比拉全量列表再匹配更准。
	req := dnspod.NewDescribeDomainListRequest()
	req.Keyword = common.StringPtr(domain)
	req.Limit = common.Int64Ptr(20)

	resp, err := client.DescribeDomainListWithContext(ctx, req)
	if err != nil {
		return fmt.Errorf("DescribeDomainList failed (check the dnspod:DescribeDomainList permission): %w", err)
	}

	var found *dnspod.DomainListItem
	if resp.Response != nil {
		for _, d := range resp.Response.DomainList {
			if d.Name != nil && strings.EqualFold(*d.Name, domain) {
				found = d
				break
			}
		}
	}

	if found == nil {
		return fmt.Errorf(
			"domain %s is not under DNSPod in this Tencent Cloud account.\n"+
				"     either the domain is hosted elsewhere, or you need a DNSPod API token (dns.provider=dnspod)",
			domain)
	}

	fmt.Printf("      OK - %s found", deref(found.Name))
	if found.Status != nil {
		fmt.Printf(", status %s", *found.Status)
	}
	if found.Grade != nil {
		fmt.Printf(", plan %s", *found.Grade)
	}
	fmt.Println()

	// 顺手检查 _acme-challenge 有没有残留记录。
	recReq := dnspod.NewDescribeRecordListRequest()
	recReq.Domain = common.StringPtr(domain)
	recReq.Subdomain = common.StringPtr("_acme-challenge")
	recReq.RecordType = common.StringPtr("TXT")

	recResp, err := client.DescribeRecordListWithContext(ctx, recReq)
	if err != nil {
		// DNSPod 在"一条记录都没有"时返回的是错误码而不是空列表，
		// 这恰恰是我们想看到的状态，不能当失败。
		if isNoRecord(err) {
			fmt.Println()
			fmt.Println("[3/4] _acme-challenge leftover check")
			fmt.Println("      OK - no leftover TXT records")
			return nil
		}
		return fmt.Errorf("DescribeRecordList failed (check the dnspod:DescribeRecordList permission): %w", err)
	}

	n := 0
	var records []*dnspod.RecordListItem
	if recResp.Response != nil {
		records = recResp.Response.RecordList
		n = len(records)
	}
	fmt.Println()
	fmt.Println("[3/4] _acme-challenge leftover check")
	if n == 0 {
		fmt.Println("      OK - no leftover TXT records")
	} else {
		fmt.Printf("      WARNING: %d TXT records already exist; confirm another system is not using them:\n", n)
		for _, r := range records {
			fmt.Printf("          %s = %s\n", deref(r.Name), deref(r.Value))
		}
	}
	return nil
}

func deref(s *string) string {
	if s == nil {
		return "<nil>"
	}
	return *s
}

// isNoRecord 判断错误是否为"记录列表为空"。
// DNSPod 用 ResourceNotFound.NoDataOfRecord 表达这个语义。
func isNoRecord(err error) bool {
	var sdkErr *tcerrors.TencentCloudSDKError
	if errors.As(err, &sdkErr) {
		return sdkErr.Code == "ResourceNotFound.NoDataOfRecord"
	}
	return strings.Contains(err.Error(), "NoDataOfRecord")
}

// listCertificates 列出账号下的 SSL 证书。
// 主要用途：确认 wecert 上传的证书到底是什么状态，
// 以及找出测试过程中堆积的证书以便清理。
func listCertificates() error {
	cred, err := creds()
	if err != nil {
		return err
	}

	cpf := profile.NewClientProfile()
	cpf.HttpProfile.Endpoint = "ssl.tencentcloudapi.com"
	client, err := ssl.NewClient(cred, "", cpf)
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	req := ssl.NewDescribeCertificatesRequest()
	req.Limit = common.Uint64Ptr(100)
	resp, err := client.DescribeCertificatesWithContext(ctx, req)
	if err != nil {
		return err
	}
	if resp.Response == nil {
		return fmt.Errorf("DescribeCertificates returned an empty response")
	}

	fmt.Printf("%-12s %-28s %-40s %-10s %s\n", "CertId", "alias", "domain", "status", "source")
	for _, c := range resp.Response.Certificates {
		fmt.Printf("%-12s %-28s %-40s %-10d %s\n",
			deref(c.CertificateId), deref(c.Alias), deref(c.Domain), derefU64(c.Status), deref(c.CertificateType))
	}

	listed := len(resp.Response.Certificates)
	total := derefU64(resp.Response.TotalCount)
	fmt.Printf("\n%d total\n", total)
	if total > uint64(listed) {
		// 不做分页就会漏删、也会让人误以为列表是完整的。
		fmt.Printf("note: the server reports %d in total, more than the %d listed here (page size 100),"+
			"so this list may be incomplete\n", total, listed)
	}
	return nil
}

func derefU64(v *uint64) uint64 {
	if v == nil {
		return 0
	}
	return *v
}

// pruneCertificates 删除 wecert 上传的证书。
//
// 为什么需要它：腾讯云账号下上传证书数量有配额，长期测试/长期运行的自动化
// 如果不回收，早晚会撞上配额导致无法续期。
//
// ⚠️ 关于范围：wecert 上传证书时给**所有**证书打的前缀都是 "wecert/"
// （见 deploy.tencent.go 的 upload），所以这里筛出来的不只是测试留下的证书，
// **也包括线上正在服务的那张**。因此必须有确认门禁 ——
// 早先的实现打印完列表就直接开删，一个没有 --dry-run 习惯的人很容易误伤生产。
func pruneCertificates(assumeYes bool) error {
	cred, err := creds()
	if err != nil {
		return err
	}

	cpf := profile.NewClientProfile()
	cpf.HttpProfile.Endpoint = "ssl.tencentcloudapi.com"
	client, err := ssl.NewClient(cred, "", cpf)
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	listReq := ssl.NewDescribeCertificatesRequest()
	listReq.Limit = common.Uint64Ptr(100)
	listResp, err := client.DescribeCertificatesWithContext(ctx, listReq)
	if err != nil {
		return err
	}
	if listResp.Response == nil {
		return fmt.Errorf("DescribeCertificates returned an empty response")
	}

	const prefix = "wecert/"
	var doomed []*ssl.Certificates
	for _, c := range listResp.Response.Certificates {
		if strings.HasPrefix(deref(c.Alias), prefix) {
			doomed = append(doomed, c)
		}
	}

	if len(doomed) == 0 {
		fmt.Println("no wecert-uploaded certificates to clean up")
		return nil
	}

	fmt.Printf("about to delete %d certificates uploaded by wecert:\n", len(doomed))
	for _, c := range doomed {
		fmt.Printf("  %-12s %-28s %s\n", deref(c.CertificateId), deref(c.Alias), deref(c.Domain))
	}
	fmt.Println()
	fmt.Println("WARNING: this list includes certificates currently serving live traffic - wecert uses the same alias prefix")
	fmt.Println("    for every certificate it uploads. Deleting one that a CLB still references will break HTTPS.")
	fmt.Println("    if you only meant to clean up test leftovers, check the alias and domain above first.")

	if !assumeYes {
		if !confirm("delete all of the certificates above?") {
			fmt.Println("cancelled; nothing was deleted")
			return nil
		}
	}

	var failed int
	for _, c := range doomed {
		req := ssl.NewDeleteCertificateRequest()
		req.CertificateId = c.CertificateId
		// 我们自己在状态库里管绑定关系，不需要服务端再检查关联资源。
		req.IsCheckResource = common.BoolPtr(false)
		if _, err := client.DeleteCertificateWithContext(ctx, req); err != nil {
			fmt.Printf("  failed to delete %s: %v\n", deref(c.CertificateId), err)
			failed++
			continue
		}
		fmt.Printf("  deleted %s\n", deref(c.CertificateId))
	}
	if failed > 0 {
		return fmt.Errorf("%d certificates could not be deleted (the rest were)", failed)
	}
	return nil
}

// confirm 在终端上读一次 y/N。非交互环境（stdin 不是终端）时按拒绝处理 ——
// 删证书这件事不该因为"没人在那儿看"就默认通过。
func confirm(prompt string) bool {
	fmt.Printf("%s [y/N] ", prompt)

	sc := bufio.NewScanner(os.Stdin)
	if !sc.Scan() {
		fmt.Println()
		return false
	}
	switch strings.ToLower(strings.TrimSpace(sc.Text())) {
	case "y", "yes":
		return true
	default:
		return false
	}
}
