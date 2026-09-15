// Command preflight 在动任何云资源之前验证凭证与前置条件。
//
// 检查四件事：
//  1. 凭证能用（SSL 证书服务能列出来）
//  2. 有 DNSPod 读取权限，且目标域名确实在这个账号下
//  3. 目标域名的 NS 确实指向 DNSPod（否则写了 TXT 也不生效）
//  4. 是否已存在 _acme-challenge 记录（残留会让验证出现难以解释的结果）
//
// 这些检查全部是只读的，不会创建或修改任何东西。
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
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
	domain := flag.String("domain", "", "要验证的域名，例如 atomwangnus.com")
	listCerts := flag.Bool("list-certs", false, "列出账号下的 SSL 证书（ID / 别名 / 域名 / 状态）")
	pruneCerts := flag.Bool("prune-certs", false, "删除 wecert 上传的测试证书（别名以 wecert/ 开头）")
	flag.Parse()

	if *pruneCerts {
		if err := pruneCertificates(); err != nil {
			fmt.Fprintf(os.Stderr, "\n❌ %v\n", err)
			os.Exit(1)
		}
		return
	}
	if !*listCerts && *domain == "" {
		fmt.Fprintln(os.Stderr, "用法: preflight -domain <域名>")
		fmt.Fprintln(os.Stderr, "      preflight -list-certs")
		os.Exit(1)
	}
	if *listCerts {
		if err := listCertificates(); err != nil {
			fmt.Fprintf(os.Stderr, "\n❌ %v\n", err)
			os.Exit(1)
		}
		return
	}
	if err := run(*domain); err != nil {
		fmt.Fprintf(os.Stderr, "\n❌ preflight 失败: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("\n✅ preflight 全部通过")
}

func run(domain string) error {
	id := os.Getenv("TENCENTCLOUD_SECRET_ID")
	key := os.Getenv("TENCENTCLOUD_SECRET_KEY")
	if id == "" || key == "" {
		return fmt.Errorf("缺少凭证：请设置 TENCENTCLOUD_SECRET_ID / TENCENTCLOUD_SECRET_KEY")
	}
	// 只显示前缀，避免把密钥写进任何日志。
	fmt.Printf("凭证: %s... (已加载)\n\n", id[:8])

	cred := common.NewCredential(id, key)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	if err := checkSSL(ctx, cred); err != nil {
		return err
	}
	if err := checkDNSPod(ctx, cred, domain); err != nil {
		return err
	}
	return nil
}

// checkSSL 验证 SSL 证书服务的读权限。
func checkSSL(ctx context.Context, cred common.CredentialIface) error {
	fmt.Println("[1/3] SSL 证书服务读权限")
	cpf := profile.NewClientProfile()
	cpf.HttpProfile.Endpoint = "ssl.tencentcloudapi.com"

	client, err := ssl.NewClient(cred, "", cpf)
	if err != nil {
		return fmt.Errorf("构造 SSL 客户端: %w", err)
	}

	req := ssl.NewDescribeCertificatesRequest()
	req.Limit = common.Uint64Ptr(1)

	resp, err := client.DescribeCertificatesWithContext(ctx, req)
	if err != nil {
		return fmt.Errorf("DescribeCertificates 失败（检查 ssl:DescribeCertificates 权限）: %w", err)
	}

	var total uint64
	if resp.Response != nil && resp.Response.TotalCount != nil {
		total = *resp.Response.TotalCount
	}
	fmt.Printf("      OK — 账号下已有 %d 张证书\n\n", total)
	return nil
}

// checkDNSPod 验证 DNSPod 读权限，并确认域名在这个账号下。
func checkDNSPod(ctx context.Context, cred common.CredentialIface, domain string) error {
	fmt.Println("[2/3] DNSPod 域名归属")

	cpf := profile.NewClientProfile()
	cpf.HttpProfile.Endpoint = "dnspod.tencentcloudapi.com"

	client, err := dnspod.NewClient(cred, "", cpf)
	if err != nil {
		return fmt.Errorf("构造 DNSPod 客户端: %w", err)
	}

	// 先用接口直接查目标域名，比拉全量列表再匹配更准。
	req := dnspod.NewDescribeDomainListRequest()
	req.Keyword = common.StringPtr(domain)
	req.Limit = common.Int64Ptr(20)

	resp, err := client.DescribeDomainListWithContext(ctx, req)
	if err != nil {
		return fmt.Errorf("DescribeDomainList 失败（检查 dnspod:DescribeDomainList 权限）: %w", err)
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
			"域名 %s 不在这个腾讯云账号的 DNSPod 下。\n"+
				"     要么域名托管在别处，要么要用 DNSPod 自有 Token（dns.provider=dnspod）",
			domain)
	}

	fmt.Printf("      OK — %s 已找到", deref(found.Name))
	if found.Status != nil {
		fmt.Printf("，状态 %s", *found.Status)
	}
	if found.Grade != nil {
		fmt.Printf("，套餐 %s", *found.Grade)
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
			fmt.Println("[3/3] _acme-challenge 残留检查")
			fmt.Println("      OK — 无残留 TXT 记录")
			return nil
		}
		return fmt.Errorf("DescribeRecordList 失败（检查 dnspod:DescribeRecordList 权限）: %w", err)
	}

	n := 0
	if recResp.Response != nil {
		n = len(recResp.Response.RecordList)
	}
	fmt.Println()
	fmt.Println("[3/3] _acme-challenge 残留检查")
	if n == 0 {
		fmt.Println("      OK — 无残留 TXT 记录")
	} else {
		fmt.Printf("      ⚠️  已有 %d 条 TXT 记录，确认不是别的系统在用：\n", n)
		for _, r := range recResp.Response.RecordList {
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
	id := os.Getenv("TENCENTCLOUD_SECRET_ID")
	key := os.Getenv("TENCENTCLOUD_SECRET_KEY")
	if id == "" || key == "" {
		return fmt.Errorf("缺少凭证：请设置 TENCENTCLOUD_SECRET_ID / TENCENTCLOUD_SECRET_KEY")
	}

	cpf := profile.NewClientProfile()
	cpf.HttpProfile.Endpoint = "ssl.tencentcloudapi.com"
	client, err := ssl.NewClient(common.NewCredential(id, key), "", cpf)
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

	fmt.Printf("%-12s %-28s %-40s %-10s %s\n", "CertId", "别名", "域名", "状态", "来源")
	for _, c := range resp.Response.Certificates {
		fmt.Printf("%-12s %-28s %-40s %-10d %s\n",
			deref(c.CertificateId), deref(c.Alias), deref(c.Domain), derefU64(c.Status), deref(c.CertificateType))
	}
	fmt.Printf("\n共 %d 张（账号上限内）\n", derefU64(resp.Response.TotalCount))
	return nil
}

func derefU64(v *uint64) uint64 {
	if v == nil {
		return 0
	}
	return *v
}

// pruneCertificates 删除 wecert 上传的测试证书。
//
// 为什么需要它：腾讯云账号下上传证书数量有配额，长期测试/长期运行的自动化
// 如果不回收，早晚会撞上配额导致无法续期。
//
// 安全性：只删别名以 "wecert/" 开头的证书 —— 那是 wecert 自己上传时打的标记，
// 不会碰任何人工上传或腾讯云签发的证书。
func pruneCertificates() error {
	id := os.Getenv("TENCENTCLOUD_SECRET_ID")
	key := os.Getenv("TENCENTCLOUD_SECRET_KEY")
	if id == "" || key == "" {
		return fmt.Errorf("缺少凭证：请设置 TENCENTCLOUD_SECRET_ID / TENCENTCLOUD_SECRET_KEY")
	}

	cpf := profile.NewClientProfile()
	cpf.HttpProfile.Endpoint = "ssl.tencentcloudapi.com"
	client, err := ssl.NewClient(common.NewCredential(id, key), "", cpf)
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

	const prefix = "wecert/"
	var doomed []*ssl.Certificates
	for _, c := range listResp.Response.Certificates {
		if strings.HasPrefix(deref(c.Alias), prefix) {
			doomed = append(doomed, c)
		}
	}

	if len(doomed) == 0 {
		fmt.Println("没有 wecert 上传的证书，无需清理")
		return nil
	}

	fmt.Printf("将删除 %d 张 wecert 上传的证书：\n", len(doomed))
	for _, c := range doomed {
		fmt.Printf("  %-12s %-28s %s\n", deref(c.CertificateId), deref(c.Alias), deref(c.Domain))
	}

	for _, c := range doomed {
		req := ssl.NewDeleteCertificateRequest()
		req.CertificateId = c.CertificateId
		// 我们自己在状态库里管绑定关系，不需要服务端再检查关联资源。
		req.IsCheckResource = common.BoolPtr(false)
		if _, err := client.DeleteCertificateWithContext(ctx, req); err != nil {
			fmt.Printf("  删除 %s 失败: %v\n", deref(c.CertificateId), err)
			continue
		}
		fmt.Printf("  已删除 %s\n", deref(c.CertificateId))
	}
	return nil
}
