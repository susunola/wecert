// Command clbverify 查询 CLB 监听器当前绑定的证书，用于端到端测试断言。
//
// 为什么需要单独一个工具：wecert 调完 UpdateCertificateInstance 之后，
// 唯一的权威事实是"监听器上的 CertId 到底变了没有"。
// 只信 wecert 自己的日志是不够的 —— 那正是"程序以为成功、实际没生效"
// 这类最隐蔽故障的盲区。这个工具从腾讯云侧独立取证。
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"

	clb "github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/clb/v20180317"
	"github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common"
	"github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common/profile"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "错误: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	var (
		region     = flag.String("region", "", "地域，例如 ap-guangzhou")
		lbID       = flag.String("clb", "", "CLB 实例 ID")
		listenerID = flag.String("listener", "", "监听器 ID；省略则取该 CLB 下的第一个监听器")
		expect     = flag.String("expect", "", "期望的主证书 ID；提供则断言必须相等")
		notExpect  = flag.String("not-expect", "", "不应出现的证书 ID；提供则断言必须不等")
		raw        = flag.Bool("raw", false, "原样打印 DescribeListeners 的 JSON 响应，用于排障")
		wait       = flag.Duration("wait", 0, "轮询等待期望证书出现的最长时间（UpdateCertificateInstance 是异步的）")
	)
	flag.Parse()

	if *region == "" || *lbID == "" {
		return fmt.Errorf("必须提供 -region 和 -clb（-listener 可省略，省略则列出全部监听器）")
	}

	cred := common.NewCredential(
		os.Getenv("TENCENTCLOUD_SECRET_ID"),
		os.Getenv("TENCENTCLOUD_SECRET_KEY"),
	)
	if cred.GetSecretId() == "" {
		return fmt.Errorf("缺少凭证：请设置 TENCENTCLOUD_SECRET_ID / TENCENTCLOUD_SECRET_KEY")
	}

	cpf := profile.NewClientProfile()
	cpf.HttpProfile.Endpoint = "clb.tencentcloudapi.com"

	client, err := clb.NewClient(cred, *region, cpf)
	if err != nil {
		return fmt.Errorf("构造 CLB 客户端: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	req := clb.NewDescribeListenersRequest()
	req.LoadBalancerId = common.StringPtr(*lbID)
	// 不传 ListenerIds 时返回该 CLB 下的全部监听器。
	// 排障中发现：带了 ListenerIds 过滤，返回里可能不带 Certificate 字段，
	// 所以留出"不带过滤"这条路用于交叉验证。
	if *listenerID != "" {
		req.ListenerIds = []*string{common.StringPtr(*listenerID)}
	}

	resp, err := client.DescribeListenersWithContext(ctx, req)
	if err != nil {
		return fmt.Errorf("DescribeListeners: %w", err)
	}
	if resp.Response == nil || len(resp.Response.Listeners) == 0 {
		return fmt.Errorf("CLB %s 下没有监听器", *lbID)
	}

	if *raw {
		// 排障用：原样打出服务端返回的内容，
		// 避免"我们以为的字段名"和"API 实际返回的"对不上时瞎猜。
		b, err := json.MarshalIndent(resp.Response, "", "  ")
		if err != nil {
			return fmt.Errorf("序列化响应: %w", err)
		}
		fmt.Println(string(b))
		return nil
	}

	l := resp.Response.Listeners[0]
	fmt.Printf("监听器 %s  (%s:%d)\n", derefStr(l.ListenerId), derefStr(l.Protocol), derefI64(l.Port))

	if l.Certificate == nil || l.Certificate.CertId == nil {
		return fmt.Errorf("监听器上没有绑定证书")
	}

	certID := *l.Certificate.CertId
	fmt.Printf("  主证书 CertId : %s\n", certID)

	// SNI 扩展证书：这正是"换一张证书时容易误伤别的证书"的地方，
	// 所以单独打出来。
	if n := len(l.Certificate.ExtCertIds); n > 0 {
		fmt.Printf("  SNI 扩展证书  : %d 张\n", n)
		for _, e := range l.Certificate.ExtCertIds {
			fmt.Printf("      %s\n", derefStr(e))
		}
	} else {
		fmt.Printf("  SNI 扩展证书  : 无\n")
	}

	// UpdateCertificateInstance 是异步 API：调用返回只代表任务创建成功，
	// 真正的重绑定要等后台跑完（实测约 15 秒）。所以断言必须带等待。
	if *expect != "" && *wait > 0 && certID != *expect {
		// 等待循环必须用自己的、足够长的 ctx。
		//
		// 复用上面那个 30 秒的 ctx 会让 -wait 超过 30s 时每次请求都立刻
		// 返回 deadline exceeded，而下面的 continue 又把错误吞掉 ——
		// 结果就是空转到超时，然后报"仍未变成期望值"的假失败。
		// 而那恰好是这个工具唯一存在的场景。
		waitCtx, cancelWait := context.WithTimeout(context.Background(), *wait+30*time.Second)
		defer cancelWait()

		deadline := time.Now().Add(*wait)
		var lastErr error
		for time.Now().Before(deadline) {
			time.Sleep(5 * time.Second)
			cur, err := fetchCertID(waitCtx, client, *lbID, *listenerID)
			if err != nil {
				// 不能再静默 continue：查询本身失败和"还没换过来"
				// 是两件完全不同的事，必须让人看得见。
				lastErr = err
				fmt.Printf("  ...查询失败，稍后重试: %v\n", err)
				continue
			}
			lastErr = nil
			fmt.Printf("  ...等待中，当前绑定 %s\n", cur)
			if cur == *expect {
				certID = cur
				break
			}
			certID = cur
		}
		if certID != *expect && lastErr != nil {
			fmt.Printf("  ...注意：最后一次查询仍然失败，上面的断言结果可能不可信: %v\n", lastErr)
		}
		fmt.Println()
	}

	if *notExpect != "" && certID == *notExpect {
		return fmt.Errorf("断言失败：监听器仍然绑着不该出现的证书 %s", *notExpect)
	}
	if *expect != "" {
		if certID != *expect {
			return fmt.Errorf("断言失败：等待 %s 后仍未变成期望的 %s，实际 %s", *wait, *expect, certID)
		}
		fmt.Printf("\n✅ 断言通过：监听器已重绑定到 %s\n", *expect)
	}
	return nil
}

// fetchCertID 单独查一次监听器当前绑定的主证书 ID。
//
// listenerID 为空时按主流程一致的方式取第一个监听器 —— 传一个空的
// ListenerIds 进去会让 API 直接报错，然后被等待循环当成"网络抖动"重试。
func fetchCertID(ctx context.Context, client *clb.Client, lbID, listenerID string) (string, error) {
	req := clb.NewDescribeListenersRequest()
	req.LoadBalancerId = common.StringPtr(lbID)
	if listenerID != "" {
		req.ListenerIds = []*string{common.StringPtr(listenerID)}
	}

	resp, err := client.DescribeListenersWithContext(ctx, req)
	if err != nil {
		return "", err
	}
	if resp.Response == nil || len(resp.Response.Listeners) == 0 {
		return "", fmt.Errorf("监听器不存在")
	}
	l := resp.Response.Listeners[0]
	if l.Certificate == nil || l.Certificate.CertId == nil {
		return "", fmt.Errorf("未绑定证书")
	}
	return *l.Certificate.CertId, nil
}

func derefStr(s *string) string {
	if s == nil {
		return "<nil>"
	}
	return *s
}

func derefI64(v *int64) int64 {
	if v == nil {
		return 0
	}
	return *v
}
