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
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	var (
		region     = flag.String("region", "", "region, e.g. ap-guangzhou")
		lbID       = flag.String("clb", "", "CLB instance ID")
		listenerID = flag.String("listener", "", "listener ID; when omitted, the first listener on that CLB is used")
		expect     = flag.String("expect", "", "expected primary certificate ID; when set the assertion must hold")
		notExpect  = flag.String("not-expect", "", "certificate ID that must NOT be present")
		raw        = flag.Bool("raw", false, "dump the raw DescribeListeners JSON response for troubleshooting")
		wait       = flag.Duration("wait", 0, "how long to poll for the expected certificate (UpdateCertificateInstance is asynchronous)")
	)
	flag.Parse()

	if *region == "" || *lbID == "" {
		return fmt.Errorf("-region and -clb are required (-listener is optional; omit it to list every listener)")
	}

	cred := common.NewCredential(
		os.Getenv("TENCENTCLOUD_SECRET_ID"),
		os.Getenv("TENCENTCLOUD_SECRET_KEY"),
	)
	if cred.GetSecretId() == "" {
		return fmt.Errorf("missing credentials: set TENCENTCLOUD_SECRET_ID / TENCENTCLOUD_SECRET_KEY")
	}

	cpf := profile.NewClientProfile()
	cpf.HttpProfile.Endpoint = "clb.tencentcloudapi.com"

	client, err := clb.NewClient(cred, *region, cpf)
	if err != nil {
		return fmt.Errorf("build CLB client: %w", err)
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
		return fmt.Errorf("CLB %s has no listeners", *lbID)
	}

	if *raw {
		// 排障用：原样打出服务端返回的内容，
		// 避免"我们以为的字段名"和"API 实际返回的"对不上时瞎猜。
		b, err := json.MarshalIndent(resp.Response, "", "  ")
		if err != nil {
			return fmt.Errorf("encode response: %w", err)
		}
		fmt.Println(string(b))
		return nil
	}

	l := resp.Response.Listeners[0]
	fmt.Printf("listener %s  (%s:%d)\n", derefStr(l.ListenerId), derefStr(l.Protocol), derefI64(l.Port))

	if l.Certificate == nil || l.Certificate.CertId == nil {
		return fmt.Errorf("the listener has no certificate bound")
	}

	certID := *l.Certificate.CertId
	fmt.Printf("  primary certificate: %s\n", certID)

	// SNI 扩展证书：这正是"换一张证书时容易误伤别的证书"的地方，
	// 所以单独打出来。
	if n := len(l.Certificate.ExtCertIds); n > 0 {
		fmt.Printf("  SNI certificates  : %d\n", n)
		for _, e := range l.Certificate.ExtCertIds {
			fmt.Printf("      %s\n", derefStr(e))
		}
	} else {
		fmt.Printf("  SNI certificates  : none\n")
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
				fmt.Printf("  ...query failed, retrying shortly: %v\n", err)
				continue
			}
			lastErr = nil
			fmt.Printf("  ...waiting; currently bound to %s\n", cur)
			if cur == *expect {
				certID = cur
				break
			}
			certID = cur
		}
		if certID != *expect && lastErr != nil {
			fmt.Printf("  ...note: the final query also failed, so the assertion above may not be trustworthy: %v\n", lastErr)
		}
		fmt.Println()
	}

	if *notExpect != "" && certID == *notExpect {
		return fmt.Errorf("assertion failed: the listener is still bound to %s, which should be gone", *notExpect)
	}
	if *expect != "" {
		if certID != *expect {
			return fmt.Errorf("assertion failed: after waiting %s it is still not %s (actual: %s)", *wait, *expect, certID)
		}
		fmt.Printf("\nOK: assertion passed - the listener is now bound to %s\n", *expect)
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
		return "", fmt.Errorf("the listener does not exist")
	}
	l := resp.Response.Listeners[0]
	if l.Certificate == nil || l.Certificate.CertId == nil {
		return "", fmt.Errorf("no certificate bound")
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
