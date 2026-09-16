// Command tatrun 通过 TAT（自动化助手）在 CVM 上执行 shell 命令并打印输出。
//
// 为什么需要它：不需要 SSH 密钥、不需要给 CVM 开公网入站端口，就能在测试机上
// 执行验证命令。最有价值的用法是从 VPC 内部 curl CLB 的 VIP，
// 读回实际正在服务的证书 —— 这是唯一能证明"证书真的在对外服务"的方式，
// 比读 wecert 自己的状态库可信得多（后者正是"程序以为成功但没生效"的盲区）。
package main

import (
	"context"
	"encoding/base64"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common"
	"github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common/profile"
	tat "github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/tat/v20201028"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	var (
		region   = flag.String("region", "", "region, e.g. ap-guangzhou")
		instance = flag.String("instance", "", "CVM instance ID, e.g. ins-xxxx")
		command  = flag.String("cmd", "", "shell command to run")
		timeout  = flag.Duration("timeout", 180*time.Second, "overall timeout")
		interval = flag.Duration("interval", 3*time.Second, "poll interval")
		quiet    = flag.Bool("quiet", false, "print only the command's stdout, for piping")
	)
	flag.Parse()

	if *region == "" || *instance == "" || *command == "" {
		return fmt.Errorf("-region, -instance and -cmd are required")
	}

	secretID := os.Getenv("TENCENTCLOUD_SECRET_ID")
	secretKey := os.Getenv("TENCENTCLOUD_SECRET_KEY")
	if secretID == "" || secretKey == "" {
		return fmt.Errorf("missing credentials: set TENCENTCLOUD_SECRET_ID / TENCENTCLOUD_SECRET_KEY")
	}

	cpf := profile.NewClientProfile()
	cpf.HttpProfile.Endpoint = "tat.tencentcloudapi.com"

	client, err := tat.NewClient(common.NewCredential(secretID, secretKey), *region, cpf)
	if err != nil {
		return fmt.Errorf("build TAT client: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	runReq := tat.NewRunCommandRequest()
	// TAT 的 Content 要求 base64 编码。直接传明文会报
	// InvalidParameterValue ... parameter `Content` is not valid。
	runReq.Content = common.StringPtr(base64.StdEncoding.EncodeToString([]byte(*command)))
	runReq.InstanceIds = []*string{common.StringPtr(*instance)}
	runReq.CommandName = common.StringPtr("wecert-e2e")
	runReq.Timeout = common.Uint64Ptr(uint64(timeout.Seconds()))
	// 测试命令没必要在 TAT 里留档。
	runReq.SaveCommand = common.BoolPtr(false)

	runResp, err := client.RunCommandWithContext(ctx, runReq)
	if err != nil {
		return fmt.Errorf("RunCommand (check the tat:RunCommand permission, and whether the CVM has the TAT agent installed): %w", err)
	}
	invocationID := deref(runResp.Response.InvocationId)
	if invocationID == "" {
		return fmt.Errorf("RunCommand returned no InvocationId")
	}

	if !*quiet {
		fmt.Fprintf(os.Stderr, "TAT command submitted (invocation=%s), waiting for it to run...\n", invocationID)
	}

	deadline := time.Now().Add(*timeout)
	for {
		task, err := fetchTask(ctx, client, invocationID)
		if err != nil {
			return err
		}

		if task != nil {
			switch deref(task.TaskStatus) {
			case "SUCCESS":
				out := ""
				exitCode := int64(0)
				if task.TaskResult != nil {
					out = deref(task.TaskResult.Output)
					exitCode = derefI64(task.TaskResult.ExitCode)
				}
				if !*quiet {
					fmt.Fprintf(os.Stderr, "--- command output (exit=%d) ---\n", exitCode)
				}
				fmt.Print(out)
				if exitCode != 0 {
					return fmt.Errorf("command exited with code %d", exitCode)
				}
				return nil

			case "FAILED", "TIMEOUT":
				if task.TaskResult != nil {
					fmt.Print(deref(task.TaskResult.Output))
				}
				return fmt.Errorf("TAT task %s: %s", deref(task.TaskStatus), deref(task.ErrorInfo))
			}
		}

		if time.Now().After(deadline) {
			return fmt.Errorf("timed out waiting for the TAT result (invocation=%s)", invocationID)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(*interval):
		}
	}
}

// fetchTask 按 invocation-id 查执行结果。返回 (nil, nil) 表示还没生成任务记录。
func fetchTask(ctx context.Context, client *tat.Client, invocationID string) (*tat.InvocationTask, error) {
	req := tat.NewDescribeInvocationTasksRequest()
	req.Filters = []*tat.Filter{{
		Name:   common.StringPtr("invocation-id"),
		Values: []*string{common.StringPtr(invocationID)},
	}}
	req.HideOutput = common.BoolPtr(false)

	resp, err := client.DescribeInvocationTasksWithContext(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("DescribeInvocationTasks: %w", err)
	}
	if resp.Response == nil || len(resp.Response.InvocationTaskSet) == 0 {
		return nil, nil
	}
	return resp.Response.InvocationTaskSet[0], nil
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

func derefI64(v *int64) int64 {
	if v == nil {
		return 0
	}
	return *v
}
