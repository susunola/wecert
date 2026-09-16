// Command tatrun runs a shell command on a CVM through TAT (TencentCloud Automation Tools) and
// prints the output.
//
// Why it exists: it runs verification commands on a test machine with no SSH key and no public
// inbound port on the CVM. Its most valuable use is curling a CLB VIP from inside the VPC and
// reading back the certificate actually being served -- the only way to prove a certificate is
// truly in service, and far more trustworthy than wecert's own state store (the blind spot of
// "the program believed it succeeded but nothing took effect").
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
	// TAT requires Content to be base64 encoded. Passing plaintext reports
	// InvalidParameterValue ... parameter `Content` is not valid.
	runReq.Content = common.StringPtr(base64.StdEncoding.EncodeToString([]byte(*command)))
	runReq.InstanceIds = []*string{common.StringPtr(*instance)}
	runReq.CommandName = common.StringPtr("wecert-e2e")
	runReq.Timeout = common.Uint64Ptr(uint64(timeout.Seconds()))
	// No reason to keep a test command on record in TAT.
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

// fetchTask looks up the execution result by invocation-id; (nil, nil) means no task record yet.
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
