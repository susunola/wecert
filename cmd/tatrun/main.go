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

	client, err := newTATClient(common.NewCredential(secretID, secretKey), *region, cpf)
	if err != nil {
		return fmt.Errorf("build TAT client: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	runResp, err := client.RunCommandWithContext(ctx, buildRunCommand(*command, *instance, *timeout))
	if err != nil {
		return fmt.Errorf("RunCommand (check the tat:RunCommand permission, and whether the CVM has the TAT agent installed): %w", err)
	}
	// Guard the Response before dereferencing it, the way fetchTask does: the SDK can
	// return a typed response with a nil Response body, and a blind dereference would
	// turn a failed submission into a panic instead of a diagnosable error.
	if runResp.Response == nil {
		return fmt.Errorf("RunCommand returned an empty response")
	}
	invocationID := deref(runResp.Response.InvocationId)
	if invocationID == "" {
		return fmt.Errorf("RunCommand returned no InvocationId")
	}

	if !*quiet {
		fmt.Fprintf(os.Stderr, "TAT command submitted (invocation=%s), waiting for it to run...\n", invocationID)
	}

	return waitForTask(ctx, client, invocationID, *timeout, *interval, *quiet)
}

// tatAPI is the slice of the TAT client this command uses, so the poll loop below can be
// driven without a live Tencent Cloud account.
type tatAPI interface {
	RunCommandWithContext(ctx context.Context, req *tat.RunCommandRequest) (*tat.RunCommandResponse, error)
	DescribeInvocationTasksWithContext(ctx context.Context, req *tat.DescribeInvocationTasksRequest) (*tat.DescribeInvocationTasksResponse, error)
}

// newTATClient builds the TAT client. A package variable so tests can substitute a fake;
// production code never reassigns it.
var newTATClient = func(cred common.CredentialIface, region string, cpf *profile.ClientProfile) (tatAPI, error) {
	return tat.NewClient(cred, region, cpf)
}

// waitForTask polls until the invocation reaches a terminal status.
//
// Split out of run() so the status table -- which is the whole point of this command, and where
// an omission once turned "the CVM has no TAT agent" into "timed out" -- is testable.
func waitForTask(ctx context.Context, client tatAPI, invocationID string, timeout, interval time.Duration, quiet bool) error {
	deadline := time.Now().Add(timeout)
	for {
		task, err := fetchTask(ctx, client, invocationID)
		if err != nil {
			return err
		}

		if task != nil {
			switch deref(task.TaskStatus) {
			case "SUCCESS":
				// A terminal SUCCESS with no result body is not "the command ran and printed
				// nothing": it is the absence of the evidence this tool exists to fetch. Exiting 0
				// with empty output makes the two indistinguishable, and the operator greps that
				// empty output to decide what a listener is serving.
				if task.TaskResult == nil {
					return fmt.Errorf("the TAT task reported SUCCESS for invocation=%s but returned no "+
						"result, so there is no evidence to report", invocationID)
				}
				out := deref(task.TaskResult.Output)
				exitCode := derefI64(task.TaskResult.ExitCode)
				if !quiet {
					fmt.Fprintf(os.Stderr, "--- command output (exit=%d) ---\n", exitCode)
				}
				fmt.Print(out)
				if exitCode != 0 {
					return fmt.Errorf("command exited with code %d", exitCode)
				}
				return nil

			case "FAILED", "TIMEOUT", "TASK_TIMEOUT", "START_FAILED", "DELIVER_FAILED", "CANCELLED", "TERMINATED":
				// Every terminal-but-not-successful status the API defines, not just the
				// two obvious ones. Anything omitted here keeps the poll loop running
				// until the deadline and then reports "timed out waiting for the TAT
				// result" -- which for START_FAILED/DELIVER_FAILED (a CVM with no TAT
				// agent installed) sends the operator looking for a timeout that never
				// happened, when the server already said exactly what was wrong.
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
		case <-time.After(interval):
		}
	}
}

// buildRunCommand assembles the RunCommand request.
//
// Split out because TAT has one non-obvious requirement: Content must be base64 encoded, and
// passing plaintext is rejected with InvalidParameterValue ... parameter `Content` is not valid,
// which reads like a permission problem.
func buildRunCommand(command, instance string, timeout time.Duration) *tat.RunCommandRequest {
	req := tat.NewRunCommandRequest()
	req.Content = common.StringPtr(base64.StdEncoding.EncodeToString([]byte(command)))
	req.InstanceIds = []*string{common.StringPtr(instance)}
	req.CommandName = common.StringPtr("wecert-e2e")
	req.Timeout = common.Uint64Ptr(uint64(timeout.Seconds()))
	// No reason to keep a test command on record in TAT.
	req.SaveCommand = common.BoolPtr(false)
	return req
}

// fetchTask looks up the execution result by invocation-id; (nil, nil) means no task record yet.
func fetchTask(ctx context.Context, client tatAPI, invocationID string) (*tat.InvocationTask, error) {
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
