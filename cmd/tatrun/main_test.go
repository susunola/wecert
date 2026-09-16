package main

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common"
	tat "github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/tat/v20201028"
)

// fakeTAT scripts the status the invocation reports, in order.
type fakeTAT struct {
	statuses []string
	idx      int

	output   string
	exitCode int64
	errorMsg string

	// err makes the describe call fail, so the retry/abort behaviour is observable.
	err error
}

func (f *fakeTAT) RunCommandWithContext(context.Context, *tat.RunCommandRequest) (*tat.RunCommandResponse, error) {
	return nil, errors.New("not used")
}

func (f *fakeTAT) DescribeInvocationTasksWithContext(context.Context, *tat.DescribeInvocationTasksRequest) (*tat.DescribeInvocationTasksResponse, error) {
	if f.err != nil {
		return nil, f.err
	}
	status := f.statuses[f.idx]
	if f.idx < len(f.statuses)-1 {
		f.idx++
	}
	task := &tat.InvocationTask{TaskStatus: common.StringPtr(status)}
	if status == "SUCCESS" || f.output != "" {
		task.TaskResult = &tat.TaskResult{
			Output:   common.StringPtr(f.output),
			ExitCode: common.Int64Ptr(f.exitCode),
		}
	}
	if f.errorMsg != "" {
		task.ErrorInfo = common.StringPtr(f.errorMsg)
	}
	return &tat.DescribeInvocationTasksResponse{
		Response: &tat.DescribeInvocationTasksResponseParams{
			InvocationTaskSet: []*tat.InvocationTask{task},
		},
	}, nil
}

func wait(t *testing.T, f *fakeTAT) error {
	t.Helper()
	return waitForTask(context.Background(), f, "inv-1", 2*time.Second, time.Millisecond, true)
}

// A successful command must report its output, and exit 0 must not be an error.
func TestWaitForTaskSucceeds(t *testing.T) {
	f := &fakeTAT{statuses: []string{"RUNNING", "SUCCESS"}, output: "hello\n"}
	if err := wait(t, f); err != nil {
		t.Fatalf("a successful command must not be an error: %v", err)
	}
}

// A non-zero exit code is a failure even though the TAT task itself succeeded: the command ran
// and returned a bad status, which is what the caller is testing for.
func TestWaitForTaskReportsANonZeroExitCode(t *testing.T) {
	f := &fakeTAT{statuses: []string{"SUCCESS"}, output: "boom", exitCode: 3}
	err := wait(t, f)
	if err == nil {
		t.Fatal("exit code 3 must be reported as a failure")
	}
	if !strings.Contains(err.Error(), "3") {
		t.Errorf("the error must name the exit code, got: %v", err)
	}
}

// Every terminal-but-unsuccessful status must be reported with the server's own message.
//
// The statuses beyond FAILED and TIMEOUT are the point: a CVM with no TAT agent reports
// START_FAILED or DELIVER_FAILED immediately, and before they were handled the loop polled to
// the deadline and then blamed a timeout that never happened.
func TestWaitForTaskReportsEveryTerminalStatus(t *testing.T) {
	for _, status := range []string{
		"FAILED", "TIMEOUT", "TASK_TIMEOUT", "START_FAILED", "DELIVER_FAILED", "CANCELLED", "TERMINATED",
	} {
		t.Run(status, func(t *testing.T) {
			f := &fakeTAT{statuses: []string{status}, errorMsg: "the CVM has no TAT agent"}
			start := time.Now()
			err := wait(t, f)
			elapsed := time.Since(start)

			if err == nil {
				t.Fatalf("%s must be reported as a failure", status)
			}
			if !strings.Contains(err.Error(), status) {
				t.Errorf("the error must name the status, got: %v", err)
			}
			if !strings.Contains(err.Error(), "no TAT agent") {
				t.Errorf("the server's explanation must survive, got: %v", err)
			}
			// The point of the fix: no waiting for the deadline.
			if elapsed > time.Second {
				t.Errorf("%s took %s, so it is polling to the deadline instead of stopping", status, elapsed)
			}
			if strings.Contains(err.Error(), "timed out") {
				t.Errorf("%s was misreported as a timeout: %v", status, err)
			}
		})
	}
}

// An unrecognised status must keep polling rather than being treated as terminal: a status this
// build does not know about could be a new in-progress one, and stopping early would report a
// running command as finished.
func TestWaitForTaskKeepsPollingAnUnknownStatus(t *testing.T) {
	f := &fakeTAT{statuses: []string{"PENDING", "DELIVERING", "DELIVER_DELAYED", "RUNNING", "SUCCESS"}}
	if err := wait(t, f); err != nil {
		t.Fatalf("an in-progress status must keep polling: %v", err)
	}
	if f.idx != len(f.statuses)-1 {
		t.Errorf("stopped at status %d of %d", f.idx, len(f.statuses)-1)
	}
}

// A task record that has not appeared yet is not an error: TAT reports the invocation before the
// task exists, and (nil, nil) means "ask again".
func TestWaitForTaskPollsUntilTheTaskAppears(t *testing.T) {
	f := &fakeTAT{statuses: []string{"SUCCESS"}}
	// No task is produced until the third call.
	calls := 0
	counting := &countingTAT{fake: f, calls: &calls}
	if err := waitForTask(context.Background(), counting, "inv-1", 2*time.Second, time.Millisecond, true); err != nil {
		t.Fatalf("waitForTask: %v", err)
	}
	if calls < 1 {
		t.Error("the loop made no calls")
	}
}

type countingTAT struct {
	fake  *fakeTAT
	calls *int
}

func (c *countingTAT) RunCommandWithContext(ctx context.Context, req *tat.RunCommandRequest) (*tat.RunCommandResponse, error) {
	return c.fake.RunCommandWithContext(ctx, req)
}

func (c *countingTAT) DescribeInvocationTasksWithContext(ctx context.Context, req *tat.DescribeInvocationTasksRequest) (*tat.DescribeInvocationTasksResponse, error) {
	*c.calls++
	if *c.calls < 3 {
		return &tat.DescribeInvocationTasksResponse{
			Response: &tat.DescribeInvocationTasksResponseParams{},
		}, nil
	}
	return c.fake.DescribeInvocationTasksWithContext(ctx, req)
}

// A describe failure must surface rather than be swallowed and retried forever: a permission
// problem would otherwise look like a command that never finishes.
func TestWaitForTaskSurfacesAPollingError(t *testing.T) {
	f := &fakeTAT{statuses: []string{"RUNNING"}, err: errors.New("AuthFailure.SignatureFailure")}
	err := wait(t, f)
	if err == nil {
		t.Fatal("a polling failure must surface")
	}
	if !strings.Contains(err.Error(), "SignatureFailure") {
		t.Errorf("the API error must survive, got: %v", err)
	}
}

// Running past the deadline must report a timeout naming the invocation, since that is what the
// operator needs to look up.
func TestWaitForTaskTimesOut(t *testing.T) {
	f := &fakeTAT{statuses: []string{"RUNNING"}}
	err := waitForTask(context.Background(), f, "inv-42", 20*time.Millisecond, time.Millisecond, true)
	if err == nil {
		t.Fatal("an invocation that never finishes must time out")
	}
	if !strings.Contains(err.Error(), "inv-42") {
		t.Errorf("the timeout must name the invocation, got: %v", err)
	}
}

// A cancelled context must stop the wait promptly.
func TestWaitForTaskHonoursCancellation(t *testing.T) {
	f := &fakeTAT{statuses: []string{"RUNNING"}}
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(10 * time.Millisecond)
		cancel()
	}()

	start := time.Now()
	err := waitForTask(ctx, f, "inv-1", time.Minute, time.Millisecond, true)
	if err == nil {
		t.Fatal("a cancelled wait must fail")
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Errorf("cancellation took %s: the loop ignores ctx", elapsed)
	}
}

// The command content must be base64 encoded: plaintext is rejected by the API with
// InvalidParameterValue, which is a confusing failure for a one-line change.
func TestBuildRunCommandEncodesTheContent(t *testing.T) {
	req := buildRunCommand("echo hi", "ins-1", 60*time.Second)
	if req.Content == nil || *req.Content == "echo hi" {
		t.Fatalf("Content must be base64 encoded, got %v", req.Content)
	}
	if req.SaveCommand == nil || *req.SaveCommand {
		t.Error("SaveCommand must be false: a test command has no reason to stay on record")
	}
	if req.Timeout == nil || *req.Timeout != 60 {
		t.Errorf("Timeout = %v, want 60", req.Timeout)
	}
	if len(req.InstanceIds) != 1 || req.InstanceIds[0] == nil || *req.InstanceIds[0] != "ins-1" {
		t.Errorf("InstanceIds = %v, want [ins-1]", req.InstanceIds)
	}
}
