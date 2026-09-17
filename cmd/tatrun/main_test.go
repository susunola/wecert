package main

import (
	"context"
	"errors"
	"io"
	"os"
	"strings"
	"testing"
	"time"

	"encoding/base64"
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

	// omitResult drops the TaskResult even on SUCCESS, which is how the API looks when the task
	// record was never instrumented.
	omitResult bool

	// dropped/outputURL script a truncated answer: the API caps Output at 24KB and says how much
	// it dropped, plus where the full log lives.
	dropped   uint64
	outputURL string
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
	if !f.omitResult && (status == "SUCCESS" || f.output != "") {
		task.TaskResult = &tat.TaskResult{
			// The real API returns Base64-encoded output; feeding plain text here is
			// what let the tool print a blob for its whole life without a test noticing.
			Output:   common.StringPtr(base64.StdEncoding.EncodeToString([]byte(f.output))),
			ExitCode: common.Int64Ptr(f.exitCode),
		}
		if f.dropped > 0 {
			task.TaskResult.Dropped = common.Uint64Ptr(f.dropped)
		}
		if f.outputURL != "" {
			task.TaskResult.OutputUrl = common.StringPtr(f.outputURL)
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

// SUCCESS without a result body is the absence of evidence, not a run that printed nothing.
//
// The tool's whole purpose is to be the evidence that does not trust the control plane, and the
// project's own test plan lists this case (a remote command that produces no output but errors):
// exit 0 with empty output is indistinguishable from a command that ran and produced nothing,
// which is the false green light an operator would act on.
func TestWaitForTaskRefusesSucceededWithoutEvidence(t *testing.T) {
	f := &fakeTAT{statuses: []string{"SUCCESS"}, omitResult: true}
	err := wait(t, f)
	if err == nil {
		t.Fatal("SUCCESS with no TaskResult must be reported as an error, not as an empty successful run")
	}
	if !strings.Contains(err.Error(), "no result") {
		t.Errorf("the error must say the result was missing, got %q", err)
	}
}

// Truncated remote output must say so.
//
// The API caps Output at 24KB and reports the dropped byte count plus a link to the full log.
// This tool is the evidence an operator greps to decide what a listener is serving, so partial
// output presented as the whole answer turns "the certificate is missing from the log" into "this
// listener is not serving it".
func TestWaitForTaskWarnsWhenTheOutputIsTruncated(t *testing.T) {
	f := &fakeTAT{
		statuses: []string{"SUCCESS"}, output: "partial", dropped: 4096,
		outputURL: "https://cos.example/log",
	}
	if err := wait(t, f); err != nil {
		t.Fatalf("a successful command with truncated output is still a successful command: %v", err)
	}

	notice := truncationNotice(&tat.TaskResult{
		Output: common.StringPtr("partial"), ExitCode: common.Int64Ptr(0),
		Dropped: common.Uint64Ptr(4096), OutputUrl: common.StringPtr("https://cos.example/log"),
	})
	for _, want := range []string{"incomplete", "4096", "https://cos.example/log"} {
		if !strings.Contains(notice, want) {
			t.Errorf("the truncation warning must mention %q so the operator can find the rest, got %q",
				want, notice)
		}
	}

	// Whole output says nothing.
	if got := truncationNotice(&tat.TaskResult{Output: common.StringPtr("all of it")}); got != "" {
		t.Errorf("complete output must not warn, got %q", got)
	}
}

// A presigned log URL must not be printed verbatim.
//
// TAT returns a link to the full output stored in COS, and a presigned link is the credential:
// anyone holding it can fetch the object until it expires. This warning goes to stderr, which under
// systemd is the journal -- often shipped somewhere with a wider audience than the command's owner.
// The operator still has to learn that the output was partial and where the rest lives.
func TestTruncationNoticeDoesNotPrintASignedURL(t *testing.T) {
	signed := "https://bucket.cos.ap-guangzhou.myqcloud.com/log.txt" +
		"?q-sign-algorithm=sha1&q-ak=AKIDEXAMPLE&q-signature=deadbeef"
	notice := truncationNotice(&tat.TaskResult{
		Output: common.StringPtr("partial"), Dropped: common.Uint64Ptr(4096),
		OutputUrl: common.StringPtr(signed),
	})
	if notice == "" {
		t.Fatal("truncated output must still warn")
	}
	for _, secret := range []string{"q-signature", "deadbeef", "AKIDEXAMPLE", "?"} {
		if strings.Contains(notice, secret) {
			t.Errorf("the warning leaks the signed part of the URL (%q present): %s", secret, notice)
		}
	}
	if !strings.Contains(notice, "bucket.cos.ap-guangzhou.myqcloud.com") {
		t.Errorf("the operator still needs to know where the log lives, got %q", notice)
	}
	if !strings.Contains(notice, "4096") {
		t.Errorf("the warning must say how much was dropped, got %q", notice)
	}

	// An unparseable value is the one case where nothing may be echoed.
	if got := truncationNotice(&tat.TaskResult{OutputUrl: common.StringPtr(":// not a url")}); strings.Contains(got, "://") {
		t.Errorf("an unparseable URL must be withheld entirely, got %q", got)
	}
	// A plain URL without a signature is printed as-is.
	if got := truncationNotice(&tat.TaskResult{OutputUrl: common.StringPtr("https://example.com/log")}); !strings.Contains(got, "https://example.com/log") {
		t.Errorf("an unsigned URL is not a credential and is useful as-is, got %q", got)
	}
}

// The remote output is Base64 on the wire and must reach the operator decoded.
//
// TaskResult.Output is documented as Base64-encoded, and this repository's own e2e captures decode
// from Base64 to the openssl output they were checking. Printing the field verbatim made every run's
// evidence a blob that `-quiet | grep` could not match.
func TestWaitForTaskPrintsDecodedOutput(t *testing.T) {
	f := &fakeTAT{statuses: []string{"SUCCESS"}, output: "root\n"}
	if err := wait(t, f); err != nil {
		t.Fatalf("a successful command must not be an error: %v", err)
	}
	if got := decodeRemoteOutput(base64.StdEncoding.EncodeToString([]byte("hello\n"))); got != "hello\n" {
		t.Errorf("decodeRemoteOutput = %q, want the decoded text", got)
	}
	// Padding-less Base64 is accepted too.
	if got := decodeRemoteOutput("aGVsbG8"); got != "hello" {
		t.Errorf("unpadded Base64 must decode, got %q", got)
	}
	// Something that is not Base64 at all is passed through rather than dropped: it is still the
	// only evidence there is.
	if got := decodeRemoteOutput("not base64 !!"); got != "not base64 !!" {
		t.Errorf("undecodable output must be passed through, got %q", got)
	}
	if got := decodeRemoteOutput(""); got != "" {
		t.Errorf("empty output stays empty, got %q", got)
	}
}

// A failing command's output must be readable.
//
// The API returns Output Base64-encoded, and the failure path printed it raw: the one moment the
// output matters most -- the remote command failed and the operator is reading its stderr -- was
// the one moment the tool handed over a blob. Found by running the tool against a real CVM, where
// a command whose last statement exited non-zero printed its error as Base64.
func TestAFailedTaskPrintsItsOutputDecoded(t *testing.T) {
	f := &fakeTAT{
		statuses: []string{"FAILED"},
		output:   "cat: /etc/wecert/config.yaml: No such file or directory\n",
		errorMsg: "the command exited with a non-zero status",
	}

	restore := captureStdout(t)
	err := wait(t, f)
	out := restore()

	if err == nil {
		t.Fatal("a FAILED task must be reported as a failure")
	}
	if !strings.Contains(out, "No such file or directory") {
		t.Errorf("the failing command's output must be readable, got %q", out)
	}
	if strings.Contains(out, "Y2F0Og") {
		t.Errorf("the output was printed as Base64: %q", out)
	}
}

// captureStdout redirects os.Stdout for the duration of one call and returns a function that
// restores it and hands back everything written.
func captureStdout(t *testing.T) func() string {
	t.Helper()
	old := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	os.Stdout = w
	return func() string {
		_ = w.Close()
		os.Stdout = old
		data, _ := io.ReadAll(r)
		_ = r.Close()
		return string(data)
	}
}

// The diagnosable timeout must survive the context deadline.
//
// run() builds the context with the same duration as the loop's own deadline -- and builds it
// first -- so the context always expired first and fetchTask handed back a raw "context deadline
// exceeded" from the SDK. The message that names the invocation (and says what to do) was
// unreachable in production; the existing tests could not see it because they pass a context
// without a deadline.
func TestTheTATTimeoutMessageSurvivesTheContextDeadline(t *testing.T) {
	f := &fakeTAT{statuses: []string{"RUNNING"}}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Millisecond)
	defer cancel()

	// The loop's own deadline is deliberately much longer than the context's: in production run()
	// creates the context first with the same duration, so the context ALWAYS expires first, and
	// this reproduces that ordering without depending on which check happens to win a race.
	err := waitForTask(ctx, f, "inv-42", 10*time.Second, 5*time.Millisecond, true)
	if err == nil {
		t.Fatal("a task that never reaches a terminal status must time out")
	}
	if !strings.Contains(err.Error(), "timed out waiting for the TAT result") {
		t.Errorf("the operator needs the message that names the invocation, got %v", err)
	}
	if !strings.Contains(err.Error(), "inv-42") {
		t.Errorf("the message must carry the invocation id, got %v", err)
	}
}
