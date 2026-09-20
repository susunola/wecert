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
	"errors"
	"flag"
	"fmt"
	"os"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common"
	"github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common/profile"
	tat "github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/tat/v20201028"
	"net/url"
	"strings"
)

// exitUsage is the conventional "the command line itself is wrong" code, the same one wecert,
// wecert-onboard, wecert-probe, preflight and clbverify use. It matters here because the
// alternative was flag.ExitOnError's 2, which this repository documents as wecert-onboard's
// "deliberately frozen, a human should look" code.
const exitUsage = 64

// errUsage marks a command-line error, so main can pick the exit code without re-printing
// what the flag package already printed to stderr.
var errUsage = errors.New("invalid command line")

// errHelp is parseArgs' answer to -h: the flag package has already printed the usage, and
// asking for help is not an error.
var errHelp = errors.New("help requested")

func main() {
	if err := run(); err != nil {
		if errors.Is(err, errUsage) {
			os.Exit(exitUsage)
		}
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

// options holds every flag this command takes.
//
// It left run's locals so parsing has a test. The flags used to be registered on the
// package-level flag.CommandLine and parsed with flag.Parse(), which is ExitOnError: a typo
// ("-instace") made the process exit 2 with the usage text, the same code wecert-onboard
// uses to mean "deliberately frozen, a human should look". Every other command in this
// repository parses its own FlagSet with ContinueOnError.
type options struct {
	region   string
	instance string
	command  string
	timeout  time.Duration
	interval time.Duration
	quiet    bool
}

// newFlagSet registers every flag on fs -- never on the package-level flag.CommandLine.
func newFlagSet(o *options) *flag.FlagSet {
	fs := flag.NewFlagSet("tatrun", flag.ContinueOnError)
	fs.StringVar(&o.region, "region", "", "region, e.g. ap-guangzhou")
	fs.StringVar(&o.instance, "instance", "", "CVM instance ID, e.g. ins-xxxx")
	fs.StringVar(&o.command, "cmd", "", "shell command to run")
	fs.DurationVar(&o.timeout, "timeout", 180*time.Second, "overall timeout")
	fs.DurationVar(&o.interval, "interval", 3*time.Second, "poll interval")
	fs.BoolVar(&o.quiet, "quiet", false, "print only the command's stdout, for piping")
	return fs
}

// parseArgs parses args into options.
func parseArgs(args []string) (*options, error) {
	var o options
	fs := newFlagSet(&o)
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil, errHelp
		}
		return nil, errUsage
	}
	return &o, nil
}

func run() error {
	o, err := parseArgs(os.Args[1:])
	if err != nil {
		if errors.Is(err, errHelp) {
			return nil
		}
		return err
	}

	if o.region == "" || o.instance == "" || o.command == "" {
		return fmt.Errorf("-region, -instance and -cmd are required")
	}
	if err := validateInterval(o.interval); err != nil {
		return err
	}

	secretID := os.Getenv("TENCENTCLOUD_SECRET_ID")
	secretKey := os.Getenv("TENCENTCLOUD_SECRET_KEY")
	if secretID == "" || secretKey == "" {
		return fmt.Errorf("missing credentials: set TENCENTCLOUD_SECRET_ID / TENCENTCLOUD_SECRET_KEY")
	}

	cpf := profile.NewClientProfile()
	cpf.HttpProfile.Endpoint = "tat.tencentcloudapi.com"

	client, err := newTATClient(common.NewCredential(secretID, secretKey), o.region, cpf)
	if err != nil {
		return fmt.Errorf("build TAT client: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), o.timeout)
	defer cancel()

	runResp, err := client.RunCommandWithContext(ctx, buildRunCommand(o.command, o.instance, o.timeout))
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

	if !o.quiet {
		fmt.Fprintf(os.Stderr, "TAT command submitted (invocation=%s), waiting for it to run...\n", invocationID)
	}

	return waitForTask(ctx, client, invocationID, o.timeout, o.interval, o.quiet)
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

// timeoutErr turns "the deadline passed" into the message that names the invocation, whichever way
// it surfaced.
//
// run() gives the context the same duration as the loop's own deadline and creates it first, so in
// production the deadline always arrives through the context -- as an error from the SDK call or as
// ctx.Done() -- and both used to hand back a bare "context deadline exceeded". That made the
// diagnosable message below it unreachable, and left the operator with an error from a nested call
// instead of the invocation id to look up. A cancellation (SIGINT) is not a timeout and is returned
// unchanged.
func timeoutErr(ctx context.Context, invocationID string) error {
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return fmt.Errorf("timed out waiting for the TAT result (invocation=%s)", invocationID)
	}
	return ctx.Err()
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
			// run() gives this context the same duration as the deadline below, and creates it
			// first -- so in production the context always expires first and this returned its
			// raw error, making the diagnosable message below unreachable: the operator saw
			// "context deadline exceeded" from a nested SDK call instead of "the command did not
			// finish in time, here is the invocation id". Both are the same event, and the second
			// is the one with something to act on.
			if ctx.Err() != nil {
				return timeoutErr(ctx, invocationID)
			}
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
				out := decodeRemoteOutput(deref(task.TaskResult.Output))
				exitCode := derefI64(task.TaskResult.ExitCode)
				if !quiet {
					fmt.Fprintf(os.Stderr, "--- command output (exit=%d) ---\n", exitCode)
				}
				fmt.Print(out)
				// The API caps Output (24KB) and reports what it dropped, plus a link to the full
				// log. This tool exists to be the evidence an operator greps: partial output
				// presented as the whole answer turns "the certificate is missing from the log" into
				// "this listener is not serving it".
				if notice := truncationNotice(task.TaskResult); notice != "" {
					fmt.Fprintf(os.Stderr, "\n%s\n", notice)
				}
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
					// Decoded like the success path. The API returns Base64, so printing it raw
					// handed the operator a blob exactly when the command had failed -- the
					// moment the output is the whole point. Found by using the tool: a command
					// whose last statement exited non-zero printed its own error as Base64.
					fmt.Print(decodeRemoteOutput(deref(task.TaskResult.Output)))
				}
				return fmt.Errorf("TAT task %s: %s", deref(task.TaskStatus), deref(task.ErrorInfo))
			}
		}

		if time.Now().After(deadline) {
			return fmt.Errorf("timed out waiting for the TAT result (invocation=%s)", invocationID)
		}
		select {
		case <-ctx.Done():
			return timeoutErr(ctx, invocationID)
		case <-time.After(interval):
		}
	}
}

// validateInterval rejects a non-positive poll interval: waitForTask sleeps for interval
// between polls, and a value at or below zero turns that loop into a hot spin against the
// TAT API.
func validateInterval(interval time.Duration) error {
	if interval <= 0 {
		return fmt.Errorf("-interval must be positive, got %s (it is the sleep between TAT API polls)", interval)
	}
	return nil
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

// decodeRemoteOutput turns the API's encoding of a command's output into what the command printed.
//
// TaskResult.Output is documented as Base64-encoded command output (up to 24KB), and the
// API really does return it that way -- the captures in this repository's own e2e runs decode from
// Base64 to the openssl output they were checking. Printing the field verbatim therefore made the
// tool's entire evidence a blob: `-quiet | grep` matched nothing, and a reader had to know to decode
// it before they could tell which certificate a listener was serving.
//
// An undecodable value is printed as-is rather than dropped: whatever the server sent is still the
// only evidence there is, and silently printing nothing would be worse than printing something
// unreadable. The caller is told which happened.
//
// Decodable is not the same as "was encoded": a short word in the Base64 alphabet ("DONE") decodes
// cleanly into bytes that are not text at all. A decode that fails looksLikeText is not the
// command's output, so the original string is printed instead of the mojibake.
func decodeRemoteOutput(raw string) string {
	if raw == "" {
		return ""
	}
	if decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(raw)); err == nil && looksLikeText(decoded) {
		return string(decoded)
	}
	// Some encoders omit padding; try the unpadded alphabet before giving up.
	if decoded, err := base64.RawStdEncoding.DecodeString(strings.TrimRight(strings.TrimSpace(raw), "=")); err == nil && looksLikeText(decoded) {
		return string(decoded)
	}
	return raw
}

// looksLikeText reports whether a decoded payload is plausibly what a shell command printed:
// valid UTF-8 with no control characters other than the usual whitespace.
func looksLikeText(b []byte) bool {
	if !utf8.Valid(b) {
		return false
	}
	for _, r := range string(b) {
		if unicode.IsControl(r) && r != '\n' && r != '\r' && r != '\t' {
			return false
		}
	}
	return true
}

// truncationNotice words the warning for a truncated TaskResult, or returns "" when the output is
// whole.
//
// The API caps Output (24KB) and reports both the dropped byte count and a link to the full log.
// This tool is the evidence an operator greps -- "which certificate is this listener serving" -- so
// partial output presented as the whole answer turns "the certificate is missing from the log" into
// "this listener is not serving it".
func truncationNotice(r *tat.TaskResult) string {
	if r == nil {
		return ""
	}
	dropped := derefU64(r.Dropped)
	full := deref(r.OutputUrl)
	if dropped == 0 && full == "" {
		return ""
	}
	return fmt.Sprintf("WARNING: the remote output is incomplete: dropped=%d bytes, full log: %s",
		dropped, redactSignedURL(full))
}

// redactSignedURL strips the query string from a log URL before it is printed.
//
// TAT stores the full output in COS and returns a link to it. A presigned link IS the credential:
// anyone holding it can fetch the object until it expires, and this warning goes to stderr, which
// under systemd means the journal -- routinely shipped somewhere with a wider audience than the
// command's owner. The operator needs to know where the rest of the log is, not to be handed a
// bearer token for it in a log line: the signature is dropped and the command that can fetch it
// again is named instead.
func redactSignedURL(raw string) string {
	if raw == "" {
		return "(no URL returned)"
	}
	u, err := url.Parse(raw)
	if err != nil {
		// Unparseable: printing it verbatim is the one thing that must not happen, because the
		// query cannot be separated from the credential.
		return "(URL withheld: it may carry a signature)"
	}
	if u.RawQuery == "" && u.Fragment == "" {
		return raw
	}
	u.RawQuery = ""
	u.Fragment = ""
	return u.String() + " (query stripped: re-read it with the TAT console or DescribeInvocationTasks)"
}

func derefU64(v *uint64) uint64 {
	if v == nil {
		return 0
	}
	return *v
}

func derefI64(v *int64) int64 {
	if v == nil {
		return 0
	}
	return *v
}
