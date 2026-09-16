// Command clbverify queries the certificate bound to a CLB listener, for end-to-end assertions.
//
// Why it is its own tool: after wecert calls UpdateCertificateInstance, the only
// authoritative fact is whether the listener's CertId actually changed. Trusting wecert's
// own logs is not enough -- that is the blind spot of "the program believed it succeeded but
// nothing took effect", the most insidious failure class. This tool gathers independent
// evidence from the Tencent Cloud side.
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
		return fmt.Errorf("-region and -clb are required (-listener is optional; when omitted, the first listener on that CLB is used)")
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
	// With no ListenerIds, every listener on the CLB comes back.
	// Observed while debugging: filtering by ListenerIds can return entries without the
	// Certificate field, so the unfiltered path is kept for cross-checking.
	if *listenerID != "" {
		req.ListenerIds = []*string{common.StringPtr(*listenerID)}
	}

	resp, err := client.DescribeListenersWithContext(ctx, req)
	if err != nil {
		return fmt.Errorf("DescribeListeners: %w", err)
	}
	if resp.Response == nil || len(resp.Response.Listeners) == 0 {
		return noListenersError(*lbID, *listenerID)
	}

	if *raw {
		// For troubleshooting: print the server's response verbatim, so that a mismatch
		// between the field names we assume and what the API really returns is not a guess.
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

	// SNI extension certificates: this is exactly where rotating one certificate can
	// clobber another, so they are printed separately.
	if n := len(l.Certificate.ExtCertIds); n > 0 {
		fmt.Printf("  SNI certificates  : %d\n", n)
		for _, e := range l.Certificate.ExtCertIds {
			fmt.Printf("      %s\n", derefStr(e))
		}
	} else {
		fmt.Printf("  SNI certificates  : none\n")
	}

	// UpdateCertificateInstance is asynchronous: a return means only that the task was
	// created; the real rebind waits on the backend (~15s measured), so the assertion must wait.
	if *expect != "" && *wait > 0 && certID != *expect {
		// The wait loop needs its own, long-enough ctx.
		//
		// Reusing the 30-second ctx above makes every request return deadline exceeded once
		// -wait exceeds 30s, while the continue below swallows the error -- so it spins until
		// the deadline and then falsely reports "still not the expected value", which is
		// precisely the one scenario this tool exists for.
		waitCtx, cancelWait := context.WithTimeout(context.Background(), *wait+30*time.Second)
		defer cancelWait()

		deadline := time.Now().Add(*wait)
		var lastErr error
		for time.Now().Before(deadline) {
			time.Sleep(5 * time.Second)
			cur, err := fetchCertID(waitCtx, client, *lbID, *listenerID)
			if err != nil {
				// No more silent continue: the query itself failing and "not switched over
				// yet" are two completely different things, and both must be visible.
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

// noListenersError words the empty-listener failure to fit how the query was made:
// without a -listener filter an empty list really means the CLB has no listeners, but
// with one it means that specific listener matched nothing -- deleted, or a typo --
// while the CLB itself may be serving other listeners just fine. Blaming the CLB in
// that case sends the operator debugging the wrong object.
func noListenersError(lbID, listenerID string) error {
	if listenerID != "" {
		return fmt.Errorf("CLB %s returned no listener %s (it may have been deleted, or the ID is a typo)", lbID, listenerID)
	}
	return fmt.Errorf("CLB %s has no listeners", lbID)
}

// fetchCertID queries the listener's currently bound primary certificate ID once.
//
// With an empty listenerID it takes the first listener, the same way the main path does
// -- passing an empty ListenerIds makes the API error out, which the wait loop would then
// retry as though it were a network blip.
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
