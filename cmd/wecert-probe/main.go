// Command wecert-probe 拨一个真实的 TLS 连接，读回对端**实际出示**的证书。
//
// 它是排障时的第一件工具，因为"云 API 说绑定成功"和"浏览器真的能拿到
// 这张证书"是两件事：换绑是异步的（实测约 15 秒），SNI 上也可能有
// 另一张证书在赢 —— 而这两件事控制面都看不出来。
//
// 用法：
//
//	wecert-probe -host www.example.com
//	wecert-probe -host www.example.com -min-valid 168h
//	wecert-probe -host www.example.com -wait 90s     # 刚换完绑，等它生效
//	wecert-probe -host a.example.com,b.example.com -json
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/susunola/wecert/internal/probe"
)

// version 可通过 -ldflags "-X main.version=..." 注入。
var version = "dev"

// 退出码。分开是有用的：脚本里"拨不到"和"服务的是错的证书"
// 需要走完全不同的处理路径。
const (
	exitOK          = 0
	exitUnreachable = 1
	exitMismatch    = 2
	exitUsage       = 64
)

func main() { os.Exit(run()) }

func run() int {
	fs := flag.NewFlagSet("wecert-probe", flag.ContinueOnError)
	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), `wecert-probe %s

Dial a real TLS connection and report the certificate the far end actually serves.

This is the only evidence in wecert that does not trust the cloud control plane:
a rebind is asynchronous, and another certificate can be winning SNI.
Neither is visible through the API.

Usage:
  wecert-probe -host www.example.com [-min-valid 168h] [-wait 90s]

Exit codes:
  0  every host served the expected certificate
  1  could not complete a probe (resolve / dial / handshake failed)
  2  a probe completed but the certificate served was not the expected one

Flags:
`, version)
		fs.PrintDefaults()
	}

	var (
		hostFlag = fs.String("host", "", "comma-separated names to probe (required)")
		port     = fs.Int("port", 443, "TCP port to dial")
		timeout  = fs.Duration("timeout", probe.DefaultTimeout, "per-attempt timeout")
		minValid = fs.Duration("min-valid", 0, "fail if the served certificate has less than this left, e.g. 168h")
		expectSA = fs.String("expect-san", "", "comma-separated SAN set that was deployed; the served set must match exactly")
		expectNA = fs.String("expect-not-after", "", "RFC3339 notAfter of the certificate that was deployed; catches a rebind that did not take effect")
		wait     = fs.Duration("wait", 0, "poll until the verdict is ok or this long elapses (e.g. 90s)")
		asJSON   = fs.Bool("json", false, "print the raw result as JSON")
		showVer  = fs.Bool("version", false, "print the version and exit")
	)

	if err := fs.Parse(os.Args[1:]); err != nil {
		return exitUsage
	}
	if *showVer {
		fmt.Println("wecert-probe", version)
		return exitOK
	}

	hosts := splitList(*hostFlag)
	if len(hosts) == 0 {
		fs.Usage()
		return exitUsage
	}

	e := probe.Expectation{
		Domains:     splitList(*expectSA),
		MinValidFor: *minValid,
	}
	if *expectNA != "" {
		t, err := time.Parse(time.RFC3339, *expectNA)
		if err != nil {
			fmt.Fprintf(os.Stderr, "wecert-probe: -expect-not-after must be RFC3339: %v\n", err)
			return exitUsage
		}
		e.NotAfter = t
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	opts := probe.Options{Port: *port, Timeout: *timeout}

	// 汇总用的最坏结果：mismatch 比 unreachable 更值得让脚本停下来，
	// 所以它优先。
	worst := exitOK
	for _, host := range hosts {
		code := checkOne(ctx, host, opts, e, *wait, *asJSON)
		if code == exitMismatch {
			worst = exitMismatch
		} else if code == exitUnreachable && worst == exitOK {
			worst = exitUnreachable
		}
	}
	return worst
}

// checkOne 探测一个名字，必要时轮询等待，返回它的退出码。
func checkOne(ctx context.Context, host string, opts probe.Options, e probe.Expectation, wait time.Duration, asJSON bool) int {
	deadline := time.Time{}
	if wait > 0 {
		deadline = time.Now().Add(wait)
	}

	attempt := 0
	for {
		attempt++
		code, retry := attemptOnce(ctx, host, opts, e, asJSON, attempt)

		// 只有"还没生效"才值得等：拨不到和证书不对都不是等一等就会好的。
		if !retry || deadline.IsZero() || time.Now().After(deadline) {
			return code
		}
		if ctx.Err() != nil {
			return code
		}
		if !asJSON {
			fmt.Fprintf(os.Stderr, "  ... not there yet, retrying until %s\n",
				deadline.Format(time.RFC3339))
		}
		select {
		case <-ctx.Done():
			return code
		case <-time.After(5 * time.Second):
		}
	}
}

// attemptOnce 探测一次。retry 为真表示"再等一会儿可能会好"。
func attemptOnce(ctx context.Context, host string, opts probe.Options, e probe.Expectation, asJSON bool, attempt int) (code int, retry bool) {
	res, err := probe.Probe(ctx, host, opts)
	if err != nil {
		if asJSON {
			emitJSON(map[string]any{"host": host, "error": err.Error()})
		} else {
			fmt.Printf("%s\n  unreachable: %v\n\n", host, err)
		}
		// 网络抖动、VIP 还没起、DNS 还没生效 —— 这些都值得再试。
		return exitUnreachable, true
	}

	if e.Now.IsZero() {
		e.Now = time.Now()
	}
	v := res.Verify(e)

	if asJSON {
		emitJSON(map[string]any{"host": host, "result": res, "verdict": v, "attempt": attempt})
	} else {
		printHuman(res, v, e.Now)
	}

	if v.OK {
		return exitOK, false
	}
	// 状态不对时也重试：刚换完绑的那十几秒里，看到旧证书是正常的。
	return exitMismatch, true
}

func printHuman(res *probe.Result, v probe.Verdict, now time.Time) {
	fmt.Printf("%s\n", res.Host)
	fmt.Printf("  remote      %s\n", res.RemoteAddr)
	fmt.Printf("  resolved    %s\n", strings.Join(res.ResolvedIPs, ", "))
	fmt.Printf("  subject     %s\n", res.Subject)
	fmt.Printf("  issuer      %s\n", res.Issuer)
	if res.Trusted {
		fmt.Printf("  trusted     yes\n")
	} else {
		// 不可信不等于坏：内网 CA 是合法的，但浏览器里会红。
		fmt.Printf("  trusted     no (%s)\n", firstLine(res.ChainError))
	}
	fmt.Printf("  validity    %s -> %s  (%d days left)\n",
		res.NotBefore.UTC().Format(time.RFC3339), res.NotAfter.UTC().Format(time.RFC3339), res.DaysLeft(now))
	fmt.Printf("  sans        %s\n", strings.Join(res.SANs, ", "))
	fmt.Printf("  handshake   %dms\n", res.HandshakeMS)

	if v.OK {
		fmt.Printf("  verdict     ok\n\n")
		return
	}
	fmt.Printf("  verdict     FAILED\n")
	for _, p := range v.Problems {
		fmt.Printf("    - %s\n", p)
	}
	fmt.Println()
}

func emitJSON(v any) {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	_ = enc.Encode(v)
}

func splitList(s string) []string {
	var out []string
	for _, p := range strings.FieldsFunc(s, func(r rune) bool {
		return r == ',' || r == ' ' || r == '\t' || r == '\n'
	}) {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	sort.Strings(out)
	return out
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	if s == "" {
		return "no chain error reported"
	}
	return s
}
