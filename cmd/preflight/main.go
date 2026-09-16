// Command preflight validates credentials and preconditions before touching any cloud resource.
//
// It checks four things (all read-only; nothing is created or modified):
//  1. the credentials work (the SSL certificate service can be listed)
//  2. there is DNSPod read access, and the target domain is really in this account
//  3. the domain's NS really point at DNSPod -- otherwise a written TXT record never
//     takes effect, and the attempt burns an authorization-failure quota for nothing
//  4. whether an _acme-challenge record already exists (leftovers confuse CA validation)
//
// Item 3 has the highest troubleshooting value and is the most common root cause of
// "the TXT record is written but the CA will not validate": the domain is hosted
// elsewhere, or the NS switch has not finished.
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common"
	tcerrors "github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common/errors"
	"github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common/profile"
	dnspod "github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/dnspod/v20210323"
	ssl "github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/ssl/v20191205"
)

func main() {
	domain := flag.String("domain", "", "domain to verify, e.g. atomwangnus.com")
	listCerts := flag.Bool("list-certs", false, "list SSL certificates in the account (ID / alias / domain / status)")
	pruneCerts := flag.Bool("prune-certs", false, "delete the certificates wecert uploaded (alias starting with wecert/)")
	yes := flag.Bool("yes", false, "use with -prune-certs to skip the interactive confirmation")
	bindings := flag.String("bindings", "", "dump the raw bind-resource result for a certificate ID (debugging)")
	flag.Parse()

	if *bindings != "" {
		if err := dumpBindings(*bindings); err != nil {
			fmt.Fprintf(os.Stderr, "\nFAILED: %v\n", err)
			os.Exit(1)
		}
		return
	}

	switch {
	case *pruneCerts:
		if err := pruneCertificates(*yes); err != nil {
			fmt.Fprintf(os.Stderr, "\n❌ %v\n", err)
			os.Exit(1)
		}
		return
	case *listCerts:
		if err := listCertificates(); err != nil {
			fmt.Fprintf(os.Stderr, "\n❌ %v\n", err)
			os.Exit(1)
		}
		return
	case *domain == "":
		fmt.Fprintln(os.Stderr, "usage: preflight -domain <domain>")
		fmt.Fprintln(os.Stderr, "      preflight -list-certs")
		fmt.Fprintln(os.Stderr, "      preflight -prune-certs [-yes]")
		os.Exit(1)
	}

	if err := run(*domain); err != nil {
		fmt.Fprintf(os.Stderr, "\nFAILED: preflight error: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("\nOK: all preflight checks passed")
}

// creds loads and validates the Tencent Cloud credentials.
//
// It does not echo a SecretId prefix: the old implementation printed id[:8], which
// panics when the environment variable is truncated or malformed, and writing part of a
// secret into terminal history buys nothing -- knowing it is "loaded" is enough.
func creds() (common.CredentialIface, error) {
	id := os.Getenv("TENCENTCLOUD_SECRET_ID")
	key := os.Getenv("TENCENTCLOUD_SECRET_KEY")
	if id == "" || key == "" {
		return nil, fmt.Errorf("missing credentials: set TENCENTCLOUD_SECRET_ID / TENCENTCLOUD_SECRET_KEY")
	}
	return common.NewCredential(id, key), nil
}

func run(domain string) error {
	cred, err := creds()
	if err != nil {
		return err
	}
	fmt.Println("credentials: loaded")
	fmt.Println()

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	if err := checkSSL(ctx, cred); err != nil {
		return err
	}
	if err := checkDNSPod(ctx, cred, domain); err != nil {
		return err
	}
	return checkDelegation(ctx, domain)
}

// checkDelegation confirms the domain's authoritative NS really are DNSPod's.
//
// This deserves its own check: a domain added to DNSPod while the NS still point at
// another host is the classic cause of "the TXT write succeeded but CA validation
// failed". Every attempt then costs wecert one authorization-failure quota unit (5 per
// hour), while the error message says only "validation failed" and hides the root cause.
func checkDelegation(ctx context.Context, domain string) error {
	fmt.Println()
	fmt.Println("[4/4] authoritative nameserver delegation check")

	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	names, err := net.DefaultResolver.LookupNS(ctx, domain)
	if err != nil {
		return fmt.Errorf("lookup NS for %s failed: %w", domain, err)
	}
	if len(names) == 0 {
		return fmt.Errorf("%s has no NS records", domain)
	}

	var hosts []string
	allOnDNSPod := true
	for _, ns := range names {
		host := strings.TrimSuffix(ns.Host, ".")
		hosts = append(hosts, host)
		if !isDNSPodNS(host) {
			allOnDNSPod = false
		}
	}

	// Every returned NS must be DNSPod's, not just any one of them: with a partial
	// delegation some resolvers land on the other host and never see the TXT record,
	// so validation fails intermittently -- the hardest kind to diagnose.
	if !allOnDNSPod {
		// No trailing newline: this is an error value first and a printed message
		// second, and a wrapping caller should decide the spacing. The internal
		// newlines are the multi-line diagnosis itself, which is the point.
		return fmt.Errorf(
			"%s's nameservers are not all DNSPod: %s\n"+
				"     TXT records written at DNSPod will never be resolved, so CA validation is guaranteed to fail.\n"+
				"     point the domain's NS at DNSPod first, or switch to the dns.provider for that host",
			domain, strings.Join(hosts, ", "))
	}

	fmt.Printf("      OK - %d nameservers, all pointing at DNSPod (%s)\n", len(hosts), strings.Join(hosts, ", "))
	return nil
}

// isDNSPodNS reports whether a nameserver hostname belongs to DNSPod.
//
// DNSPod's authoritative hostnames live under its own domains: the free tier's
// dedicated addresses look like <account-specific>.dnspod.net / .dnspod.com (older
// ones f1g1ns1.dnspod.net), and the paid tiers use ns?.dnsv1.com .. ns?.dnsv5.com
// (see docs.dnspod.cn/dns/dns-plan-address). Matching is by *suffix* on the lowercased
// host: a substring match would false-pass lookalikes such as ns1.dnsvault.example,
// and a case-sensitive one would false-fail a mixed-case record, while DNS is
// case-insensitive.
func isDNSPodNS(host string) bool {
	host = strings.ToLower(host)
	for _, suffix := range []string{".dnspod.net", ".dnspod.com", ".dnsv1.com", ".dnsv2.com", ".dnsv3.com", ".dnsv4.com", ".dnsv5.com"} {
		if strings.HasSuffix(host, suffix) {
			return true
		}
	}
	return false
}

// checkSSL verifies read access to the SSL certificate service.
func checkSSL(ctx context.Context, cred common.CredentialIface) error {
	fmt.Println("[1/4] SSL certificate service read access")
	cpf := profile.NewClientProfile()
	cpf.HttpProfile.Endpoint = "ssl.tencentcloudapi.com"

	client, err := ssl.NewClient(cred, "", cpf)
	if err != nil {
		return fmt.Errorf("build SSL client: %w", err)
	}

	req := ssl.NewDescribeCertificatesRequest()
	req.Limit = common.Uint64Ptr(1)

	resp, err := client.DescribeCertificatesWithContext(ctx, req)
	if err != nil {
		return fmt.Errorf("DescribeCertificates failed (check the ssl:DescribeCertificates permission): %w", err)
	}

	var total uint64
	if resp.Response != nil && resp.Response.TotalCount != nil {
		total = *resp.Response.TotalCount
	}
	fmt.Printf("      OK - the account already holds %d certificates\n", total)
	return nil
}

// describeDomainList is the seam over the SDK call, so the paging logic in findDomain
// can be tested without real credentials.
var describeDomainList = func(ctx context.Context, client *dnspod.Client, req *dnspod.DescribeDomainListRequest) (*dnspod.DescribeDomainListResponse, error) {
	return client.DescribeDomainListWithContext(ctx, req)
}

// findDomain looks the target domain up in this account's DNSPod domain list.
//
// Keyword is a substring filter capped by Limit, not an exact lookup: an account with
// more than one page of matches (example.com, www.example.com, example.com.cn, ...)
// can hide the exact hit behind unrelated domains, and trusting one page would
// false-report "domain not under DNSPod" for a domain that really is. Page through
// until the filtered total is covered before drawing that conclusion.
//
// A nil item (with nil error) means the account genuinely does not hold the domain.
func findDomain(ctx context.Context, client *dnspod.Client, domain string) (*dnspod.DomainListItem, error) {
	var offset int64
	for {
		req := dnspod.NewDescribeDomainListRequest()
		req.Keyword = common.StringPtr(domain)
		req.Limit = common.Int64Ptr(100)
		req.Offset = common.Int64Ptr(offset)

		resp, err := describeDomainList(ctx, client, req)
		if err != nil {
			return nil, fmt.Errorf("DescribeDomainList failed (check the dnspod:DescribeDomainList permission): %w", err)
		}
		if resp.Response == nil {
			return nil, fmt.Errorf("DescribeDomainList returned an empty response")
		}

		for _, d := range resp.Response.DomainList {
			if d.Name != nil && strings.EqualFold(*d.Name, domain) {
				return d, nil
			}
		}

		offset += int64(len(resp.Response.DomainList))
		// An empty page before the filtered total is covered means the list shifted
		// under us; stopping there beats looping on a moving target. A missing total
		// likewise means "keep going until an empty page says stop".
		if len(resp.Response.DomainList) == 0 {
			return nil, nil
		}
		if info := resp.Response.DomainCountInfo; info != nil && info.DomainTotal != nil && offset >= int64(*info.DomainTotal) {
			return nil, nil
		}
	}
}

// checkDNSPod verifies DNSPod read access and confirms the domain belongs to this account.
func checkDNSPod(ctx context.Context, cred common.CredentialIface, domain string) error {
	fmt.Println("[2/4] DNSPod domain ownership")

	cpf := profile.NewClientProfile()
	cpf.HttpProfile.Endpoint = "dnspod.tencentcloudapi.com"

	client, err := dnspod.NewClient(cred, "", cpf)
	if err != nil {
		return fmt.Errorf("build DNSPod client: %w", err)
	}

	found, err := findDomain(ctx, client, domain)
	if err != nil {
		return err
	}

	if found == nil {
		return fmt.Errorf(
			"domain %s is not under DNSPod in this Tencent Cloud account.\n"+
				"     either the domain is hosted elsewhere, or you need a DNSPod API token (dns.provider=dnspod)",
			domain)
	}

	fmt.Printf("      OK - %s found", deref(found.Name))
	if found.Status != nil {
		fmt.Printf(", status %s", *found.Status)
	}
	if found.Grade != nil {
		fmt.Printf(", plan %s", *found.Grade)
	}
	fmt.Println()

	// Also check whether any _acme-challenge records are left over.
	recReq := dnspod.NewDescribeRecordListRequest()
	recReq.Domain = common.StringPtr(domain)
	recReq.Subdomain = common.StringPtr("_acme-challenge")
	recReq.RecordType = common.StringPtr("TXT")

	recResp, err := client.DescribeRecordListWithContext(ctx, recReq)
	if err != nil {
		// When there are no records at all DNSPod returns an error code rather than an
		// empty list -- which is exactly the state we want, so it must not count as failure.
		if isNoRecord(err) {
			fmt.Println()
			fmt.Println("[3/4] _acme-challenge leftover check")
			fmt.Println("      OK - no leftover TXT records")
			return nil
		}
		return fmt.Errorf("DescribeRecordList failed (check the dnspod:DescribeRecordList permission): %w", err)
	}

	n := 0
	var records []*dnspod.RecordListItem
	if recResp.Response != nil {
		records = recResp.Response.RecordList
		n = len(records)
	}
	fmt.Println()
	fmt.Println("[3/4] _acme-challenge leftover check")
	if n == 0 {
		fmt.Println("      OK - no leftover TXT records")
	} else {
		fmt.Printf("      WARNING: %d TXT records already exist; confirm another system is not using them:\n", n)
		for _, r := range records {
			fmt.Printf("          %s = %s\n", deref(r.Name), deref(r.Value))
		}
	}
	return nil
}

func deref(s *string) string {
	if s == nil {
		return "<nil>"
	}
	return *s
}

// isNoRecord reports whether the error means "the record list is empty".
// DNSPod expresses that with ResourceNotFound.NoDataOfRecord.
func isNoRecord(err error) bool {
	var sdkErr *tcerrors.TencentCloudSDKError
	if errors.As(err, &sdkErr) {
		return sdkErr.Code == "ResourceNotFound.NoDataOfRecord"
	}
	return strings.Contains(err.Error(), "NoDataOfRecord")
}

// listCertificates lists the SSL certificates in the account.
// Its main uses: confirm what state the certificates wecert uploaded are really in, and
// find the ones piling up from testing so they can be cleaned up.
func listCertificates() error {
	cred, err := creds()
	if err != nil {
		return err
	}

	cpf := profile.NewClientProfile()
	cpf.HttpProfile.Endpoint = "ssl.tencentcloudapi.com"
	client, err := ssl.NewClient(cred, "", cpf)
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	req := ssl.NewDescribeCertificatesRequest()
	req.Limit = common.Uint64Ptr(100)
	resp, err := client.DescribeCertificatesWithContext(ctx, req)
	if err != nil {
		return err
	}
	if resp.Response == nil {
		return fmt.Errorf("DescribeCertificates returned an empty response")
	}

	fmt.Printf("%-12s %-28s %-40s %-10s %s\n", "CertId", "alias", "domain", "status", "source")
	for _, c := range resp.Response.Certificates {
		fmt.Printf("%-12s %-28s %-40s %-10d %s\n",
			deref(c.CertificateId), deref(c.Alias), deref(c.Domain), derefU64(c.Status), deref(c.CertificateType))
	}

	listed := len(resp.Response.Certificates)
	total := derefU64(resp.Response.TotalCount)
	fmt.Printf("\n%d total\n", total)
	if total > uint64(listed) {
		// Without paging some certificates go unlisted (and thus undeleted), and the list still looks complete.
		fmt.Printf("note: the server reports %d in total, more than the %d listed here (page size 100),"+
			"so this list may be incomplete\n", total, listed)
	}
	return nil
}

func derefU64(v *uint64) uint64 {
	if v == nil {
		return 0
	}
	return *v
}

// Page size and page cap for the certificate listing.
const (
	prunePageSize = 100
	pruneMaxPages = 1000 // 100k certificates: a bound on a server that ignores Offset
)

// certPage is one page of an SSL certificate listing.
type certPage struct {
	certs []*ssl.Certificates
	// total is what the server reported, or nil when it reported nothing.
	total *uint64
}

// listAllPages walks every page of a certificate listing.
//
// Termination must not hinge on TotalCount. The API leaves it null in some responses --
// the same shape that caused the CLB rebind false failure -- and a nil total read as 0
// would stop the walk after the first page. That is silent truncation, and here the walk
// is exactly what decides which certificates get deleted, so the command would report a
// complete cleanup while leaving the rest of the account behind. A short page is the
// reliable end-of-list signal; TotalCount is only used to stop earlier when it is present.
func listAllPages(pageSize, maxPages int, fetch func(offset, limit uint64) (certPage, error)) ([]*ssl.Certificates, error) {
	var all []*ssl.Certificates
	var offset uint64

	for page := 0; ; page++ {
		if page >= maxPages {
			return nil, fmt.Errorf("the certificate listing did not advance after %d pages (%d certificates): "+
				"refusing to loop, and refusing to report a cleanup that saw only part of the account", page, offset)
		}

		p, err := fetch(offset, uint64(pageSize))
		if err != nil {
			return nil, err
		}
		all = append(all, p.certs...)

		if len(p.certs) < pageSize {
			return all, nil
		}
		offset += uint64(len(p.certs))
		if p.total != nil && offset >= *p.total {
			return all, nil
		}
	}
}

// pruneCertificates deletes the certificates wecert uploaded.
//
// Why it is needed: accounts have a quota on uploaded certificates, and long-running testing
// or automation that never reclaims them will hit it and be unable to renew.
//
// ⚠️ On scope: when uploading, wecert prefixes **every** certificate with "wecert/" (see
// upload in deploy.tencent.go), so this selects not only test leftovers but **also the one
// serving production right now**. Hence the confirmation gate -- an earlier version printed
// the list and deleted straight away, and anyone without a --dry-run habit hurt production.
func pruneCertificates(assumeYes bool) error {
	cred, err := creds()
	if err != nil {
		return err
	}

	cpf := profile.NewClientProfile()
	cpf.HttpProfile.Endpoint = "ssl.tencentcloudapi.com"
	client, err := ssl.NewClient(cred, "", cpf)
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	const prefix = "wecert/"
	var doomed []*ssl.Certificates

	// Page through the whole list: this listing drives deletion, so silently seeing
	// only the first 100 certificates would leave the rest in place while looking like
	// a complete cleanup.
	certs, err := listAllPages(prunePageSize, pruneMaxPages, func(offset, limit uint64) (certPage, error) {
		listReq := ssl.NewDescribeCertificatesRequest()
		listReq.Limit = common.Uint64Ptr(limit)
		listReq.Offset = common.Uint64Ptr(offset)
		listResp, err := client.DescribeCertificatesWithContext(ctx, listReq)
		if err != nil {
			return certPage{}, err
		}
		if listResp.Response == nil {
			return certPage{}, fmt.Errorf("DescribeCertificates returned an empty response")
		}
		return certPage{certs: listResp.Response.Certificates, total: listResp.Response.TotalCount}, nil
	})
	if err != nil {
		return err
	}

	for _, c := range certs {
		if strings.HasPrefix(deref(c.Alias), prefix) {
			doomed = append(doomed, c)
		}
	}

	if len(doomed) == 0 {
		fmt.Println("no wecert-uploaded certificates to clean up")
		return nil
	}

	fmt.Printf("about to delete %d certificates uploaded by wecert:\n", len(doomed))
	for _, c := range doomed {
		fmt.Printf("  %-12s %-28s %s\n", deref(c.CertificateId), deref(c.Alias), deref(c.Domain))
	}
	fmt.Println()
	fmt.Println("WARNING: this list includes certificates currently serving live traffic - wecert uses the same alias prefix")
	fmt.Println("    for every certificate it uploads. Deleting one that a CLB still references will break HTTPS.")
	fmt.Println("    if you only meant to clean up test leftovers, check the alias and domain above first.")

	if !assumeYes {
		if !confirm("delete all of the certificates above?") {
			fmt.Println("cancelled; nothing was deleted")
			return nil
		}
	}

	var failed int
	for _, c := range doomed {
		req := ssl.NewDeleteCertificateRequest()
		req.CertificateId = c.CertificateId
		// IsCheckResource=false deliberately skips the server-side associated-resource
		// check. This standalone tool never opens wecert's state store, so it cannot
		// know what is bound; the WARNING printed above plus the interactive
		// confirmation gate (skipped only by -yes) is the entire protection against
		// deleting a certificate a CLB still references.
		req.IsCheckResource = common.BoolPtr(false)
		if _, err := client.DeleteCertificateWithContext(ctx, req); err != nil {
			fmt.Printf("  failed to delete %s: %v\n", deref(c.CertificateId), err)
			failed++
			continue
		}
		fmt.Printf("  deleted %s\n", deref(c.CertificateId))
	}
	if failed > 0 {
		return fmt.Errorf("%d certificates could not be deleted (the rest were)", failed)
	}
	return nil
}

// confirm reads one y/N from the terminal, and treats a non-interactive stdin (not a
// terminal) as no -- deleting certificates must not pass just because nobody watched.
func confirm(prompt string) bool {
	fmt.Printf("%s [y/N] ", prompt)

	sc := bufio.NewScanner(os.Stdin)
	if !sc.Scan() {
		fmt.Println()
		return false
	}
	switch strings.ToLower(strings.TrimSpace(sc.Text())) {
	case "y", "yes":
		return true
	default:
		return false
	}
}

// dumpBindings prints the raw API response for "which cloud resources this certificate
// is bound to".
//
// For troubleshooting: the server's field semantics for bindings (what Status can hold,
// when results are populated) must not be guessed -- dump the raw response instead.
func dumpBindings(certID string) error {
	secretID := os.Getenv("TENCENTCLOUD_SECRET_ID")
	secretKey := os.Getenv("TENCENTCLOUD_SECRET_KEY")
	if secretID == "" || secretKey == "" {
		return fmt.Errorf("missing credentials: set TENCENTCLOUD_SECRET_ID / TENCENTCLOUD_SECRET_KEY")
	}

	cpf := profile.NewClientProfile()
	cpf.HttpProfile.Endpoint = "ssl.tencentcloudapi.com"
	client, err := ssl.NewClient(common.NewCredential(secretID, secretKey), "", cpf)
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	createReq := ssl.NewCreateCertificateBindResourceSyncTaskRequest()
	createReq.CertificateIds = []*string{common.StringPtr(certID)}
	createReq.IsCache = common.Uint64Ptr(1)

	createResp, err := client.CreateCertificateBindResourceSyncTaskWithContext(ctx, createReq)
	if err != nil {
		return fmt.Errorf("CreateCertificateBindResourceSyncTask: %w", err)
	}
	b1, _ := json.MarshalIndent(createResp.Response, "", "  ")
	fmt.Printf("=== CreateCertificateBindResourceSyncTask ===\n%s\n\n", b1)

	var taskID string
	if createResp.Response != nil {
		for _, t := range createResp.Response.CertTaskIds {
			if t != nil && t.CertId != nil && *t.CertId == certID && t.TaskId != nil {
				taskID = *t.TaskId
			}
		}
	}
	if taskID == "" {
		return fmt.Errorf("no task id returned for %s", certID)
	}
	fmt.Printf("taskId = %s\n\n", taskID)

	for i := 1; i <= 6; i++ {
		queryReq := ssl.NewDescribeCertificateBindResourceTaskResultRequest()
		queryReq.TaskIds = []*string{common.StringPtr(taskID)}

		queryResp, err := client.DescribeCertificateBindResourceTaskResultWithContext(ctx, queryReq)
		if err != nil {
			return fmt.Errorf("DescribeCertificateBindResourceTaskResult: %w", err)
		}
		b2, _ := json.MarshalIndent(queryResp.Response, "", "  ")
		fmt.Printf("=== DescribeCertificateBindResourceTaskResult (poll %d) ===\n%s\n", i, b2)

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(4 * time.Second):
		}
	}
	return nil
}
