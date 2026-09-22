// Package tcerr classifies Tencent Cloud API errors whose codes matter to a caller.
//
// It exists because two tools need the same answer and had grown their own copy: DNSPod's
// DescribeRecordList reports "this query matched nothing" as an error
// (ResourceNotFound.NoDataOfRecord) rather than as an empty list, so every caller that lists
// records has to recognise it. Two copies of an API quirk drift the first time one is touched.
package tcerr

import (
	"errors"
	"strings"

	tcerrors "github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common/errors"
)

// CodeNoDataOfRecord is the code DNSPod returns when a record query matches nothing.
const CodeNoDataOfRecord = "ResourceNotFound.NoDataOfRecord"

// CodeNoDataOfDomain is a code DNSPod has been reported to return when a domain query matches
// nothing.
//
// It is the sibling of CodeNoDataOfRecord one level up, and it is kept as a defensive case: the
// round-11 verification pass called the live API and could NOT reproduce it. What the API actually
// does (measured): a Keyword-filtered DescribeDomainList with no match answers HTTP 200 with an
// empty DomainList and DomainCountInfo.DomainTotal = 0 -- no error at all -- and a domain that is
// not in the account answers InvalidParameterValue.DomainNotExists ("Domain not exist.") for both
// DescribeDomainList and DescribeRecordList. Classifying only the record code left that shape
// unhandled, so cmd/preflight's findDomain -- documented as "nil, nil means the domain is not under
// DNSPod in this account" -- never reached its own documented answer: the operator got
// "DescribeDomainList failed (check the dnspod:DescribeDomainList permission)" for a permission that
// was fine and a domain that simply is not there.
const CodeNoDataOfDomain = "ResourceNotFound.NoDataOfDomain"

// CodeDomainNotExists is what the live API returns for a domain outside this account.
//
// Measured on both DescribeDomainList and DescribeRecordList during the round-11 verification, in
// place of the CodeNoDataOfDomain shape the code was written against.
const CodeDomainNotExists = "InvalidParameterValue.DomainNotExists"

// IsNoDataOfRecord reports whether err means "the query matched no record".
//
// It is not a failure to read the zone: DNSPod returns this both for a zone with no records and
// for a filtered query whose filter matched none. The typed check comes first; the substring
// fallback covers an error that was already wrapped into a plain error somewhere above, or that
// came back through a path that dropped the SDK type.
func IsNoDataOfRecord(err error) bool {
	return isNoData(err, CodeNoDataOfRecord)
}

// IsNoDataOfDomain reports whether err means "the query matched no domain in this account".
//
// Two codes, because the API has two shapes for it and only one of them is an error: a query with a
// Keyword filter that matches nothing returns an empty list (handled by the caller), while a domain
// that belongs to someone else comes back as InvalidParameterValue.DomainNotExists. Recognising only
// the documented-but-unobserved code made the caller's own answer unreachable.
func IsNoDataOfDomain(err error) bool {
	return isNoData(err, CodeNoDataOfDomain) || isNoData(err, CodeDomainNotExists)
}

func isNoData(err error, code string) bool {
	if err == nil {
		return false
	}
	var sdkErr *tcerrors.TencentCloudSDKError
	if errors.As(err, &sdkErr) {
		return sdkErr.Code == code
	}
	return strings.Contains(err.Error(), code)
}

// permanentCodePrefixes are the error-code families a retry cannot fix.
//
// A polling loop that treats these the same as "the answer is not ready yet" burns its whole
// budget on an error that will answer identically every time, and then reports the timeout --
// so a revoked key or a missing permission reaches the operator as "the task was slow".
//
// Deliberately absent: RequestLimitExceeded (throttling is transient, it only needs a longer
// wait -- see IsThrottled) and FailedOperation.* (its meaning is per-API and some of its
// members are genuinely transient).
var permanentCodePrefixes = []string{
	"AuthFailure.",          // the key is wrong, disabled or deleted
	"UnauthorizedOperation", // the key is fine, the account may not call this API
	"InvalidParameter.",     // the request itself is malformed
	"InvalidParameterValue.",
	"MissingParameter",
	"UnsupportedOperation", // not available for this account/region/resource
	"UnsupportedRegion",
	"LimitExceeded.", // a quota ceiling no retry will lift
}

// IsPermanent reports whether err is an API error that retrying cannot fix.
//
// It is the answer a polling loop needs before deciding to wait again: not every failure of a
// *query* means "the answer is not ready yet". An error with no recognisable code at all is
// treated as retryable -- guessing otherwise would abandon a task on the strength of an
// error nobody classified.
func IsPermanent(err error) bool {
	if err == nil {
		return false
	}
	if code := Code(err); code != "" {
		return hasAnyPrefix(code, permanentCodePrefixes)
	}
	// A wrapped or plain error still carries the code somewhere in its text.
	return containsAny(err.Error(), permanentCodePrefixes)
}

// IsThrottled reports whether err is the API asking the caller to slow down.
//
// It is retryable, so it must not be treated as permanent -- but hammering it at the polling
// interval amplifies the throttling instead of waiting it out.
//
// Nil is not throttled. IsPermanent and isNoData already guard nil; this one used to fall
// through to err.Error() on the right of || and panic on a nil error from a polling loop.
func IsThrottled(err error) bool {
	if err == nil {
		return false
	}
	return strings.HasPrefix(Code(err), "RequestLimitExceeded") ||
		strings.Contains(err.Error(), "RequestLimitExceeded")
}

// Code returns the Tencent Cloud API error code carried by err, or "" when it has none.
func Code(err error) string {
	if err == nil {
		return ""
	}
	var sdkErr *tcerrors.TencentCloudSDKError
	if errors.As(err, &sdkErr) {
		return sdkErr.Code
	}
	return ""
}

func hasAnyPrefix(s string, prefixes []string) bool {
	for _, p := range prefixes {
		if strings.HasPrefix(s, p) {
			return true
		}
	}
	return false
}

func containsAny(s string, prefixes []string) bool {
	for _, p := range prefixes {
		if strings.Contains(s, p) {
			return true
		}
	}
	return false
}
