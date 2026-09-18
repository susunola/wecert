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
