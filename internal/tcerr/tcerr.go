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

// IsNoDataOfRecord reports whether err means "the query matched no record".
//
// It is not a failure to read the zone: DNSPod returns this both for a zone with no records and
// for a filtered query whose filter matched none. The typed check comes first; the substring
// fallback covers an error that was already wrapped into a plain error somewhere above, or that
// came back through a path that dropped the SDK type.
func IsNoDataOfRecord(err error) bool {
	if err == nil {
		return false
	}
	var sdkErr *tcerrors.TencentCloudSDKError
	if errors.As(err, &sdkErr) {
		return sdkErr.Code == CodeNoDataOfRecord
	}
	return strings.Contains(err.Error(), CodeNoDataOfRecord)
}
