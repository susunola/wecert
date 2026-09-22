package deploy

import (
	"fmt"
	"strings"

	"github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common"
	ssl "github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/ssl/v20191205"
)

func toPtrSlice(in []string) []*string {
	out := make([]*string, 0, len(in))
	for _, s := range in {
		out = append(out, common.StringPtr(s))
	}
	return out
}

func progressBoundCount(progress []*ssl.UpdateSyncProgress) (count int64, ready bool) {
	var n int64
	listed := 0
	answered := 0
	unanswered := 0
	for _, p := range progress {
		if p == nil {
			unanswered++
			continue
		}
		if len(p.UpdateSyncProgressRegions) == 0 {
			unanswered++
		}
		for _, r := range p.UpdateSyncProgressRegions {
			if r == nil {
				unanswered++
				continue
			}
			listed++
			if r.TotalCount != nil {
				answered++
				n += *r.TotalCount
			}
		}
	}
	return n, listed > 0 && answered == listed && unanswered == 0
}

func noResourceBoundError(oldID string, regions []string) error {
	return fmt.Errorf("UpdateCertificateInstance found no resource bound to the old certificate %s (regions=%v); refusing to mark the new certificate as deployed. Check that the CLB listener has it bound (an SNI listener must use multi_cert_info; the primary certificate_id is silently ignored)",
		oldID, regions)
}

func formatProgress(progress []*ssl.UpdateSyncProgress) string {
	if len(progress) == 0 {
		return "(the server returned no progress detail)"
	}
	var parts []string
	for _, p := range progress {
		if p == nil {
			continue
		}
		for _, r := range p.UpdateSyncProgressRegions {
			if r == nil {
				continue
			}
			parts = append(parts,
				fmt.Sprintf("%s/%s total=%d status=%d",
					derefStr(p.ResourceType), derefStr(r.Region), derefI64(r.TotalCount), derefI64(r.Status)))
		}
	}
	if len(parts) == 0 {
		return fmt.Sprintf("(%d resource types, but no per-region detail)", len(progress))
	}
	return strings.Join(parts, "; ")
}

func derefStr(s *string) string {
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
