package deploy

import (
	"context"
	"fmt"

	clb "github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/clb/v20180317"
	"github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common"
)

// listenerBindingsForCert reports where certID is bound, by reading CLB directly in every
// configured region.
//
// Why this exists (measured 2026-09-28, ap-singapore, lb-hsj1v9eq / listener lbl-mt59gog6):
//
// The SSL bind-resource enumeration (CreateCertificateBindResourceSyncTask then
// DescribeCertificateBindResourceTaskResult / DescribeCertificateBindResourceTaskDetail)
// anchors on the certificate's PRIMARY slot. A certificate that is bound only as an SNI
// extension (Listener.Certificate.ExtCertIds) is reported as "bound nowhere": with
// Certificate.CertId=b9Z14O6y and Certificate.ExtCertIds=["b9USe8CP"] on the same listener,
// the task returned clb/ap-singapore=1 for b9Z14O6y and every region TotalCount=0 for
// b9USe8CP -- while clb:DescribeListeners returns the extension ID verbatim, and the
// TaskDetail payload for the primary lists the same listener.
//
// Without this fallback the reconciler never confirms such a certificate (confirmBinding
// only sees n == 0, so it stays at waiting_manual_bind for the certificate's whole
// lifetime) and the read-only inventory shows it as not bound.
//
// The scan is read-only -- DescribeLoadBalancers and DescribeListeners, both of which the
// shipped runtime CAM policy already allows.
func (d *TencentCLB) listenerBindingsForCert(ctx context.Context, certID string) (BindingSnapshot, error) {
	out := BindingSnapshot{Items: []BindingRow{}}
	if certID == "" {
		out.Complete = true
		return out, nil
	}
	cred, err := d.credential(ctx)
	if err != nil {
		return out, err
	}
	if len(d.regions) == 0 {
		// No region list means nothing can be enumerated, and a complete zero here would
		// claim "bound nowhere" -- the one answer this scan must never fake.
		out.Complete = false
		return out, fmt.Errorf("no regions configured: cannot scan CLB listeners for %s", certID)
	}

	complete := true
	for _, region := range d.regions {
		api, err := newCLBClient(cred, region)
		if err != nil {
			return out, fmt.Errorf("build CLB client for %s: %w", region, err)
		}
		rows, regionComplete, err := scanCLBRegionForCert(ctx, api, region, certID)
		if err != nil {
			// One region failing cannot be read as "bound nowhere": keep the rows found so
			// far, mark the walk incomplete and let the caller treat the answer as a lower
			// bound (the same rule the SSL enumeration follows).
			d.logger().Warn("could not scan CLB listeners in one region; the listener fallback is a lower bound",
				"certId", certID, "region", region, "err", err)
			complete = false
			continue
		}
		if !regionComplete {
			complete = false
		}
		out.Items = append(out.Items, rows...)
	}
	out.Count = len(out.Items)
	out.Complete = complete
	return out, nil
}

// scanCLBRegionForCert walks every load balancer and its listeners in one region.
//
// complete is false when a page of load balancers came back short or a listener listing
// could not be read, so a partial walk is never mistaken for "bound nowhere".
func scanCLBRegionForCert(ctx context.Context, api clbAPI, region, certID string) ([]BindingRow, bool, error) {
	var (
		rows     []BindingRow
		complete = true
		offset   int
	)
	const limit = 100
	for {
		req := clb.NewDescribeLoadBalancersRequest()
		req.Offset = i64Ptr(int64(offset))
		req.Limit = i64Ptr(limit)
		resp, err := api.DescribeLoadBalancersWithContext(ctx, req)
		if err != nil {
			return rows, false, fmt.Errorf("DescribeLoadBalancers: %w", err)
		}
		if resp == nil || resp.Response == nil {
			return rows, false, fmt.Errorf("DescribeLoadBalancers: empty response")
		}

		set := resp.Response.LoadBalancerSet
		for _, lb := range set {
			if lb == nil {
				complete = false
				continue
			}
			lbID := deref(lb.LoadBalancerId)
			lreq := clb.NewDescribeListenersRequest()
			lreq.LoadBalancerId = common.StringPtr(lbID)
			lresp, err := api.DescribeListenersWithContext(ctx, lreq)
			if err != nil {
				return rows, false, fmt.Errorf("DescribeListeners(%s): %w", lbID, err)
			}
			if lresp == nil || lresp.Response == nil {
				complete = false
				continue
			}
			for _, lis := range lresp.Response.Listeners {
				rows = append(rows, rowsForCertOnListener(region, lbID, lis, certID)...)
			}
		}

		total := uint64(0)
		if resp.Response.TotalCount != nil {
			total = *resp.Response.TotalCount
		}
		offset += len(set)
		if len(set) == 0 || uint64(offset) >= total {
			break
		}
	}
	return rows, complete, nil
}

// rowsForCertOnListener turns one listener into the rows that mention certID.
//
// All three slots are checked because they are independent: the listener's primary
// certificate, its SNI extensions (ExtCertIds) and each forwarding rule's certificate.
// A renewal switches exactly one of them, so a certificate that lives in the extension
// slot must be visible as such.
func rowsForCertOnListener(region, lbID string, lis *clb.Listener, certID string) []BindingRow {
	if lis == nil || certID == "" {
		return nil
	}
	base := BindingRow{
		ResourceType:   "clb",
		Region:         region,
		LoadBalancerID: lbID,
		ListenerID:     deref(lis.ListenerId),
		Protocol:       deref(lis.Protocol),
		Port:           int(derefI64(lis.Port)),
		Complete:       true,
	}

	var rows []BindingRow
	if cert := lis.Certificate; cert != nil {
		if deref(cert.CertId) == certID {
			rows = append(rows, withRole(base, "primary"))
		}
		for _, ext := range cert.ExtCertIds {
			if deref(ext) == certID {
				rows = append(rows, withRole(base, "ext"))
			}
		}
	}
	for _, rule := range lis.Rules {
		if rule == nil || rule.Certificate == nil {
			continue
		}
		row := base
		row.SNIDomain = deref(rule.Domain)
		if deref(rule.Certificate.CertId) == certID {
			rows = append(rows, withRole(row, "rule"))
		}
		for _, ext := range rule.Certificate.ExtCertIds {
			if deref(ext) == certID {
				rows = append(rows, withRole(row, "ext"))
			}
		}
	}
	return rows
}

func withRole(row BindingRow, role string) BindingRow {
	row.Role = role
	return row
}

// i64Ptr exists because the CLB request fields are *int64 while the offsets this scan
// keeps are plain ints. (common.IntPtr returns *int and does not fit those fields.)
func i64Ptr(v int64) *int64 {
	return &v
}
