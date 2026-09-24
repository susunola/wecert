package deploy

import (
	"context"
	"fmt"
	"sort"

	"github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common"
	ssl "github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/ssl/v20191205"
)

// PatrolKind classifies one binding-patrol finding.
//
// The console maps these to the three words an operator actually uses: confirmed /
// incomplete / drift. "orphan_upload" and "unmanaged" are both forms of drift -- a
// cloud certificate that is not the one this deployment believes it is serving.
type PatrolKind string

const (
	// PatrolConfirmed: the certificate's binding enumeration is complete and it is
	// bound to at least one resource.
	PatrolConfirmed PatrolKind = "confirmed"
	// PatrolIncomplete: the enumeration could not finish (region error, missing
	// TotalCount). The binding count is a lower bound, not the whole answer.
	PatrolIncomplete PatrolKind = "incomplete"
	// PatrolDrift: state says this cert is deployed but the cloud says it is bound
	// nowhere (a manual unbind), or the enumeration disagrees with what was recorded.
	PatrolDrift PatrolKind = "drift"
	// PatrolOrphanUpload: an uploaded certificate with no state row and no bindings
	// -- usually a deploy that died between Upload and the resume-anchor write.
	PatrolOrphanUpload PatrolKind = "orphan_upload"
	// PatrolUnmanaged: an uploaded certificate this deployment never recorded (a
	// console upload or another client).
	PatrolUnmanaged PatrolKind = "unmanaged"
)

// PatrolFinding is one row of the periodic full-binding check.
type PatrolFinding struct {
	Kind     PatrolKind
	CertID   string
	CertName string
	Detail   string
	Items    []BindingRow
	Complete bool
}

// KnownCert is what the state store believes is deployed.
type KnownCert struct {
	Name         string
	DeployedID   string
	DeployedName string
}

// PatrolBindings enumerates the account's uploaded certificates and each known
// certificate's live bindings, then classifies every gap between that and the state
// store's view.
//
// Rate-limited by the caller (the reconciler runs this on an interval, not every
// pass): DescribeCertificates + one bind-resource task per certificate is an API
// storm on a large account if it is left at the pass rate.
//
// It is read-only. Nothing here unbinds, deletes or re-uploads -- a manual console
// change is reported so a human decides, which is the only safe response to "someone
// swapped the certificate behind my back".
func (d *TencentCLB) PatrolBindings(ctx context.Context, known []KnownCert) ([]PatrolFinding, error) {
	client, err := d.client(ctx)
	if err != nil {
		return nil, err
	}
	cloud, err := listUploadedCertificates(ctx, client)
	if err != nil {
		return nil, err
	}

	inState := map[string]KnownCert{}
	for _, k := range known {
		if k.DeployedID != "" {
			inState[k.DeployedID] = k
		}
	}

	var out []PatrolFinding
	for _, k := range known {
		if k.DeployedID == "" {
			continue
		}
		snap, err := d.bindingItemsWith(ctx, client, k.DeployedID, false)
		if err != nil {
			out = append(out, PatrolFinding{
				Kind:     PatrolIncomplete,
				CertID:   k.DeployedID,
				CertName: k.Name,
				Detail:   fmt.Sprintf("binding enumeration failed: %v", err),
			})
			continue
		}
		switch {
		case !snap.Complete:
			out = append(out, PatrolFinding{
				Kind: PatrolIncomplete, CertID: k.DeployedID, CertName: k.Name,
				Detail:   "binding enumeration is incomplete; the count is a lower bound",
				Items:    snap.Items,
				Complete: false,
			})
		case snap.Count == 0:
			out = append(out, PatrolFinding{
				Kind: PatrolDrift, CertID: k.DeployedID, CertName: k.Name,
				Detail: "state says this certificate is deployed but the cloud reports no " +
					"binding: someone unbound it in the console (or the rebind never happened)",
				Items: snap.Items, Complete: true,
			})
		default:
			out = append(out, PatrolFinding{
				Kind: PatrolConfirmed, CertID: k.DeployedID, CertName: k.Name,
				Detail: fmt.Sprintf("bound to %d resource(s)", snap.Count),
				Items:  snap.Items, Complete: true,
			})
		}
	}

	// Cloud certificates this deployment never named. Sorted so a report is stable.
	ids := make([]string, 0, len(cloud))
	for id := range cloud {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		if _, knownID := inState[id]; knownID {
			continue
		}
		kind := PatrolUnmanaged
		detail := "uploaded certificate this deployment never recorded (console upload or another client)"
		if cloud[id] == "" {
			kind = PatrolOrphanUpload
			detail = "uploaded certificate with no remark and no state row: likely a deploy that " +
				"died between upload and the resume anchor"
		}
		out = append(out, PatrolFinding{
			Kind:   kind,
			CertID: id,
			Detail: detail,
		})
	}
	return out, nil
}

// bindingItemsWith is the full-row form of bindingsWith (see ParseCLBBindingItems).
func (d *TencentCLB) bindingItemsWith(ctx context.Context, client sslAPI, certID string, cached bool) (BindingSnapshot, error) {
	if certID == "" {
		return BindingSnapshot{Items: []BindingRow{}}, nil
	}
	if cached {
		if snap, at, ok := LookupCachedBindings(certID); ok && !at.IsZero() {
			return snap, nil
		}
	}
	// Reuse the existing refresh path so task creation / polling / caching stay in one place.
	n, err := d.bindingsWith(ctx, client, certID, false)
	if err != nil {
		return BindingSnapshot{}, err
	}
	if snap, _, ok := LookupCachedBindings(certID); ok {
		snap.Count = n.count
		snap.Complete = n.complete
		return snap, nil
	}
	return BindingSnapshot{Count: n.count, Complete: n.complete, Items: []BindingRow{}}, nil
}

// listUploadedCertificates pages DescribeCertificates (filterSource=upload) and returns
// certId -> remark name. The remark is how a wecert upload identifies itself
// ("wecert/<certificate name>"); an empty remark is the orphan-upload fingerprint.
func listUploadedCertificates(ctx context.Context, client sslAPI) (map[string]string, error) {
	out := map[string]string{}
	var offset uint64
	const limit uint64 = 100
	for {
		req := ssl.NewDescribeCertificatesRequest()
		req.Offset = common.Uint64Ptr(offset)
		req.Limit = common.Uint64Ptr(limit)
		upload := int64(1)
		req.Upload = &upload
		resp, err := client.DescribeCertificatesWithContext(ctx, req)
		if err != nil {
			return nil, fmt.Errorf("list uploaded certificates: %w", sdkCallError(ctx, "DescribeCertificates", err))
		}
		if resp == nil || resp.Response == nil {
			return nil, fmt.Errorf("list uploaded certificates: empty response")
		}
		list := resp.Response.Certificates
		for _, c := range list {
			if c == nil || c.CertificateId == nil {
				continue
			}
			name := ""
			if c.Alias != nil {
				name = *c.Alias
			}
			out[*c.CertificateId] = name
		}
		if uint64(len(list)) < limit {
			break
		}
		offset += limit
		if resp.Response.TotalCount != nil && offset >= *resp.Response.TotalCount {
			break
		}
	}
	return out, nil
}

// PatrolKindForConsole is the three-word console status the read-only page shows.
func PatrolKindForConsole(k PatrolKind) string {
	switch k {
	case PatrolConfirmed:
		return "confirmed"
	case PatrolIncomplete:
		return "incomplete"
	default:
		return "drift"
	}
}
