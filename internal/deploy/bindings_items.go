package deploy

import (
	"strings"

	ssl "github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/ssl/v20191205"
)

// BindingRow is one CLB / listener / SNI binding. It is a view of the SSL
// TaskDetail payload, not a thing the reconciler acts on.
type BindingRow struct {
	ResourceType   string
	Region         string
	LoadBalancerID string
	ListenerID     string
	Protocol       string
	Port           int
	SNIDomain      string
	Role           string
	Complete       bool
}

// BindingSnapshot is what inventory consumes. Freshness is the caller's to set.
type BindingSnapshot struct {
	Count    int
	Complete bool
	Items    []BindingRow
}

// ParseCLBBindingItems turns a DescribeCertificateBindResourceTaskDetail
// response into rows. Bindings() stays count-only; this is the sibling the
// inventory page needs.
//
// complete is false when any CLB region is missing, errored, or lacks
// TotalCount. A zero with complete=false must not be read as "bound nowhere".
func ParseCLBBindingItems(resp *ssl.DescribeCertificateBindResourceTaskDetailResponse, certID string) BindingSnapshot {
	out := BindingSnapshot{Items: []BindingRow{}}
	if resp == nil || resp.Response == nil {
		return out
	}
	r := resp.Response
	if r.Status == nil || *r.Status != bindStatusDone {
		return out
	}

	complete := true
	if len(r.CLB) == 0 {
		// A successful task with no CLB section is an answered zero for CLB,
		// not an unanswered region — other resource types may still be present.
		out.Complete = true
		return out
	}
	for _, region := range r.CLB {
		if region == nil {
			complete = false
			continue
		}
		regName := deref(region.Region)
		if region.Error != nil && *region.Error != "" {
			complete = false
			continue
		}
		if region.TotalCount == nil {
			complete = false
			continue
		}
		listed := 0
		for _, inst := range region.InstanceList {
			if inst == nil {
				complete = false
				continue
			}
			listed++
			lb := deref(inst.LoadBalancerId)
			if len(inst.Listeners) == 0 {
				out.Items = append(out.Items, BindingRow{
					ResourceType:   "clb",
					Region:         regName,
					LoadBalancerID: lb,
					Complete:       true,
				})
				continue
			}
			for _, lis := range inst.Listeners {
				if lis == nil {
					complete = false
					continue
				}
				rows := rowsForListener(regName, lb, lis, certID)
				out.Items = append(out.Items, rows...)
			}
		}
		if int(*region.TotalCount) > listed {
			complete = false
		}
	}
	out.Count = len(out.Items)
	out.Complete = complete
	return out
}

func rowsForListener(region, lb string, lis *ssl.ClbListener, certID string) []BindingRow {
	base := BindingRow{
		ResourceType:   "clb",
		Region:         region,
		LoadBalancerID: lb,
		ListenerID:     deref(lis.ListenerId),
		Protocol:       deref(lis.Protocol),
		Complete:       true,
		Role:           roleOf(lis.Certificate, certID),
	}
	if len(lis.Rules) == 0 {
		return []BindingRow{base}
	}
	var rows []BindingRow
	for _, rule := range lis.Rules {
		if rule == nil {
			continue
		}
		row := base
		row.SNIDomain = deref(rule.Domain)
		if rule.Certificate != nil {
			row.Role = roleOf(rule.Certificate, certID)
		}
		rows = append(rows, row)
	}
	if len(rows) == 0 {
		return []BindingRow{base}
	}
	return rows
}

func roleOf(cert *ssl.Certificate, want string) string {
	if cert == nil || want == "" || cert.CertId == nil {
		return ""
	}
	if strings.EqualFold(*cert.CertId, want) {
		return "primary"
	}
	return "ext"
}

func deref(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}
