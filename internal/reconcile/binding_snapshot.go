package reconcile

import (
	"github.com/susunola/wecert/internal/deploy"
	"github.com/susunola/wecert/internal/inventory"
	"time"
)

// BindingSnapshot implements webhook.BindingReader. The rows were cached the
// last time a Bindings poll finished a bind-resource task.
//
// The observation instant travels with them: rows without it are served as if they
// had just been read, which is how a memo from an hour ago becomes a page that
// claims to know the current binding set.
func (r *Reconciler) BindingSnapshot(certID string) (inventory.Bindings, bool) {
	snap, observedAt, ok := deploy.LookupCachedBindings(certID)
	if !ok {
		return inventory.Bindings{}, false
	}
	out := inventory.Bindings{
		Count:     snap.Count,
		Complete:  snap.Complete,
		Freshness: inventory.FreshnessCached,
		Items:     make([]inventory.BindingItem, 0, len(snap.Items)),
	}
	if !observedAt.IsZero() {
		out.ObservedAt = observedAt.UTC().Format(time.RFC3339)
	}
	for _, row := range snap.Items {
		out.Items = append(out.Items, inventory.BindingItem{
			ResourceType:   row.ResourceType,
			Region:         row.Region,
			LoadBalancerID: row.LoadBalancerID,
			ListenerID:     row.ListenerID,
			Protocol:       row.Protocol,
			Port:           row.Port,
			SNIDomain:      row.SNIDomain,
			Role:           row.Role,
			Complete:       row.Complete,
		})
	}
	return out, true
}
