package inventory

// ApplyLiveBindings copies a parsed bind-resource snapshot onto a row.
// Freshness defaults to cached: the page must not pretend the walk just happened.
func ApplyLiveBindings(row *Certificate, live Bindings) {
	if row == nil {
		return
	}
	row.Bindings = live
	if row.Bindings.Items == nil {
		row.Bindings.Items = []BindingItem{}
	}
	if row.Bindings.Freshness == "" {
		row.Bindings.Freshness = FreshnessCached
	}
	if !live.Complete {
		row.Drift = appendUnique(row.Drift, DriftBindingIncomplete)
	}
}
